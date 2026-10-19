//go:build e2e

package agentrouter

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

var chatBody = []byte(`{"model":"test-model","messages":[{"role":"user","content":"hello"}]}`)

// TestStandaloneWiring proves the Envoy Gateway seam under `aigw run` with an allow-all stub in
// place of the verifier: a Backend-kind gRPC ext_authz service receives the body and the
// context-extension sentinel, verifier-set headers overwrite client copies and drive the
// authorization rule, denials pass through with their challenge, oversize bodies stop at the
// gateway, and a verifier outage is reported as 503 rather than as a denial.
func TestStandaloneWiring(t *testing.T) {
	requireFixedPortsFree(t)
	bin := aigwBinary(t)
	upstream := startMockUpstream(t)
	stub := startStubAuthz(t)

	const maxBody = 4096
	config := filepath.Join(repoRoot(t), "examples", "agent-router", "standalone", "aigw-ans-llm.yaml")
	proc := startAigw(t, bin, config, map[string]string{
		"AIGW_PORT":            strconv.Itoa(gatewayPort),
		"UPSTREAM_PORT":        strconv.Itoa(upstream.port),
		"ANS_AUTHZ_PORT":       portOf(t, stub.addr),
		"ANS_MAX_BODY":         strconv.Itoa(maxBody),
		"ANS_ALLOWED_AGENT_ID": spikeAgentID,
	})
	waitUntil(t, proc, "gateway to route a chat completion", func() error {
		return probe(chatRequest(t, chatBody, nil), 200)
	})

	t.Run("allow forwards body and sets identity headers", func(t *testing.T) {
		res := send(t, chatRequest(t, chatBody, nil))
		if res.Status != 200 {
			t.Fatalf("status %d, body %s", res.Status, res.Body)
		}
		up := upstream.lastRequest()
		if up == nil {
			t.Fatal("upstream saw no request")
		}
		if got := up.Header.Get("X-Ans-Spike"); got != "ok" {
			t.Errorf("x-ans-spike at upstream = %q, want ok", got)
		}
		if got := up.Header.Get("X-Ans-Agent-Id"); got != spikeAgentID {
			t.Errorf("x-ans-agent-id at upstream = %q, want %q", got, spikeAgentID)
		}
		if !bytes.Equal(up.Body, chatBody) {
			t.Errorf("upstream body = %s, want %s", up.Body, chatBody)
		}
		check := stub.lastRequest()
		if check == nil {
			t.Fatal("stub saw no check request")
		}
		http := check.GetAttributes().GetRequest().GetHttp()
		if got := http.GetBody(); got != string(chatBody) {
			t.Errorf("check body = %q, want %q", got, chatBody)
		}
		if got := http.GetMethod(); got != "POST" {
			t.Errorf("check method = %q", got)
		}
		if got := http.GetPath(); got != "/v1/chat/completions" {
			t.Errorf("check path = %q", got)
		}
		if got := http.GetHost(); got != "127.0.0.1:"+strconv.Itoa(gatewayPort) {
			t.Errorf("check host = %q", got)
		}
		if got := check.GetAttributes().GetContextExtensions()["ans-authz"]; got != "body-forwarded" {
			t.Errorf("context extension ans-authz = %q, want body-forwarded", got)
		}
	})

	t.Run("client-supplied identity header is overwritten", func(t *testing.T) {
		res := send(t, chatRequest(t, chatBody, map[string]string{"X-ANS-Agent-Id": "attacker", "X-ANS-Spike": "forged"}))
		if res.Status != 200 {
			t.Fatalf("status %d, body %s", res.Status, res.Body)
		}
		up := upstream.lastRequest()
		if got := up.Header.Get("X-Ans-Agent-Id"); got != spikeAgentID {
			t.Errorf("x-ans-agent-id at upstream = %q, want %q", got, spikeAgentID)
		}
		if got := up.Header.Values("X-Ans-Spike"); len(got) != 1 || got[0] != "ok" {
			t.Errorf("x-ans-spike at upstream = %v, want [ok]", got)
		}
	})

	t.Run("authorization denies an identity the rule does not list", func(t *testing.T) {
		stub.setMode(stubAllowWithoutIdentity)
		defer stub.setMode(stubAllowWithIdentity)
		before := upstream.count()
		res := send(t, chatRequest(t, chatBody, nil))
		if res.Status != 403 {
			t.Fatalf("status %d, want 403; body %s", res.Status, res.Body)
		}
		if upstream.count() != before {
			t.Error("denied request reached the upstream")
		}
	})

	t.Run("verifier denial passes through with its challenge", func(t *testing.T) {
		stub.setMode(stubDeny)
		defer stub.setMode(stubAllowWithIdentity)
		res := send(t, chatRequest(t, chatBody, nil))
		if res.Status != 401 {
			t.Fatalf("status %d, want 401; body %s", res.Status, res.Body)
		}
		if got := res.Header.Get("WWW-Authenticate"); got != `DPoP algs="ES256"` {
			t.Errorf("WWW-Authenticate = %q", got)
		}
		if !strings.Contains(string(res.Body), "MISSING_HEADERS") {
			t.Errorf("body = %s", res.Body)
		}
	})

	t.Run("body above the cap is rejected before the check", func(t *testing.T) {
		before := len(stubRequests(stub))
		big := []byte(`{"model":"test-model","messages":[{"role":"user","content":"` + strings.Repeat("x", maxBody) + `"}]}`)
		res := send(t, chatRequest(t, big, nil))
		if res.Status != 413 {
			t.Fatalf("status %d, want 413; body %s", res.Status, res.Body)
		}
		if got := len(stubRequests(stub)); got != before {
			t.Errorf("stub received %d extra check(s) for an oversize body", got-before)
		}
	})

	t.Run("verifier outage is reported as 503", func(t *testing.T) {
		stub.Stop()
		res := send(t, chatRequest(t, chatBody, nil))
		if res.Status != 503 {
			t.Fatalf("status %d, want 503; body %s", res.Status, res.Body)
		}
	})
}

func stubRequests(s *stubAuthz) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.requests))
	for i, r := range s.requests {
		out[i] = r.GetAttributes().GetRequest().GetHttp().GetPath()
	}
	return out
}
