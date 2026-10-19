//go:build e2e

package agentrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// accessLogFlushTimeout bounds the wait for an access-log entry: Envoy flushes file sinks on a
// ten-second interval by default.
const accessLogFlushTimeout = 20 * time.Second

type routeEnv struct {
	ids      identities
	upstream *mockUpstream
	verifier *process
	proc     *process
	url      string
}

// TestAIGatewayRoute_DPoP runs the real verifier binary behind Agent Router's standalone LLM
// recipe and exercises ANS-6 Method B end to end: a signed request is admitted with its verified
// identity attached, and unsigned, replayed, tampered, misdirected, untrusted and unauthorized
// requests are rejected with the status and challenge the recipe documents.
func TestAIGatewayRoute_DPoP(t *testing.T) {
	env := startLLMRoute(t)
	cases := []struct {
		name string
		run  func(*testing.T, *routeEnv)
	}{
		{"unsigned request is challenged", caseUnsigned},
		{"signed request is admitted with its identity", caseSigned},
		{"client-forged identity header is overwritten", caseForgedHeader},
		{"replayed proof is rejected", caseReplay},
		{"body changed after signing is rejected", caseTamperedBody},
		{"proof for another authority is rejected", caseWrongAuthority},
		{"identity from an untrusted log is rejected", caseUntrustedRoot},
		{"missing receipt is rejected", caseMissingReceipt},
		{"verified agent outside the authorization rule gets 403", caseUnauthorizedAgent},
		{"response above the body cap fails on the gateway", caseResponseAboveCap},
		{"rejections appear in the access log", caseAccessLog},
		{"verifier outage is reported as 503", caseVerifierOutage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.run(t, env) })
	}
}

func startLLMRoute(t *testing.T) *routeEnv {
	t.Helper()
	requireFixedPortsFree(t)
	aigw := aigwBinary(t)
	verifierBin := verifierBinary(t)
	env := &routeEnv{ids: provisionIdentities(t), upstream: startMockUpstream(t), url: gatewayURL("/v1/chat/completions")}

	grpcPort, httpPort := freePort(t), freePort(t)
	cfg := writeVerifierConfig(t, []string{env.ids.a.RootKeyC2SP, env.ids.b.RootKeyC2SP}, grpcPort, httpPort)
	env.verifier = startVerifier(t, verifierBin, cfg, httpPort)

	config := filepath.Join(repoRoot(t), "examples", "agent-router", "standalone", "aigw-ans-llm.yaml")
	env.proc = startAigw(t, aigw, config, map[string]string{
		"AIGW_PORT":            strconv.Itoa(gatewayPort),
		"UPSTREAM_PORT":        strconv.Itoa(env.upstream.port),
		"ANS_AUTHZ_PORT":       strconv.Itoa(grpcPort),
		"ANS_ALLOWED_AGENT_ID": agentAID,
	})
	waitUntil(t, env.proc, "gateway to challenge an unsigned request", func() error {
		return probe(chatRequest(t, chatBody, nil), http.StatusUnauthorized)
	})
	return env
}

func signedChat(t *testing.T, env *routeEnv, body []byte, headers map[string]string) *http.Request {
	t.Helper()
	req := chatRequest(t, body, headers)
	if err := env.ids.a.Bundle.Attach(req); err != nil {
		t.Fatal(err)
	}
	return req
}

func requireUnauthorized(t *testing.T, res httpResult, category string) {
	t.Helper()
	if res.Status != http.StatusUnauthorized || !strings.Contains(string(res.Body), category) {
		t.Fatalf("status %d, body %s; want 401 with %s", res.Status, res.Body, category)
	}
}

func caseUnsigned(t *testing.T, _ *routeEnv) {
	res := send(t, chatRequest(t, chatBody, nil))
	requireUnauthorized(t, res, "MISSING_HEADERS")
	if got := res.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "DPoP") {
		t.Errorf("WWW-Authenticate = %q, want a DPoP challenge", got)
	}
}

func caseSigned(t *testing.T, env *routeEnv) {
	res := send(t, signedChat(t, env, chatBody, nil))
	if res.Status != http.StatusOK {
		t.Fatalf("status %d, body %s", res.Status, res.Body)
	}
	up := env.upstream.lastRequest()
	if up == nil {
		t.Fatal("upstream saw no request")
	}
	if !bytes.Equal(up.Body, chatBody) {
		t.Errorf("upstream body = %s", up.Body)
	}
	jkt, err := env.ids.a.Bundle.JKT()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"X-Ans-Name":          agentAName,
		"X-Ans-Agent-Id":      agentAID,
		"X-Ans-Fingerprint":   env.ids.a.Bundle.FingerprintHex(),
		"X-Ans-Jkt":           jkt,
		"X-Ai-Eg-Mcp-Subject": agentAID,
	}
	for k, v := range want {
		if got := up.Header.Get(k); got != v {
			t.Errorf("upstream %s = %q, want %q", k, got, v)
		}
	}
	for _, stripped := range []string{"Dpop", scitt.HeaderReceipt, scitt.HeaderStatusToken} {
		if got := up.Header.Values(stripped); len(got) != 0 {
			t.Errorf("upstream still sees %s = %v", stripped, got)
		}
	}
}

func caseForgedHeader(t *testing.T, env *routeEnv) {
	res := send(t, signedChat(t, env, chatBody, map[string]string{"X-ANS-Name": "ans://v1.0.0.forged.example", "X-ANS-Agent-Id": "forged"}))
	if res.Status != http.StatusOK {
		t.Fatalf("status %d, body %s", res.Status, res.Body)
	}
	up := env.upstream.lastRequest()
	if got := up.Header.Values("X-Ans-Name"); len(got) != 1 || got[0] != agentAName {
		t.Errorf("upstream X-Ans-Name = %v, want [%s]", got, agentAName)
	}
	if got := up.Header.Values("X-Ans-Agent-Id"); len(got) != 1 || got[0] != agentAID {
		t.Errorf("upstream X-Ans-Agent-Id = %v, want [%s]", got, agentAID)
	}
}

func caseReplay(t *testing.T, env *routeEnv) {
	signed, err := env.ids.a.Bundle.Sign(context.Background(), http.MethodPost, env.url, chatBody)
	if err != nil {
		t.Fatal(err)
	}
	first := send(t, withHeaders(chatRequest(t, chatBody, nil), signed))
	if first.Status != http.StatusOK {
		t.Fatalf("first use: status %d, body %s", first.Status, first.Body)
	}
	requireUnauthorized(t, send(t, withHeaders(chatRequest(t, chatBody, nil), signed)), "REPLAY")
}

func caseTamperedBody(t *testing.T, env *routeEnv) {
	signed, err := env.ids.a.Bundle.Sign(context.Background(), http.MethodPost, env.url, chatBody)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(`{"model":"test-model","messages":[{"role":"user","content":"tampered"}]}`)
	requireUnauthorized(t, send(t, withHeaders(chatRequest(t, tampered, nil), signed)), "CONTENT_BINDING_MISMATCH")
}

func caseWrongAuthority(t *testing.T, env *routeEnv) {
	signed, err := env.ids.a.Bundle.Sign(context.Background(), http.MethodPost, "http://other.example:1975/v1/chat/completions", chatBody)
	if err != nil {
		t.Fatal(err)
	}
	requireUnauthorized(t, send(t, withHeaders(chatRequest(t, chatBody, nil), signed)), "HTTP_BINDING_MISMATCH")
}

func caseUntrustedRoot(t *testing.T, env *routeEnv) {
	req := chatRequest(t, chatBody, nil)
	if err := env.ids.c.Bundle.Attach(req); err != nil {
		t.Fatal(err)
	}
	requireUnauthorized(t, send(t, req), "STATUS_INVALID")
}

func caseMissingReceipt(t *testing.T, env *routeEnv) {
	signed, err := env.ids.a.Bundle.Sign(context.Background(), http.MethodPost, env.url, chatBody)
	if err != nil {
		t.Fatal(err)
	}
	signed.Del(scitt.HeaderReceipt)
	requireUnauthorized(t, send(t, withHeaders(chatRequest(t, chatBody, nil), signed)), "MISSING_HEADERS")
}

func caseUnauthorizedAgent(t *testing.T, env *routeEnv) {
	req := chatRequest(t, chatBody, nil)
	if err := env.ids.b.Bundle.Attach(req); err != nil {
		t.Fatal(err)
	}
	before := env.upstream.count()
	res := send(t, req)
	if res.Status != http.StatusForbidden {
		t.Fatalf("status %d, body %s", res.Status, res.Body)
	}
	if env.upstream.count() != before {
		t.Error("denied request reached the upstream")
	}
}

func caseResponseAboveCap(t *testing.T, env *routeEnv) {
	res := send(t, signedChat(t, env, chatBody, map[string]string{bigResponseHeader: "1"}))
	if res.Status != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (Envoy applies the ext_authz body cap to buffered responses); body %.200s", res.Status, res.Body)
	}
	t.Logf("response above cap: details %q", res.Header.Get("X-Envoy-Response-Code-Details"))
}

// caseAccessLog checks that the rejection sink attributes requests from the verifier's dynamic
// metadata: a forged identity header on an unsigned request is not logged as the agent, and a
// verified agent refused by the authorization rule is. Query strings tag the requests, which a
// signed request can carry because htu excludes them.
func caseAccessLog(t *testing.T, env *routeEnv) {
	forged := fmt.Sprintf("forged-%d", time.Now().UnixNano())
	req := chatRequest(t, chatBody, map[string]string{"X-ANS-Name": "ans://v1.0.0.forged.example", "X-ANS-Agent-Id": "forged-agent"})
	req.URL.RawQuery = "log=" + forged
	if res := send(t, req); res.Status != http.StatusUnauthorized {
		t.Fatalf("unsigned forged request: status %d, want 401", res.Status)
	}
	denied := fmt.Sprintf("denied-%d", time.Now().UnixNano())
	req = chatRequest(t, chatBody, nil)
	req.URL.RawQuery = "log=" + denied
	if err := env.ids.b.Bundle.Attach(req); err != nil {
		t.Fatal(err)
	}
	if res := send(t, req); res.Status != http.StatusForbidden {
		t.Fatalf("agent B: status %d, want 403", res.Status)
	}

	entry := waitForAccessLog(t, env.proc, forged)
	if entry["response_code_details"] != "ext_authz_denied" {
		t.Errorf("401 logged with response_code_details %v, want ext_authz_denied", entry["response_code_details"])
	}
	if id, _ := entry["ans.agent_id"].(string); id != "" {
		t.Errorf("forged header was attributed: ans.agent_id = %q, want empty", id)
	}
	entry = waitForAccessLog(t, env.proc, denied)
	if entry["ans.agent_id"] != agentBID {
		t.Errorf("403 logged with ans.agent_id %v, want %q", entry["ans.agent_id"], agentBID)
	}
}

// waitForAccessLog returns the JSON access-log entry whose request path carries tag.
func waitForAccessLog(t *testing.T, p *process, tag string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(accessLogFlushTimeout)
	for {
		for _, line := range strings.Split(p.stdout.String(), "\n") {
			if !strings.HasPrefix(line, "{") || !strings.Contains(line, tag) {
				continue
			}
			var entry map[string]any
			if err := json.Unmarshal([]byte(line), &entry); err == nil {
				return entry
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access-log entry for %q within %s", tag, accessLogFlushTimeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func caseVerifierOutage(t *testing.T, env *routeEnv) {
	env.verifier.stop()
	res := send(t, signedChat(t, env, chatBody, nil))
	if res.Status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503; body %s", res.Status, res.Body)
	}
}

// withHeaders copies pre-signed identity headers onto a request so one signature can be sent
// more than once or against a different body.
func withHeaders(req *http.Request, h http.Header) *http.Request {
	for k, vals := range h {
		req.Header.Del(k)
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	return req
}
