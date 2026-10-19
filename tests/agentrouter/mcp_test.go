//go:build e2e

package agentrouter

import (
	"context"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpEndpoint      = "/mcp"
	mcpProxyURL      = "http://127.0.0.1:9856/mcp"
	mcpRouteHeader   = "x-ai-eg-mcp-route"
	mcpRouteValue    = "default/mcp-ans"
	mcpSubjectHeader = "x-ai-eg-mcp-subject"
	toolsListBody    = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	initializeBody   = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bypass","version":"0"}}}`
)

type mcpEnv struct {
	ids   identities
	tools *toolServer
}

// TestMCPRoute_DPoP drives Agent Router's standalone MCP recipe with the real verifier: a signed
// agent completes the MCP handshake and calls tools, the backend receives the forwarded identity,
// the per-tool rules admit only verified agents and reserve one tool for the listed agent, forged
// identity headers are overwritten, one agent cannot resume another agent's session, and unsigned
// clients are challenged.
func TestMCPRoute_DPoP(t *testing.T) {
	requireFixedPortsFree(t)
	aigw := aigwBinary(t)
	verifierBin := verifierBinary(t)
	env := &mcpEnv{ids: provisionIdentities(t), tools: startToolServer(t)}

	grpcPort, httpPort := freePort(t), freePort(t)
	cfg := writeVerifierConfig(t, []string{env.ids.a.RootKeyC2SP, env.ids.b.RootKeyC2SP}, grpcPort, httpPort)
	startVerifier(t, verifierBin, cfg, httpPort)

	config := filepath.Join(repoRoot(t), "examples", "agent-router", "standalone", "aigw-ans-mcp.yaml")
	proc := startAigw(t, aigw, config, map[string]string{
		"AIGW_PORT":            strconv.Itoa(gatewayPort),
		"MCP_UPSTREAM_PORT":    strconv.Itoa(env.tools.port),
		"ANS_AUTHZ_PORT":       strconv.Itoa(grpcPort),
		"ANS_ALLOWED_AGENT_ID": agentAID,
	})
	waitUntil(t, proc, "MCP route to challenge an unsigned request", func() error {
		return probe(mcpRawRequest(t, gatewayURL(mcpEndpoint), toolsListBody, nil), http.StatusUnauthorized)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var sessionA string
	t.Run("signed agent completes the handshake and calls tools", func(t *testing.T) {
		sess := connectMCP(ctx, t, env.ids.a.Bundle.Transport(nil))
		sessionA = sess.ID()
		names := toolNames(ctx, t, sess)
		for _, want := range []string{"tools__echo", "tools__sum"} {
			if !names[want] {
				t.Errorf("tools/list lacks %s; got %v", want, names)
			}
		}
		callTool(ctx, t, sess, "tools__echo", map[string]any{"text": "hi"}, true)
		h := env.tools.lastHeaders()
		if h == nil {
			t.Fatal("backend recorded no tool call")
		}
		if got := h.Get("X-Ans-Name"); got != agentAName {
			t.Errorf("backend X-Ans-Name = %q, want %q", got, agentAName)
		}
		if got := h.Get("X-Ans-Agent-Id"); got != agentAID {
			t.Errorf("backend X-Ans-Agent-Id = %q, want %q", got, agentAID)
		}
		callTool(ctx, t, sess, "tools__sum", map[string]any{"a": 2, "b": 3}, true)
	})

	t.Run("tool rules admit a verified agent and reserve sum for the listed one", func(t *testing.T) {
		sess := connectMCP(ctx, t, env.ids.b.Bundle.Transport(nil))
		callTool(ctx, t, sess, "tools__echo", map[string]any{"text": "hi"}, true)
		callTool(ctx, t, sess, "tools__sum", map[string]any{"a": 2, "b": 3}, false)
	})

	t.Run("forged agent id header does not satisfy the rule", func(t *testing.T) {
		forging := headerInjector{base: env.ids.b.Bundle.Transport(nil), header: "X-ANS-Agent-Id", value: agentAID}
		sess := connectMCP(ctx, t, forging)
		callTool(ctx, t, sess, "tools__sum", map[string]any{"a": 1, "b": 1}, false)
	})

	t.Run("another agent cannot resume a session", func(t *testing.T) {
		if sessionA == "" {
			t.Skip("no session from the first subtest")
		}
		req := mcpRawRequest(t, gatewayURL(mcpEndpoint), toolsListBody, map[string]string{"Mcp-Session-Id": sessionA})
		if err := env.ids.b.Bundle.Attach(req); err != nil {
			t.Fatal(err)
		}
		if res := send(t, req); res.Status != http.StatusUnauthorized {
			t.Fatalf("agent B resumed agent A's session: status %d, body %.300s", res.Status, res.Body)
		}
	})

	t.Run("forged session subject header does not help", func(t *testing.T) {
		if sessionA == "" {
			t.Skip("no session from the first subtest")
		}
		req := mcpRawRequest(t, gatewayURL(mcpEndpoint), toolsListBody, map[string]string{"Mcp-Session-Id": sessionA, mcpSubjectHeader: agentAID})
		if err := env.ids.b.Bundle.Attach(req); err != nil {
			t.Fatal(err)
		}
		if res := send(t, req); res.Status != http.StatusUnauthorized {
			t.Fatalf("forged %s let agent B resume agent A's session: status %d, body %.300s", mcpSubjectHeader, res.Status, res.Body)
		}
	})

	t.Run("unsigned client is challenged", func(t *testing.T) {
		client := mcp.NewClient(&mcp.Implementation{Name: "e2e-unsigned", Version: "0.1.0"}, nil)
		sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: gatewayURL(mcpEndpoint), HTTPClient: &http.Client{Timeout: 15 * time.Second}}, nil)
		if err == nil {
			_ = sess.Close()
			t.Fatal("unsigned client connected")
		}
		// The go-sdk reports a rejected initialize by HTTP status text, not status code.
		if msg := err.Error(); !strings.Contains(msg, http.StatusText(http.StatusUnauthorized)) && !strings.Contains(msg, "401") {
			t.Errorf("unsigned connect error = %v, want a 401", err)
		}
	})

	t.Run("forged identity without a proof is challenged", func(t *testing.T) {
		req := mcpRawRequest(t, gatewayURL(mcpEndpoint), toolsListBody, map[string]string{"X-ANS-Agent-Id": agentAID, "X-ANS-Name": agentAName})
		res := send(t, req)
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("status %d, body %.300s", res.Status, res.Body)
		}
		if got := res.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "DPoP") {
			t.Errorf("WWW-Authenticate = %q, want the DPoP challenge on the MCP route", got)
		}
	})
}

// TestMCPProxyBypassKnownGap demonstrates that under `aigw run` Agent Router's MCP proxy on port
// 9856 accepts requests that never passed Envoy's ext_authz: an unsigned initialize carrying
// the route header and a forged identity is answered as if authenticated. The recipe's README
// caveat (d) and the Kubernetes NetworkPolicy keep the port unreachable; binding the proxy to
// loopback upstream is a follow-up. The assertion records today's behaviour so a fix is noticed.
func TestMCPProxyBypassKnownGap(t *testing.T) {
	requireFixedPortsFree(t)
	aigw := aigwBinary(t)
	tools := startToolServer(t)
	stub := startStubAuthz(t)
	config := filepath.Join(repoRoot(t), "examples", "agent-router", "standalone", "aigw-ans-mcp.yaml")
	proc := startAigw(t, aigw, config, map[string]string{
		"AIGW_PORT":         strconv.Itoa(gatewayPort),
		"MCP_UPSTREAM_PORT": strconv.Itoa(tools.port),
		"ANS_AUTHZ_PORT":    portOf(t, stub.addr),
	})
	waitUntil(t, proc, "MCP route to be served", func() error {
		return probe(mcpRawRequest(t, gatewayURL(mcpEndpoint), initializeBody, nil), http.StatusOK)
	})

	req := mcpRawRequest(t, mcpProxyURL, initializeBody, map[string]string{mcpRouteHeader: mcpRouteValue, "X-ANS-Agent-Id": agentAID})
	res := send(t, req)
	if res.Status == http.StatusUnauthorized {
		t.Fatalf("the MCP proxy now challenges direct requests (status 401); the known gap is closed, update README caveat (d)")
	}
	if res.Status != http.StatusOK {
		t.Fatalf("direct request to the MCP proxy: status %d, body %.300s", res.Status, res.Body)
	}
	t.Logf("known gap: an unsigned initialize sent straight to %s was answered %d; keep the port unreachable from other hosts and pods", mcpProxyURL, res.Status)
}

func connectMCP(ctx context.Context, t *testing.T, rt http.RoundTripper) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "0.1.0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   gatewayURL(mcpEndpoint),
		HTTPClient: &http.Client{Transport: rt, Timeout: 15 * time.Second},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func toolNames(ctx context.Context, t *testing.T, sess *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := sess.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	names := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	return names
}

func callTool(ctx context.Context, t *testing.T, sess *mcp.ClientSession, name string, args map[string]any, wantAllowed bool) {
	t.Helper()
	_, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	switch {
	case wantAllowed && err != nil:
		t.Fatalf("%s: %v", name, err)
	case !wantAllowed && err == nil:
		t.Fatalf("%s was allowed; the rule should deny it", name)
	case !wantAllowed:
		t.Logf("%s denied as expected: %v", name, err)
	}
}

func mcpRawRequest(t *testing.T, url, body string, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// headerInjector adds a client-controlled header before the signing transport runs, modelling a
// caller that tries to claim another agent's id alongside its own valid proof.
type headerInjector struct {
	base   http.RoundTripper
	header string
	value  string
}

func (h headerInjector) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(h.header, h.value)
	return h.base.RoundTrip(clone)
}
