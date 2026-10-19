//go:build e2e

package agentgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mcpPort            = 3000
	mcpUpstreamPort    = 3001
	exampleMCPYAML     = "examples/agentgateway/config-mcp.yaml"
	mcpRulePlaceholder = "ans://v1.0.0.caller.example"
)

type echoArgs struct {
	Text string `json:"text"`
}

type echoResult struct {
	Text    string `json:"text"`
	AnsName string `json:"ansName"`
}

type secretResult struct {
	Value string `json:"value"`
}

// mcpUpstream is an in-test MCP server over Streamable HTTP with an `echo`
// tool that reports the identity header it received and a `secret` tool the
// gateway must keep callers away from.
type mcpUpstream struct {
	mu      sync.Mutex
	headers []http.Header
}

func (u *mcpUpstream) record(h http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.headers = append(u.headers, h.Clone())
}

func startMCPUpstream(t *testing.T) *mcpUpstream {
	t.Helper()
	u := &mcpUpstream{}
	server := mcp.NewServer(&mcp.Implementation{Name: "ans-e2e-upstream", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Echoes text and the caller's ANS name."},
		func(_ context.Context, req *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, echoResult, error) {
			var name string
			if req.Extra != nil && req.Extra.Header != nil {
				u.record(req.Extra.Header)
				name = req.Extra.Header.Get(identityNameHdr)
			}
			return nil, echoResult{Text: in.Text, AnsName: name}, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "secret", Description: "Must not be reachable through the gateway."},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, secretResult, error) {
			return nil, secretResult{Value: "s3cr3t"}, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", mcpUpstreamPort), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	lis, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("mcp upstream listen: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return u
}

// signingTransport attaches the agent identity to every outgoing request,
// cloning first so the retrying MCP client never sees a mutated request.
type signingTransport struct {
	s    *signer
	base http.RoundTripper
}

func (st *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		c.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := pop.AttachIdentity(c, st.s.sign, st.s.scitt); err != nil {
		return nil, err
	}
	return st.base.RoundTrip(c)
}

func mcpSession(ctx context.Context, t *testing.T, client *http.Client) (*mcp.ClientSession, error) {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "ans-e2e-client", Version: "0.0.1"}, nil)
	return c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort),
		HTTPClient: client,
	}, nil)
}

func structured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structured content %s: %v", raw, err)
	}
	return out
}

func TestAgentgatewayMCP(t *testing.T) {
	e := loadEnv(t)
	requireFreePorts(t, mcpPort, mcpUpstreamPort, verifierGRPC, verifierHTTP, agwAdminPort, agwStatsPort, agwReadyPort)
	ensureStack(t, e)
	ag := provisionAgent(t, e)
	other := provisionAgent(t, e)

	dir := t.TempDir()
	bin := buildVerifier(t, e, dir)
	cfgPath := writeFile(t, dir, "ans-authz.yaml", renderVerifierConfig(e.tlURL, ag.rootKeys, false))
	upstream := startMCPUpstream(t)
	startProc(t, "ans-authz", fmt.Sprintf("http://127.0.0.1:%d/readyz", verifierHTTP), e.repoRoot, bin, "--config", cfgPath)

	src, err := os.ReadFile(filepath.Join(e.repoRoot, exampleMCPYAML))
	if err != nil {
		t.Fatal(err)
	}
	recipe := mustReplace(t, string(src), mcpRulePlaceholder, ag.ansName)
	startGateway(t, e, writeFile(t, dir, "config-mcp.yaml", recipe))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	signed := &http.Client{Transport: &signingTransport{s: newSigner(t, ag), base: http.DefaultTransport}}

	t.Run("signed client initializes, lists tools and calls echo with its identity", func(t *testing.T) {
		session, err := mcpSession(ctx, t, signed)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer session.Close()
		tools, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("tools/list: %v", err)
		}
		names := make([]string, 0, len(tools.Tools))
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		if !strings.Contains(strings.Join(names, ","), "echo") {
			t.Fatalf("tools = %v, want echo", names)
		}
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: echoArgs{Text: "hello"}})
		if err != nil {
			t.Fatalf("tools/call echo: %v", err)
		}
		if res.IsError {
			t.Fatalf("echo returned an error result: %+v", res.Content)
		}
		out := structured[echoResult](t, res)
		if out.Text != "hello" || out.AnsName != ag.ansName {
			t.Fatalf("echo result = %+v, want text hello from %s", out, ag.ansName)
		}
		upstream.mu.Lock()
		defer upstream.mu.Unlock()
		for _, h := range upstream.headers {
			for _, stripped := range []string{"Dpop", "X-Scitt-Receipt", "X-Ans-Status-Token"} {
				if h.Get(stripped) != "" {
					t.Fatalf("header %s reached the MCP upstream", stripped)
				}
			}
		}
	})

	t.Run("secret tool is denied by mcpAuthorization", func(t *testing.T) {
		session, err := mcpSession(ctx, t, signed)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer session.Close()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "secret", Arguments: map[string]any{}})
		if err == nil && !res.IsError {
			t.Fatalf("secret succeeded: %+v", structured[secretResult](t, res))
		}
		if err == nil {
			for _, c := range res.Content {
				if tc, ok := c.(*mcp.TextContent); ok && strings.Contains(tc.Text, "s3cr3t") {
					t.Fatal("secret value leaked through an error result")
				}
			}
		}
	})

	t.Run("another verified agent is not authorized for echo", func(t *testing.T) {
		otherClient := &http.Client{Transport: &signingTransport{s: newSigner(t, other), base: http.DefaultTransport}}
		session, err := mcpSession(ctx, t, otherClient)
		if err != nil {
			t.Fatalf("connect as other agent: %v", err)
		}
		defer session.Close()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: echoArgs{Text: "x"}})
		if err == nil && !res.IsError {
			t.Fatalf("echo succeeded for %s: %+v", other.ansName, structured[echoResult](t, res))
		}
	})

	t.Run("client without identity is challenged", func(t *testing.T) {
		if _, err := mcpSession(ctx, t, http.DefaultClient); err == nil {
			t.Fatal("connect without identity succeeded")
		}
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/mcp", mcpPort),
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, respBody := do(t, req)
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != dpopChallenge {
			t.Fatalf("status = %d WWW-Authenticate = %q body %s", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), respBody)
		}
	})
}
