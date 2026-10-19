//go:build e2e

package agentrouter

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type echoArgs struct {
	Text string `json:"text"`
}

type echoResult struct {
	Text string `json:"text"`
}

type sumArgs struct {
	A int `json:"a"`
	B int `json:"b"`
}

type sumResult struct {
	Sum int `json:"sum"`
}

// toolServer is a minimal MCP server (Streamable HTTP) with two tools. It records the HTTP
// headers of every tool call so tests can see which identity headers the gateway forwarded.
type toolServer struct {
	mu      sync.Mutex
	headers []http.Header
	server  *http.Server
	port    int
}

func startToolServer(t *testing.T) *toolServer {
	t.Helper()
	ts := &toolServer{}
	srv := mcp.NewServer(&mcp.Implementation{Name: "tools", Version: "0.1.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "returns its input"},
		func(_ context.Context, req *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, echoResult, error) {
			ts.record(req)
			return nil, echoResult(in), nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "sum", Description: "adds two integers"},
		func(_ context.Context, req *mcp.CallToolRequest, in sumArgs) (*mcp.CallToolResult, sumResult, error) {
			ts.record(req)
			return nil, sumResult{Sum: in.A + in.B}, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ts.port = lis.Addr().(*net.TCPAddr).Port
	ts.server = &http.Server{Handler: handler}
	go func() { _ = ts.server.Serve(lis) }()
	t.Cleanup(func() { _ = ts.server.Close() })
	return ts
}

func (ts *toolServer) record(req *mcp.CallToolRequest) {
	if req == nil || req.Extra == nil {
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.headers = append(ts.headers, req.Extra.Header.Clone())
}

func (ts *toolServer) callCount() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.headers)
}

func (ts *toolServer) lastHeaders() http.Header {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.headers) == 0 {
		return nil
	}
	return ts.headers[len(ts.headers)-1]
}
