// Command mcpecho is a development MCP server over Streamable HTTP with an
// `echo` tool that reports the caller's ANS identity as the gateway forwarded it
// (plus the instance headers for an instance-mode caller),
// and a `secret` tool that gateway authorization should keep callers from.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const readHeaderTimeout = 5 * time.Second

type echoArgs struct {
	Text string `json:"text"`
}

type echoResult struct {
	Text        string `json:"text"`
	AnsName     string `json:"ansName"`
	JKT         string `json:"jkt,omitempty"`
	InstanceSub string `json:"instanceSub,omitempty"`
	Act         string `json:"act,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

type secretResult struct {
	Value string `json:"value"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:3001", "address to listen on")
	flag.Parse()

	server := mcp.NewServer(&mcp.Implementation{Name: "ans-mcpecho", Version: "0.0.1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "echo", Description: "Echoes text and the caller's ANS name."},
		func(_ context.Context, req *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, echoResult, error) {
			out := echoResult{Text: in.Text}
			if req.Extra != nil && req.Extra.Header != nil {
				h := req.Extra.Header
				out.AnsName, out.JKT = h.Get("X-ANS-Name"), h.Get("X-ANS-JKT")
				// Set by the verifier only for instance-mode callers.
				out.InstanceSub, out.Act, out.Scope = h.Get("X-ANS-Instance-Sub"), h.Get("X-ANS-Act"), h.Get("X-ANS-Scope")
			}
			return nil, out, nil
		})
	mcp.AddTool(server, &mcp.Tool{Name: "secret", Description: "Must be denied by the gateway's mcpAuthorization rules."},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, secretResult, error) {
			return nil, secretResult{Value: "s3cr3t"}, nil
		})

	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil))
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: readHeaderTimeout}
	log.Printf("mcp echo upstream listening on http://%s/mcp", *listen)
	log.Fatal(srv.ListenAndServe())
}
