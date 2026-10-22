// Command mcpecho is a development MCP server over Streamable HTTP with an
// `echo` tool that reports the caller's ANS name as the gateway forwarded it,
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
	Text    string `json:"text"`
	AnsName string `json:"ansName"`
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
			var name string
			if req.Extra != nil && req.Extra.Header != nil {
				name = req.Extra.Header.Get("X-ANS-Name")
			}
			return nil, echoResult{Text: in.Text, AnsName: name}, nil
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
