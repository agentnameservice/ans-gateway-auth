//go:build e2e

package agentrouter

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const chatCompletion = `{"id":"chatcmpl-e2e","object":"chat.completion","created":1700000000,"model":"test-model",` +
	`"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],` +
	`"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`

type recordedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// mockUpstream is an OpenAI-shaped upstream that records what the gateway forwards and
// answers every chat completion with a fixed, well-formed response.
type mockUpstream struct {
	mu       sync.Mutex
	requests []recordedRequest
	server   *http.Server
	port     int
}

func startMockUpstream(t *testing.T) *mockUpstream {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	m := &mockUpstream{port: lis.Addr().(*net.TCPAddr).Port}
	m.server = &http.Server{Handler: m}
	go func() { _ = m.server.Serve(lis) }()
	t.Cleanup(func() { _ = m.server.Close() })
	return m
}

// bigResponseHeader asks the mock for a response larger than any body cap the tests configure,
// so the gateway's response-buffer behaviour can be observed.
const bigResponseHeader = "X-E2e-Big-Response"

func (m *mockUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.requests = append(m.requests, recordedRequest{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get(bigResponseHeader) != "" {
		filler := strings.Repeat("x", 2<<20)
		_, _ = w.Write([]byte(`{"id":"chatcmpl-big","object":"chat.completion","created":1700000000,"model":"test-model",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"` + filler + `"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`))
		return
	}
	_, _ = w.Write([]byte(chatCompletion))
}

func (m *mockUpstream) lastRequest() *recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		return nil
	}
	r := m.requests[len(m.requests)-1]
	return &r
}

func (m *mockUpstream) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}
