package identity_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/identity"
)

const target = "https://gateway.example/mcp"

// recorder captures what the authenticated handler saw so that assertions run
// on the test goroutine.
type recorder struct {
	mu      sync.Mutex
	callers []*pop.CallerIdentity
	bodies  []string
}

func (r *recorder) add(id *pop.CallerIdentity, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callers = append(r.callers, id)
	r.bodies = append(r.bodies, string(body))
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.callers)
}

func (r *recorder) last() (*pop.CallerIdentity, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(r.callers)
	return r.callers[n-1], r.bodies[n-1]
}

// newServer starts an httptest server whose handler sits behind pop.Middleware
// and records every authenticated caller.
func newServer(t *testing.T, keys scitt.KeyLookup) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pop.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller in context", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rec.add(id, body)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewUnstartedServer(nil)
	authenticate := pop.Middleware(keys, pop.NewMemoryReplayCache(t.Context(), 0),
		pop.WithTrustedHosts(srv.Listener.Addr().String()),
		pop.WithMiddlewareLogger(slog.New(slog.DiscardHandler)))
	srv.Config.Handler = authenticate(handler)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, rec
}

// newRedirectingServer is newServer with two routes behind the middleware: /old
// answers with a same-host redirect to /new, which records the caller.
func newRedirectingServer(t *testing.T, keys scitt.KeyLookup) (*httptest.Server, *recorder) {
	t.Helper()
	rec := &recorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/old", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/new", http.StatusFound)
	})
	mux.HandleFunc("/new", func(w http.ResponseWriter, r *http.Request) {
		id, ok := pop.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller in context", http.StatusInternalServerError)
			return
		}
		rec.add(id, nil)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewUnstartedServer(nil)
	authenticate := pop.Middleware(keys, pop.NewMemoryReplayCache(t.Context(), 0),
		pop.WithTrustedHosts(srv.Listener.Addr().String()),
		pop.WithMiddlewareLogger(slog.New(slog.DiscardHandler)))
	srv.Config.Handler = authenticate(mux)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, rec
}

// newRedirector starts a plain server that redirects every request to target.
func newRedirector(t *testing.T, target string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newRequest(t *testing.T, method, rawURL string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, rawURL, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

func bodyReader(body string) io.Reader {
	if body == "" {
		return nil
	}
	return strings.NewReader(body)
}

func do(t *testing.T, client *http.Client, req *http.Request) int {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode
}

func assertRecorded(t *testing.T, rec *recorder, wantCount int, wantBody string) {
	t.Helper()
	if n := rec.count(); n != wantCount {
		t.Fatalf("handler ran %d times, want %d", n, wantCount)
	}
	id, body := rec.last()
	if id.AgentID != testAgentID || id.AnsName != testAnsName {
		t.Fatalf("caller = %+v, want %s / %s", id, testAnsName, testAgentID)
	}
	if body != wantBody {
		t.Fatalf("handler body = %q, want %q", body, wantBody)
	}
}

func securityHeaders() []string {
	return []string{pop.DPoPHeader, scitt.HeaderReceipt, scitt.HeaderStatusToken}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAttach(t *testing.T) {
	p := provision(t)
	srv, rec := newServer(t, p.KeyLookup)
	tests := []struct {
		name          string
		method        string
		body          string
		authorization string
		stale         bool
	}{
		{name: "GET", method: http.MethodGet},
		{name: "POST with body", method: http.MethodPost, body: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{name: "stale headers are replaced", method: http.MethodPost, body: "retry", stale: true},
		{name: "DPoP-bound access token is bound via ath", method: http.MethodGet, authorization: "DPoP opaque-access-token"},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRequest(t, tt.method, srv.URL+"/mcp", bodyReader(tt.body))
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			if tt.stale {
				for _, h := range securityHeaders() {
					req.Header.Set(h, "stale")
				}
			}
			if err := p.Bundle.Attach(req); err != nil {
				t.Fatalf("Attach: %v", err)
			}
			for _, h := range securityHeaders() {
				if n := len(req.Header.Values(h)); n != 1 {
					t.Fatalf("%s header count = %d, want 1", h, n)
				}
			}
			if status := do(t, srv.Client(), req); status != http.StatusOK {
				t.Fatalf("status = %d, want %d", status, http.StatusOK)
			}
			assertRecorded(t, rec, i+1, tt.body)
		})
	}
}

func TestAttachErrors(t *testing.T) {
	p := provision(t)
	tests := []struct {
		name    string
		bundle  *identity.Bundle
		req     *http.Request
		wantErr string
	}{
		{name: "nil request", bundle: p.Bundle, wantErr: "nil request"},
		{name: "key does not match certificate", bundle: mismatched(t), req: newRequest(t, http.MethodGet, target, nil), wantErr: "does not match"},
		{name: "unreadable body", bundle: p.Bundle, req: newRequest(t, http.MethodPost, target, errReader{}), wantErr: "read failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertErrorContains(t, tt.bundle.Attach(tt.req), tt.wantErr)
		})
	}
}

func TestTransport(t *testing.T) {
	p := provision(t)
	srv, rec := newServer(t, p.KeyLookup)
	client := &http.Client{Transport: p.Bundle.Transport(nil)}
	steps := []struct {
		method string
		body   string
	}{
		{method: http.MethodGet},
		{method: http.MethodPost, body: `{"jsonrpc":"2.0","id":1,"method":"initialize"}`},
		{method: http.MethodPost, body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		{method: http.MethodPost, body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`},
	}
	for i, step := range steps {
		req := newRequest(t, step.method, srv.URL+"/mcp", bodyReader(step.body))
		if status := do(t, client, req); status != http.StatusOK {
			t.Fatalf("step %d: status = %d, want %d", i, status, http.StatusOK)
		}
		for _, h := range securityHeaders() {
			if req.Header.Get(h) != "" {
				t.Fatalf("step %d: the caller's request gained a %s header", i, h)
			}
		}
		assertRecorded(t, rec, i+1, step.body)
	}
}

func TestTransportClonesRequest(t *testing.T) {
	p := provision(t)
	tests := []struct {
		name string
		body string
	}{
		{name: "without body"},
		{name: "with body", body: "payload"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen *http.Request
			base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				seen = r
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Request: r}, nil
			})
			req := newRequest(t, http.MethodPost, target, bodyReader(tt.body))
			resp, err := p.Bundle.Transport(base).RoundTrip(req)
			if err != nil {
				t.Fatalf("RoundTrip: %v", err)
			}
			defer resp.Body.Close()
			if seen == nil || seen == req {
				t.Fatal("the base transport must receive a clone, not the caller's request")
			}
			for _, h := range securityHeaders() {
				if req.Header.Get(h) != "" {
					t.Fatalf("the caller's request gained a %s header", h)
				}
				if seen.Header.Get(h) == "" {
					t.Fatalf("clone lacks the %s header", h)
				}
			}
			if tt.body == "" {
				return
			}
			got, err := io.ReadAll(seen.Body)
			if err != nil || string(got) != tt.body {
				t.Fatalf("clone body = %q, %v; want %q", got, err, tt.body)
			}
			rewound, err := seen.GetBody()
			if err != nil {
				t.Fatalf("GetBody: %v", err)
			}
			again, err := io.ReadAll(rewound)
			if err != nil || string(again) != tt.body {
				t.Fatalf("rewound body = %q, %v; want %q", again, err, tt.body)
			}
		})
	}
}

func TestTransportErrors(t *testing.T) {
	p := provision(t)
	accept := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: r}, nil
	})
	refuse := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial failed") })
	tests := []struct {
		name    string
		bundle  *identity.Bundle
		base    http.RoundTripper
		body    io.Reader
		wantErr string
	}{
		{name: "unreadable body", bundle: p.Bundle, base: accept, body: errReader{}, wantErr: "read failed"},
		{name: "key does not match certificate", bundle: mismatched(t), base: accept, body: strings.NewReader("x"), wantErr: "does not match"},
		{name: "base transport error", bundle: p.Bundle, base: refuse, wantErr: "dial failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRequest(t, http.MethodPost, target, tt.body)
			resp, err := tt.bundle.Transport(tt.base).RoundTrip(req)
			if resp != nil {
				t.Fatalf("RoundTrip returned %v alongside error %v", resp, err)
			}
			assertErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSign(t *testing.T) {
	p := provision(t)
	ctx := t.Context()
	replay := pop.NewMemoryReplayCache(ctx, 0)
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)

	h, err := p.Bundle.Sign(ctx, http.MethodPost, target, body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	for _, name := range securityHeaders() {
		if n := len(h.Values(name)); n != 1 {
			t.Fatalf("%s header count = %d, want 1", name, n)
		}
	}
	hdrs, err := scitt.ExtractHeaders(h)
	if err != nil {
		t.Fatalf("ExtractHeaders: %v", err)
	}
	verify := func(method, rawURL string, content []byte) (*pop.CallerIdentity, error) {
		return pop.VerifyCaller(ctx, h.Get(pop.DPoPHeader), hdrs, method, rawURL, p.KeyLookup, replay,
			pop.WithVerifyOptions(pop.WithReceivedContent(func() ([]byte, error) { return content, nil })))
	}

	mismatches := []struct {
		name   string
		method string
		rawURL string
	}{
		{name: "different path", method: http.MethodPost, rawURL: "https://gateway.example/other"},
		{name: "different authority", method: http.MethodPost, rawURL: "https://other.example/mcp"},
		{name: "different method", method: http.MethodGet, rawURL: target},
	}
	for _, tt := range mismatches {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verify(tt.method, tt.rawURL, body)
			assertProofError(t, err, pop.ErrHTTPBindingMismatch)
		})
	}
	t.Run("different content", func(t *testing.T) {
		_, err := verify(http.MethodPost, target, []byte("tampered"))
		assertProofError(t, err, pop.ErrContentBindingMismatch)
	})
	t.Run("matching request verifies once", func(t *testing.T) {
		id, err := verify(http.MethodPost, target, body)
		if err != nil {
			t.Fatalf("VerifyCaller: %v", err)
		}
		jkt, err := p.Bundle.JKT()
		if err != nil {
			t.Fatalf("JKT: %v", err)
		}
		if id.AgentID != testAgentID || id.FingerprintHex() != p.Bundle.FingerprintHex() || id.JKT != jkt {
			t.Fatalf("caller = %+v, want agent %s, fingerprint %s, jkt %s", id, testAgentID, p.Bundle.FingerprintHex(), jkt)
		}
	})
	t.Run("the same headers again are a replay", func(t *testing.T) {
		_, err := verify(http.MethodPost, target, body)
		assertProofError(t, err, pop.ErrReplay)
	})
}

func TestSignErrors(t *testing.T) {
	p := provision(t)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	tests := []struct {
		name    string
		ctx     context.Context
		bundle  *identity.Bundle
		rawURL  string
		wantErr string
	}{
		{name: "relative URL", ctx: t.Context(), bundle: p.Bundle, rawURL: "/mcp", wantErr: "absolute URL"},
		{name: "key does not match certificate", ctx: t.Context(), bundle: mismatched(t), rawURL: target, wantErr: "does not match"},
		{name: "canceled context", ctx: canceled, bundle: p.Bundle, rawURL: target, wantErr: "canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := tt.bundle.Sign(tt.ctx, http.MethodGet, tt.rawURL, nil)
			if h != nil {
				t.Fatalf("Sign returned %v alongside error %v", h, err)
			}
			assertErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestHeaders(t *testing.T) {
	p := provision(t)
	hdrs, err := scitt.ExtractHeaders(p.Bundle.Headers())
	if err != nil {
		t.Fatalf("ExtractHeaders: %v", err)
	}
	if string(hdrs.Receipt) != string(p.Bundle.Receipt) || string(hdrs.StatusToken) != string(p.Bundle.StatusToken) {
		t.Fatal("Headers do not round-trip the receipt and status token")
	}
	if h := (&identity.Bundle{}).Headers(); len(h) != 0 {
		t.Fatalf("empty bundle Headers = %v, want none", h)
	}
}

func TestClientStopsAtRedirect(t *testing.T) {
	p := provision(t)
	protected, rec := newServer(t, p.KeyLookup)
	redirector := newRedirector(t, protected.URL+"/mcp")

	base := &http.Client{Timeout: 7 * time.Second}
	client := p.Bundle.Client(base)
	if client.Timeout != base.Timeout || base.Transport != nil || base.CheckRedirect != nil {
		t.Fatal("Client must copy base's settings without modifying base")
	}
	if status := do(t, client, newRequest(t, http.MethodGet, redirector.URL+"/start", nil)); status != http.StatusFound {
		t.Fatalf("status = %d, want the redirect itself (%d)", status, http.StatusFound)
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("the redirect target received %d signed request(s), want none", n)
	}
	if status := do(t, p.Bundle.Client(nil), newRequest(t, http.MethodGet, protected.URL+"/mcp", nil)); status != http.StatusOK {
		t.Fatalf("direct request through Client(nil): status = %d, want %d", status, http.StatusOK)
	}
	assertRecorded(t, rec, 1, "")
}

func TestTransportRefusesCrossHostRedirect(t *testing.T) {
	p := provision(t)
	protected, rec := newServer(t, p.KeyLookup)
	redirector := newRedirector(t, protected.URL+"/mcp")

	client := &http.Client{Transport: p.Bundle.Transport(nil)}
	resp, err := client.Do(newRequest(t, http.MethodGet, redirector.URL+"/start", nil))
	if err == nil {
		resp.Body.Close()
		t.Fatal("the transport followed a cross-host redirect with identity headers")
	}
	if !strings.Contains(err.Error(), "refusing to follow a redirect") {
		t.Fatalf("error = %v, want the transport's redirect refusal", err)
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("the redirect target received %d signed request(s), want none", n)
	}
}

func TestTransportFollowsSameHostRedirect(t *testing.T) {
	p := provision(t)
	srv, rec := newRedirectingServer(t, p.KeyLookup)
	client := &http.Client{Transport: p.Bundle.Transport(nil)}
	if status := do(t, client, newRequest(t, http.MethodGet, srv.URL+"/old", nil)); status != http.StatusOK {
		t.Fatalf("status = %d, want %d after a same-host redirect", status, http.StatusOK)
	}
	assertRecorded(t, rec, 1, "")
}

func TestTransportRefusesSchemeDowngrade(t *testing.T) {
	p := provision(t)
	base := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("the base transport must not be reached")
		return nil, errors.New("unreachable")
	})
	hop := newRequest(t, http.MethodGet, "http://gateway.example/mcp", nil)
	hop.Response = &http.Response{Request: newRequest(t, http.MethodGet, "https://gateway.example/mcp", nil)}
	if _, err := p.Bundle.Transport(base).RoundTrip(hop); err == nil || !strings.Contains(err.Error(), "refusing to follow a redirect") {
		t.Fatalf("error = %v, want the transport's redirect refusal", err)
	}
}

// trackedBody records whether it was closed, so a test can check the RoundTripper contract on
// paths where the transport never sends the request. net/http closes a redirected request's
// body itself as well, so the check is "every body closed", not a count.
type trackedBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackedBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestTransportClosesBodyOnRefusedRedirect(t *testing.T) {
	p := provision(t)
	protected, rec := newServer(t, p.KeyLookup)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, protected.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	var mu sync.Mutex
	var bodies []*trackedBody
	open := func() io.ReadCloser {
		b := &trackedBody{Reader: strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)}
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		return b
	}
	req := newRequest(t, http.MethodPost, redirector.URL+"/start", nil)
	req.Body = open()
	req.GetBody = func() (io.ReadCloser, error) { return open(), nil }

	client := &http.Client{Transport: p.Bundle.Transport(nil)}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("the transport followed a cross-host 307 with identity headers")
	}
	if !strings.Contains(err.Error(), "refusing to follow a redirect") {
		t.Fatalf("error = %v, want the transport's redirect refusal", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("bodies opened = %d, want the original and one hop body from GetBody", len(bodies))
	}
	for i, b := range bodies {
		if !b.closed.Load() {
			t.Fatalf("body %d was never closed; the refused hop must close the body GetBody opened", i)
		}
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("the redirect target received %d signed request(s), want none", n)
	}
}
