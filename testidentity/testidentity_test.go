package testidentity_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

const (
	ansName       = "ans://v1.0.0.caller.example"
	agentID       = "caller-1"
	target        = "https://gateway.example/mcp"
	maxAgentIDLen = 128
)

func provision(t *testing.T) *testidentity.Provisioned {
	t.Helper()
	p, err := testidentity.Provision(ansName, agentID)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return p
}

// verifyCaller signs a request for target with p and verifies it against keys
// the way an ext_authz check would.
func verifyCaller(t *testing.T, p *testidentity.Provisioned, keys scitt.KeyLookup, method string, body []byte) (*pop.CallerIdentity, error) {
	t.Helper()
	h, err := p.Bundle.Sign(t.Context(), method, target, body)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	hdrs, err := scitt.ExtractHeaders(h)
	if err != nil {
		t.Fatalf("ExtractHeaders: %v", err)
	}
	return pop.VerifyCaller(t.Context(), h.Get(pop.DPoPHeader), hdrs, method, target, keys,
		pop.NewMemoryReplayCache(t.Context(), 0),
		pop.WithVerifyOptions(pop.WithReceivedContent(func() ([]byte, error) { return body, nil })))
}

func TestProvisionedBundleVerifies(t *testing.T) {
	p := provision(t)
	keys, err := scitt.NewKeyStore([]string{p.RootKeyC2SP})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	tests := []struct {
		name   string
		method string
		body   []byte
	}{
		{name: "GET", method: http.MethodGet},
		{name: "POST with body", method: http.MethodPost, body: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := verifyCaller(t, p, keys, tt.method, tt.body)
			if err != nil {
				t.Fatalf("VerifyCaller: %v", err)
			}
			if id.AnsName != ansName || id.AgentID != agentID {
				t.Fatalf("caller = %+v, want %s / %s", id, ansName, agentID)
			}
		})
	}
}

func TestProvisionedBundleVerifiesWithMiddleware(t *testing.T) {
	p := provision(t)
	var mu sync.Mutex
	var seen []*pop.CallerIdentity
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := pop.CallerFromContext(r.Context())
		if !ok {
			http.Error(w, "no caller in context", http.StatusInternalServerError)
			return
		}
		mu.Lock()
		seen = append(seen, id)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewUnstartedServer(nil)
	authenticate := pop.Middleware(p.KeyLookup, pop.NewMemoryReplayCache(t.Context(), 0),
		pop.WithTrustedHosts(srv.Listener.Addr().String()),
		pop.WithMiddlewareLogger(slog.New(slog.DiscardHandler)))
	srv.Config.Handler = authenticate(handler)
	srv.Start()
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/mcp", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := p.Bundle.Attach(req); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].AgentID != agentID || seen[0].AnsName != ansName {
		t.Fatalf("callers = %+v, want one %s / %s", seen, ansName, agentID)
	}
}

func TestProvisionedBundleIsRejectedByAnotherRoot(t *testing.T) {
	first, second := provision(t), provision(t)
	keys, err := scitt.NewKeyStore([]string{first.RootKeyC2SP})
	if err != nil {
		t.Fatalf("NewKeyStore: %v", err)
	}
	_, err = verifyCaller(t, second, keys, http.MethodGet, nil)
	var pe *pop.ProofError
	if !errors.As(err, &pe) || pe.Type != pop.ErrStatusInvalid {
		t.Fatalf("error = %v, want %s", err, pop.ErrStatusInvalid)
	}
}

func TestRootKeyC2SP(t *testing.T) {
	p, other := provision(t), provision(t)
	tk, err := scitt.ParseC2SPKey(p.RootKeyC2SP)
	if err != nil {
		t.Fatalf("ParseC2SPKey(%q): %v", p.RootKeyC2SP, err)
	}
	if tk.Name != "dev-tl" || !strings.HasPrefix(p.RootKeyC2SP, "dev-tl+") {
		t.Fatalf("root key %q: name = %q, want dev-tl", p.RootKeyC2SP, tk.Name)
	}
	st, err := scitt.VerifyStatusTokenAt(p.Bundle.StatusToken, p.KeyLookup, 0, time.Now().Unix())
	if err != nil {
		t.Fatalf("VerifyStatusTokenAt: %v", err)
	}
	if st.KeyID != tk.Kid {
		t.Fatalf("status token kid = %x, root key kid = %x", st.KeyID, tk.Kid)
	}
	if st.Payload.AgentID != agentID || st.Payload.AnsName != ansName {
		t.Fatalf("status payload = %+v", st.Payload)
	}
	got, err := p.KeyLookup.Get(st.KeyID)
	if err != nil {
		t.Fatalf("KeyLookup.Get: %v", err)
	}
	if got.Name != tk.Name || !got.Key.Equal(tk.Key) {
		t.Fatal("KeyLookup does not resolve the kid to the formatted root key")
	}
	if other.RootKeyC2SP == p.RootKeyC2SP {
		t.Fatal("two provisionings share one transparency-log key")
	}
}

func TestProvisionAcceptsAgentIDs(t *testing.T) {
	for _, id := range []string{"a", "a.b_c-d", strings.Repeat("x", maxAgentIDLen)} {
		t.Run(id, func(t *testing.T) {
			p, err := testidentity.Provision(ansName, id)
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			st, err := p.Bundle.Status(p.KeyLookup, time.Now())
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if st.Payload.AgentID != id {
				t.Fatalf("agent id = %q, want %q", st.Payload.AgentID, id)
			}
		})
	}
}

func TestProvisionRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		ansName string
		agentID string
		wantErr string
	}{
		{name: "empty ans name", ansName: "", agentID: agentID, wantErr: "empty"},
		{name: "wrong scheme", ansName: "https://caller.example", agentID: agentID, wantErr: "ans://"},
		{name: "missing version", ansName: "ans://caller.example", agentID: agentID, wantErr: "version"},
		{name: "missing host", ansName: "ans://v1.0.0", agentID: agentID, wantErr: "FQDN"},
		{name: "empty agent id", ansName: ansName, agentID: "", wantErr: "agent id"},
		{name: "agent id with space", ansName: ansName, agentID: "caller 1", wantErr: "agent id"},
		{name: "agent id with slash", ansName: ansName, agentID: "caller/1", wantErr: "agent id"},
		{name: "agent id too long", ansName: ansName, agentID: strings.Repeat("a", maxAgentIDLen+1), wantErr: "agent id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := testidentity.Provision(tt.ansName, tt.agentID)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if p != nil {
				t.Fatalf("Provision returned %+v alongside error", p)
			}
		})
	}
}
