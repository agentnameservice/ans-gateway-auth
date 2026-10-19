package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/identity"
	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

type seen struct {
	mu     sync.Mutex
	method string
	body   []byte
	auth   string
	extra  string
	count  int
}

// newProtectedServer runs an upstream behind the SDK's own DPoP middleware trusting the given
// root key, so ans-curl is tested against a real verifier rather than a stub.
func newProtectedServer(t *testing.T, rootKey string) (*httptest.Server, *seen) {
	t.Helper()
	keys, err := scitt.NewKeyStore([]string{rootKey})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	replay := pop.NewMemoryReplayCache(ctx, 0)
	t.Cleanup(replay.Close)

	s := &seen{}
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.method, s.body, s.auth, s.extra = r.Method, body, r.Header.Get("Authorization"), r.Header.Get("X-Extra")
		s.count++
		s.mu.Unlock()
		w.Header().Set("X-Upstream", "yes")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewUnstartedServer(nil)
	srv.Start()
	t.Cleanup(srv.Close)
	host := mustHost(t, srv.URL)
	srv.Config.Handler = pop.Middleware(keys, replay, pop.WithTrustedHosts(host))(handler)
	return srv, s
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func writeBundle(t *testing.T, withRootKeys bool) (string, *testidentity.Provisioned) {
	t.Helper()
	p, err := testidentity.Provision("ans://v1.0.0.curl.example", "curl-agent")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	opts := []identity.WriteOption{}
	if withRootKeys {
		opts = append(opts, identity.WithRootKeys(p.RootKeyC2SP))
	}
	if err := p.Bundle.Write(dir, opts...); err != nil {
		t.Fatal(err)
	}
	return dir, p
}

func TestRunUsage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no identity", []string{"http://127.0.0.1:1/"}, "--identity"},
		{"no url", []string{"--identity", "x"}, "exactly one URL"},
		{"bad header", []string{"--identity", "x", "-H", "nocolon", "http://127.0.0.1:1/"}, "must be Name: value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != exitUsage {
				t.Fatalf("exit %d, want %d", got, exitUsage)
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr %q lacks %q", stderr.String(), tc.want)
			}
		})
	}
}

// The subtests share one recording upstream and inspect its last request, so they run in order.
func TestRunSignsRequests(t *testing.T) {
	dir, p := writeBundle(t, true)
	srv, s := newProtectedServer(t, p.RootKeyC2SP)

	tests := []struct {
		name       string
		args       []string
		wantMethod string
		wantBody   string
		wantAuth   string
		wantExtra  string
		wantOut    []string
	}{
		{
			name:       "GET",
			args:       []string{"--identity", dir, srv.URL + "/v1/things"},
			wantMethod: http.MethodGet,
			wantOut:    []string{"200 OK", "X-Upstream: yes", `{"ok":true}`},
		},
		{
			name:       "POST with inline body and header",
			args:       []string{"--identity", dir, "-d", `{"a":1}`, "-H", "X-Extra: v", srv.URL + "/v1/things"},
			wantMethod: http.MethodPost,
			wantBody:   `{"a":1}`,
			wantExtra:  "v",
			wantOut:    []string{"200 OK"},
		},
		{
			name:       "explicit method with body file",
			args:       []string{"--identity", dir, "-X", "PUT", "-d", "@" + writeFile(t, "body.json", `{"b":2}`), srv.URL + "/v1/things"},
			wantMethod: http.MethodPut,
			wantBody:   `{"b":2}`,
			wantOut:    []string{"200 OK"},
		},
		{
			name:       "access token is bound",
			args:       []string{"--identity", dir, "--token", "tok-123", srv.URL + "/v1/things"},
			wantMethod: http.MethodGet,
			wantAuth:   "DPoP tok-123",
			wantOut:    []string{"200 OK"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != exitOK {
				t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", got, stdout.String(), stderr.String())
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout.String())
				}
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.method != tc.wantMethod {
				t.Errorf("method = %s, want %s", s.method, tc.wantMethod)
			}
			if string(s.body) != tc.wantBody {
				t.Errorf("body = %q, want %q", s.body, tc.wantBody)
			}
			if s.auth != tc.wantAuth {
				t.Errorf("Authorization = %q, want %q", s.auth, tc.wantAuth)
			}
			if s.extra != tc.wantExtra {
				t.Errorf("X-Extra = %q, want %q", s.extra, tc.wantExtra)
			}
		})
	}
}

func TestRunReplayShowsRejection(t *testing.T) {
	t.Parallel()
	dir, p := writeBundle(t, true)
	srv, s := newProtectedServer(t, p.RootKeyC2SP)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"--identity", dir, "--replay", srv.URL + "/v1/things"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit %d: %s", got, stderr.String())
	}
	out := stdout.String()
	if strings.Count(out, "200 OK") != 1 || strings.Count(out, "401 Unauthorized") != 1 {
		t.Errorf("expected one 200 and one 401:\n%s", out)
	}
	if !strings.Contains(out, "replaying the identical signed request") {
		t.Errorf("replay banner missing:\n%s", out)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count != 1 {
		t.Errorf("upstream served %d requests, want 1", s.count)
	}
}

func TestRunStatusTokenChecks(t *testing.T) {
	t.Parallel()
	t.Run("warns when the bundle has no root keys", func(t *testing.T) {
		t.Parallel()
		dir, p := writeBundle(t, false)
		srv, _ := newProtectedServer(t, p.RootKeyC2SP)
		var stdout, stderr bytes.Buffer
		if got := run([]string{"--identity", dir, srv.URL + "/"}, &stdout, &stderr); got != exitOK {
			t.Fatalf("exit %d: %s", got, stderr.String())
		}
		if !strings.Contains(stderr.String(), "not checked") {
			t.Errorf("stderr lacks the warning: %s", stderr.String())
		}
	})
	t.Run("refuses an untrusted status token unless forced", func(t *testing.T) {
		t.Parallel()
		dir, p := writeBundle(t, false)
		other, err := testidentity.Provision("ans://v1.0.0.other.example", "other")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, identity.FileRootKeys), []byte(other.RootKeyC2SP+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		srv, _ := newProtectedServer(t, p.RootKeyC2SP)
		var stdout, stderr bytes.Buffer
		if got := run([]string{"--identity", dir, srv.URL + "/"}, &stdout, &stderr); got != exitFailure {
			t.Fatalf("exit %d, want %d", got, exitFailure)
		}
		if !strings.Contains(stderr.String(), "--force") {
			t.Errorf("stderr lacks the --force hint: %s", stderr.String())
		}
		stdout.Reset()
		stderr.Reset()
		if got := run([]string{"--identity", dir, "--force", srv.URL + "/"}, &stdout, &stderr); got != exitOK {
			t.Fatalf("forced exit %d: %s", got, stderr.String())
		}
	})
	t.Run("rejects an unreadable root-keys file", func(t *testing.T) {
		t.Parallel()
		dir, _ := writeBundle(t, false)
		if err := os.WriteFile(filepath.Join(dir, identity.FileRootKeys), []byte("garbage\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if got := run([]string{"--identity", dir, "http://127.0.0.1:1/"}, &stdout, &stderr); got != exitFailure {
			t.Fatalf("exit %d, want %d", got, exitFailure)
		}
	})
}

func TestRunLoadAndRequestErrors(t *testing.T) {
	t.Parallel()
	t.Run("missing bundle", func(t *testing.T) {
		t.Parallel()
		var stdout, stderr bytes.Buffer
		if got := run([]string{"--identity", filepath.Join(t.TempDir(), "nope"), "http://127.0.0.1:1/"}, &stdout, &stderr); got != exitFailure {
			t.Fatalf("exit %d, want %d", got, exitFailure)
		}
	})
	t.Run("missing body file", func(t *testing.T) {
		t.Parallel()
		dir, _ := writeBundle(t, true)
		var stdout, stderr bytes.Buffer
		if got := run([]string{"--identity", dir, "-d", "@" + filepath.Join(t.TempDir(), "missing"), "http://127.0.0.1:1/"}, &stdout, &stderr); got != exitFailure {
			t.Fatalf("exit %d, want %d", got, exitFailure)
		}
	})
	t.Run("unreachable server", func(t *testing.T) {
		t.Parallel()
		dir, _ := writeBundle(t, true)
		var stdout, stderr bytes.Buffer
		if got := run([]string{"--identity", dir, "--timeout", "2s", "http://127.0.0.1:1/"}, &stdout, &stderr); got != exitFailure {
			t.Fatalf("exit %d, want %d", got, exitFailure)
		}
	})
	t.Run("invalid url", func(t *testing.T) {
		t.Parallel()
		dir, _ := writeBundle(t, true)
		var stdout, stderr bytes.Buffer
		if got := run([]string{"--identity", dir, "::not a url"}, &stdout, &stderr); got != exitFailure {
			t.Fatalf("exit %d, want %d", got, exitFailure)
		}
	})
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
