//go:build e2e

// Package agentgateway holds the end-to-end suite that runs the ans-authz
// binary and a real agentgateway against the local ANS registration
// authority and transparency log.
package agentgateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

const (
	gatewayPort   = 8080
	echoPort      = 8081
	verifierGRPC  = 9191
	verifierHTTP  = 9192
	agwAdminPort  = 15000
	agwStatsPort  = 15020
	agwReadyPort  = 15021
	readyTimeout  = 60 * time.Second
	stackTimeout  = 5 * time.Minute
	receiptWait   = 30 * time.Second
	registerLimit = 2 * time.Minute
)

type env struct {
	raURL      string
	tlURL      string
	apiKey     string
	ansRepo    string
	agwBin     string
	startStack bool
	repoRoot   string
}

// skipOrFailf skips when a prerequisite is missing, or fails when
// ANS_E2E_REQUIRED=1 says the suite must run (CI).
func skipOrFailf(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("ANS_E2E_REQUIRED") == "1" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func goarch() string {
	if runtime.GOARCH == "x86_64" {
		return "amd64"
	}
	return runtime.GOARCH
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadEnv(t *testing.T) env {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	e := env{
		raURL:      getenv("ANS_E2E_RA_URL", "http://localhost:18080"),
		tlURL:      getenv("ANS_E2E_TL_URL", "http://localhost:18081"),
		apiKey:     getenv("ANS_E2E_RA_API_KEY", "ans-dev-key-change-me"),
		ansRepo:    os.Getenv("ANS_E2E_ANS_REPO"),
		agwBin:     getenv("ANS_E2E_AGENTGATEWAY_BIN", filepath.Join(root, ".cache", "agentgateway-"+runtime.GOOS+"-"+goarch())),
		startStack: os.Getenv("ANS_E2E_START_STACK") == "1",
		repoRoot:   root,
	}
	if _, err := os.Stat(e.agwBin); err != nil {
		skipOrFailf(t, "agentgateway binary %s not found; run `make agentgateway-bin`", e.agwBin)
	}
	return e
}

func requireFreePorts(t *testing.T, ports ...int) {
	t.Helper()
	for _, p := range ports {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Fatalf("port %d is in use; the e2e suite needs it free: %v", p, err)
		}
		_ = l.Close()
	}
}

func httpOK(url string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func waitFor(t *testing.T, what, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if httpOK(url) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("%s did not become ready at %s within %s", what, url, timeout)
}

// ensureStack makes sure the local RA and TL answer, starting them from the
// ANS repository checkout when ANS_E2E_START_STACK=1, and skipping otherwise.
func ensureStack(t *testing.T, e env) {
	t.Helper()
	ready := e.raURL + "/v2/admin/ready"
	if httpOK(ready) && httpOK(e.tlURL+"/v2/admin/ready") {
		return
	}
	if !e.startStack {
		skipOrFailf(t, "local ANS stack is not running at %s / %s; start it with scripts/demo/start.sh in the ANS checkout or set ANS_E2E_START_STACK=1 with ANS_E2E_ANS_REPO", e.raURL, e.tlURL)
	}
	if e.ansRepo == "" {
		t.Fatal("ANS_E2E_START_STACK=1 requires ANS_E2E_ANS_REPO")
	}
	ctx, cancel := context.WithTimeout(context.Background(), stackTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "scripts/demo/start.sh")
	cmd.Dir = e.ansRepo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("start.sh: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		stop := exec.Command("scripts/demo/stop.sh")
		stop.Dir = e.ansRepo
		_, _ = stop.CombinedOutput()
	})
	waitFor(t, "ans-ra", ready, readyTimeout)
	waitFor(t, "ans-tl", e.tlURL+"/v2/admin/ready", readyTimeout)
}

// agent is a provisioned ANS identity with everything a caller needs.
type agent struct {
	id          string
	ansName     string
	key         *ecdsa.PrivateKey
	certDER     []byte
	receipt     []byte
	statusToken []byte
	rootKeys    []string
}

// provisionAgent registers a fresh ACTIVE agent through the demo script and
// collects its key, certificate, status token, receipt and the log's root keys.
func provisionAgent(t *testing.T, e env) *agent {
	t.Helper()
	repo := e.ansRepo
	if repo == "" {
		skipOrFailf(t, "ANS_E2E_ANS_REPO is not set; it must point at an ANS reference checkout with scripts/demo/register.sh")
	}
	if _, err := os.Stat(filepath.Join(repo, "scripts", "demo", "register.sh")); err != nil {
		skipOrFailf(t, "ANS checkout with scripts/demo/register.sh not found at %s; set ANS_E2E_ANS_REPO", repo)
	}
	dataDir := filepath.Join(repo, "data", "demo")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dataDir, ".e2e.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	host := fmt.Sprintf("e2e-%d.example.com", time.Now().UnixNano()%1_000_000_000)
	ctx, cancel := context.WithTimeout(context.Background(), registerLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "scripts/demo/register.sh", "--v2")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "AGENT_HOST="+host, "RA_URL="+e.raURL, "TL_URL="+e.tlURL, "RA_API_KEY="+e.apiKey)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("register.sh: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	lines := strings.Fields(stdout.String())
	if len(lines) == 0 {
		t.Fatalf("register.sh printed no agent id\nstderr:\n%s", stderr.String())
	}
	a := &agent{id: lines[len(lines)-1]}

	keyPEM, err := os.ReadFile(filepath.Join(dataDir, "csr", "identity.key"))
	if err != nil {
		t.Fatalf("identity key: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("identity.key is not PEM")
	}
	a.key, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse identity key: %v", err)
	}

	a.certDER = fetchIdentityCert(t, e, a.id)
	cert, err := x509.ParseCertificate(a.certDER)
	if err != nil {
		t.Fatalf("parse identity cert: %v", err)
	}
	if len(cert.URIs) == 0 {
		t.Fatal("identity cert has no URI SAN")
	}
	a.ansName = cert.URIs[0].String()
	a.statusToken = fetchBytes(t, e.tlURL+"/v1/agents/"+a.id+"/status-token", "", 0)
	a.receipt = fetchBytes(t, e.tlURL+"/v1/agents/"+a.id+"/receipt", "", receiptWait)
	for _, line := range strings.Split(string(fetchBytes(t, e.tlURL+"/root-keys", "", 0)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			a.rootKeys = append(a.rootKeys, line)
		}
	}
	return a
}

func fetchIdentityCert(t *testing.T, e env, id string) []byte {
	t.Helper()
	body := fetchBytes(t, e.raURL+"/v2/ans/agents/"+id+"/certificates/identity", e.apiKey, 0)
	var certs []struct {
		CertificatePEM string `json:"certificatePEM"`
	}
	if err := json.Unmarshal(body, &certs); err != nil || len(certs) == 0 {
		t.Fatalf("identity certificates response %q: %v", body, err)
	}
	block, _ := pem.Decode([]byte(certs[0].CertificatePEM))
	if block == nil {
		t.Fatal("certificatePEM is not PEM")
	}
	return block.Bytes
}

// fetchBytes GETs url, retrying 503 responses until retryFor elapses.
func fetchBytes(t *testing.T, url, bearer string, retryFor time.Duration) []byte {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(retryFor)
	for {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return body
		}
		if resp.StatusCode == http.StatusServiceUnavailable && time.Now().Before(deadline) {
			time.Sleep(time.Second)
			continue
		}
		t.Fatalf("GET %s: %d %s", url, resp.StatusCode, body)
	}
}

// echoResponse is what the upstream echo server returns.
type echoResponse struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func startEcho(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echoResponse{Method: r.Method, Path: r.URL.RequestURI(), Headers: r.Header, Body: string(body)})
	}), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// proc is a subprocess under test with its output captured for diagnostics.
type proc struct {
	name     string
	cmd      *exec.Cmd
	out      bytes.Buffer
	stopOnce sync.Once
}

func startProc(t *testing.T, name string, readyURL string, dir string, bin string, args ...string) *proc {
	t.Helper()
	p := &proc{name: name, cmd: exec.Command(bin, args...)}
	p.cmd.Dir = dir
	p.cmd.Stdout, p.cmd.Stderr = &p.out, &p.out
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			t.Logf("---- %s output ----\n%s", name, p.out.String())
		}
	})
	deadline := time.Now().Add(readyTimeout)
	for time.Now().Before(deadline) {
		if httpOK(readyURL) {
			return p
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("%s not ready at %s\n%s", name, readyURL, p.out.String())
	return nil
}

// stop terminates the process; it is safe to call more than once.
func (p *proc) stop() {
	p.stopOnce.Do(func() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = p.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
	})
}

// buildVerifier compiles cmd/ans-authz into dir and returns the binary path.
func buildVerifier(t *testing.T, e env, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "ans-authz")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/ans-authz")
	cmd.Dir = e.repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/ans-authz: %v\n%s", err, out)
	}
	return bin
}

// signer builds the SDK pieces that mint ANS identity headers for an agent.
type signer struct {
	sign  *pop.Signer
	scitt http.Header
	agent *agent
}

func newSigner(t *testing.T, a *agent) *signer {
	t.Helper()
	s, err := pop.NewSigner(a.key, a.certDER)
	if err != nil {
		t.Fatalf("pop.NewSigner: %v", err)
	}
	return &signer{sign: s, scitt: scitt.GenerateHeaders(a.receipt, a.statusToken), agent: a}
}

// request builds a fully signed request; mutate runs before signing so it can
// set an Authorization header that the proof must bind (ath).
func (s *signer) request(t *testing.T, method, url string, body []byte, mutate func(*http.Request)) *http.Request {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(req)
	}
	if err := pop.AttachIdentity(req, s.sign, s.scitt); err != nil {
		t.Fatalf("pop.AttachIdentity: %v", err)
	}
	return req
}

// proofFor mints a proof for an arbitrary method, URL and body so tests can
// present it on a different request.
func (s *signer) proofFor(t *testing.T, method, url string, body []byte) string {
	t.Helper()
	proof, err := s.sign.Sign(context.Background(), method, url, pop.WithContent(body))
	if err != nil {
		t.Fatalf("pop.Sign: %v", err)
	}
	return proof
}

func do(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

func decodeEcho(t *testing.T, body []byte) echoResponse {
	t.Helper()
	var e echoResponse
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("echo body %q: %v", body, err)
	}
	return e
}

func denyCategory(t *testing.T, body []byte) string {
	t.Helper()
	var d struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("deny body %q is not the verifier's JSON: %v", body, err)
	}
	return d.Error
}
