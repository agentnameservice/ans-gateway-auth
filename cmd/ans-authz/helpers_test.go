package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

const (
	testAnsName   = "ans://v1.0.0.caller.example"
	testAuthority = "gw.example"
)

// trust is a demokit-minted transparency log plus one agent.
type trust struct {
	tlKey  *ecdsa.PrivateKey
	bundle *demokit.Bundle
	line   string
}

func newTrust(t *testing.T) *trust {
	t.Helper()
	tlKey, bundle, err := demokit.Provision(testAnsName, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	return &trust{tlKey: tlKey, bundle: bundle, line: c2spLine(t, "demo-tl", &tlKey.PublicKey)}
}

// c2spLine renders name+hexkid+base64(0x02||SPKI); the kid is the first four
// bytes of SHA-256(SPKI), the convention the demo log uses in its tokens.
func c2spLine(t *testing.T, name string, pub *ecdsa.PublicKey) string {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return fmt.Sprintf("%s+%s+%s", name, hex.EncodeToString(sum[:4]), base64.StdEncoding.EncodeToString(append([]byte{0x02}, spki...)))
}

// rootKeysServer serves /root-keys with the given body and status.
func rootKeysServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/root-keys" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ans-authz.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// configYAML renders a loopback configuration with ephemeral ports.
func configYAML(tlBlock string, extra ...string) string {
	var b strings.Builder
	b.WriteString("transparencyLogs:\n" + tlBlock)
	b.WriteString("trustedHosts: [http://" + testAuthority + "]\n")
	b.WriteString("grpc: {listen: \"127.0.0.1:0\"}\nhttpListen: \"127.0.0.1:0\"\nstartupTimeout: 300ms\n")
	b.WriteString("replay: {type: memory, maxEntries: 100}\n")
	for _, line := range extra {
		b.WriteString(line + "\n")
	}
	return b.String()
}

func pinnedTL(line string) string {
	return "- name: pinned\n  rootKeys: [\"" + line + "\"]\n"
}

func remoteTL(baseURL string) string {
	return "- name: remote\n  baseURL: " + baseURL + "\n  allowInsecure: true\n"
}

func remoteTLWithPin(baseURL, line string) string {
	return "- name: remote\n  baseURL: " + baseURL + "\n  allowInsecure: true\n  rootKeys: [\"" + line + "\"]\n"
}

// signedCheckRequest builds the CheckRequest for a request carrying a valid
// identity from the trust fixture.
func (tr *trust) signedCheckRequest(t *testing.T, method, path string, body []byte) *authv3.CheckRequest {
	t.Helper()
	signer, err := pop.NewSigner(tr.bundle.AgentKey, tr.bundle.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(method, "http://"+testAuthority+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := pop.AttachIdentity(req, signer, scitt.GenerateHeaders(tr.bundle.Receipt, tr.bundle.StatusToken)); err != nil {
		t.Fatal(err)
	}
	return checkRequestFrom(req, body)
}

func checkRequestFrom(req *http.Request, body []byte) *authv3.CheckRequest {
	headers := map[string]string{":authority": req.URL.Host}
	for k, vs := range req.Header {
		headers[strings.ToLower(k)] = strings.Join(vs, ",")
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method: req.Method, Path: req.URL.RequestURI(), Host: req.URL.Host, Scheme: req.URL.Scheme,
			Headers: headers, RawBody: body, Size: int64(len(body)),
		}},
	}}
}

// syncBuffer is a goroutine-safe bytes.Buffer for captured output.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// fakeRedis is a minimal RESP2 server: enough of INFO, SET NX PX, GET, PING,
// HELLO and CLIENT for the verifier's replay backend to start and run.
type fakeRedis struct {
	lis  net.Listener
	info string
	mu   sync.Mutex
	keys map[string]string
}

func startFakeRedis(t *testing.T, info string) *fakeRedis {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{lis: lis, info: info, keys: map[string]string{}}
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = lis.Close() })
	return f
}

func (f *fakeRedis) addr() string { return f.lis.Addr().String() }

func (f *fakeRedis) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		args, err := readRESPArray(r)
		if err != nil {
			return
		}
		if _, err := conn.Write([]byte(f.handle(args))); err != nil {
			return
		}
	}
}

func readRESPArray(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return nil, errors.New("expected array")
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for range n {
		sizeLine, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimSpace(sizeLine[1:]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

func (f *fakeRedis) handle(args []string) string {
	if len(args) == 0 {
		return "-ERR empty\r\n"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch strings.ToUpper(args[0]) {
	case "HELLO":
		return "-ERR unknown command 'HELLO'\r\n"
	case "CLIENT", "PING":
		return "+OK\r\n"
	case "INFO":
		return fmt.Sprintf("$%d\r\n%s\r\n", len(f.info), f.info)
	case "SET":
		if len(args) < 3 {
			return "-ERR syntax\r\n"
		}
		if _, exists := f.keys[args[1]]; exists && containsFold(args[3:], "NX") {
			return "$-1\r\n"
		}
		f.keys[args[1]] = args[2]
		return "+OK\r\n"
	case "GET":
		if v, ok := f.keys[args[1]]; ok {
			return fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)
		}
		return "$-1\r\n"
	default:
		return "-ERR unknown command\r\n"
	}
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

const fakeRedisInfo = "# Server\r\nrun_id:fake\r\n# Memory\r\nused_memory:10\r\nmaxmemory:4096\r\nmaxmemory_policy:noeviction\r\n" +
	"# Persistence\r\naof_enabled:1\r\n# Stats\r\nevicted_keys:0\r\n"
