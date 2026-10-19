//go:build e2e

package agentrouter

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	gatewayPort  = 1975
	spikeAgentID = "demo-agent-1"
	startTimeout = 4 * time.Minute
)

// Ports aigw run binds besides the Gateway listener: extension server, admin, MCP proxy and
// the MCP backend listener. None of them is configurable, so tests run serially.
var fixedPorts = []int{1061, 1064, gatewayPort, 9856, 10088}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// aigwBinary returns the Agent Router CLI under test. It must be supplied through AIGW_BIN
// (a local build or a downloaded release); the suite fails rather than skips without it so a
// green run always means the gateway was exercised.
func aigwBinary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("AIGW_BIN")
	if bin == "" {
		t.Fatal("AIGW_BIN is not set: point it at an aigw binary (go build -o bin/aigw ./cmd/aigw in an Agent Router checkout, or a release asset)")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("AIGW_BIN: %v", err)
	}
	return bin
}

func requireFixedPortsFree(t *testing.T) {
	t.Helper()
	for _, port := range fixedPorts {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("port %d is in use; aigw run needs it (another aigw or Envoy is still running?)", port)
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := lis.Addr().(*net.TCPAddr).Port
	_ = lis.Close()
	return port
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	return port
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// process is a child under test. It runs in its own process group so that a forced stop also
// takes down anything it spawned (aigw starts Envoy), and its output is kept for failure dumps.
type process struct {
	name   string
	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer
	exited chan struct{}
}

func startProcess(t *testing.T, name string, cmd *exec.Cmd) *process {
	t.Helper()
	p := &process{name: name, cmd: cmd, stdout: &syncBuffer{}, stderr: &syncBuffer{}, exited: make(chan struct{})}
	cmd.Stdout = p.stdout
	cmd.Stderr = p.stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	go func() {
		_ = cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			t.Logf("%s stdout:\n%s", name, p.stdout.String())
			t.Logf("%s stderr:\n%s", name, p.stderr.String())
		}
	})
	return p
}

// stop interrupts the process for a graceful shutdown and, failing that, kills its whole
// process group so no Envoy survives holding the fixed ports.
func (p *process) stop() {
	if !p.running() {
		return
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-p.exited:
		case <-time.After(5 * time.Second):
		}
	}
}

func (p *process) running() bool {
	select {
	case <-p.exited:
		return false
	default:
		return true
	}
}

// startAigw runs `aigw run --debug <config>` with the given environment on top of the
// current one. State lives under the test's temp dir; the runtime dir, which holds a Unix
// socket, uses a short path under /tmp to stay within the socket path limit; the data dir keeps
// its default so the Envoy binary func-e downloads is cached between runs.
func startAigw(t *testing.T, bin, configPath string, env map[string]string) *process {
	t.Helper()
	runtimeDir, err := os.MkdirTemp("/tmp", "aigw-e2e-") //nolint:usetesting // t.TempDir paths exceed the Unix socket path limit on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	cmd := exec.Command(bin, "run", "--debug", configPath)
	cmd.Env = append(os.Environ(),
		"DISABLE_PPROF=1",
		"AIGW_STATE_HOME="+filepath.Join(t.TempDir(), "state"),
		"AIGW_RUNTIME_DIR="+runtimeDir,
	)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return startProcess(t, "aigw", cmd)
}

func waitUntil(t *testing.T, p *process, what string, cond func() error) {
	t.Helper()
	deadline := time.Now().Add(startTimeout)
	var last error
	for time.Now().Before(deadline) {
		if !p.running() {
			t.Fatalf("%s exited while waiting for %s\nstdout:\n%s\nstderr:\n%s", p.name, what, p.stdout.String(), p.stderr.String())
		}
		if last = cond(); last == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s: %v", what, last)
}

func gatewayURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", gatewayPort, path)
}

type httpResult struct {
	Status int
	Header http.Header
	Body   []byte
}

func send(t *testing.T, req *http.Request) httpResult {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return httpResult{Status: resp.StatusCode, Header: resp.Header, Body: body}
}

func chatRequest(t *testing.T, body []byte, headers map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gatewayURL("/v1/chat/completions"), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func probe(req *http.Request, want int) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != want {
		return fmt.Errorf("status %d, want %d", resp.StatusCode, want)
	}
	return nil
}
