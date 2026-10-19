//go:build e2e

package agentgateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	verifierBodyCap  = 65536
	gatewayBodyCap   = 1 << 20
	dpopChallenge    = `DPoP algs="ES256"`
	contextSentinel  = "ans-authz: body-forwarded"
	exampleHTTPYAML  = "examples/agentgateway/config-http.yaml"
	identityNameHdr  = "X-Ans-Name"
	identityFPHdr    = "X-Ans-Fingerprint"
	identityAgentHdr = "X-Ans-Agent-Id"
	identityJKTHdr   = "X-Ans-Jkt"
	spoofedName      = "ans://v1.0.0.spoof.example"
)

func renderVerifierConfig(tlURL string, rootKeys []string, requireTokenClaims bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "transparencyLogs:\n- name: local-tl\n  baseURL: %s\n  allowInsecure: true\n  rootKeys:\n", tlURL)
	for _, k := range rootKeys {
		fmt.Fprintf(&b, "  - %q\n", k)
	}
	fmt.Fprintf(&b, "trustedHosts:\n- http://127.0.0.1:%d\n- http://127.0.0.1:%d\n", gatewayPort, mcpPort)
	b.WriteString("requiredContext:\n  key: ans-authz\n  value: body-forwarded\n")
	fmt.Fprintf(&b, "requireTokenClaims: %t\n", requireTokenClaims)
	fmt.Fprintf(&b, "maxContentBytes: %d\n", verifierBodyCap)
	b.WriteString("replay:\n  type: memory\n  maxEntries: 10000\n")
	fmt.Fprintf(&b, "grpc:\n  listen: 127.0.0.1:%d\nhttpListen: 127.0.0.1:%d\nlogLevel: debug\n", verifierGRPC, verifierHTTP)
	return b.String()
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func validateGatewayConfig(t *testing.T, e env, path string) {
	t.Helper()
	cmd := exec.Command(e.agwBin, "--validate-only", "-f", path)
	cmd.Dir = e.repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("agentgateway --validate-only %s: %v\n%s", path, err, out)
	}
}

func startGateway(t *testing.T, e env, configPath string) *proc {
	t.Helper()
	validateGatewayConfig(t, e, configPath)
	return startProc(t, "agentgateway", fmt.Sprintf("http://127.0.0.1:%d/healthz/ready", agwReadyPort), e.repoRoot, e.agwBin, "-f", configPath)
}

// httpFixture is the running HTTP recipe: stack, agent, echo upstream,
// verifier and gateway, plus a signer for the agent.
type httpFixture struct {
	e      env
	ag     *agent
	s      *signer
	gw     *proc
	dir    string
	base   string
	body   []byte
	wantFP string
}

func startHTTPRecipe(t *testing.T) *httpFixture {
	t.Helper()
	e := loadEnv(t)
	requireFreePorts(t, gatewayPort, echoPort, verifierGRPC, verifierHTTP, agwAdminPort, agwStatsPort, agwReadyPort)
	ensureStack(t, e)
	ag := provisionAgent(t, e)

	dir := t.TempDir()
	bin := buildVerifier(t, e, dir)
	cfgPath := writeFile(t, dir, "ans-authz.yaml", renderVerifierConfig(e.tlURL, ag.rootKeys, false))
	startEcho(t)
	startProc(t, "ans-authz", fmt.Sprintf("http://127.0.0.1:%d/readyz", verifierHTTP), e.repoRoot, bin, "--config", cfgPath)
	gw := startGateway(t, e, exampleHTTPYAML)

	fp := sha256.Sum256(ag.certDER)
	return &httpFixture{
		e: e, ag: ag, s: newSigner(t, ag), gw: gw, dir: dir,
		base:   fmt.Sprintf("http://127.0.0.1:%d", gatewayPort),
		body:   []byte(`{"hello":"gateway"}`),
		wantFP: hex.EncodeToString(fp[:]),
	}
}

func expectDeny(t *testing.T, resp *http.Response, respBody []byte, status int, category string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d; body %s", resp.StatusCode, status, respBody)
	}
	if status == http.StatusUnauthorized {
		if got := resp.Header.Get("WWW-Authenticate"); got != dpopChallenge {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, dpopChallenge)
		}
	}
	if category != "" {
		if got := denyCategory(t, respBody); got != category {
			t.Fatalf("category = %q, want %q", got, category)
		}
	}
}

func expectHeader(t *testing.T, echo echoResponse, name, want string) {
	t.Helper()
	if got := echo.Headers[name]; len(got) != 1 || got[0] != want {
		t.Fatalf("%s = %v, want [%s]", name, got, want)
	}
}

func TestAgentgatewayHTTP(t *testing.T) {
	f := startHTTPRecipe(t)
	scenarios := []struct {
		name string
		run  func(t *testing.T, f *httpFixture)
	}{
		{"post with body is allowed and identity reaches the upstream", testAllowPost},
		{"get without body is allowed", testAllowGet},
		{"replayed request is rejected", testReplay},
		{"request without identity is challenged", testNoIdentity},
		{"proof for another path is rejected", testWrongPath},
		{"client scheme header does not change htu", testForwardedProto},
		{"spoofed identity header without identity is rejected", testSpoofWithoutIdentity},
		{"spoofed identity header is overwritten by the verified name", testSpoofOverwritten},
		{"body over the verifier cap is rejected with 413", testVerifierBodyCap},
		{"body over the gateway cap is rejected before the verifier", testGatewayBodyCap},
		{"dpop-bound access token passes through on a route without jwtAuth", testTokenPassthrough},
		{"route without the context sentinel is misconfigured", testMissingSentinel},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) { sc.run(t, f) })
	}
}

func testAllowPost(t *testing.T, f *httpFixture) {
	resp, respBody := do(t, f.s.request(t, http.MethodPost, f.base+"/echo", f.body, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, respBody)
	}
	echo := decodeEcho(t, respBody)
	expectHeader(t, echo, identityNameHdr, f.ag.ansName)
	expectHeader(t, echo, identityFPHdr, f.wantFP)
	expectHeader(t, echo, identityAgentHdr, f.ag.id)
	expectHeader(t, echo, identityJKTHdr, f.s.sign.JKT())
	for _, h := range []string{"Dpop", "X-Scitt-Receipt", "X-Ans-Status-Token"} {
		if _, present := echo.Headers[h]; present {
			t.Fatalf("header %s reached the upstream", h)
		}
	}
	if echo.Body != string(f.body) {
		t.Fatalf("upstream body = %q, want %q", echo.Body, f.body)
	}
}

func testAllowGet(t *testing.T, f *httpFixture) {
	resp, respBody := do(t, f.s.request(t, http.MethodGet, f.base+"/echo", nil, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, respBody)
	}
}

func testReplay(t *testing.T, f *httpFixture) {
	req := f.s.request(t, http.MethodPost, f.base+"/echo", f.body, nil)
	send := func() (*http.Response, []byte) {
		c := req.Clone(req.Context())
		c.Body, _ = req.GetBody()
		return do(t, c)
	}
	if resp, respBody := send(); resp.StatusCode != http.StatusOK {
		t.Fatalf("first send: status = %d, body %s", resp.StatusCode, respBody)
	}
	resp, respBody := send()
	expectDeny(t, resp, respBody, http.StatusUnauthorized, "REPLAY")
}

func testNoIdentity(t *testing.T, f *httpFixture) {
	req, _ := http.NewRequest(http.MethodPost, f.base+"/echo", bytes.NewReader(f.body))
	resp, respBody := do(t, req)
	expectDeny(t, resp, respBody, http.StatusUnauthorized, "MISSING_HEADERS")
}

func testWrongPath(t *testing.T, f *httpFixture) {
	req := f.s.request(t, http.MethodPost, f.base+"/echo", f.body, nil)
	req.Header.Set("DPoP", f.s.proofFor(t, http.MethodPost, f.base+"/other", f.body))
	resp, respBody := do(t, req)
	expectDeny(t, resp, respBody, http.StatusUnauthorized, "HTTP_BINDING_MISMATCH")
}

func testForwardedProto(t *testing.T, f *httpFixture) {
	req := f.s.request(t, http.MethodPost, f.base+"/echo", f.body, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if resp, respBody := do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("http-signed proof with forwarded https: status = %d, body %s", resp.StatusCode, respBody)
	}
	req = f.s.request(t, http.MethodPost, f.base+"/echo", f.body, nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("DPoP", f.s.proofFor(t, http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d/echo", gatewayPort), f.body))
	resp, respBody := do(t, req)
	expectDeny(t, resp, respBody, http.StatusUnauthorized, "HTTP_BINDING_MISMATCH")
}

func testSpoofWithoutIdentity(t *testing.T, f *httpFixture) {
	req, _ := http.NewRequest(http.MethodGet, f.base+"/echo", nil)
	req.Header.Set(identityNameHdr, spoofedName)
	resp, respBody := do(t, req)
	expectDeny(t, resp, respBody, http.StatusUnauthorized, "")
}

func testSpoofOverwritten(t *testing.T, f *httpFixture) {
	req := f.s.request(t, http.MethodGet, f.base+"/echo", nil, func(r *http.Request) {
		r.Header.Set(identityNameHdr, spoofedName)
		r.Header.Set(identityAgentHdr, "spoof")
	})
	resp, respBody := do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, respBody)
	}
	echo := decodeEcho(t, respBody)
	expectHeader(t, echo, identityNameHdr, f.ag.ansName)
	expectHeader(t, echo, identityAgentHdr, f.ag.id)
}

func testVerifierBodyCap(t *testing.T, f *httpFixture) {
	big := bytes.Repeat([]byte("x"), verifierBodyCap+1)
	resp, respBody := do(t, f.s.request(t, http.MethodPost, f.base+"/echo", big, nil))
	expectDeny(t, resp, respBody, http.StatusRequestEntityTooLarge, "CONTENT_UNREADABLE")
}

func testGatewayBodyCap(t *testing.T, f *httpFixture) {
	huge := bytes.Repeat([]byte("x"), gatewayBodyCap+1)
	resp, respBody := do(t, f.s.request(t, http.MethodPost, f.base+"/echo", huge, nil))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body %s", resp.StatusCode, respBody)
	}
}

func testTokenPassthrough(t *testing.T, f *httpFixture) {
	const token = "DPoP e2e-opaque-token"
	req := f.s.request(t, http.MethodPost, f.base+"/echo", f.body, func(r *http.Request) {
		r.Header.Set("Authorization", token)
	})
	resp, respBody := do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, respBody)
	}
	echo := decodeEcho(t, respBody)
	expectHeader(t, echo, "Authorization", token)
	if _, present := echo.Headers["Dpop"]; !present {
		t.Fatal("DPoP header must reach the upstream when a bound token is present")
	}
}

func testMissingSentinel(t *testing.T, f *httpFixture) {
	f.gw.stop()
	src, err := os.ReadFile(filepath.Join(f.e.repoRoot, exampleHTTPYAML))
	if err != nil {
		t.Fatal(err)
	}
	stripped := mustReplace(t, string(src), contextSentinel, "unrelated: value")
	f.gw = startGateway(t, f.e, writeFile(t, f.dir, "config-no-sentinel.yaml", stripped))
	resp, respBody := do(t, f.s.request(t, http.MethodPost, f.base+"/echo", f.body, nil))
	expectDeny(t, resp, respBody, http.StatusServiceUnavailable, "MISCONFIGURED")
}
