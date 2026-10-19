//go:build e2e

package agentgateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	exampleOAuthYAML = "examples/agentgateway/config-oauth.yaml"
	jwksPathLine     = "file: ./examples/agentgateway/jwks.rfc7515-a3.example.json"
	celBindingRule   = "          - require: 'has(jwt.cnf) && jwt.cnf.jkt == extauthz.jkt'\n"
	metadataBlock    = "              # Forward the validated claims so the verifier compares cnf.jkt.\n              metadata:\n                ans-authz: '{\"jwt_payload\": jwt}'\n"
	tokenIssuer      = "https://as.example.com"
	tokenAudience    = "ans-authz-example"
	tokenKID         = "e2e-as-key"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwksFor renders a one-key JWKS for the authorization server key.
func jwksFor(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	point, err := pub.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "kid": tokenKID, "use": "sig", "alg": "ES256",
		"x": b64url(point[1:33]), "y": b64url(point[33:65]),
	}}}
	out, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// mintJWT signs an ES256 access token with the standard claims the recipe's
// jwtAuth policy requires; extra claims (such as cnf) are merged in.
func mintJWT(t *testing.T, key *ecdsa.PrivateKey, extra map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": tokenIssuer, "aud": tokenAudience, "sub": "agent-e2e",
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": strconv.FormatInt(now.UnixNano(), 10),
	}
	for k, v := range extra {
		claims[k] = v
	}
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": tokenKID})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := b64url(header) + "." + b64url(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64url(sig)
}

func mustReplace(t *testing.T, text, old, replacement string) string {
	t.Helper()
	if !strings.Contains(text, old) {
		t.Fatalf("recipe no longer contains %q; update the test", old)
	}
	return strings.Replace(text, old, replacement, 1)
}

func TestAgentgatewayOAuth(t *testing.T) {
	e := loadEnv(t)
	requireFreePorts(t, gatewayPort, echoPort, verifierGRPC, verifierHTTP, agwAdminPort, agwStatsPort, agwReadyPort)
	ensureStack(t, e)
	ag := provisionAgent(t, e)

	dir := t.TempDir()
	bin := buildVerifier(t, e, dir)
	strictCfg := writeFile(t, dir, "ans-authz-oauth.yaml", renderVerifierConfig(e.tlURL, ag.rootKeys, true))
	startEcho(t)
	startProc(t, "ans-authz", fmt.Sprintf("http://127.0.0.1:%d/readyz", verifierHTTP), e.repoRoot, bin, "--config", strictCfg)

	asKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwksPath := writeFile(t, dir, "jwks.json", string(jwksFor(t, &asKey.PublicKey)))
	src, err := os.ReadFile(filepath.Join(e.repoRoot, exampleOAuthYAML))
	if err != nil {
		t.Fatal(err)
	}
	recipe := mustReplace(t, string(src), jwksPathLine, "file: "+jwksPath)
	gw := startGateway(t, e, writeFile(t, dir, "config-oauth.yaml", recipe))

	s := newSigner(t, ag)
	base := fmt.Sprintf("http://127.0.0.1:%d", gatewayPort)
	body := []byte(`{"hello":"oauth"}`)
	boundToken := func() string { return mintJWT(t, asKey, map[string]any{"cnf": map[string]any{"jkt": s.sign.JKT()}}) }
	withAuth := func(scheme, token string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", scheme+" "+token) }
	}
	expect := func(t *testing.T, resp *http.Response, respBody []byte, status int, category string) {
		t.Helper()
		if resp.StatusCode != status {
			t.Fatalf("status = %d, want %d; body %s", resp.StatusCode, status, respBody)
		}
		if category != "" {
			if got := denyCategory(t, respBody); got != category {
				t.Fatalf("category = %q, want %q", got, category)
			}
		}
	}

	t.Run("token bound to the proof key is allowed", func(t *testing.T) {
		tok := boundToken()
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, withAuth("DPoP", tok)))
		expect(t, resp, respBody, http.StatusOK, "")
		echo := decodeEcho(t, respBody)
		if got := echo.Headers["Authorization"]; len(got) != 1 || got[0] != "DPoP "+tok {
			t.Fatalf("upstream Authorization = %v", got)
		}
		if _, ok := echo.Headers["Dpop"]; !ok {
			t.Fatal("proof must reach the upstream when a bound token is present")
		}
		if got := echo.Headers[identityNameHdr]; len(got) != 1 || got[0] != ag.ansName {
			t.Fatalf("%s = %v", identityNameHdr, got)
		}
	})

	t.Run("token bound to another key is rejected by the verifier", func(t *testing.T) {
		tok := mintJWT(t, asKey, map[string]any{"cnf": map[string]any{"jkt": "someone-else"}})
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, withAuth("DPoP", tok)))
		expect(t, resp, respBody, http.StatusUnauthorized, "TOKEN_BINDING_MISMATCH")
	})

	t.Run("token without cnf is rejected by the verifier", func(t *testing.T) {
		tok := mintJWT(t, asKey, nil)
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, withAuth("DPoP", tok)))
		expect(t, resp, respBody, http.StatusUnauthorized, "TOKEN_BINDING_MISMATCH")
	})

	t.Run("bearer scheme is rejected by strict jwtAuth", func(t *testing.T) {
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, withAuth("Bearer", boundToken())))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body %s", resp.StatusCode, respBody)
		}
	})

	t.Run("missing token is rejected by strict jwtAuth", func(t *testing.T) {
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, nil))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401; body %s", resp.StatusCode, respBody)
		}
	})

	// Variants below restart processes inside the subtest, so they die with it;
	// each variant starts everything it needs and relies on nothing a previous
	// variant started.
	t.Run("binding is enforced without the CEL rule", func(t *testing.T) {
		gw.stop()
		gw = startGateway(t, e, writeFile(t, dir, "config-oauth-no-cel.yaml", mustReplace(t, recipe, celBindingRule, "")))
		tok := mintJWT(t, asKey, map[string]any{"cnf": map[string]any{"jkt": "someone-else"}})
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, withAuth("DPoP", tok)))
		expect(t, resp, respBody, http.StatusUnauthorized, "TOKEN_BINDING_MISMATCH")
	})

	// agentgateway forwards validated claims in the jwt_authn namespace even
	// without an explicit metadata expression, so "claims not forwarded" only
	// happens when the route validates no token at all.
	t.Run("bound token without gateway validation is a misconfiguration", func(t *testing.T) {
		gw.stop()
		gw = startGateway(t, e, writeFile(t, dir, "config-oauth-no-jwtauth.yaml", withoutJWTAuth(t, recipe)))
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, withAuth("DPoP", boundToken())))
		expect(t, resp, respBody, http.StatusServiceUnavailable, "MISCONFIGURED")
	})

	t.Run("stripping the token before the verifier breaks the binding", func(t *testing.T) {
		gw.stop()
		variant := mustReplace(t, recipe, "preserveToken: true", "preserveToken: false")
		gw = startGateway(t, e, writeFile(t, dir, "config-oauth-no-preserve.yaml", variant))
		resp, respBody := do(t, s.request(t, http.MethodPost, base+"/echo", body, withAuth("DPoP", boundToken())))
		expect(t, resp, respBody, http.StatusUnauthorized, "TOKEN_BINDING_MISMATCH")
	})
}

// withoutJWTAuth removes the jwtAuth policy, the claims-forwarding expression
// and the CEL rule that reads jwt from the recipe.
func withoutJWTAuth(t *testing.T, recipe string) string {
	t.Helper()
	const jwtStart, jwtEnd = "        jwtAuth:\n", "        extAuthz:\n"
	i, j := strings.Index(recipe, jwtStart), strings.Index(recipe, jwtEnd)
	if i < 0 || j < i {
		t.Fatalf("recipe no longer has a jwtAuth block before extAuthz; update the test")
	}
	out := recipe[:i] + recipe[j:]
	out = mustReplace(t, out, metadataBlock, "")
	return mustReplace(t, out, celBindingRule, "")
}
