package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/replay"
)

// instanceVectors is testdata/instance-vectors.json, minted by ans-agent's
// scripts/gen_instance_vectors.py from the Python reference implementation
// (src/instance_token.py). Every verdict there was checked against the Python
// verifier; these tests hold the Go verifier to the same verdicts.
type instanceVectors struct {
	Now            int64            `json:"now"`
	TrustedHost    string           `json:"trustedHost"`
	ExpectedAud    string           `json:"expectedAud"`
	AllowedIssuers []string         `json:"allowedIssuers"`
	AgentID        string           `json:"agentId"`
	RootKeys       []string         `json:"rootKeys"`
	Vectors        []instanceVector `json:"vectors"`
	CapRequests    []instanceVector `json:"capRequests"`
}

type instanceVector struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Method       string         `json:"method"`
	URL          string         `json:"url"`
	Body         string         `json:"body"`
	Token        string         `json:"token"`
	DPoP         string         `json:"dpop"`
	StatusToken  string         `json:"statusToken"`
	PresentTwice bool           `json:"presentTwice"`
	MaxStatusAge int64          `json:"maxStatusAge"`
	Expect       instanceExpect `json:"expect"`
}

type instanceExpect struct {
	Verdict              string          `json:"verdict"`
	Code                 string          `json:"code"`
	Iss                  string          `json:"iss"`
	AnsName              string          `json:"ansName"`
	Sub                  string          `json:"sub"`
	JKT                  string          `json:"jkt"`
	Fingerprint          string          `json:"fingerprint"`
	Scope                string          `json:"scope"`
	Act                  json.RawMessage `json:"act"`
	AuthorizationDetails json.RawMessage `json:"authorizationDetails"`
	Sid                  string          `json:"sid"`
}

func loadInstanceVectors(t *testing.T) *instanceVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "instance-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var iv instanceVectors
	if err := json.Unmarshal(raw, &iv); err != nil {
		t.Fatal(err)
	}
	if len(iv.Vectors) == 0 || len(iv.RootKeys) == 0 {
		t.Fatal("instance vectors file is empty")
	}
	return &iv
}

// countingKeys is a KeyProvider that counts every lookup and refresh, so a
// test can prove a request was refused before any trust material was touched.
type countingKeys struct {
	inner     KeyProvider
	gets      atomic.Int64
	refreshes atomic.Int64
}

func (c *countingKeys) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	c.gets.Add(1)
	return c.inner.Get(kid)
}

func (c *countingKeys) RefreshFor(ctx context.Context) bool {
	c.refreshes.Add(1)
	return c.inner.RefreshFor(ctx)
}

func (c *countingKeys) calls() int64 { return c.gets.Load() + c.refreshes.Load() }

// HoldsKey forwards to the wrapped provider, so a countingKeys over a
// Keyring still binds issuers[].tl.
func (c *countingKeys) HoldsKey(source string, kid [4]byte) bool {
	h, ok := c.inner.(interface{ HoldsKey(string, [4]byte) bool })
	return ok && h.HoldsKey(source, kid)
}

func (iv *instanceVectors) config() Config {
	c := DefaultConfig()
	c.TrustedHosts = []string{iv.TrustedHost}
	c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: slices.Clone(iv.AllowedIssuers)}
	return c
}

func (iv *instanceVectors) keys(t *testing.T) *countingKeys {
	t.Helper()
	store, err := scitt.NewKeyStore(iv.RootKeys)
	if err != nil {
		t.Fatalf("pinned test TL root key: %v", err)
	}
	return &countingKeys{inner: mustKeyring(t, NoopObserver{}, KeySource{Name: "test-tl", Lookup: store})}
}

// verifier builds an instance-mode verifier over the pinned test root key,
// a fresh memory replay cache and the vectors' fixed clock.
func (iv *instanceVectors) verifier(t *testing.T, cfg Config, keys KeyProvider) *Verifier {
	t.Helper()
	mem := replay.NewMemory(t.Context(), 1000, nil)
	t.Cleanup(func() { _ = mem.Close() })
	v, err := NewVerifier(cfg, keys, mem, nil, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	now := time.Unix(iv.Now, 0)
	v.now = func() time.Time { return now }
	return v
}

// cacheVerifier runs a maxStatusAge vector in status-cache mode, the only
// mode maxStatusAge selects. The cache is seeded with the vector's own status
// token, as if the TL had served it, so the presented token is never newer
// than the cache and the verdict rests on that token's age, as the vector
// intends.
func (iv *instanceVectors) cacheVerifier(t *testing.T, vec instanceVector) *Verifier {
	t.Helper()
	cfg := iv.config()
	cfg.InstanceMode.MaxStatusAge = time.Duration(vec.MaxStatusAge) * time.Second
	cfg.InstanceMode.Issuers = []InstanceIssuer{{Host: iv.AllowedIssuers[0], AgentID: iv.AgentID, TL: "test-tl"}}
	raw, err := base64.StdEncoding.DecodeString(vec.StatusToken)
	if err != nil {
		t.Fatal(err)
	}
	keys := iv.keys(t)
	st, err := scitt.VerifyStatusTokenAt(raw, keys, 0, iv.Now)
	if err != nil {
		t.Fatalf("seed status token: %v", err)
	}
	cache := NewMemoryStatusCache()
	cache.Install(IssuerStatus{AgentID: st.Payload.AgentID, Iat: st.Payload.Iat, Raw: raw, Token: st})
	mem := replay.NewMemory(t.Context(), 1000, nil)
	t.Cleanup(func() { _ = mem.Close() })
	v, err := NewVerifier(cfg, keys, mem, nil, nil, WithStatusCache(cache))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	now := time.Unix(iv.Now, 0)
	v.now = func() time.Time { return now }
	return v
}

func (vec *instanceVector) request(t *testing.T) *Request {
	t.Helper()
	u, err := url.Parse(vec.URL)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Authorization", "DPoP "+vec.Token)
	h.Set("Dpop", vec.DPoP)
	h.Set(scitt.HeaderStatusToken, vec.StatusToken)
	return &Request{Method: vec.Method, Authority: u.Host, Path: u.RequestURI(), Header: h, Body: []byte(vec.Body)}
}

func requireInstanceDenial(t *testing.T, d Decision, code string) {
	t.Helper()
	if d.Allowed || d.Deny == nil || d.Identity != nil || d.Headers != nil || d.Metadata != nil || d.RemoveHeaders != nil {
		t.Fatalf("Verify() = %+v, want a bare denial", d)
	}
	if !strings.HasPrefix(d.Deny.Detail, code+": ") {
		t.Fatalf("Detail = %q, want reason code %q", d.Deny.Detail, code)
	}
	if d.Deny.Category == "" || (d.Deny.HTTPStatus != http.StatusUnauthorized && d.Deny.HTTPStatus != http.StatusForbidden) {
		t.Fatalf("Deny = %+v, want a 401 or 403 category", d.Deny)
	}
}

func requireJSONEqual(t *testing.T, name, got string, want json.RawMessage) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		t.Fatalf("%s = %q is not JSON: %v", name, got, err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	gb, _ := json.Marshal(g)
	wb, _ := json.Marshal(w)
	if string(gb) != string(wb) {
		t.Fatalf("%s = %s, want %s", name, gb, wb)
	}
}

func requireInstanceAllow(t *testing.T, d Decision, iv *instanceVectors, e instanceExpect) {
	t.Helper()
	if !d.Allowed || d.Deny != nil || d.Identity == nil {
		t.Fatalf("Verify() = %+v (deny %+v), want allow", d, d.Deny)
	}
	want := map[string]string{
		HeaderANSName:        e.AnsName,
		HeaderANSAgentID:     iv.AgentID,
		HeaderANSFingerprint: e.Fingerprint,
		HeaderANSJKT:         e.JKT,
		HeaderANSInstanceSub: e.Sub,
		HeaderANSScope:       e.Scope,
	}
	for k, w := range want {
		if d.Headers[k] != w {
			t.Fatalf("Headers[%s] = %q, want %q (all: %v)", k, d.Headers[k], w, d.Headers)
		}
	}
	for name, raw := range map[string]json.RawMessage{HeaderANSAct: e.Act, HeaderANSAuthorizationDetails: e.AuthorizationDetails} {
		if len(raw) == 0 || string(raw) == "null" {
			if _, set := d.Headers[name]; set || !slices.Contains(d.RemoveHeaders, strings.ToLower(name)) {
				t.Fatalf("%s absent from the token must be removed, not set: headers %v, remove %v", name, d.Headers, d.RemoveHeaders)
			}
			continue
		}
		requireJSONEqual(t, name, d.Headers[name], raw)
	}
	for name := range d.Headers {
		if slices.Contains(d.RemoveHeaders, strings.ToLower(name)) {
			t.Fatalf("%s is both set and removed; Envoy applies removals after additions", name)
		}
	}
	if d.Identity.AnsName != e.AnsName || d.Identity.JKT != e.JKT || d.Identity.FingerprintHex() != e.Fingerprint {
		t.Fatalf("Identity = %+v, want %s %s %s", d.Identity, e.AnsName, e.JKT, e.Fingerprint)
	}
	if d.Metadata[MetadataInstanceSub] != e.Sub || d.Metadata[MetadataJKT] != e.JKT {
		t.Fatalf("Metadata = %v", d.Metadata)
	}
}

// TestInstanceVectors replays every cross-language vector.
func TestInstanceVectors(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	for _, vec := range iv.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			t.Parallel()
			cfg := iv.config()
			v := iv.verifier(t, cfg, iv.keys(t))
			if vec.MaxStatusAge > 0 {
				v = iv.cacheVerifier(t, vec)
			}
			if vec.PresentTwice {
				if d := v.Verify(t.Context(), vec.request(t)); !d.Allowed {
					t.Fatalf("first presentation denied: %+v", d.Deny)
				}
			}
			d := v.Verify(t.Context(), vec.request(t))
			if vec.Expect.Verdict == ResultAllow {
				requireInstanceAllow(t, d, iv, vec.Expect)
				return
			}
			requireInstanceDenial(t, d, vec.Expect.Code)
		})
	}
}

// validInstanceVector returns the accepted base vector the policy tests edit.
func validInstanceVector(t *testing.T, iv *instanceVectors) instanceVector {
	t.Helper()
	for _, vec := range iv.Vectors {
		if vec.Name == "valid" {
			return vec
		}
	}
	t.Fatal(`no vector "valid"`)
	return instanceVector{}
}

// TestInstanceIssuerRefusedBeforeLookup proves the iss allowlist runs before
// any root-key lookup or refresh.
func TestInstanceIssuerRefusedBeforeLookup(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)

	keys := iv.keys(t)
	cfg := iv.config()
	cfg.InstanceMode.AllowedIssuers = []string{"other.example.test"}
	d := iv.verifier(t, cfg, keys).Verify(t.Context(), vec.request(t))
	requireInstanceDenial(t, d, "iss_mismatch")
	if d.Deny.Category != CategoryExpectedPeerMismatch || d.Deny.HTTPStatus != http.StatusForbidden {
		t.Fatalf("Deny = %+v, want 403 %s", d.Deny, CategoryExpectedPeerMismatch)
	}
	if n := keys.calls(); n != 0 {
		t.Fatalf("key provider called %d times before the issuer was refused", n)
	}

	// The same request under an allowlist that names the issuer does reach
	// the key provider, so the zero above is not an unwired fake.
	allowed := iv.keys(t)
	if d := iv.verifier(t, iv.config(), allowed).Verify(t.Context(), vec.request(t)); !d.Allowed {
		t.Fatalf("allowed issuer denied: %+v", d.Deny)
	}
	if allowed.calls() == 0 {
		t.Fatal("an accepted instance request never consulted the key provider")
	}
}

// TestInstanceModeOff refuses an instance request when instance mode is off,
// without touching trust material.
func TestInstanceModeOff(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	keys := iv.keys(t)
	cfg := iv.config()
	cfg.InstanceMode = InstanceMode{}
	d := iv.verifier(t, cfg, keys).Verify(t.Context(), vec.request(t))
	requireInstanceDenial(t, d, "instance_disabled")
	if d.Deny.Category != CategoryMissingHeaders {
		t.Fatalf("Category = %q, want %q", d.Deny.Category, CategoryMissingHeaders)
	}
	if n := keys.calls(); n != 0 {
		t.Fatalf("key provider called %d times with instance mode off", n)
	}
}

// TestInstanceClientHeadersOverwritten sends forged identity headers with a
// valid instance request: each one the verifier sets is overwritten, and each
// one the token leaves unset is removed.
func TestInstanceClientHeadersOverwritten(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	r := vec.request(t)
	forged := map[string]string{
		HeaderANSName: "ans://v1.0.0.evil.example.test", HeaderANSAgentID: "forged",
		HeaderANSFingerprint: "00", HeaderANSJKT: "forged",
		HeaderANSInstanceSub: "user:admin", HeaderANSAct: `{"sub":"instance:forged"}`,
		HeaderANSScope: "admin", HeaderANSAuthorizationDetails: `[{"type":"everything"}]`,
	}
	for k, val := range forged {
		r.Header.Set(k, val)
	}
	d := iv.verifier(t, iv.config(), iv.keys(t)).Verify(t.Context(), r)
	requireInstanceAllow(t, d, iv, vec.Expect)
	for k, val := range forged {
		if d.Headers[k] == val {
			t.Fatalf("forged %s survived: %q", k, val)
		}
		if _, set := d.Headers[k]; !set && !slices.Contains(d.RemoveHeaders, strings.ToLower(k)) {
			t.Fatalf("forged %s is neither overwritten nor removed", k)
		}
	}
}

// TestInstanceCapPerSub admits at most maxInstancesPerSub distinct instance
// keys per sub, re-admits a key already counted, and leaves other subs alone.
func TestInstanceCapPerSub(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	cfg := iv.config()
	cfg.InstanceMode.MaxInstancesPerSub = 2
	v := iv.verifier(t, cfg, iv.keys(t))
	want := map[string]bool{"sub1_key1": true, "sub1_key1_again": true, "sub1_key2": true, "sub1_key3": false, "sub2_key4": true}
	if len(iv.CapRequests) != len(want) {
		t.Fatalf("cap requests %d, want %d", len(iv.CapRequests), len(want))
	}
	for _, vec := range iv.CapRequests {
		d := v.Verify(t.Context(), vec.request(t))
		if want[vec.Name] {
			if !d.Allowed {
				t.Fatalf("%s denied: %+v", vec.Name, d.Deny)
			}
			continue
		}
		requireInstanceDenial(t, d, "instance_cap")
	}

	// With the cap off the third key is admitted.
	off := iv.verifier(t, iv.config(), iv.keys(t))
	for _, vec := range iv.CapRequests {
		if d := off.Verify(t.Context(), vec.request(t)); !d.Allowed {
			t.Fatalf("cap off: %s denied: %+v", vec.Name, d.Deny)
		}
	}
}

// TestInstanceContentBinding refuses a body the proof did not sign. The
// Python reference does not bind the body; the gateway does, as it does in
// certificate mode.
func TestInstanceContentBinding(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	r := vec.request(t)
	r.Body = []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything"}}`)
	d := iv.verifier(t, iv.config(), iv.keys(t)).Verify(t.Context(), r)
	requireInstanceDenial(t, d, "bad_dpop")
	if d.Deny.Category != CategoryContentBindingMismatch {
		t.Fatalf("Category = %q, want %q", d.Deny.Category, CategoryContentBindingMismatch)
	}
}

// TestInstanceMissingHeaders refuses an instance token without its proof or
// status token.
func TestInstanceMissingHeaders(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	for _, drop := range []string{"Dpop", scitt.HeaderStatusToken} {
		r := vec.request(t)
		r.Header.Del(drop)
		d := iv.verifier(t, iv.config(), iv.keys(t)).Verify(t.Context(), r)
		requireInstanceDenial(t, d, "bad_request")
		if d.Deny.Category != CategoryMissingHeaders {
			t.Fatalf("without %s: Category = %q", drop, d.Deny.Category)
		}
	}
}

// TestCertificateModeUnchangedWithInstanceMode runs a certificate-mode caller
// through a verifier with instance mode on: it is still admitted with the
// same identity, and forged instance headers are stripped so an upstream that
// reads them cannot be fed a client's value.
func TestCertificateModeUnchangedWithInstanceMode(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	cfg := testConfig()
	cfg.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"}}
	v := f.verifier(t, cfg)
	d := v.Verify(t.Context(), f.signed(t, http.MethodGet, fixtureTarget, nil, func(req *http.Request) {
		for name, value := range map[string]string{HeaderANSInstanceSub: "user:admin", HeaderANSAct: `{"sub":"x"}`} {
			req.Header.Set(name, value)
		}
	}))
	if !d.Allowed || d.Identity.AnsName != fixtureAnsName || d.Identity.AgentID != fixtureAgentID {
		t.Fatalf("certificate-mode caller: %+v (deny %+v)", d, d.Deny)
	}
	if len(d.Headers) != 4 {
		t.Fatalf("Headers = %v, want the four certificate-mode headers", d.Headers)
	}
	for _, name := range []string{HeaderANSInstanceSub, HeaderANSAct, HeaderANSScope, HeaderANSAuthorizationDetails} {
		if !slices.Contains(d.RemoveHeaders, strings.ToLower(name)) {
			t.Fatalf("RemoveHeaders = %v, want %s stripped in certificate mode", d.RemoveHeaders, name)
		}
	}
}

// TestInstanceTokenWithReceiptTakesCertificatePath keeps routing narrow: an
// instance+jwt token sent alongside a SCITT receipt is a certificate-mode
// request, judged by the unchanged certificate pipeline.
func TestInstanceTokenWithReceiptTakesCertificatePath(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	r := vec.request(t)
	r.Header.Set(scitt.HeaderReceipt, "AAAA")
	keys := iv.keys(t)
	d := iv.verifier(t, iv.config(), keys).Verify(t.Context(), r)
	if d.Allowed || d.Deny == nil {
		t.Fatalf("Verify() = %+v, want a denial", d)
	}
	for _, code := range []string{"iss_mismatch", "bad_dpop", "bad_token", "instance_disabled"} {
		if strings.HasPrefix(d.Deny.Detail, code+": ") {
			t.Fatalf("Detail = %q: the instance path judged a request carrying a receipt", d.Deny.Detail)
		}
	}
}

// goMint signs instance tokens and proofs in Go, for edge cases the shared
// vectors do not carry. Its issuer is not in any status token, so a request
// it builds is refused at the status step at the latest; each case below
// targets a check that runs earlier.
type goMint struct {
	t        *testing.T
	iv       *instanceVectors
	issuer   *ecdsa.PrivateKey
	certDER  []byte
	instance *ecdsa.PrivateKey
}

func newGoMint(t *testing.T, iv *instanceVectors) *goMint {
	t.Helper()
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("ans://v1.0.0." + iv.AllowedIssuers[0])
	now := time.Unix(iv.Now, 0)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &issuer.PublicKey, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return &goMint{t: t, iv: iv, issuer: issuer, certDER: der, instance: instance}
}

func (m *goMint) jwk(key *ecdsa.PrivateKey) map[string]any {
	b, err := key.PublicKey.Bytes()
	if err != nil {
		m.t.Fatal(err)
	}
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64url(b[1:33]), "y": b64url(b[33:])}
}

func (m *goMint) jkt() string {
	j := m.jwk(m.instance)
	return jwkThumbprint(j["x"].(string), j["y"].(string))
}

func (m *goMint) sign(key *ecdsa.PrivateKey, header, payload any) string {
	m.t.Helper()
	enc := func(v any) string {
		if s, ok := v.(string); ok {
			return s // a raw segment, already encoded
		}
		b, err := json.Marshal(v)
		if err != nil {
			m.t.Fatal(err)
		}
		return b64url(b)
	}
	input := enc(header) + "." + enc(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		m.t.Fatal(err)
	}
	sig := make([]byte, es256SigLen)
	r.FillBytes(sig[:p256CoordLen])
	s.FillBytes(sig[p256CoordLen:])
	return input + "." + b64url(sig)
}

func (m *goMint) claims() map[string]any {
	return map[string]any{
		"iss": m.iv.AllowedIssuers[0], "ans_name": "ans://v1.0.0." + m.iv.AllowedIssuers[0], "aud": m.iv.ExpectedAud,
		"sub": "user:go-1", "scope": "mcp:list_tools", "iat": m.iv.Now, "exp": m.iv.Now + 300, "jti": "go-jti",
		"cnf": map[string]any{"jkt": m.jkt()},
	}
}

func (m *goMint) header() map[string]any {
	return map[string]any{"alg": "ES256", "typ": "instance+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(m.certDER)}}
}

func (m *goMint) proofPayload(tok string, body []byte) map[string]any {
	ath := sha256.Sum256([]byte(tok))
	digest := sha256.Sum256(body)
	return map[string]any{"jti": "p-" + tok[len(tok)-8:], "htm": http.MethodPost, "htu": m.iv.TrustedHost + "/mcp",
		"iat": m.iv.Now, "ath": b64url(ath[:]), "ans_content_digest": b64url(digest[:])}
}

func (m *goMint) proofHeader() map[string]any {
	return map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": m.jwk(m.instance)}
}

type goCase struct {
	name     string
	header   func(map[string]any)
	claims   func(map[string]any)
	token    func(string) string
	pheader  func(map[string]any)
	payload  func(map[string]any)
	proof    func(string) string
	body     []byte
	code     string
	category string
}

func (m *goMint) request(t *testing.T, c goCase) *Request {
	t.Helper()
	h, cl := m.header(), m.claims()
	if c.header != nil {
		c.header(h)
	}
	if c.claims != nil {
		c.claims(cl)
	}
	tok := m.sign(m.issuer, h, cl)
	if c.token != nil {
		tok = c.token(tok)
	}
	body := []byte("{}")
	if c.body != nil {
		body = c.body
	}
	ph, pp := m.proofHeader(), m.proofPayload(tok, body)
	if c.pheader != nil {
		c.pheader(ph)
	}
	if c.payload != nil {
		c.payload(pp)
	}
	proof := m.sign(m.instance, ph, pp)
	if c.proof != nil {
		proof = c.proof(proof)
	}
	vec := validInstanceVector(t, m.iv)
	vec.Token, vec.DPoP, vec.Body = tok, proof, string(body)
	return vec.request(t)
}

// TestInstanceEdgeCases covers the shape checks the cross-language vectors do
// not each exercise.
func TestInstanceEdgeCases(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	m := newGoMint(t, iv)
	segment := func(s string) string { return b64url([]byte(s)) }
	cases := []goCase{
		{name: "token payload not base64", token: func(s string) string {
			p := strings.Split(s, ".")
			return p[0] + ".!!." + p[2]
		}, code: "bad_token", category: CategoryMalformedProof},
		{name: "token payload not an object", token: func(s string) string {
			p := strings.Split(s, ".")
			return p[0] + "." + segment("[1]") + "." + p[2]
		}, code: "bad_token", category: CategoryMalformedProof},
		{name: "token with four segments", token: func(s string) string { return s + ".x" }, code: "bad_token", category: CategoryMalformedProof},
		{name: "token alg ES384", header: func(h map[string]any) { h["alg"] = "ES384" }, code: "bad_token", category: CategoryUnsupportedAlg},
		{name: "x5c with two certificates", header: func(h map[string]any) { h["x5c"] = []string{"AA==", "AA=="} }, code: "bad_token", category: CategoryCertInvalid},
		{name: "x5c not base64", header: func(h map[string]any) { h["x5c"] = []string{"!!"} }, code: "bad_token", category: CategoryCertInvalid},
		{name: "x5c not a certificate", header: func(h map[string]any) { h["x5c"] = []string{"AAAA"} }, code: "bad_token", category: CategoryCertInvalid},
		{name: "no cnf.jkt", claims: func(c map[string]any) { delete(c, "cnf") }, code: "bad_token", category: CategoryMalformedProof},
		{name: "iat not an integer", claims: func(c map[string]any) { c["iat"] = 1.5 }, code: "bad_token", category: CategoryMalformedProof},
		{name: "scope not a string", claims: func(c map[string]any) { c["scope"] = []string{"a"} }, code: "bad_token", category: CategoryMalformedProof},
		{name: "authorization_details not a list", claims: func(c map[string]any) { c["authorization_details"] = map[string]any{"type": "x"} }, code: "bad_token", category: CategoryMalformedProof},
		{name: "act not an object", claims: func(c map[string]any) { c["act"] = "instance:x" }, code: "bad_token", category: CategoryMalformedProof},
		{name: "act without sub", claims: func(c map[string]any) { c["act"] = map[string]any{"iss": "x"} }, code: "bad_token", category: CategoryMalformedProof},
		{name: "proof with two segments", proof: func(s string) string { return s[:strings.LastIndex(s, ".")] }, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof header not base64", proof: func(s string) string { _, rest, _ := strings.Cut(s, "."); return "!!." + rest }, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof alg ES384", pheader: func(h map[string]any) { h["alg"] = "ES384" }, code: "bad_dpop", category: CategoryUnsupportedAlg},
		{name: "proof jwk not an object", pheader: func(h map[string]any) { h["jwk"] = "k" }, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof jwk is private", pheader: func(h map[string]any) {
			j := m.jwk(m.instance)
			j["d"] = "AAAA"
			h["jwk"] = j
		}, code: "bad_dpop", category: CategoryUnsupportedAlg},
		{name: "proof jwk off the curve", claims: func(c map[string]any) {
			c["cnf"] = map[string]any{"jkt": jwkThumbprint(b64url(make([]byte, 32)), b64url(make([]byte, 32)))}
		}, pheader: func(h map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": b64url(make([]byte, 32)), "y": b64url(make([]byte, 32))}
		}, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof jwk short coordinate", claims: func(c map[string]any) {
			c["cnf"] = map[string]any{"jkt": jwkThumbprint("AAAA", "AAAA")}
		}, pheader: func(h map[string]any) {
			h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"}
		}, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof payload not an object", proof: func(s string) string {
			p := strings.Split(s, ".")
			return m.sign(m.instance, p[0], segment("1"))
		}, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof without jti", payload: func(p map[string]any) { delete(p, "jti") }, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof jti over the SDK limit", payload: func(p map[string]any) { p["jti"] = strings.Repeat("j", 129) }, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof without iat", payload: func(p map[string]any) { delete(p, "iat") }, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof iat in the future", payload: func(p map[string]any) { p["iat"] = iv.Now + 500 }, code: "clock_skew", category: CategoryProofStale},
		// now-iat wraps to a negative int64 for this iat, which an overflowing
		// skew check reads as fresh.
		{name: "bad_dpop_iat_overflow", payload: func(p map[string]any) { p["iat"] = iv.Now + math.MinInt64 }, code: "clock_skew", category: CategoryProofStale},
		// The reference requires a JSON integer (isinstance int); a quoted
		// number, which json.Number would otherwise accept, is refused.
		{name: "bad_dpop_iat_quoted", payload: func(p map[string]any) { p["iat"] = strconv.FormatInt(iv.Now, 10) }, code: "bad_dpop", category: CategoryMalformedProof},
		// RFC 9110 method names are case-sensitive, as the SDK compares them.
		{name: "proof htm in lower case", payload: func(p map[string]any) { p["htm"] = "post" }, code: "bad_dpop", category: CategoryHTTPBindingMismatch},
		{name: "proof iat at the int64 minimum", payload: func(p map[string]any) { p["iat"] = int64(math.MinInt64) }, code: "clock_skew", category: CategoryProofStale},
		{name: "proof iat zero", payload: func(p map[string]any) { p["iat"] = 0 }, code: "clock_skew", category: CategoryProofStale},
		{name: "proof htu not absolute", payload: func(p map[string]any) { p["htu"] = "/mcp" }, code: "htu_mismatch", category: CategoryHTTPBindingMismatch},
		{name: "proof htu not a URL", payload: func(p map[string]any) { p["htu"] = "https://%zz" }, code: "htu_mismatch", category: CategoryHTTPBindingMismatch},
		{name: "proof htu on another port", payload: func(p map[string]any) { p["htu"] = iv.TrustedHost + ":8443/mcp" }, code: "htu_mismatch", category: CategoryHTTPBindingMismatch},
		{name: "proof digest malformed", payload: func(p map[string]any) { p["ans_content_digest"] = "short" }, code: "bad_dpop", category: CategoryMalformedProof},
		{name: "proof signature not base64", proof: func(s string) string { return s[:strings.LastIndex(s, ".")] + ".!!" }, code: "bad_dpop", category: CategorySignatureInvalid},
		{name: "bad_token_iat_quoted", claims: func(c map[string]any) { c["iat"] = strconv.FormatInt(iv.Now, 10) }, code: "bad_token", category: CategoryMalformedProof},
		{name: "bad_token_exp_quoted", claims: func(c map[string]any) { c["exp"] = strconv.FormatInt(iv.Now+300, 10) }, code: "bad_token", category: CategoryMalformedProof},
		{name: "bad_token_iat_bool", claims: func(c map[string]any) { c["iat"] = true }, code: "bad_token", category: CategoryMalformedProof},
		{name: "bad_token_exp_bool", claims: func(c map[string]any) { c["exp"] = true }, code: "bad_token", category: CategoryMalformedProof},
		// exp-iat wraps negative for this iat, which an overflowing cap reads
		// as a short lifetime; the reference's integers do not wrap.
		{name: "bad_token_lifetime_overflow", claims: func(c map[string]any) { c["iat"] = int64(math.MinInt64); c["exp"] = int64(4102444800) }, code: "bad_token", category: CategoryMalformedProof},
		{name: "token iat in the future", claims: func(c map[string]any) { c["iat"] = iv.Now + 500; c["exp"] = iv.Now + 600 }, code: "clock_skew", category: CategoryProofStale},
		{name: "unknown status-token issuer", code: "cert_not_current", category: CategoryBindingFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := iv.verifier(t, iv.config(), iv.keys(t)).Verify(t.Context(), m.request(t, c))
			requireInstanceDenial(t, d, c.code)
			if d.Deny.Category != c.category {
				t.Fatalf("Category = %q, want %q (detail %q)", d.Deny.Category, c.category, d.Deny.Detail)
			}
		})
	}
}

// TestInstancePresentedStatusUnknownKid: with the status cache off, a status
// token under a TL key the keyring does not hold yet is verified again after
// one on-demand root-key refresh, as certificate mode does.
func TestInstancePresentedStatusUnknownKid(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	lookup := newMapLookup()
	keys := &countingKeys{inner: mustKeyring(t, NoopObserver{}, KeySource{Name: "test-tl", Lookup: lookup, Timeout: time.Second,
		Refresh: func(context.Context) error {
			tk, err := scitt.ParseC2SPKey(h.line)
			if err != nil {
				return err
			}
			lookup.add(tk)
			return nil
		}})}
	v := h.iv.verifier(t, h.iv.config(), keys)
	requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -1))), "after a root-key refresh")
	if n := keys.refreshes.Load(); n != 1 {
		t.Fatalf("root-key refreshes = %d, want 1", n)
	}
}

// TestInstancePresentedStatusExpired maps the SDK's expired-token error to
// status_expired with the status cache off.
func TestInstancePresentedStatusExpired(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	v := h.iv.verifier(t, h.iv.config(), h.keys)
	expired := h.mintFor(h.iv.AgentID, h.ansName, scitt.StatusActive, -7200, -3600)
	d := v.Verify(t.Context(), h.request(expired))
	requireInstanceDenial(t, d, codeStatusExpired)
	if !strings.Contains(d.Deny.Detail, "token expired at") {
		t.Fatalf("Detail = %q, want the SDK's expiry error", d.Deny.Detail)
	}
}

// TestInstanceRouting keeps the instance path narrow: only a DPoP token whose
// header decodes and names typ instance+jwt selects it.
func TestInstanceRouting(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		auth string
		want bool
	}{
		{"instance token", "DPoP " + b64url([]byte(`{"typ":"instance+jwt"}`)) + ".e30.sig", true},
		{"bearer scheme", "Bearer " + b64url([]byte(`{"typ":"instance+jwt"}`)) + ".e30.sig", false},
		{"access token typ", "DPoP " + b64url([]byte(`{"typ":"at+jwt"}`)) + ".e30.sig", false},
		{"opaque token", "DPoP opaque", false},
		{"header not base64", "DPoP !!.e30.sig", false},
		{"header not JSON", "DPoP " + b64url([]byte("typ")) + ".e30.sig", false},
		{"no authorization", "", false},
	} {
		h := http.Header{}
		if tc.auth != "" {
			h.Set("Authorization", tc.auth)
		}
		if _, got := isInstanceRequest(h); got != tc.want {
			t.Errorf("%s: isInstanceRequest = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestInstanceReplayReleasesCapSlot gives a cap slot back when the replay
// check refuses the request that took it.
func TestInstanceReplayReleasesCapSlot(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	cfg := iv.config()
	cfg.InstanceMode.MaxInstancesPerSub = 1
	mem := &fakeCache{check: func(context.Context, string, time.Time) (bool, error) { return true, nil }}
	v, err := NewVerifier(cfg, iv.keys(t), mem, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(iv.Now, 0)
	v.now = func() time.Time { return now }
	first := iv.CapRequests[0]
	requireInstanceDenial(t, v.Verify(t.Context(), first.request(t)), "replay")
	// Had the slot stuck, a second key for the same sub would hit the cap.
	mem.check = func(context.Context, string, time.Time) (bool, error) { return false, nil }
	second := iv.CapRequests[2]
	if d := v.Verify(t.Context(), second.request(t)); !d.Allowed {
		t.Fatalf("second key after a replayed first: %+v", d.Deny)
	}
}

// TestInstanceCapExpiry frees a sub's slots once their tokens expire.
func TestInstanceCapExpiry(t *testing.T) {
	t.Parallel()
	c := newInstanceCap(1)
	if added, ok := c.admit("s", "k1", 100, 0); !added || !ok {
		t.Fatal("first key refused")
	}
	if _, ok := c.admit("s", "k2", 200, 50); ok {
		t.Fatal("second live key admitted over the cap")
	}
	if added, ok := c.admit("s", "k2", 200, 100); !added || !ok {
		t.Fatal("second key refused after the first expired")
	}
	if _, ok := c.admit("other", "k3", 300, 250); !ok || len(c.subs) != 1 {
		t.Fatalf("sweep left %d subs, want only the live one", len(c.subs))
	}
	if newInstanceCap(0) != nil {
		t.Fatal("a zero cap must be off")
	}
}

// TestInstanceInfrastructureFaults maps replay-cache and budget faults the
// same way certificate mode does.
func TestInstanceInfrastructureFaults(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	cache := &fakeCache{check: func(context.Context, string, time.Time) (bool, error) { return false, replay.ErrUnavailable }}
	v, err := NewVerifier(iv.config(), iv.keys(t), cache, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(iv.Now, 0)
	v.now = func() time.Time { return now }
	if d := v.Verify(t.Context(), vec.request(t)); d.Deny == nil || d.Deny.Category != CategoryReplayCacheUnavailable {
		t.Fatalf("replay backend down: %+v", d.Deny)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if d := v.Verify(ctx, vec.request(t)); d.Deny == nil || d.Deny.Category != CategoryClientGone {
		t.Fatalf("cancelled request: %+v", d.Deny)
	}
	if (&deniedError{denial: &Denial{Detail: "x"}}).Error() != "x" {
		t.Fatal("deniedError text")
	}
}

// TestInstanceAllowedAnsNames applies allowedAnsNames to the issuer in
// instance mode, as it applies to the caller in certificate mode.
func TestInstanceAllowedAnsNames(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	cfg := iv.config()
	cfg.AllowedAnsNames = []string{"ans://v1.0.0.other.example.test"}
	d := iv.verifier(t, cfg, iv.keys(t)).Verify(t.Context(), vec.request(t))
	requireInstanceDenial(t, d, "iss_mismatch")
	if d.Deny.Category != CategoryExpectedPeerMismatch || d.Deny.HTTPStatus != http.StatusForbidden {
		t.Fatalf("Deny = %+v", d.Deny)
	}
	cfg.AllowedAnsNames = []string{vec.Expect.AnsName}
	if d := iv.verifier(t, cfg, iv.keys(t)).Verify(t.Context(), vec.request(t)); !d.Allowed {
		t.Fatalf("issuer listed in allowedAnsNames denied: %+v", d.Deny)
	}
}

// TestCertificateModeStripsInstanceHeadersWhenOff strips the instance
// headers from a certificate-mode allow even with instance mode off.
func TestCertificateModeStripsInstanceHeadersWhenOff(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	d := f.verifier(t, testConfig()).Verify(t.Context(), f.signed(t, http.MethodGet, fixtureTarget, nil, nil))
	if !d.Allowed {
		t.Fatalf("denied: %+v", d.Deny)
	}
	for _, name := range []string{"x-ans-act", "x-ans-instance-sub", "x-ans-scope", "x-ans-authorization-details"} {
		if !slices.Contains(d.RemoveHeaders, name) {
			t.Fatalf("RemoveHeaders = %v, want %s", d.RemoveHeaders, name)
		}
	}
}

// TestInstanceExtraIdentityHeaders maps agent_id and jkt to the instance in
// instance mode, so two instances of one issuer never share a session
// subject, while ans_name and fingerprint stay the issuer's.
func TestInstanceExtraIdentityHeaders(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	cfg := iv.config()
	cfg.ExtraIdentityHeaders = map[string]string{
		"x-session-subject": "agent_id", "x-key": "jkt", "x-caller": "ans_name", "x-cert": "fingerprint",
	}
	v := iv.verifier(t, cfg, iv.keys(t))
	seen := map[string]bool{}
	for _, vec := range iv.CapRequests[:3] { // sub1 key1, key1 again, key2
		d := v.Verify(t.Context(), vec.request(t))
		if !d.Allowed {
			t.Fatalf("%s denied: %+v", vec.Name, d.Deny)
		}
		jkt := d.Headers[HeaderANSJKT]
		if d.Headers["x-session-subject"] != jkt || d.Headers["x-key"] != jkt {
			t.Fatalf("%s: extra headers %v, want agent_id and jkt = instance jkt %s", vec.Name, d.Headers, jkt)
		}
		if d.Headers["x-caller"] != d.Headers[HeaderANSName] || d.Headers["x-cert"] != d.Headers[HeaderANSFingerprint] {
			t.Fatalf("%s: ans_name/fingerprint must stay the issuer's: %v", vec.Name, d.Headers)
		}
		if d.Headers[HeaderANSAgentID] != iv.AgentID {
			t.Fatalf("X-ANS-Agent-Id = %q, want the issuer's %q", d.Headers[HeaderANSAgentID], iv.AgentID)
		}
		seen[d.Headers["x-session-subject"]] = true
	}
	if len(seen) != 2 {
		t.Fatalf("two instance keys produced %d distinct session subjects, want 2", len(seen))
	}
}

// TestInstanceEmptyBody admits an empty body bound by the empty-content
// digest (pop.EmptyContentDigest) and refuses one whose proof has no digest.
func TestInstanceEmptyBody(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	byName := map[string]instanceVector{}
	for _, vec := range iv.Vectors {
		byName[vec.Name] = vec
	}
	ok, missing := byName["valid_empty_body"], byName["bad_dpop_no_content_digest"]
	if ok.Body != "" || missing.Body != "" {
		t.Fatalf("empty-body vectors carry bodies %q / %q", ok.Body, missing.Body)
	}
	if d := iv.verifier(t, iv.config(), iv.keys(t)).Verify(t.Context(), ok.request(t)); !d.Allowed {
		t.Fatalf("empty body with the empty-content digest denied: %+v", d.Deny)
	}
	d := iv.verifier(t, iv.config(), iv.keys(t)).Verify(t.Context(), missing.request(t))
	requireInstanceDenial(t, d, "bad_dpop")
	if d.Deny.Category != CategoryMalformedProof {
		t.Fatalf("Category = %q, want %q", d.Deny.Category, CategoryMalformedProof)
	}
}
