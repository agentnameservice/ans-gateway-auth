package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testTxnIssuer   = "https://gw.example.test"
	testTxnAudience = "upstream.example.test"
	testRequestID   = "req-7f3a9c"
)

func newTxnKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func txnConfig() TransactionToken {
	return TransactionToken{Enabled: true, SigningKeyFile: "/unused-in-authz-tests.pem", Issuer: testTxnIssuer,
		Audience: testTxnAudience, TTL: DefaultTxnTTL, Header: DefaultTxnHeader}
}

func mustMinter(t *testing.T, cfg TransactionToken, key *ecdsa.PrivateKey) *TxnMinter {
	t.Helper()
	m, err := NewTxnMinter(cfg, key)
	if err != nil {
		t.Fatalf("NewTxnMinter: %v", err)
	}
	return m
}

// buildTxnVerifier wires a verifier that never reports a replay and, when m
// is set, mints with it; now, when set, fixes the clock.
func buildTxnVerifier(t *testing.T, cfg Config, keys KeyProvider, m *TxnMinter, now *time.Time) *Verifier {
	t.Helper()
	var opts []VerifierOption
	if m != nil {
		cfg.TransactionToken = m.cfg
		opts = append(opts, WithTxnMinter(m))
	}
	noReplay := &fakeCache{check: func(context.Context, string, time.Time) (bool, error) { return false, nil }}
	v, err := NewVerifier(cfg, keys, noReplay, nil, nil, opts...)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if now != nil {
		fixed := *now
		v.now = func() time.Time { return fixed }
	}
	return v
}

// txnVerifier is an instance-mode verifier over the vectors, minting with m.
func txnVerifier(t *testing.T, iv *instanceVectors, m *TxnMinter) *Verifier {
	t.Helper()
	now := time.Unix(iv.Now, 0)
	return buildTxnVerifier(t, iv.config(), iv.keys(t), m, &now)
}

// decodeTxn verifies a transaction token under the minter's published JWKS
// and returns its header and claims.
func decodeTxn(t *testing.T, m *TxnMinter, tok string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != jwsSegments {
		t.Fatalf("token %q is not a compact JWS", tok)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(m.JWKS(), &jwks); err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("JWKS %s: %v", m.JWKS(), err)
	}
	jwk := jwks.Keys[0]
	pub, err := p256Key(jwk["x"], jwk["y"])
	if err != nil {
		t.Fatal(err)
	}
	if !verifyES256(pub, parts[0]+"."+parts[1], parts[2]) {
		t.Fatal("transaction token does not verify under the JWKS key")
	}
	decode := func(seg string) map[string]any {
		raw, err := b64urlDecode(seg)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	return decode(parts[0]), decode(parts[1])
}

func requireJSON(t *testing.T, what string, got any, want string) {
	t.Helper()
	gb, _ := json.Marshal(got)
	var w any
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatal(err)
	}
	wb, _ := json.Marshal(w)
	if string(gb) != string(wb) {
		t.Fatalf("%s =\n %s\nwant\n %s", what, gb, wb)
	}
}

// checkRandomIDs removes jti (and, when wantTxn is empty, txn) after checking
// each is a 128-bit base64url value, so the rest can be compared exactly.
func checkRandomIDs(t *testing.T, claims map[string]any, randomTxn bool) {
	t.Helper()
	names := []string{"jti"}
	if randomTxn {
		names = append(names, "txn")
	}
	for _, name := range names {
		s, _ := claims[name].(string)
		if raw, err := b64urlDecode(s); err != nil || len(raw) != txnRandomBytes {
			t.Fatalf("%s = %q, want %d random bytes in base64url", name, s, txnRandomBytes)
		}
		delete(claims, name)
	}
}

// TestTxnTokenInstanceModeClaims mints on an instance-mode allow with the
// exact claim set. act is always the single hop {"sub":"instance:<cnf.jkt>"}:
// for a child (whose act already names that key) and for a parent alike. The
// parent instance of a child is not named. exp is iat + ttl, below the
// instance token's own exp. sid, the issuer's session id, is copied when the
// instance token carries one and absent otherwise, so an upstream's audit
// line can name the session an issuer later revokes.
func TestTxnTokenInstanceModeClaims(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	byName := map[string]instanceVector{}
	for _, vec := range iv.Vectors {
		byName[vec.Name] = vec
	}
	for _, name := range []string{"valid", "valid_child_with_act", "valid_with_sid"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			vec, ok := byName[name]
			if !ok {
				t.Fatalf("no vector %q", name)
			}
			e := vec.Expect
			wantClaims := map[string]any{
				"iss": testTxnIssuer, "aud": testTxnAudience, "iat": iv.Now, "exp": iv.Now + 60,
				"txn": testRequestID, "sub": e.Sub, "act": map[string]string{"sub": "instance:" + e.JKT},
				"cnf": map[string]string{"jkt": e.JKT}, "scope": e.Scope,
				"authorization_details": e.AuthorizationDetails,
				"ans_issuer":            map[string]string{"host": e.Iss, "ans_name": e.AnsName, "cert_fp": e.Fingerprint},
				"rctx":                  map[string]string{"method": "POST", "path": "/mcp"},
			}
			if e.Sid != "" {
				wantClaims["sid"] = e.Sid
			}
			if name == "valid_with_sid" && e.Sid != "sess-test-0001" {
				t.Fatalf("vector sid = %q, want sess-test-0001", e.Sid)
			}
			want, err := json.Marshal(wantClaims)
			if err != nil {
				t.Fatal(err)
			}
			if name == "valid_child_with_act" {
				requireJSON(t, "vector act", e.Act, `{"sub":"instance:`+e.JKT+`"}`)
			}
			m := mustMinter(t, txnConfig(), newTxnKey(t))
			r := vec.request(t)
			r.RequestID = testRequestID
			d := txnVerifier(t, iv, m).Verify(t.Context(), r)
			if !d.Allowed {
				t.Fatalf("denied: %+v", d.Deny)
			}
			header, claims := decodeTxn(t, m, d.Headers[DefaultTxnHeader])
			requireJSON(t, "header", header, `{"alg":"ES256","typ":"txntoken+jwt","kid":"`+m.KeyID()+`"}`)
			checkRandomIDs(t, claims, false)
			requireJSON(t, "claims", claims, string(want))
			if slices.Contains(d.RemoveHeaders, strings.ToLower(DefaultTxnHeader)) {
				t.Fatal("the minted header is also removed")
			}
		})
	}
}

// TestTxnTokenExpClampedToInstanceToken: an instance token expiring 10 s
// after the request bounds the transaction token too.
func TestTxnTokenExpClampedToInstanceToken(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	m := mustMinter(t, txnConfig(), newTxnKey(t))
	r := validReq(t, iv)
	exp := int64(0)
	if it, err := parseInstanceToken(validInstanceVector(t, iv).Token); err == nil {
		exp = it.claims.exp
	}
	// Pin the verifier's clock 10 s before the instance token's exp, widening
	// popSkew so the vector's proof (iat = the vectors' now) still verifies.
	now := time.Unix(exp-10, 0)
	cfg := iv.config()
	cfg.PoPSkew = time.Duration(exp-iv.Now) * time.Second
	v := buildTxnVerifier(t, cfg, iv.keys(t), m, &now)
	d := v.Verify(t.Context(), r)
	if !d.Allowed {
		t.Fatalf("denied: %+v", d.Deny)
	}
	_, claims := decodeTxn(t, m, d.Headers[DefaultTxnHeader])
	if got := int64(claims["exp"].(float64)); got != exp {
		t.Fatalf("exp = %d, want the instance token's exp %d (iat %v + ttl 60 would be later)", got, exp, claims["iat"])
	}
	if got := int64(claims["iat"].(float64)); got != exp-10 {
		t.Fatalf("iat = %d, want %d", got, exp-10)
	}
}

// TestTxnTokenCertificateModeClaims mints for a certificate-mode caller: sub
// is the caller's ANS name, cnf.jkt its key, and there is no act.
func TestTxnTokenCertificateModeClaims(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	m := mustMinter(t, txnConfig(), newTxnKey(t))
	v := buildTxnVerifier(t, testConfig(), f.keyring(t), m, nil)
	r := f.signed(t, http.MethodPost, fixtureTarget+"?q=secret", []byte(`{"a":1}`), nil)
	r.RequestID = testRequestID
	before := time.Now().Unix()
	d := v.Verify(t.Context(), r)
	if !d.Allowed {
		t.Fatalf("denied: %+v", d.Deny)
	}
	_, claims := decodeTxn(t, m, d.Headers[DefaultTxnHeader])
	iat, _ := claims["iat"].(float64)
	if int64(iat) < before || int64(iat) > time.Now().Unix() {
		t.Fatalf("iat %v is not now", iat)
	}
	if exp, _ := claims["exp"].(float64); exp-iat != 60 {
		t.Fatalf("exp - iat = %v, want 60", exp-iat)
	}
	delete(claims, "iat")
	delete(claims, "exp")
	checkRandomIDs(t, claims, false)
	requireJSON(t, "claims", claims, `{"iss":"https://gw.example.test","aud":"upstream.example.test","txn":"req-7f3a9c",
		"sub":"`+fixtureAnsName+`","cnf":{"jkt":"`+d.Identity.JKT+`"},"rctx":{"method":"POST","path":"/v1/resource"}}`)
}

// TestTxnTokenNotMintedOnDeny: a refused request carries no token in either
// mode.
func TestTxnTokenNotMintedOnDeny(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	m := mustMinter(t, txnConfig(), newTxnKey(t))
	r := validReq(t, iv)
	r.Body = []byte("tampered")
	if d := txnVerifier(t, iv, m).Verify(t.Context(), r); d.Allowed || d.Headers != nil {
		t.Fatalf("instance deny: %+v", d)
	}
	f := newFixture(t)
	v := buildTxnVerifier(t, testConfig(), f.keyring(t), m, nil)
	if d := v.Verify(t.Context(), bare(t, http.MethodPost, "https://api.example/other", []byte("{}"))); d.Allowed || d.Headers != nil {
		t.Fatalf("certificate deny: %+v", d)
	}
}

// TestTxnTokenClientHeaderStripped: a client-supplied token never reaches the
// upstream. Enabled, the header is overwritten with the minted token;
// disabled, it is removed; both in both modes, and under a custom name.
func TestTxnTokenClientHeaderStripped(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	f := newFixture(t)
	const forged = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
	for _, tc := range []struct {
		name    string
		enabled bool
		header  string
	}{
		{"enabled", true, DefaultTxnHeader},
		{"enabled, custom header", true, "X-Gw-Txn"},
		{"disabled", false, DefaultTxnHeader},
		{"disabled, custom header", false, "X-Gw-Txn"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tcfg := txnConfig()
			tcfg.Enabled, tcfg.Header = tc.enabled, tc.header
			var m *TxnMinter
			if tc.enabled {
				m = mustMinter(t, tcfg, newTxnKey(t))
			}
			instance := validReq(t, iv)
			instance.Header.Set(tc.header, forged)
			icfg, ccfg := iv.config(), testConfig()
			icfg.TransactionToken, ccfg.TransactionToken = tcfg, tcfg
			now := time.Unix(iv.Now, 0)
			iver := buildTxnVerifier(t, icfg, iv.keys(t), m, &now)
			cver := buildTxnVerifier(t, ccfg, f.keyring(t), m, nil)
			cert := f.signed(t, http.MethodGet, fixtureTarget, nil, func(req *http.Request) { req.Header.Set(tc.header, forged) })

			for mode, d := range map[string]Decision{
				"instance": iver.Verify(t.Context(), instance), "certificate": cver.Verify(t.Context(), cert),
			} {
				if !d.Allowed {
					t.Fatalf("%s: denied %+v", mode, d.Deny)
				}
				got, set := d.Headers[tc.header]
				removed := slices.Contains(d.RemoveHeaders, strings.ToLower(tc.header))
				switch {
				case tc.enabled && (!set || got == forged || removed):
					t.Fatalf("%s: header %q set=%v removed=%v, want the minted token", mode, got, set, removed)
				case !tc.enabled && (set || !removed):
					t.Fatalf("%s: header set=%v removed=%v, want removed", mode, set, removed)
				}
				if tc.enabled {
					decodeTxn(t, m, got)
				}
			}
		})
	}
}

// TestTxnTokenLifetime: exp - iat is exactly the configured ttl, at most 300s.
func TestTxnTokenLifetime(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	for _, ttl := range []time.Duration{time.Second, DefaultTxnTTL, MaxTxnTTL} {
		cfg := txnConfig()
		cfg.TTL = ttl
		m := mustMinter(t, cfg, newTxnKey(t))
		d := txnVerifier(t, iv, m).Verify(t.Context(), validReq(t, iv))
		_, claims := decodeTxn(t, m, d.Headers[DefaultTxnHeader])
		iat, exp := claims["iat"].(float64), claims["exp"].(float64)
		if time.Duration(exp-iat)*time.Second != ttl || exp-iat > MaxTxnTTL.Seconds() {
			t.Fatalf("ttl %s: exp - iat = %v", ttl, exp-iat)
		}
	}
}

// TestTxnTokenTxnFallback: without a request id, or with one too long or not
// printable, txn is a fresh random id distinct from jti.
func TestTxnTokenTxnFallback(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	m := mustMinter(t, txnConfig(), newTxnKey(t))
	for _, id := range []string{"", strings.Repeat("r", maxTxnRequestID+1), "bad\x01id"} {
		r := validReq(t, iv)
		r.RequestID = id
		d := txnVerifier(t, iv, m).Verify(t.Context(), r)
		_, claims := decodeTxn(t, m, d.Headers[DefaultTxnHeader])
		if claims["txn"] == claims["jti"] {
			t.Fatalf("request id %q: txn equals jti", id)
		}
		checkRandomIDs(t, claims, true)
	}
	r := validReq(t, iv)
	r.RequestID = strings.Repeat("r", maxTxnRequestID)
	d := txnVerifier(t, iv, m).Verify(t.Context(), r)
	if _, claims := decodeTxn(t, m, d.Headers[DefaultTxnHeader]); claims["txn"] != r.RequestID {
		t.Fatalf("txn = %v, want the %d-character request id", claims["txn"], maxTxnRequestID)
	}
}

// TestTxnTokenJWKS publishes the public key with kid = RFC 7638 thumbprint,
// alg ES256 and use sig, and no private part.
func TestTxnTokenJWKS(t *testing.T) {
	t.Parallel()
	key := newTxnKey(t)
	m := mustMinter(t, txnConfig(), key)
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(m.JWKS(), &jwks); err != nil || len(jwks.Keys) != 1 {
		t.Fatalf("JWKS %s: %v", m.JWKS(), err)
	}
	k := jwks.Keys[0]
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	wantKid := jwkThumbprint(b64url(pub[1:33]), b64url(pub[33:]))
	requireJSON(t, "jwk", k, `{"kty":"EC","crv":"P-256","x":"`+b64url(pub[1:33])+`","y":"`+b64url(pub[33:])+
		`","kid":"`+wantKid+`","alg":"ES256","use":"sig"}`)
	if m.KeyID() != wantKid {
		t.Fatalf("KeyID = %q, want %q", m.KeyID(), wantKid)
	}
}

// TestTxnTokenMintFailure denies (503) rather than allowing without a token
// when the random source fails.
func TestTxnTokenMintFailure(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	m := mustMinter(t, txnConfig(), newTxnKey(t))
	m.random = failingReader{}
	d := txnVerifier(t, iv, m).Verify(t.Context(), validReq(t, iv))
	if d.Allowed || d.Deny == nil || d.Deny.HTTPStatus != http.StatusServiceUnavailable || d.Deny.Category != CategoryInternalError {
		t.Fatalf("Verify = %+v (deny %+v)", d, d.Deny)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

// TestNewTxnMinterErrors rejects a missing or non-P-256 key and a disabled
// or invalid configuration.
func TestNewTxnMinterErrors(t *testing.T) {
	t.Parallel()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	disabled := txnConfig()
	disabled.Enabled = false
	bad := txnConfig()
	bad.TTL = 0
	for _, tc := range []struct {
		name string
		cfg  TransactionToken
		key  *ecdsa.PrivateKey
		want string
	}{
		{"nil key", txnConfig(), nil, "signing key"},
		{"P-384 key", txnConfig(), p384, "P-256"},
		{"disabled", disabled, newTxnKey(t), "not enabled"},
		{"invalid config", bad, newTxnKey(t), "ttl"},
	} {
		if _, err := NewTxnMinter(tc.cfg, tc.key); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

// TestWithTxnMinter wires a minter through NewVerifier and ignores one when
// the configuration has transaction tokens off.
func TestWithTxnMinter(t *testing.T) {
	t.Parallel()
	iv := loadInstanceVectors(t)
	m := mustMinter(t, txnConfig(), newTxnKey(t))
	cfg := iv.config()
	cfg.TransactionToken = m.cfg
	v, err := NewVerifier(cfg, iv.keys(t), &fakeCache{}, nil, nil, WithTxnMinter(m))
	if err != nil || v.txn != m {
		t.Fatalf("NewVerifier: %v, minter wired %v", err, v.txn == m)
	}
	if _, err := NewVerifier(iv.config(), iv.keys(t), &fakeCache{}, nil, nil, WithTxnMinter(m)); err == nil ||
		!strings.Contains(err.Error(), "transactionToken") {
		t.Fatalf("a minter with transaction tokens off: err = %v", err)
	}
	if _, err := NewVerifier(cfg, iv.keys(t), &fakeCache{}, nil, nil); err == nil || !strings.Contains(err.Error(), "minter") {
		t.Fatalf("transaction tokens on without a minter: err = %v", err)
	}
	other := cfg
	other.TransactionToken.Header = "X-Other-Txn"
	if _, err := NewVerifier(other, iv.keys(t), &fakeCache{}, nil, nil, WithTxnMinter(m)); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a minter built for another transactionToken config: err = %v", err)
	}
}

func writePEM(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadTxnSigningKey reads SEC1 and PKCS #8 P-256 keys and refuses
// anything else.
func TestLoadTxnSigningKey(t *testing.T) {
	t.Parallel()
	key := newTxnKey(t)
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	readable := writePEM(t, "EC PRIVATE KEY", sec1)
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644} {
		if err := os.Chmod(readable, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTxnSigningKey(readable); err == nil || !strings.Contains(err.Error(), "readable by group or others") {
			t.Fatalf("mode %o: err = %v, want a refusal", mode, err)
		}
	}
	if err := os.Chmod(readable, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTxnSigningKey(readable); err != nil {
		t.Fatalf("mode 0400: %v", err)
	}
	for _, path := range []string{writePEM(t, "EC PRIVATE KEY", sec1), writePEM(t, "PRIVATE KEY", pkcs8)} {
		got, err := LoadTxnSigningKey(path)
		if err != nil || !got.Equal(key) {
			t.Fatalf("LoadTxnSigningKey(%s) = %v", path, err)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384DER, _ := x509.MarshalECPrivateKey(p384)
	edPKCS8 := mustEd25519PKCS8(t)
	notPEM := filepath.Join(t.TempDir(), "x.pem")
	if err := os.WriteFile(notPEM, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, want string
	}{
		{"missing file", filepath.Join(t.TempDir(), "missing.pem"), "no such file"},
		{"not PEM", notPEM, "no PEM block"},
		{"P-384", writePEM(t, "EC PRIVATE KEY", p384DER), "P-256"},
		{"Ed25519 PKCS #8", writePEM(t, "PRIVATE KEY", edPKCS8), "ECDSA"},
		{"garbage SEC1", writePEM(t, "EC PRIVATE KEY", []byte{1, 2, 3}), "parse"},
		{"garbage PKCS #8", writePEM(t, "PRIVATE KEY", []byte{1, 2, 3}), "parse"},
		{"certificate", writePEM(t, "CERTIFICATE", []byte{1}), "EC PRIVATE KEY or PRIVATE KEY"},
	} {
		if _, err := LoadTxnSigningKey(tc.path); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func mustEd25519PKCS8(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func validReq(t *testing.T, iv *instanceVectors) *Request {
	t.Helper()
	vec := validInstanceVector(t, iv)
	return vec.request(t)
}
