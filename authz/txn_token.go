package authz

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Transaction tokens (draft-ietf-oauth-transaction-tokens). After every
// allow, in either caller mode, the verifier signs a short-lived JWT naming
// the verified context and hands it to the upstream in one header. An
// upstream authorizes on that signature, scoped to its own aud, instead of
// trusting bare X-ANS-* headers that any hop could have set.

// Transaction-token defaults and limits.
const (
	DefaultTxnTTL    = 60 * time.Second
	MaxTxnTTL        = 300 * time.Second
	DefaultTxnHeader = "Txn-Token"
	// TxnTokenTyp is the JWS typ header of a transaction token.
	TxnTokenTyp = "txntoken+jwt" //nolint:gosec // G101: a JWS media type, not a credential
	// txnRandomBytes sizes jti, and txn when the gateway sent no request id.
	txnRandomBytes = 16
	// maxTxnRequestID bounds a request id copied into txn.
	maxTxnRequestID = 128
	// instanceActorPrefix names the instance key in act.sub.
	instanceActorPrefix = "instance:"
)

// TransactionToken configures the token the verifier mints for upstreams.
type TransactionToken struct {
	// Enabled turns minting on. Off by default; the header is stripped from
	// every allowed request either way.
	Enabled bool `yaml:"enabled"`
	// SigningKeyFile is a PEM P-256 private key (SEC1 "EC PRIVATE KEY" or
	// PKCS #8 "PRIVATE KEY"). It is never generated at runtime. Required
	// when enabled.
	SigningKeyFile string `yaml:"signingKeyFile"`
	// Issuer is the iss claim: this gateway, as an https URL.
	Issuer string `yaml:"issuer"`
	// Audience is the aud claim: the one upstream the token is for.
	Audience string `yaml:"audience"`
	// TTL is exp - iat, a whole number of seconds up to MaxTxnTTL.
	TTL time.Duration `yaml:"ttl"`
	// Header carries the token to the upstream; DefaultTxnHeader by default.
	Header string `yaml:"header"`
}

// reservedTxnHeaders are header names the transaction-token header may not
// take: credentials the verifier reads and identity headers it sets.
func reservedTxnHeaders() []string {
	names := []string{headerAuthorization, "DPoP", "X-SCITT-Receipt", "X-ANS-Status-Token",
		HeaderANSName, HeaderANSAgentID, HeaderANSFingerprint, HeaderANSJKT}
	return append(names, instanceHeaders...)
}

func (tt TransactionToken) validate(extra map[string]string) error {
	if !validHeaderName(tt.Header) {
		return fmt.Errorf("authz: transactionToken.header %q is not a valid header name", tt.Header)
	}
	for _, name := range reservedTxnHeaders() {
		if strings.EqualFold(name, tt.Header) {
			return fmt.Errorf("authz: transactionToken.header %q collides with %s", tt.Header, name)
		}
	}
	for name := range extra {
		if strings.EqualFold(name, tt.Header) {
			return fmt.Errorf("authz: transactionToken.header %q collides with extraIdentityHeaders %q", tt.Header, name)
		}
	}
	if !tt.Enabled {
		return nil
	}
	if tt.SigningKeyFile == "" {
		return errors.New("authz: transactionToken.signingKeyFile is required when transaction tokens are enabled")
	}
	if u, err := url.Parse(tt.Issuer); err != nil || u.Scheme != schemeHTTPS || u.Host == "" {
		return fmt.Errorf("authz: transactionToken.issuer %q must be an https URL naming this gateway", tt.Issuer)
	}
	if tt.Audience == "" {
		return errors.New("authz: transactionToken.audience is required: the upstream the token is for")
	}
	if tt.TTL <= 0 || tt.TTL > MaxTxnTTL {
		return fmt.Errorf("authz: transactionToken.ttl must be positive and at most %s", MaxTxnTTL)
	}
	if tt.TTL%time.Second != 0 {
		return errors.New("authz: transactionToken.ttl must be a whole number of seconds")
	}
	return nil
}

// LoadTxnSigningKey reads a PEM P-256 private key.
func LoadTxnSigningKey(path string) (*ecdsa.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("transactionToken.signingKeyFile: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("transactionToken.signingKeyFile %s: mode %04o is readable by group or others; chmod 600",
			path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("transactionToken.signingKeyFile: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("transactionToken.signingKeyFile %s: no PEM block", path)
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("transactionToken.signingKeyFile %s: parse: %w", path, err)
		}
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("transactionToken.signingKeyFile %s: parse: %w", path, err)
		}
		var ok bool
		if key, ok = parsed.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("transactionToken.signingKeyFile %s: not an ECDSA key", path)
		}
	default:
		return nil, fmt.Errorf("transactionToken.signingKeyFile %s: PEM type %q, want EC PRIVATE KEY or PRIVATE KEY", path, block.Type)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("transactionToken.signingKeyFile %s: key must be P-256 for ES256", path)
	}
	return key, nil
}

// TxnMinter signs transaction tokens with one P-256 key.
type TxnMinter struct {
	cfg    TransactionToken
	key    *ecdsa.PrivateKey
	kid    string
	header string // the encoded JWS protected header
	jwks   []byte
	random io.Reader
}

// NewTxnMinter validates an enabled configuration and prepares the key.
func NewTxnMinter(cfg TransactionToken, key *ecdsa.PrivateKey) (*TxnMinter, error) {
	if !cfg.Enabled {
		return nil, errors.New("authz: transaction tokens are not enabled")
	}
	if err := cfg.validate(nil); err != nil {
		return nil, err
	}
	if key == nil {
		return nil, errors.New("authz: transaction tokens need a signing key")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("authz: transaction-token signing key must be P-256")
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("authz: transaction-token key: %w", err)
	}
	x, y := b64url(pub[1:1+p256CoordLen]), b64url(pub[1+p256CoordLen:])
	m := &TxnMinter{cfg: cfg, key: key, kid: jwkThumbprint(x, y), random: rand.Reader}
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}{algES256, TxnTokenTyp, m.kid})
	if err != nil {
		return nil, err
	}
	m.header = b64url(header)
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
	}
	if m.jwks, err = json.Marshal(struct {
		Keys []jwk `json:"keys"`
	}{[]jwk{{Kty: "EC", Crv: "P-256", X: x, Y: y, Kid: m.kid, Alg: algES256, Use: "sig"}}}); err != nil {
		return nil, err
	}
	return m, nil
}

// KeyID is the signing key's RFC 7638 thumbprint, the tokens' kid.
func (m *TxnMinter) KeyID() string { return m.kid }

// JWKS is the public JWK Set an upstream verifies tokens against.
func (m *TxnMinter) JWKS() []byte { return m.jwks }

// HeaderName is the header the token travels in.
func (m *TxnMinter) HeaderName() string { return m.cfg.Header }

// txnIssuer is the ANS issuer behind an instance-mode caller.
type txnIssuer struct {
	Host    string `json:"host"`
	AnsName string `json:"ans_name"`
	CertFP  string `json:"cert_fp"`
}

type txnRequestContext struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type txnConfirmation struct {
	JKT string `json:"jkt"`
}

// txnClaims is the verified context. Optional members are omitted, never
// sent empty.
type txnClaims struct {
	Iss string          `json:"iss"`
	Aud string          `json:"aud"`
	Iat int64           `json:"iat"`
	Exp int64           `json:"exp"`
	Jti string          `json:"jti"`
	Txn string          `json:"txn"`
	Sub string          `json:"sub"`
	Act json.RawMessage `json:"act,omitempty"`
	Cnf txnConfirmation `json:"cnf"`
	// Sid is the issuer's session id from an instance token, so an
	// upstream's audit can name the session its issuer may later revoke.
	Sid                  string            `json:"sid,omitempty"`
	Scope                *string           `json:"scope,omitempty"`
	AuthorizationDetails json.RawMessage   `json:"authorization_details,omitempty"`
	AnsIssuer            *txnIssuer        `json:"ans_issuer,omitempty"`
	Rctx                 txnRequestContext `json:"rctx"`
	// notAfter, when set, caps exp: an instance token's own exp, so the
	// transaction token never outlives the credential it was derived from.
	notAfter int64
}

// mint signs claims after filling iss, aud, iat, exp, jti and txn.
func (m *TxnMinter) mint(c txnClaims, r *Request, now time.Time) (string, error) {
	jti, err := m.randomID()
	if err != nil {
		return "", err
	}
	txn := r.RequestID
	if txn == "" || len(txn) > maxTxnRequestID || !validHeaderValue(txn) {
		if txn, err = m.randomID(); err != nil {
			return "", err
		}
	}
	c.Iss, c.Aud, c.Jti, c.Txn = m.cfg.Issuer, m.cfg.Audience, jti, txn
	c.Iat = now.Unix()
	c.Exp = c.Iat + int64(m.cfg.TTL/time.Second)
	if c.notAfter > 0 {
		c.Exp = min(c.Exp, c.notAfter)
	}
	c.Rctx = txnRequestContext{Method: r.Method, Path: pathOnly(r.Path)}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := m.header + "." + b64url(payload)
	digest := sha256.Sum256([]byte(input))
	sr, ss, err := ecdsa.Sign(m.random, m.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign transaction token: %w", err)
	}
	sig := make([]byte, es256SigLen)
	sr.FillBytes(sig[:p256CoordLen])
	ss.FillBytes(sig[p256CoordLen:])
	return input + "." + b64url(sig), nil
}

func (m *TxnMinter) randomID() (string, error) {
	b := make([]byte, txnRandomBytes)
	if _, err := io.ReadFull(m.random, b); err != nil {
		return "", fmt.Errorf("transaction token id: %w", err)
	}
	return b64url(b), nil
}

// instanceTxnClaims is the verified instance context: sub is the user and
// act the single hop {"sub":"instance:<cnf.jkt>"}, the key that signed this
// request. A child token's own act already names that key (checkAct), and
// the parent instance it derives from is not named: one hop, and the child
// token carries no parent jkt. exp is clamped to the instance token's exp.
func instanceTxnClaims(it *instanceToken) (txnClaims, error) {
	c := it.claims
	act, err := json.Marshal(map[string]string{"sub": instanceActorPrefix + c.jkt})
	if err != nil {
		return txnClaims{}, err
	}
	fp := sha256.Sum256(it.certDER)
	claims := txnClaims{
		Sub: c.sub, Act: act, Cnf: txnConfirmation{JKT: c.jkt}, Sid: c.sid,
		AuthorizationDetails: c.authorizationDetails,
		AnsIssuer:            &txnIssuer{Host: c.iss, AnsName: c.ansName, CertFP: hex.EncodeToString(fp[:])},
		notAfter:             c.exp,
	}
	if c.hasScope {
		scope := c.scope
		claims.Scope = &scope
	}
	return claims, nil
}

// WithTxnMinter supplies the minter for transactionToken.enabled.
func WithTxnMinter(m *TxnMinter) VerifierOption {
	return func(v *Verifier) { v.txn = m }
}

// attachTxn mints the token into an allow, or strips the header when
// minting is off, so a client-supplied value never reaches the upstream in
// any mode. A mint failure denies: an upstream that authorizes on the token
// must never receive an allow without one.
func (v *Verifier) attachTxn(d Decision, r *Request, claims txnClaims) Decision {
	if !d.Allowed {
		return d
	}
	if v.txn == nil {
		d.RemoveHeaders = append(d.RemoveHeaders, strings.ToLower(v.cfg.TransactionToken.Header))
		return d
	}
	tok, err := v.txn.mint(claims, r, v.now())
	if err != nil {
		return denied(withDetail(deny(http.StatusServiceUnavailable, CategoryInternalError), err))
	}
	if d.Headers == nil {
		d.Headers = map[string]string{}
	}
	d.Headers[v.txn.HeaderName()] = tok
	return d
}

// Config is the transactionToken configuration the minter was built for.
func (m *TxnMinter) Config() TransactionToken { return m.cfg }
