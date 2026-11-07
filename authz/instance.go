package authz

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// Instance mode admits a caller that holds no ANS certificate of its own: a
// local agent instance with only a P-256 key. It presents a short-lived
// instance token that an ANS-registered issuer signed with its identity
// certificate's key, the certificate itself in x5c, and proves possession of
// the token's cnf key with a DPoP proof carrying a bare jwk. The issuer's TL
// status token ties the certificate to ANS. The wire format and the reason
// codes follow the reference implementation, ans-agent src/instance_token.py,
// and testdata/instance-vectors.json holds the two to the same verdicts.

// Upstream headers an instance-mode allow sets, alongside X-ANS-Name,
// X-ANS-Agent-Id, X-ANS-Fingerprint and X-ANS-JKT (all of them the issuer's,
// except X-ANS-JKT, which names the instance key).
const (
	HeaderANSInstanceSub          = "X-ANS-Instance-Sub"
	HeaderANSAct                  = "X-ANS-Act"
	HeaderANSScope                = "X-ANS-Scope"
	HeaderANSAuthorizationDetails = "X-ANS-Authorization-Details"
)

// Metadata keys an instance-mode allow adds.
const (
	MetadataInstanceSub = "instance_sub"
	MetadataScope       = "scope"
	MetadataAct         = "act"
)

// Categories instance mode reports that certificate mode reaches only through
// the SDK.
const (
	CategoryContentBindingMismatch = string(pop.ErrContentBindingMismatch)
	CategoryExpectedPeerMismatch   = string(pop.ErrExpectedPeerMismatch)
	CategoryUnsupportedAlg         = string(pop.ErrUnsupportedAlg)
	CategorySignatureInvalid       = string(pop.ErrSignatureInvalid)
	CategoryProofStale             = string(pop.ErrProofStale)
	CategoryCertInvalid            = string(pop.ErrCertInvalid)
	CategoryBindingFailed          = string(pop.ErrBindingFailed)
	CategoryStatusInvalid          = string(pop.ErrStatusInvalid)
)

// Reason codes, spelled as the Python reference spells them. They lead the
// denial Detail ("code: message"), which reaches the decision log only.
const (
	codeExpired          = "expired"
	codeBadToken         = "bad_token"
	codeBadSignature     = "bad_signature"
	codeBadDPoP          = "bad_dpop"
	codeReplay           = "replay"
	codeRevoked          = "revoked"
	codeCertNotCurrent   = "cert_not_current"
	codeIssMismatch      = "iss_mismatch"
	codeAudMismatch      = "aud_mismatch"
	codeHTUMismatch      = "htu_mismatch"
	codeClockSkew        = "clock_skew"
	codeBadStatusToken   = "bad_status_token"
	codeStatusExpired    = "status_expired"
	codeStatusStale      = "status_stale"
	codeBadRequest       = "bad_request"
	codeBadAlg           = "bad_alg"
	codeDepthExceeded    = "depth_exceeded"
	codeInstanceCap      = "instance_cap"
	codeInstanceDisabled = "instance_disabled"
)

const (
	instanceTokenTyp = "instance+jwt"
	dpopTyp          = "dpop+jwt"
	algES256         = "ES256"
	// instanceMaxTTL is the longest lifetime an instance token may claim.
	instanceMaxTTL int64 = 900
	// instanceIATSkew is how far an instance token's iat may lead our clock.
	instanceIATSkew int64 = 120
	// statusIATSkew is how far a status token's iat may lead our clock.
	statusIATSkew int64 = 600
	// boundedStatusIATSkew replaces statusIATSkew when maxStatusAge is set,
	// so a future-dated status token cannot stretch its freshness window.
	boundedStatusIATSkew int64 = 60
	// instanceReplayGrace extends a proof's replay entry past its freshness
	// window, as the SDK does for certificate-mode proofs.
	instanceReplayGrace = 5 * time.Second
	// instanceReplayPrefix separates instance-proof jti digests from
	// certificate-mode ones in a shared replay cache.
	instanceReplayPrefix = "instance-jti:"
	// capSweepInterval spaces the full sweep of expired cap entries.
	capSweepInterval int64 = 60
)

// P-256 and ES256 encoding sizes.
const (
	p256CoordLen         = 32
	es256SigLen          = 64
	uncompressedPointTag = 0x04
)

// instanceHeaders are the upstream headers only instance mode sets. When
// instance mode is enabled, a certificate-mode allow removes them so a
// client-supplied value never reaches the upstream.
var instanceHeaders = []string{ //nolint:gochecknoglobals // immutable header list
	HeaderANSInstanceSub, HeaderANSAct, HeaderANSScope, HeaderANSAuthorizationDetails,
}

// instanceError is one refused instance request, with the reference
// implementation's reason code.
type instanceError struct {
	code     string
	status   int
	category string
	msg      string
}

func (f *instanceError) Error() string { return f.code + ": " + f.msg }

func refuse(code, category, msg string) *instanceError {
	return &instanceError{code: code, status: http.StatusUnauthorized, category: category, msg: msg}
}

// refusePolicy is a refusal on this verifier's own policy (issuer allowlist,
// delegation depth, instance cap), reported like allowedAnsNames refusals.
func refusePolicy(code, msg string) *instanceError {
	return &instanceError{code: code, status: http.StatusForbidden, category: CategoryExpectedPeerMismatch, msg: msg}
}

// instanceClaims are the instance token's claims after shape checks.
type instanceClaims struct {
	iss, ansName, sub, jti, jkt string
	iat, exp                    int64
	aud                         json.RawMessage
	scope                       string
	hasScope                    bool
	act                         json.RawMessage
	authorizationDetails        json.RawMessage
}

// instanceToken is a parsed, not yet verified, instance token.
type instanceToken struct {
	signingInput string
	sig          string
	certDER      []byte
	cert         *x509.Certificate
	claims       instanceClaims
}

// instanceProof is what a verified DPoP proof contributes to the decision.
type instanceProof struct {
	jti string
	iat int64
}

// isInstanceRequest reports whether a request selects instance mode: a DPoP
// access token whose JWS header names typ instance+jwt, and no SCITT receipt.
// The header is read unverified; it only routes the request.
func isInstanceRequest(h http.Header) (string, bool) {
	tok, presented := pop.AccessTokenFromAuthorization(h.Get(headerAuthorization))
	if !presented || h.Get(scitt.HeaderReceipt) != "" {
		return "", false
	}
	head, _, ok := strings.Cut(tok, ".")
	if !ok {
		return "", false
	}
	raw, err := b64urlDecode(head)
	if err != nil {
		return "", false
	}
	var header struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(raw, &header) != nil || header.Typ != instanceTokenTyp {
		return "", false
	}
	return tok, true
}

// verifyInstance runs the instance-mode checks: the issuer allowlist before
// any lookup; the DPoP proof under its own jwk (htm, htu, ath, body digest,
// freshness, cnf.jkt); the token's ES256 signature under x5c; the issuer's
// status token against the cached TL root keys; aud; then the optional
// per-sub cap and, last, the replay check, so a refused request never burns
// its jti or records an unvouched proof.
func (v *Verifier) verifyInstance(ctx context.Context, r *Request, base, tok string) Decision {
	d, err := v.instanceDecision(ctx, r, base, tok)
	if err != nil {
		return denied(v.instanceDenial(ctx, err))
	}
	return d
}

func (v *Verifier) instanceDecision(ctx context.Context, r *Request, base, tok string) (Decision, error) {
	now := v.now().Unix()
	it, status, proof, err := v.checkInstanceRequest(r, base, tok, now)
	if err != nil {
		return Decision{}, err
	}
	st, err := v.issuerStatus(ctx, status, it, now)
	if err != nil {
		return Decision{}, err
	}
	if err := v.checkIssuerAllowed(it); err != nil {
		return Decision{}, err
	}
	if err := v.checkAudience(it, base); err != nil {
		return Decision{}, err
	}
	d, err := v.instanceAllow(it, st)
	if err != nil {
		return Decision{}, &deniedError{denial: withDetail(deny(http.StatusServiceUnavailable, CategoryInternalError), err)}
	}
	if err := v.admitInstance(ctx, it, proof, now); err != nil {
		return Decision{}, err
	}
	return d, nil
}

// checkInstanceRequest runs every check that needs no trust material.
func (v *Verifier) checkInstanceRequest(r *Request, base, tok string, now int64) (*instanceToken, []byte, *instanceProof, error) {
	if !v.cfg.InstanceMode.Enabled {
		return nil, nil, nil, refuse(codeInstanceDisabled, CategoryMissingHeaders,
			"instance tokens are not accepted here; present an ANS identity certificate")
	}
	proofJWS := r.Header.Get(pop.DPoPHeader)
	if proofJWS == "" {
		return nil, nil, nil, refuse(codeBadRequest, CategoryMissingHeaders, "no DPoP proof on request")
	}
	hdrs, err := scitt.ExtractHeaders(r.Header)
	if err != nil {
		return nil, nil, nil, refuse(codeBadStatusToken, CategorySCITTHeaderInvalid, err.Error())
	}
	if len(hdrs.StatusToken) == 0 {
		return nil, nil, nil, refuse(codeBadRequest, CategoryMissingHeaders, "no issuer status token on request")
	}
	it, err := parseInstanceToken(tok)
	if err != nil {
		return nil, nil, nil, err
	}
	if !slices.Contains(v.cfg.InstanceMode.AllowedIssuers, it.claims.iss) {
		return nil, nil, nil, refusePolicy(codeIssMismatch, "issuer "+echoValue(it.claims.iss)+" is not in allowedIssuers")
	}
	proof, err := v.checkInstanceProof(r, proofJWS, tok, base+pathOnly(r.Path), it.claims.jkt, now)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := it.verifySignature(); err != nil {
		return nil, nil, nil, err
	}
	if err := it.checkLifetime(now); err != nil {
		return nil, nil, nil, err
	}
	return it, hdrs.StatusToken, proof, nil
}

func (v *Verifier) instanceDenial(ctx context.Context, err error) *Denial {
	var f *instanceError
	if ctx.Err() == nil && errors.As(err, &f) {
		return &Denial{HTTPStatus: f.status, Category: f.category, Detail: f.Error()}
	}
	var d *deniedError
	if ctx.Err() == nil && errors.As(err, &d) {
		return d.denial
	}
	return v.mapError(ctx, err)
}

// deniedError carries an already-built Denial through the error path.
type deniedError struct{ denial *Denial }

func (e *deniedError) Error() string { return e.denial.Detail }

// parseInstanceToken checks the token's shape: a compact JWS whose header is
// exactly {alg ES256, typ instance+jwt, x5c [one certificate]}, and the
// claims the reference implementation requires.
func parseInstanceToken(tok string) (*instanceToken, error) {
	h, p, s, err := splitJWS(tok, codeBadToken)
	if err != nil {
		return nil, err
	}
	header, err := decodeSegment(h, codeBadToken)
	if err != nil {
		return nil, err
	}
	certDER, err := instanceHeaderCert(header)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, refuse(codeBadToken, CategoryCertInvalid, "x5c does not parse: "+err.Error())
	}
	payload, err := decodeSegment(p, codeBadToken)
	if err != nil {
		return nil, err
	}
	claims, err := decodeInstanceClaims(payload)
	if err != nil {
		return nil, err
	}
	return &instanceToken{signingInput: h + "." + p, sig: s, certDER: certDER, cert: cert, claims: claims}, nil
}

func instanceHeaderCert(header map[string]json.RawMessage) ([]byte, error) {
	for name := range header {
		if name != "alg" && name != "typ" && name != "x5c" {
			return nil, refuse(codeBadToken, CategoryMalformedProof,
				"header must be exactly {alg: ES256, typ: instance+jwt, x5c}")
		}
	}
	if jsonString(header["alg"]) != algES256 || jsonString(header["typ"]) != instanceTokenTyp {
		return nil, refuse(codeBadToken, CategoryUnsupportedAlg, "header must carry alg ES256 and typ instance+jwt")
	}
	var x5c []string
	if json.Unmarshal(header["x5c"], &x5c) != nil || len(x5c) != 1 {
		return nil, refuse(codeBadToken, CategoryCertInvalid, "x5c must hold exactly the identity certificate")
	}
	der, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		return nil, refuse(codeBadToken, CategoryCertInvalid, "x5c is not base64")
	}
	return der, nil
}

func decodeInstanceClaims(payload map[string]json.RawMessage) (instanceClaims, error) {
	c := instanceClaims{
		iss: jsonString(payload["iss"]), ansName: jsonString(payload["ans_name"]),
		sub: jsonString(payload["sub"]), jti: jsonString(payload["jti"]),
		aud: payload["aud"], act: nullAsAbsent(payload["act"]),
		authorizationDetails: nullAsAbsent(payload["authorization_details"]),
	}
	var cnf map[string]json.RawMessage
	if json.Unmarshal(payload[claimConfirmation], &cnf) == nil {
		c.jkt = jsonString(cnf[claimThumbprint])
	}
	iat, iatOK := jsonInt(payload["iat"])
	exp, expOK := jsonInt(payload["exp"])
	c.iat, c.exp = iat, exp
	if c.iss == "" || c.ansName == "" || c.sub == "" || c.jti == "" || c.jkt == "" || !iatOK || !expOK {
		return c, refuse(codeBadToken, CategoryMalformedProof, "missing iss, ans_name, sub, iat, exp, jti or cnf.jkt")
	}
	if raw := nullAsAbsent(payload["scope"]); raw != nil {
		if json.Unmarshal(raw, &c.scope) != nil {
			return c, refuse(codeBadToken, CategoryMalformedProof, "scope must be a string")
		}
		c.hasScope = c.scope != ""
	}
	if c.authorizationDetails != nil && !bytes.HasPrefix(bytes.TrimSpace(c.authorizationDetails), []byte("[")) {
		return c, refuse(codeBadToken, CategoryMalformedProof, "authorization_details must be a list")
	}
	return c, checkAct(c.act)
}

// checkAct enforces RFC 8693 actor claims one hop deep: act, when present,
// is an object naming its actor in sub and carrying no nested act.
func checkAct(raw json.RawMessage) error {
	if raw == nil {
		return nil
	}
	var act map[string]json.RawMessage
	if json.Unmarshal(raw, &act) != nil {
		return refuse(codeBadToken, CategoryMalformedProof, "act must be an object")
	}
	if _, nested := act["act"]; nested {
		return refusePolicy(codeDepthExceeded, "act nests a second actor; one delegation hop is allowed")
	}
	if jsonString(act["sub"]) == "" {
		return refuse(codeBadToken, CategoryMalformedProof, "act.sub must name the actor")
	}
	return nil
}

// verifySignature checks the ES256 signature under x5c[0], which must hold a
// P-256 key.
func (it *instanceToken) verifySignature() error {
	pub, ok := it.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return refuse(codeBadAlg, CategoryUnsupportedAlg, "x5c[0] key is not P-256, so cannot be ES256")
	}
	if !verifyES256(pub, it.signingInput, it.sig) {
		return refuse(codeBadSignature, CategorySignatureInvalid, "token signature does not verify under x5c[0]")
	}
	return nil
}

func (it *instanceToken) checkLifetime(now int64) error {
	c := it.claims
	switch {
	case now >= c.exp:
		return refuse(codeExpired, CategoryProofStale, fmt.Sprintf("token expired at %d", c.exp))
	case c.iat > now+instanceIATSkew:
		return refuse(codeClockSkew, CategoryProofStale, fmt.Sprintf("token iat %d is %ds in the future", c.iat, c.iat-now))
	case c.exp-c.iat > instanceMaxTTL:
		return refuse(codeBadToken, CategoryMalformedProof, fmt.Sprintf("token lifetime exceeds %ds", instanceMaxTTL))
	}
	return nil
}

// checkInstanceProof verifies the DPoP proof under its own bare jwk, which
// must be the token's cnf.jkt key, and binds it to this request: method,
// htu rebuilt from configuration, the presented token (ath) and the body
// digest. Its jti is recorded later, once the whole request is trusted.
func (v *Verifier) checkInstanceProof(r *Request, proofJWS, tok, rawURL, jkt string, now int64) (*instanceProof, error) {
	h, p, s, err := splitJWS(proofJWS, codeBadDPoP)
	if err != nil {
		return nil, err
	}
	header, err := decodeSegment(h, codeBadDPoP)
	if err != nil {
		return nil, err
	}
	pub, err := proofKey(header, jkt)
	if err != nil {
		return nil, err
	}
	if !verifyES256(pub, h+"."+p, s) {
		return nil, refuse(codeBadDPoP, CategorySignatureInvalid, "proof signature does not verify")
	}
	payload, err := decodeSegment(p, codeBadDPoP)
	if err != nil {
		return nil, err
	}
	return v.checkProofClaims(r, payload, tok, rawURL, now)
}

// proofKey checks the proof header and returns its jwk as a P-256 key.
func proofKey(header map[string]json.RawMessage, jkt string) (*ecdsa.PublicKey, error) {
	for name := range header {
		if name != "alg" && name != "typ" && name != "jwk" {
			return nil, refuse(codeBadDPoP, CategoryMalformedProof, "forbidden header parameter "+echoValue(name))
		}
	}
	if jsonString(header["typ"]) != dpopTyp || jsonString(header["alg"]) != algES256 {
		return nil, refuse(codeBadDPoP, CategoryUnsupportedAlg, "typ must be dpop+jwt and alg ES256")
	}
	var jwk map[string]json.RawMessage
	if json.Unmarshal(header["jwk"], &jwk) != nil {
		return nil, refuse(codeBadDPoP, CategoryMalformedProof, "jwk must be an object")
	}
	_, private := jwk["d"]
	if jsonString(jwk["kty"]) != "EC" || jsonString(jwk["crv"]) != "P-256" || private {
		return nil, refuse(codeBadDPoP, CategoryUnsupportedAlg, "jwk must be a public EC P-256 key")
	}
	x, y := jsonString(jwk["x"]), jsonString(jwk["y"])
	if subtle.ConstantTimeCompare([]byte(jwkThumbprint(x, y)), []byte(jkt)) != 1 {
		return nil, refuse(codeBadDPoP, CategoryTokenBindingMismatch, "proof key is not the token's cnf.jkt")
	}
	pub, err := p256Key(x, y)
	if err != nil {
		return nil, refuse(codeBadDPoP, CategoryMalformedProof, "jwk does not decode: "+err.Error())
	}
	return pub, nil
}

func (v *Verifier) checkProofClaims(r *Request, payload map[string]json.RawMessage, tok, rawURL string,
	now int64) (*instanceProof, error) {
	jti := jsonString(payload["jti"])
	iat, ok := jsonInt(payload["iat"])
	switch {
	case jti == "" || len(jti) > pop.MaxJTISize:
		return nil, refuse(codeBadDPoP, CategoryMalformedProof, "missing or oversized jti")
	case !ok:
		return nil, refuse(codeBadDPoP, CategoryMalformedProof, "missing iat")
	}
	if skew := int64(v.cfg.PoPSkew / time.Second); now-iat > skew || iat-now > skew {
		return nil, refuse(codeClockSkew, CategoryProofStale, fmt.Sprintf("proof iat %d is %+ds from now", iat, iat-now))
	}
	if !strings.EqualFold(jsonString(payload["htm"]), r.Method) {
		return nil, refuse(codeBadDPoP, CategoryHTTPBindingMismatch, "htm does not match the request method")
	}
	want, _ := normalizeHTU(rawURL)
	if got, err := normalizeHTU(jsonString(payload["htu"])); err != nil || got != want {
		return nil, refuse(codeHTUMismatch, CategoryHTTPBindingMismatch, "htu does not name "+want)
	}
	ath := sha256.Sum256([]byte(tok))
	if subtle.ConstantTimeCompare([]byte(jsonString(payload["ath"])), []byte(b64url(ath[:]))) != 1 {
		return nil, refuse(codeBadDPoP, CategoryTokenBindingMismatch, "ath does not match the presented token")
	}
	if err := checkBodyDigest(jsonString(payload["ans_content_digest"]), r.Body); err != nil {
		return nil, err
	}
	return &instanceProof{jti: jti, iat: iat}, nil
}

// checkBodyDigest binds the request content, as certificate-mode proofs do:
// ans_content_digest is base64url(SHA-256(body)).
func checkBodyDigest(claim string, body []byte) error {
	digest, err := b64urlDecode(claim)
	if err != nil || len(digest) != sha256.Size {
		return refuse(codeBadDPoP, CategoryMalformedProof, "ans_content_digest must be base64url(SHA-256(content))")
	}
	got := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(digest, got[:]) != 1 {
		return refuse(codeBadDPoP, CategoryContentBindingMismatch, "ans_content_digest does not match the received content")
	}
	return nil
}

// issuerStatus verifies the issuer's status token against the cached TL root
// keys (refreshing once for an unknown kid, as certificate mode does) and
// checks that it vouches for the x5c certificate under the token's name.
func (v *Verifier) issuerStatus(ctx context.Context, raw []byte, it *instanceToken,
	now int64) (*scitt.VerifiedStatusToken, error) {
	st, err := scitt.VerifyStatusTokenAt(raw, v.keys, 0, now)
	if kid, unknown := unknownKeyID(err); unknown && v.keyAvailable(ctx, kid) {
		st, err = scitt.VerifyStatusTokenAt(raw, v.keys, 0, now)
	}
	if err != nil {
		return nil, statusFailure(ctx, err)
	}
	p := &st.Payload
	if now >= p.Exp {
		return nil, refuse(codeStatusExpired, CategoryStatusInvalid, fmt.Sprintf("status token expired at %d", p.Exp))
	}
	maxAge := int64(v.cfg.InstanceMode.MaxStatusAge / time.Second)
	skew := statusIATSkew
	if maxAge > 0 {
		skew = boundedStatusIATSkew
	}
	if p.Iat > now+skew {
		return nil, refuse(codeClockSkew, CategoryStatusInvalid, fmt.Sprintf("status token iat %d is %ds ahead", p.Iat, p.Iat-now))
	}
	if maxAge > 0 && now-p.Iat > maxAge {
		return nil, refuse(codeStatusStale, CategoryStatusInvalid,
			fmt.Sprintf("status token issued %ds ago, over maxStatusAge %ds", now-p.Iat, maxAge))
	}
	if err := checkIssuerNames(p, it); err != nil {
		return nil, err
	}
	if p.Status != scitt.StatusActive && p.Status != scitt.StatusWarning {
		return nil, refuse(codeRevoked, CategoryStatusInvalid, "issuer registration is "+echoValue(string(p.Status)))
	}
	if now < it.cert.NotBefore.Unix() || now >= it.cert.NotAfter.Unix() {
		return nil, refuse(codeCertNotCurrent, CategoryCertInvalid, "identity certificate is outside its validity dates")
	}
	if !scitt.MatchesIdentityCert(p, sha256.Sum256(it.certDER)) {
		return nil, refuse(codeCertNotCurrent, CategoryBindingFailed, "x5c certificate is not in the issuer's validIdentityCerts")
	}
	return st, nil
}

func statusFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return err
	}
	var te *scitt.TokenError
	if errors.As(err, &te) {
		switch te.Type {
		case scitt.TokenErrExpired:
			return refuse(codeStatusExpired, CategoryStatusInvalid, err.Error())
		case scitt.TokenErrTerminalStatus:
			return refuse(codeRevoked, CategoryStatusInvalid, err.Error())
		case scitt.TokenErrMissingField, scitt.TokenErrPayloadInvalid, scitt.TokenErrPayloadEmpty:
		}
	}
	return refuse(codeBadStatusToken, CategoryStatusInvalid, err.Error())
}

// checkIssuerNames binds the token's iss and ans_name to the status token and
// the certificate: the status token names this ans_name, whose host is iss,
// and the certificate carries it as a URI SAN.
func checkIssuerNames(p *scitt.StatusTokenPayload, it *instanceToken) error {
	stName, err := verify.ParseAnsName(p.AnsName)
	if err != nil || stName.Host != it.claims.iss || p.AnsName != it.claims.ansName {
		return refuse(codeIssMismatch, CategoryBindingFailed, "status token names "+echoValue(p.AnsName)+
			", token says "+echoValue(it.claims.iss)+" "+echoValue(it.claims.ansName))
	}
	for _, u := range it.cert.URIs {
		if u.String() == it.claims.ansName {
			return nil
		}
	}
	return refuse(codeIssMismatch, CategoryBindingFailed, "identity certificate does not name "+echoValue(it.claims.ansName))
}

// checkIssuerAllowed applies allowedAnsNames to the issuer, compared on
// version and host as the SDK compares certificate-mode callers.
func (v *Verifier) checkIssuerAllowed(it *instanceToken) error {
	if len(v.allowedNames) == 0 {
		return nil
	}
	name, err := verify.ParseAnsName(it.claims.ansName)
	if err == nil && v.allowedNames[canonicalAnsName(name)] {
		return nil
	}
	return refusePolicy(codeIssMismatch, "issuer "+echoValue(it.claims.ansName)+" is not in allowedAnsNames")
}

// canonicalAnsName spells an ans:// name by version and host only, the SDK's
// rule for allowedAnsNames.
func canonicalAnsName(n *verify.AnsName) string {
	return "ans://" + n.Version.String() + "." + n.Host
}

// checkAudience requires aud to be this verifier: instanceMode.expectedAud,
// or the host of the authority the request matched.
func (v *Verifier) checkAudience(it *instanceToken, base string) error {
	want := v.cfg.InstanceMode.ExpectedAud
	if want == "" {
		if u, err := url.Parse(base); err == nil {
			want = u.Hostname()
		}
	}
	var aud string
	if json.Unmarshal(it.claims.aud, &aud) != nil || want == "" || aud != want {
		return refuse(codeAudMismatch, CategoryTokenBindingMismatch, "token aud is not "+echoValue(want))
	}
	return nil
}

// admitInstance applies the per-sub cap and then records the proof's jti. A
// cap slot taken for a request the replay check then refuses is given back.
func (v *Verifier) admitInstance(ctx context.Context, it *instanceToken, proof *instanceProof, now int64) error {
	c := it.claims
	added := false
	if v.instances != nil {
		var ok bool
		if added, ok = v.instances.admit(c.iss+"\x00"+c.sub, c.jkt, c.exp, now); !ok {
			return refusePolicy(codeInstanceCap, fmt.Sprintf("%s already holds %d live instance keys",
				echoValue(c.sub), v.cfg.InstanceMode.MaxInstancesPerSub))
		}
	}
	err := v.recordInstanceJTI(ctx, proof)
	if err != nil && added {
		v.instances.forget(c.iss+"\x00"+c.sub, c.jkt)
	}
	return err
}

func (v *Verifier) recordInstanceJTI(ctx context.Context, proof *instanceProof) error {
	key := sha256.Sum256([]byte(instanceReplayPrefix + proof.jti))
	exp := time.Unix(proof.iat, 0).Add(v.cfg.PoPSkew + instanceReplayGrace)
	seen, err := v.cache.CheckAndStore(ctx, b64url(key[:]), exp)
	if err != nil {
		return err
	}
	if seen {
		return refuse(codeReplay, CategoryReplay, "DPoP jti already used")
	}
	return nil
}

// instanceAllow builds the identity contract. Every header is set with
// overwrite semantics; an optional header the token does not carry is
// removed instead, so a client-supplied value never survives.
func (v *Verifier) instanceAllow(it *instanceToken, st *scitt.VerifiedStatusToken) (Decision, error) {
	c := it.claims
	id := &pop.CallerIdentity{AnsName: c.ansName, AgentID: st.Payload.AgentID,
		Fingerprint: sha256.Sum256(it.certDER), JKT: c.jkt}
	fingerprint := hex.EncodeToString(id.Fingerprint[:])
	attributes := map[string]string{
		// agent_id names the instance, not the issuer, for extraIdentityHeaders:
		// a gateway keying a session subject on it must not merge every
		// instance an issuer signs into one session.
		MetadataANSName: id.AnsName, MetadataAgentID: c.jkt, MetadataFingerprint: fingerprint, MetadataJKT: c.jkt,
	}
	headers := map[string]string{
		HeaderANSName: id.AnsName, HeaderANSAgentID: id.AgentID, HeaderANSFingerprint: fingerprint,
		HeaderANSJKT: id.JKT, HeaderANSInstanceSub: c.sub,
	}
	metadata := map[string]any{
		MetadataANSName: id.AnsName, MetadataAgentID: id.AgentID, MetadataFingerprint: fingerprint,
		MetadataJKT: id.JKT, MetadataInstanceSub: c.sub,
	}
	var remove []string
	optional := []struct {
		header, metadata, value string
		present                 bool
	}{
		{HeaderANSScope, MetadataScope, c.scope, c.hasScope},
		{HeaderANSAct, MetadataAct, compactJSON(c.act), c.act != nil},
		{HeaderANSAuthorizationDetails, "", compactJSON(c.authorizationDetails), c.authorizationDetails != nil},
	}
	for _, o := range optional {
		if !o.present {
			remove = append(remove, strings.ToLower(o.header))
			continue
		}
		headers[o.header] = o.value
		if o.metadata != "" {
			metadata[o.metadata] = o.value
		}
	}
	for _, e := range v.extra {
		headers[e.name] = attributes[e.attribute]
	}
	for name, value := range headers {
		if !validHeaderValue(value) {
			return Decision{}, fmt.Errorf("identity attribute for header %s is not a valid header field value", name)
		}
	}
	if v.cfg.StripIdentityHeaders {
		// The verifier is the token's audience and has consumed the proof, so
		// neither is meant for the upstream.
		remove = append(remove, strings.ToLower(scitt.HeaderReceipt), strings.ToLower(scitt.HeaderStatusToken),
			strings.ToLower(pop.DPoPHeader), strings.ToLower(headerAuthorization))
	}
	return Decision{Allowed: true, Identity: id, Headers: headers, RemoveHeaders: remove, Metadata: metadata}, nil
}

// instanceCap counts the distinct instance keys each issuer sub presents
// while their tokens are live.
type instanceCap struct {
	max       int
	mu        sync.Mutex
	subs      map[string]map[string]int64 // sub key -> jkt -> token exp
	lastSweep int64
}

func newInstanceCap(limit int) *instanceCap {
	if limit <= 0 {
		return nil
	}
	return &instanceCap{max: limit, subs: make(map[string]map[string]int64)}
}

// admit counts jkt for key until exp. ok is false when key already holds the
// maximum number of other live keys; added reports a newly counted key.
func (c *instanceCap) admit(key, jkt string, exp, now int64) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now-c.lastSweep >= capSweepInterval {
		for k, keys := range c.subs {
			pruneExpired(keys, now)
			if len(keys) == 0 {
				delete(c.subs, k)
			}
		}
		c.lastSweep = now
	}
	keys := c.subs[key]
	if keys == nil {
		keys = make(map[string]int64)
		c.subs[key] = keys
	}
	pruneExpired(keys, now)
	if prev, known := keys[jkt]; known {
		keys[jkt] = max(prev, exp)
		return false, true
	}
	if len(keys) >= c.max {
		return false, false
	}
	keys[jkt] = exp
	return true, true
}

func (c *instanceCap) forget(key, jkt string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if keys := c.subs[key]; keys != nil {
		delete(keys, jkt)
		if len(keys) == 0 {
			delete(c.subs, key)
		}
	}
}

func pruneExpired(keys map[string]int64, now int64) {
	for jkt, exp := range keys {
		if now >= exp {
			delete(keys, jkt)
		}
	}
}

// ---- JWS and JSON helpers ----

func splitJWS(jws, code string) (string, string, string, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != jwsSegments {
		return "", "", "", refuse(code, CategoryMalformedProof, "not a compact JWS")
	}
	return parts[0], parts[1], parts[2], nil
}

func decodeSegment(seg, code string) (map[string]json.RawMessage, error) {
	raw, err := b64urlDecode(seg)
	if err != nil {
		return nil, refuse(code, CategoryMalformedProof, "segment is not base64url")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, refuse(code, CategoryMalformedProof, "segment is not a JSON object")
	}
	return m, nil
}

// b64urlDecode tolerates padding, so a re-encoded segment decodes the same.
func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jsonString(raw json.RawMessage) string {
	var s string
	if raw == nil || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// jsonInt reads a JSON integer; a fraction, exponent or non-number fails.
func jsonInt(raw json.RawMessage) (int64, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if raw == nil || dec.Decode(&n) != nil {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func nullAsAbsent(raw json.RawMessage) json.RawMessage {
	if raw == nil || string(bytes.TrimSpace(raw)) == "null" {
		return nil
	}
	return raw
}

// compactJSON re-renders signed JSON on one line; json.Compact keeps it
// byte-for-byte otherwise, and JSON escapes every control character.
func compactJSON(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var buf bytes.Buffer
	if json.Compact(&buf, raw) != nil {
		return ""
	}
	return buf.String()
}

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint of a P-256 JWK.
func jwkThumbprint(x, y string) string {
	canonical, _ := json.Marshal(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}{Crv: "P-256", Kty: "EC", X: x, Y: y})
	sum := sha256.Sum256(canonical)
	return b64url(sum[:])
}

func p256Key(x, y string) (*ecdsa.PublicKey, error) {
	xb, errX := base64.RawURLEncoding.DecodeString(x)
	yb, errY := base64.RawURLEncoding.DecodeString(y)
	if errX != nil || errY != nil || len(xb) != p256CoordLen || len(yb) != p256CoordLen {
		return nil, errors.New("x and y must be 32-byte base64url coordinates")
	}
	point := append(append([]byte{uncompressedPointTag}, xb...), yb...)
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
}

// verifyES256 checks a JWS ES256 signature (64-byte r||s).
func verifyES256(pub *ecdsa.PublicKey, signingInput, sigB64 string) bool {
	sig, err := b64urlDecode(sigB64)
	if err != nil || len(sig) != es256SigLen {
		return false
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(sig[:p256CoordLen]), new(big.Int).SetBytes(sig[p256CoordLen:]),
	})
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(signingInput))
	return ecdsa.VerifyASN1(pub, digest[:], der)
}

// normalizeHTU applies the SDK's htu rule (RFC 9449 section 4.3): lowercase
// scheme and host, default port dropped, query and fragment removed, empty
// path as "/".
func normalizeHTU(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return "", errors.New("htu must be an absolute URL")
	}
	if port := u.Port(); port != "" && normalizeAuthority(scheme, "h:"+port) != "h" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// echoValue bounds a client-influenced value quoted into a log detail.
func echoValue(s string) string {
	const maxEcho = 128
	if len(s) > maxEcho {
		s = s[:maxEcho] + "..."
	}
	return fmt.Sprintf("%q", s)
}
