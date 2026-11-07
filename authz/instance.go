package authz

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
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
	codeActMismatch      = "act_mismatch"
	codeInstanceCap      = "instance_cap"
	codeInstanceDisabled = "instance_disabled"
)

const (
	instanceTokenTyp = "instance+jwt"
	dpopTyp          = "dpop+jwt"
	algES256         = "ES256"
	// instanceMaxTTL is the longest lifetime an instance token may claim:
	// 5 minutes, so a stolen key plus token stops working within 5 minutes
	// of its issuer refusing to renew it (ans-spec issue 90). Renewal happens
	// at the issuer; this verifier never accepts an expired token.
	instanceMaxTTL int64 = 300
	// instanceMaxSidLen bounds sid, the issuer's session id.
	instanceMaxSidLen = 128
	// instanceIATSkew is how far an instance token's iat may lead our clock.
	instanceIATSkew int64 = 120
	// statusIATSkew is how far a status token's iat may lead our clock.
	statusIATSkew int64 = 600
	// boundedStatusIATSkew replaces statusIATSkew when maxStatusAge is set
	// (the status cache is on), so a future-dated status token cannot
	// stretch its freshness window or pin the cache ahead.
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
	// sid is the issuer's session id; empty when the token carries none.
	sid string
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
	claims, err := instanceTxnClaims(it)
	if err != nil {
		return Decision{}, &deniedError{denial: withDetail(deny(http.StatusServiceUnavailable, CategoryInternalError), err)}
	}
	if d = v.attachTxn(d, r, claims); !d.Allowed {
		return Decision{}, &deniedError{denial: d.Deny}
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
