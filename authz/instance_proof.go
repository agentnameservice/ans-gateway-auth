package authz

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
)

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
