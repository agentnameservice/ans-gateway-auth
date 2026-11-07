package authz

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ansNameScheme prefixes an ANS name, the certificate-mode transaction-token
// sub.
const ansNameScheme = "ans://"

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
	// The transaction token's sub is the caller's ANS name in certificate
	// mode, so an instance sub must not claim that namespace.
	if strings.HasPrefix(strings.ToLower(c.sub), ansNameScheme) {
		return c, refuse(codeBadToken, CategoryMalformedProof, "sub must not be an ans:// name")
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
	if raw, present := payload["sid"]; present {
		if json.Unmarshal(raw, &c.sid) != nil || !validSid(c.sid) {
			return c, refuse(codeBadToken, CategoryMalformedProof, "sid must be 1-128 printable characters")
		}
	}
	return c, checkAct(c.act, c.jkt)
}

// validSid reports whether s is a session id as the issuer mints one: 1 to
// 128 printable ASCII characters, no space (src/instance_token.py _valid_sid).
func validSid(s string) bool {
	if s == "" || len(s) > instanceMaxSidLen {
		return false
	}
	for i := range len(s) {
		if s[i] < '!' || s[i] > '~' {
			return false
		}
	}
	return true
}

// checkAct enforces RFC 8693 actor claims one hop deep: act, when present,
// is an object naming its actor in sub, carrying no nested act, and its sub
// is the token's own instance key, instance:<cnf.jkt>, as the issuer's
// mint_child sets it (act_mismatch otherwise). The parent instance a child
// derives from is not named anywhere in the token.
func checkAct(raw json.RawMessage, jkt string) error {
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
	sub := jsonString(act["sub"])
	if sub == "" {
		return refuse(codeBadToken, CategoryMalformedProof, "act.sub must name the actor")
	}
	if sub != instanceActorPrefix+jkt {
		return refuse(codeActMismatch, CategoryTokenBindingMismatch, "act.sub "+echoValue(sub)+
			" is not the token's instance key "+echoValue(instanceActorPrefix+jkt))
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
	// Compare without subtracting: for an iat near the int64 minimum, exp-iat
	// wraps negative and would pass the cap. iat is at most now+skew here, so
	// iat+instanceMaxTTL cannot overflow.
	case c.exp > c.iat+instanceMaxTTL:
		return refuse(codeBadToken, CategoryMalformedProof, fmt.Sprintf("token lifetime exceeds %ds", instanceMaxTTL))
	}
	return nil
}
