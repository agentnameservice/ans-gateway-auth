package authz

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
)

// JWS and JSON helpers for instance mode.

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
