// Package identity holds an agent's credential material - the ECDSA P-256
// identity key, its certificate carrying an ans:// URI SAN, and the IETF SCITT
// receipt and status token a transparency log issued for that certificate -
// and signs outbound HTTP requests with it: an RFC 9449 DPoP proof plus the
// two SCITT headers that pop.Middleware and an ANS-6 ext_authz verifier
// expect. It mints nothing. Material comes from a bundle directory an RA
// provisioned (Load) or, for tests and development, from package
// testidentity.
package identity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// Bundle is the holder material for one agent identity.
type Bundle struct {
	// Key is the P-256 private key the certificate binds.
	Key *ecdsa.PrivateKey
	// CertDER is the identity certificate in DER form.
	CertDER []byte
	// Receipt is the SCITT receipt for the certificate's transparency-log entry.
	Receipt []byte
	// StatusToken is the COSE_Sign1 status token vouching for the certificate.
	StatusToken []byte
}

// New checks once that the material belongs together - a P-256 key matching
// the certificate's public key, an ans:// URI SAN on the certificate, and a
// non-empty receipt and status token - and returns the Bundle.
func New(key *ecdsa.PrivateKey, certDER, receipt, statusToken []byte) (*Bundle, error) {
	b := &Bundle{Key: key, CertDER: certDER, Receipt: receipt, StatusToken: statusToken}
	if _, err := b.Signer(); err != nil {
		return nil, err
	}
	if _, err := b.AnsName(); err != nil {
		return nil, err
	}
	if len(receipt) == 0 || len(statusToken) == 0 {
		return nil, errors.New("identity: receipt and status token are required")
	}
	return b, nil
}

// AnsName returns the ans:// URI SAN of the identity certificate.
func (b *Bundle) AnsName() (string, error) {
	cert, err := x509.ParseCertificate(b.CertDER)
	if err != nil {
		return "", fmt.Errorf("identity: parse certificate: %w", err)
	}
	name := verify.CertIdentityFromX509(cert).AnsName()
	if name == nil {
		return "", errors.New("identity: certificate has no ans:// URI SAN")
	}
	return name.String(), nil
}

// FingerprintHex returns the lowercase hex SHA-256 of CertDER, the value
// pop.CallerIdentity.FingerprintHex reports for requests this bundle signs.
func (b *Bundle) FingerprintHex() string {
	sum := sha256.Sum256(b.CertDER)
	return hex.EncodeToString(sum[:])
}

// JKT returns the RFC 7638 thumbprint of the identity key, the value an
// authorization server records as a DPoP-bound access token's cnf.jkt.
func (b *Bundle) JKT() (string, error) {
	signer, err := b.Signer()
	if err != nil {
		return "", err
	}
	return signer.JKT(), nil
}

// Signer returns a DPoP signer over the key and certificate; it fails when the
// two do not belong together.
func (b *Bundle) Signer() (*pop.Signer, error) {
	return pop.NewSigner(b.Key, b.CertDER)
}

// Status verifies the status token against keys as of now, within the SDK's
// maximum clock-skew tolerance, and returns its payload.
func (b *Bundle) Status(keys scitt.KeyLookup, now time.Time) (*scitt.VerifiedStatusToken, error) {
	st, err := scitt.VerifyStatusTokenAt(b.StatusToken, keys, scitt.MaxClockSkew, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("identity: status token: %w", err)
	}
	return st, nil
}
