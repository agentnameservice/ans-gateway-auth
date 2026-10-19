// Package testidentity provisions throwaway agent identities for tests and
// local development by wrapping the SDK's demokit. Each Provision call mints a
// fresh transparency-log key and a holder bundle - a P-256 key, a certificate
// carrying the ans:// URI SAN, and the IETF SCITT receipt and status token for
// it - with one-hour certificate and status-token lifetimes. The log's private
// key is discarded; its public key is returned as a C2SP root-key line so a
// verifier can be made to trust exactly this identity.
//
// Nothing here is a credential outside a test. The demokit's
// MintUnsignedDemoToken is never used as a credential in this repository, and
// a bundle from this package carries no standing with a real transparency log.
package testidentity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/identity"
)

// Provisioned is a freshly minted identity and the root key that vouches for it.
type Provisioned struct {
	// Bundle is the holder material.
	Bundle *identity.Bundle
	// RootKeyC2SP is the transparency-log public key as a C2SP line
	// (name+hex_kid+base64_spki_der) named "dev-tl".
	RootKeyC2SP string
	// KeyLookup resolves the receipt's and status token's kid to that key.
	KeyLookup scitt.KeyLookup
}

const (
	rootKeyName = "dev-tl"
	kidLen      = 4
)

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type mintFunc func(ansName, agentID string) (*ecdsa.PrivateKey, *demokit.Bundle, error)

// Provision mints an identity for ansName, an ans:// URI, and agentID, 1 to
// 128 characters from [A-Za-z0-9._-].
func Provision(ansName, agentID string) (*Provisioned, error) {
	return provision(ansName, agentID, demokit.Provision)
}

func provision(ansName, agentID string, mint mintFunc) (*Provisioned, error) {
	if _, err := verify.ParseAnsName(ansName); err != nil {
		return nil, fmt.Errorf("testidentity: ans name: %w", err)
	}
	if !agentIDPattern.MatchString(agentID) {
		return nil, fmt.Errorf("testidentity: agent id %q must match %s", agentID, agentIDPattern)
	}
	logKey, b, err := mint(ansName, agentID)
	if err != nil {
		return nil, fmt.Errorf("testidentity: provision: %w", err)
	}
	line, err := rootKeyLine(&logKey.PublicKey)
	if err != nil {
		return nil, err
	}
	keys, err := scitt.NewKeyStore([]string{line})
	if err != nil {
		return nil, fmt.Errorf("testidentity: root key: %w", err)
	}
	bundle, err := identity.New(b.AgentKey, b.CertDER, b.Receipt, b.StatusToken)
	if err != nil {
		return nil, fmt.Errorf("testidentity: provision: %w", err)
	}
	return &Provisioned{Bundle: bundle, RootKeyC2SP: line, KeyLookup: keys}, nil
}

func rootKeyLine(pub *ecdsa.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("testidentity: root key: %w", err)
	}
	sum := sha256.Sum256(spki)
	return rootKeyName + "+" + hex.EncodeToString(sum[:kidLen]) + "+" + base64.StdEncoding.EncodeToString(spki), nil
}
