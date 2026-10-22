package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/identity"
	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

const (
	testAnsName = "ans://v1.0.0.holder.example"
	testAgentID = "holder-1"
)

func provision(t *testing.T) *testidentity.Provisioned {
	t.Helper()
	p, err := testidentity.Provision(testAnsName, testAgentID)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return p
}

// mismatched pairs one identity's private key with another identity's
// certificate and SCITT artifacts, so every signer-backed method must fail.
func mismatched(t *testing.T) *identity.Bundle {
	t.Helper()
	a, b := provision(t), provision(t)
	return &identity.Bundle{
		Key:         b.Bundle.Key,
		CertDER:     a.Bundle.CertDER,
		Receipt:     a.Bundle.Receipt,
		StatusToken: a.Bundle.StatusToken,
	}
}

func certWithURI(t *testing.T, uri string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("Parse(%q): %v", uri, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func assertProofError(t *testing.T, err error, want pop.ErrorType) {
	t.Helper()
	var pe *pop.ProofError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *pop.ProofError", err)
	}
	if pe.Type != want {
		t.Fatalf("error type = %s, want %s (%v)", pe.Type, want, err)
	}
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want containing %q", err, want)
	}
}

func TestBundleAnsName(t *testing.T) {
	p := provision(t)
	tests := []struct {
		name    string
		bundle  *identity.Bundle
		want    string
		wantErr string
	}{
		{name: "provisioned", bundle: p.Bundle, want: testAnsName},
		{name: "no ans URI SAN", bundle: &identity.Bundle{CertDER: certWithURI(t, "https://holder.example")}, wantErr: "ans://"},
		{name: "unparseable ans URI SAN", bundle: &identity.Bundle{CertDER: certWithURI(t, "ans://noversion.example")}, wantErr: "ans://"},
		{name: "malformed certificate", bundle: &identity.Bundle{CertDER: []byte("not der")}, wantErr: "parse certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.bundle.AnsName()
			if tt.wantErr != "" {
				assertErrorContains(t, err, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("AnsName: %v", err)
			}
			if got != tt.want {
				t.Fatalf("AnsName = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBundleFingerprintHex(t *testing.T) {
	p := provision(t)
	sum := sha256.Sum256(p.Bundle.CertDER)
	if got, want := p.Bundle.FingerprintHex(), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("FingerprintHex = %q, want %q", got, want)
	}
}

func TestBundleSigner(t *testing.T) {
	p := provision(t)
	tests := []struct {
		name    string
		bundle  *identity.Bundle
		wantErr string
	}{
		{name: "provisioned", bundle: p.Bundle},
		{name: "nil key", bundle: &identity.Bundle{CertDER: p.Bundle.CertDER}, wantErr: "nil private key"},
		{name: "key does not match certificate", bundle: mismatched(t), wantErr: "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := tt.bundle.Signer()
			if tt.wantErr != "" {
				assertErrorContains(t, err, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			jkt, err := tt.bundle.JKT()
			if err != nil {
				t.Fatalf("JKT: %v", err)
			}
			if jkt == "" || jkt != signer.JKT() {
				t.Fatalf("JKT = %q, want signer thumbprint %q", jkt, signer.JKT())
			}
		})
	}
}

func TestBundleJKTError(t *testing.T) {
	if _, err := mismatched(t).JKT(); err == nil {
		t.Fatal("JKT on a mismatched bundle: want error")
	}
}

func TestBundleStatus(t *testing.T) {
	p, other := provision(t), provision(t)
	now := time.Now()

	st, err := p.Bundle.Status(p.KeyLookup, now)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Payload.AgentID != testAgentID || st.Payload.AnsName != testAnsName || st.Payload.Status != scitt.StatusActive {
		t.Fatalf("Status payload = %+v", st.Payload)
	}
	if exp := time.Unix(st.Payload.Exp, 0); !exp.After(now) {
		t.Fatalf("Status exp %v is not after %v", exp, now)
	}

	_, err = p.Bundle.Status(other.KeyLookup, now)
	var se *scitt.SignatureError
	if !errors.As(err, &se) || se.Type != scitt.SigErrUnknownKeyID {
		t.Fatalf("Status with untrusted keys: error = %v, want unknown key ID", err)
	}

	_, err = p.Bundle.Status(p.KeyLookup, now.Add(2*time.Hour))
	var te *scitt.TokenError
	if !errors.As(err, &te) || te.Type != scitt.TokenErrExpired {
		t.Fatalf("Status two hours on: error = %v, want expired", err)
	}
}
