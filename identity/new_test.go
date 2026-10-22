package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/fs"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans-gateway-auth/identity"
	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey, sans ...string) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	for _, s := range sans {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNew(t *testing.T) {
	t.Parallel()
	p, err := testidentity.Provision("ans://v1.0.0.new.example", "new-agent")
	if err != nil {
		t.Fatal(err)
	}
	good := p.Bundle
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		key     *ecdsa.PrivateKey
		cert    []byte
		receipt []byte
		status  []byte
		wantErr bool
	}{
		{"valid", good.Key, good.CertDER, good.Receipt, good.StatusToken, false},
		{"nil key", nil, good.CertDER, good.Receipt, good.StatusToken, true},
		{"key does not match certificate", otherKey, good.CertDER, good.Receipt, good.StatusToken, true},
		{"certificate without ans SAN", otherKey, selfSignedCert(t, otherKey, "https://example.com"), good.Receipt, good.StatusToken, true},
		{"missing receipt", good.Key, good.CertDER, nil, good.StatusToken, true},
		{"missing status token", good.Key, good.CertDER, good.Receipt, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b, err := identity.New(tc.key, tc.cert, tc.receipt, tc.status)
			if tc.wantErr {
				if err == nil {
					t.Fatal("New succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if b.FingerprintHex() != good.FingerprintHex() {
				t.Errorf("fingerprint = %s, want %s", b.FingerprintHex(), good.FingerprintHex())
			}
		})
	}
}

func TestLoadRootKeys(t *testing.T) {
	t.Parallel()
	p, err := testidentity.Provision("ans://v1.0.0.keys.example", "keys-agent")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("missing file wraps fs.ErrNotExist", func(t *testing.T) {
		t.Parallel()
		_, err := identity.LoadRootKeys(t.TempDir())
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("error = %v, want fs.ErrNotExist", err)
		}
	})
	t.Run("garbage line is rejected", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, identity.FileRootKeys), []byte("garbage\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := identity.LoadRootKeys(dir); err == nil {
			t.Fatal("LoadRootKeys accepted a garbage line")
		}
	})
	t.Run("blank lines are ignored", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, identity.FileRootKeys), []byte("\n"+p.RootKeyC2SP+"\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		keys, err := identity.LoadRootKeys(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Bundle.Status(keys, time.Now()); err != nil {
			t.Fatalf("status token does not verify: %v", err)
		}
	})
}

func TestWriteNeverFollowsSymlinks(t *testing.T) {
	t.Parallel()
	p, err := testidentity.Provision("ans://v1.0.0.link.example", "link-agent")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, identity.FileKey)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := p.Bundle.Write(dir); !errors.Is(err, identity.ErrExists) {
		t.Fatalf("Write without force: error = %v, want identity.ErrExists", err)
	}
	if err := p.Bundle.Write(dir, identity.WithForce()); err != nil {
		t.Fatalf("Write with force: %v", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "victim" {
		t.Fatalf("symlink target was written through: %q, %v", data, err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&fs.ModeSymlink != 0 {
		t.Fatalf("agent.key should be a regular file after a forced write: %v, %v", info, err)
	}
	if _, err := identity.Load(dir); err != nil {
		t.Fatalf("Load after forced write: %v", err)
	}
}
