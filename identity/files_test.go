package identity_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentnameservice/ans-gateway-auth/identity"
	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

const (
	modeDir     fs.FileMode = 0o700
	modePrivate fs.FileMode = 0o600
	modePublic  fs.FileMode = 0o644
	rsaBits                 = 2048
)

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

// assertPublicMode accepts 0644 narrowed by any umask: owner read-write, nothing wider.
func assertPublicMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm&^modePublic != 0 || perm&modePrivate != modePrivate {
		t.Fatalf("%s mode = %o, want 0644 or narrower with owner read-write", path, perm)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Fatalf("%s: want absent, but it exists", path)
	}
}

func assertSameBundle(t *testing.T, got, want *identity.Bundle) {
	t.Helper()
	if !got.Key.Equal(want.Key) {
		t.Fatal("loaded key differs")
	}
	if string(got.CertDER) != string(want.CertDER) {
		t.Fatal("loaded certificate differs")
	}
	if string(got.Receipt) != string(want.Receipt) {
		t.Fatal("loaded receipt differs")
	}
	if string(got.StatusToken) != string(want.StatusToken) {
		t.Fatal("loaded status token differs")
	}
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestWriteLoadRoundTrip(t *testing.T) {
	p := provision(t)
	dir := filepath.Join(t.TempDir(), "nested", "bundle")
	if err := p.Bundle.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	assertMode(t, dir, modeDir)
	assertMode(t, filepath.Join(dir, identity.FileKey), modePrivate)
	assertMode(t, filepath.Join(dir, identity.FileReceipt), modePrivate)
	assertMode(t, filepath.Join(dir, identity.FileStatus), modePrivate)
	assertPublicMode(t, filepath.Join(dir, identity.FileCert))
	assertAbsent(t, filepath.Join(dir, identity.FileRootKeys))

	got, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertSameBundle(t, got, p.Bundle)
}

func TestWriteOptionalFiles(t *testing.T) {
	p, other := provision(t), provision(t)
	dir := t.TempDir()
	err := p.Bundle.Write(dir, identity.WithRootKeys(p.RootKeyC2SP, other.RootKeyC2SP))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	rootKeys := filepath.Join(dir, identity.FileRootKeys)
	assertPublicMode(t, rootKeys)
	lines, err := os.ReadFile(rootKeys)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if want := p.RootKeyC2SP + "\n" + other.RootKeyC2SP + "\n"; string(lines) != want {
		t.Fatalf("%s = %q, want %q", identity.FileRootKeys, lines, want)
	}

	keys, err := identity.LoadRootKeys(dir)
	if err != nil {
		t.Fatalf("LoadRootKeys: %v", err)
	}
	for _, b := range []*testidentity.Provisioned{p, other} {
		if _, statusErr := b.Bundle.Status(keys, time.Now()); statusErr != nil {
			t.Fatalf("status token does not verify under the written root keys: %v", statusErr)
		}
	}

	// root-keys.c2sp is not an input to Load: Load succeeds however it reads.
	if err := os.WriteFile(rootKeys, []byte("not a key\n"), modePrivate); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	loaded, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertSameBundle(t, loaded, p.Bundle)
}

func TestLoadSEC1Key(t *testing.T) {
	p := provision(t)
	dir := t.TempDir()
	if err := p.Bundle.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(p.Bundle.Key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, identity.FileKey), pemOf("EC PRIVATE KEY", der), modePrivate); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertSameBundle(t, got, p.Bundle)
}

func TestWriteRefusesOverwrite(t *testing.T) {
	a, b := provision(t), provision(t)
	dir := t.TempDir()
	if err := a.Bundle.Write(dir); err != nil {
		t.Fatalf("Write: %v", err)
	}

	err := b.Bundle.Write(dir)
	if !errors.Is(err, identity.ErrExists) {
		t.Fatalf("second Write: error = %v, want identity.ErrExists", err)
	}
	assertErrorContains(t, err, identity.FileKey)
	got, err := identity.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertSameBundle(t, got, a.Bundle)

	if err := b.Bundle.Write(dir, identity.WithForce()); err != nil {
		t.Fatalf("Write with force: %v", err)
	}
	got, err = identity.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertSameBundle(t, got, b.Bundle)
	assertMode(t, filepath.Join(dir, identity.FileKey), modePrivate)
}

func TestWriteChecksEveryTargetFirst(t *testing.T) {
	p := provision(t)
	all := []string{
		identity.FileKey, identity.FileCert, identity.FileReceipt, identity.FileStatus,
		identity.FileRootKeys,
	}
	for _, existing := range all {
		t.Run(existing, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, existing)
			if err := os.WriteFile(path, []byte("old"), modePrivate); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			err := p.Bundle.Write(dir, identity.WithRootKeys(p.RootKeyC2SP))
			if !errors.Is(err, identity.ErrExists) {
				t.Fatalf("Write: error = %v, want identity.ErrExists", err)
			}
			assertErrorContains(t, err, path)
			for _, name := range all {
				if name != existing {
					assertAbsent(t, filepath.Join(dir, name))
				}
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
				t.Fatalf("%s = %q, %v; want untouched", existing, data, err)
			}
		})
	}
}

func TestWriteErrors(t *testing.T) {
	p := provision(t)
	tests := []struct {
		name    string
		bundle  *identity.Bundle
		dir     func(t *testing.T) string
		opts    []identity.WriteOption
		wantErr string
	}{
		{
			name:   "directory path is a file",
			bundle: p.Bundle,
			dir: func(t *testing.T) string {
				t.Helper()
				path := filepath.Join(t.TempDir(), "file")
				if err := os.WriteFile(path, nil, modePrivate); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
				return path
			},
			wantErr: "not a directory",
		},
		{
			name:   "unwritable directory",
			bundle: p.Bundle,
			dir: func(t *testing.T) string {
				t.Helper()
				if os.Geteuid() == 0 {
					t.Skip("root ignores directory permissions")
				}
				dir := t.TempDir()
				if err := os.Chmod(dir, 0o500); err != nil {
					t.Fatalf("Chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, modeDir) })
				return dir
			},
			wantErr: "permission denied",
		},
		{
			name:    "malformed root key",
			bundle:  p.Bundle,
			dir:     func(t *testing.T) string { t.Helper(); return t.TempDir() },
			opts:    []identity.WriteOption{identity.WithRootKeys(p.RootKeyC2SP, "not+a+key")},
			wantErr: "root key 1",
		},
		{
			name:    "missing private key",
			bundle:  &identity.Bundle{CertDER: p.Bundle.CertDER},
			dir:     func(t *testing.T) string { t.Helper(); return t.TempDir() },
			wantErr: "no private key",
		},
		{
			name:    "unmarshalable private key",
			bundle:  &identity.Bundle{Key: &ecdsa.PrivateKey{}, CertDER: p.Bundle.CertDER},
			dir:     func(t *testing.T) string { t.Helper(); return t.TempDir() },
			wantErr: "private key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.dir(t)
			assertErrorContains(t, tt.bundle.Write(dir, tt.opts...), tt.wantErr)
			assertAbsent(t, filepath.Join(dir, identity.FileKey))
		})
	}
}

func TestLoadErrors(t *testing.T) {
	p := provision(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rsaDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	remove := func(name string) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatalf("Remove: %v", err)
			}
		}
	}
	replace := func(name string, data []byte) func(t *testing.T, dir string) {
		return func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, name), data, modePrivate); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
		}
	}
	garbage := []byte{1, 2, 3}
	tests := []struct {
		name    string
		mutate  func(t *testing.T, dir string)
		wantErr string
	}{
		{name: "missing directory", mutate: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.RemoveAll(dir); err != nil {
				t.Fatalf("RemoveAll: %v", err)
			}
		}, wantErr: identity.FileKey},
		{name: "missing key", mutate: remove(identity.FileKey), wantErr: identity.FileKey},
		{name: "key readable by others", mutate: func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Chmod(filepath.Join(dir, identity.FileKey), modePublic); err != nil {
				t.Fatalf("Chmod: %v", err)
			}
		}, wantErr: "readable by other users"},
		{name: "missing certificate", mutate: remove(identity.FileCert), wantErr: identity.FileCert},
		{name: "missing receipt", mutate: remove(identity.FileReceipt), wantErr: identity.FileReceipt},
		{name: "missing status token", mutate: remove(identity.FileStatus), wantErr: identity.FileStatus},
		{name: "key is not PEM", mutate: replace(identity.FileKey, []byte("not pem")), wantErr: "PEM"},
		{name: "key PEM type unsupported", mutate: replace(identity.FileKey, pemOf("RSA PRIVATE KEY", garbage)), wantErr: "RSA PRIVATE KEY"},
		{name: "key is RSA", mutate: replace(identity.FileKey, pemOf("PRIVATE KEY", rsaDER)), wantErr: "*rsa.PrivateKey"},
		{name: "key PKCS#8 malformed", mutate: replace(identity.FileKey, pemOf("PRIVATE KEY", garbage)), wantErr: identity.FileKey},
		{name: "key SEC1 malformed", mutate: replace(identity.FileKey, pemOf("EC PRIVATE KEY", garbage)), wantErr: identity.FileKey},
		{name: "certificate is not PEM", mutate: replace(identity.FileCert, []byte("not pem")), wantErr: "PEM"},
		{name: "certificate PEM type unsupported", mutate: replace(identity.FileCert, pemOf("PUBLIC KEY", garbage)), wantErr: "PUBLIC KEY"},
		{name: "certificate malformed", mutate: replace(identity.FileCert, pemOf("CERTIFICATE", garbage)), wantErr: identity.FileCert},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := p.Bundle.Write(dir); err != nil {
				t.Fatalf("Write: %v", err)
			}
			tt.mutate(t, dir)
			got, err := identity.Load(dir)
			assertErrorContains(t, err, tt.wantErr)
			if got != nil {
				t.Fatalf("Load returned %+v with error", got)
			}
		})
	}
}
