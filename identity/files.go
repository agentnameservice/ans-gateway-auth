package identity

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// Files in a bundle directory. Load reads the first four; LoadRootKeys reads
// FileRootKeys, which lists the transparency-log keys a verifier of this
// identity must trust.
const (
	FileKey      = "agent.key"
	FileCert     = "agent.crt"
	FileReceipt  = "receipt.cose"
	FileStatus   = "status.cose"
	FileRootKeys = "root-keys.c2sp"
)

// ErrExists reports that Write would overwrite an existing file; WithForce
// allows that.
var ErrExists = errors.New("identity: file already exists")

const (
	modeDir     fs.FileMode = 0o700
	modePrivate fs.FileMode = 0o600
	modePublic  fs.FileMode = 0o644

	pemPKCS8 = "PRIVATE KEY"
	pemSEC1  = "EC PRIVATE KEY"
	pemCert  = "CERTIFICATE"
)

// Load reads a bundle directory: agent.key as a PKCS#8 or SEC1 PEM private
// key, agent.crt as a PEM certificate, and receipt.cose and status.cose as raw
// COSE_Sign1 bytes, then validates them with New.
func Load(dir string) (*Bundle, error) {
	key, err := loadKey(filepath.Join(dir, FileKey))
	if err != nil {
		return nil, err
	}
	certDER, err := loadCert(filepath.Join(dir, FileCert))
	if err != nil {
		return nil, err
	}
	receipt, err := readFile(filepath.Join(dir, FileReceipt))
	if err != nil {
		return nil, err
	}
	status, err := readFile(filepath.Join(dir, FileStatus))
	if err != nil {
		return nil, err
	}
	return New(key, certDER, receipt, status)
}

// LoadRootKeys reads root-keys.c2sp from a bundle directory into a key store,
// one C2SP line per key. The error wraps fs.ErrNotExist when the file is absent.
func LoadRootKeys(dir string) (scitt.KeyLookup, error) {
	data, err := readFile(filepath.Join(dir, FileRootKeys))
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	keys, err := scitt.NewKeyStore(lines)
	if err != nil {
		return nil, fmt.Errorf("identity: %s: %w", FileRootKeys, err)
	}
	return keys, nil
}

func loadKey(path string) (*ecdsa.PrivateKey, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	var parsed any
	switch block.Type {
	case pemPKCS8:
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case pemSEC1:
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("identity: %s: PEM type %q, want %q or %q", path, block.Type, pemPKCS8, pemSEC1)
	}
	if err != nil {
		return nil, fmt.Errorf("identity: %s: %w", path, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("identity: %s: key is %T, want *ecdsa.PrivateKey", path, parsed)
	}
	return key, nil
}

func loadCert(path string) ([]byte, error) {
	block, err := readPEM(path)
	if err != nil {
		return nil, err
	}
	if block.Type != pemCert {
		return nil, fmt.Errorf("identity: %s: PEM type %q, want %q", path, block.Type, pemCert)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("identity: %s: %w", path, err)
	}
	return block.Bytes, nil
}

func readPEM(path string) (*pem.Block, error) {
	data, err := readFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("identity: %s: no PEM block", path)
	}
	return block, nil
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return data, nil
}

// WriteOption adjusts Write.
type WriteOption func(*writeOptions)

type writeOptions struct {
	force       bool
	rootKeys    []string
	rootKeysSet bool
}

// WithForce lets Write replace files that already exist.
func WithForce() WriteOption {
	return func(o *writeOptions) { o.force = true }
}

// WithRootKeys also writes root-keys.c2sp, one C2SP key line per entry: the
// transparency-log root keys a verifier of this identity must trust. Every
// line must parse with scitt.ParseC2SPKey.
func WithRootKeys(lines ...string) WriteOption {
	return func(o *writeOptions) {
		o.rootKeys = lines
		o.rootKeysSet = true
	}
}

type fileSpec struct {
	name string
	data []byte
	mode fs.FileMode
}

// Write stores the bundle in dir, creating it with mode 0700: agent.key as
// PKCS#8 PEM (0600), agent.crt as PEM (0644), receipt.cose and status.cose
// (0600), plus the 0644 root-keys.c2sp WithRootKeys adds. Every file is created
// exclusively, so nothing is written through a path that already exists,
// symlinks included; without WithForce an existing target is ErrExists and
// nothing is written.
func (b *Bundle) Write(dir string, opts ...WriteOption) error {
	var o writeOptions
	for _, opt := range opts {
		opt(&o)
	}
	files, err := b.files(&o)
	if err != nil {
		return err
	}
	if !o.force {
		for _, f := range files {
			path := filepath.Join(dir, f.name)
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("%w: %s", ErrExists, path)
			}
		}
	}
	if err := os.MkdirAll(dir, modeDir); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	for _, f := range files {
		if err := writeFile(filepath.Join(dir, f.name), f.data, f.mode, o.force); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bundle) files(o *writeOptions) ([]fileSpec, error) {
	if b.Key == nil {
		return nil, errors.New("identity: bundle has no private key")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(b.Key)
	if err != nil {
		return nil, fmt.Errorf("identity: marshal private key: %w", err)
	}
	files := []fileSpec{
		{name: FileKey, data: pem.EncodeToMemory(&pem.Block{Type: pemPKCS8, Bytes: keyDER}), mode: modePrivate},
		{name: FileCert, data: pem.EncodeToMemory(&pem.Block{Type: pemCert, Bytes: b.CertDER}), mode: modePublic},
		{name: FileReceipt, data: b.Receipt, mode: modePrivate},
		{name: FileStatus, data: b.StatusToken, mode: modePrivate},
	}
	if o.rootKeysSet {
		var lines strings.Builder
		for i, line := range o.rootKeys {
			if _, err := scitt.ParseC2SPKey(line); err != nil {
				return nil, fmt.Errorf("identity: root key %d: %w", i, err)
			}
			lines.WriteString(line)
			lines.WriteByte('\n')
		}
		files = append(files, fileSpec{name: FileRootKeys, data: []byte(lines.String()), mode: modePublic})
	}
	return files, nil
}

// writeFile creates path exclusively (removing an existing entry first when
// force is set, which replaces a symlink rather than following it) and sets
// the mode on the descriptor so umask cannot widen it.
func writeFile(path string, data []byte, mode fs.FileMode, force bool) error {
	if force {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("identity: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, path)
		}
		return fmt.Errorf("identity: %w", err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return fmt.Errorf("identity: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("identity: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	return nil
}
