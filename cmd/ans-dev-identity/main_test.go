package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/identity"
	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		args       func(dir string) []string
		wantExit   int
		wantStderr string
		check      func(t *testing.T, dir, stdout string)
	}{
		{
			name:       "missing flags",
			args:       func(string) []string { return []string{"--out", "x"} },
			wantExit:   exitUsage,
			wantStderr: "are required",
		},
		{
			name:       "unknown flag",
			args:       func(string) []string { return []string{"--bogus"} },
			wantExit:   exitUsage,
			wantStderr: "flag provided but not defined",
		},
		{
			name:       "help",
			args:       func(string) []string { return []string{"--help"} },
			wantExit:   exitOK,
			wantStderr: "Usage",
		},
		{
			name: "invalid ans name",
			args: func(dir string) []string {
				return []string{"--out", dir, "--ans-name", "not-an-ans-name", "--agent-id", "a"}
			},
			wantExit:   exitFailure,
			wantStderr: "ans-dev-identity:",
		},
		{
			name: "unwritable output directory",
			args: func(dir string) []string {
				blocker := filepath.Join(filepath.Dir(dir), "file")
				if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"--out", filepath.Join(blocker, "bundle"), "--ans-name", "ans://v1.0.0.demo.example", "--agent-id", "a"}
			},
			wantExit:   exitFailure,
			wantStderr: "ans-dev-identity:",
		},
		{
			name: "writes a loadable bundle and prints the root key",
			args: func(dir string) []string {
				return []string{"--out", dir, "--ans-name", "ans://v1.0.0.demo.example", "--agent-id", "demo-agent-1"}
			},
			wantExit: exitOK,
			check: func(t *testing.T, dir, stdout string) {
				b, err := identity.Load(dir)
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				line := rootKeyLine(t, stdout)
				keys, err := scitt.NewKeyStore([]string{line})
				if err != nil {
					t.Fatalf("printed root key does not parse: %v", err)
				}
				st, err := b.Status(keys, time.Now())
				if err != nil {
					t.Fatalf("status token does not verify under the printed root key: %v", err)
				}
				if st.Payload.AgentID != "demo-agent-1" {
					t.Errorf("agent id = %q", st.Payload.AgentID)
				}
				for _, f := range []string{identity.FileKey, identity.FileCert, identity.FileReceipt, identity.FileStatus, identity.FileRootKeys} {
					if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
						t.Errorf("%s: %v", f, err)
					}
				}
				if !strings.Contains(stdout, "status token expires") {
					t.Errorf("stdout lacks the expiry line:\n%s", stdout)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := filepath.Join(t.TempDir(), "bundle")
			var stdout, stderr bytes.Buffer
			got := run(tc.args(dir), &stdout, &stderr)
			if got != tc.wantExit {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", got, tc.wantExit, stdout.String(), stderr.String())
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
			if tc.check != nil {
				tc.check(t, dir, stdout.String())
			}
		})
	}
}

func TestRunRefusesToOverwriteWithoutForce(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "bundle")
	args := []string{"--out", dir, "--ans-name", "ans://v1.0.0.demo.example", "--agent-id", "demo-agent-1"}
	var stdout, stderr bytes.Buffer
	if got := run(args, &stdout, &stderr); got != exitOK {
		t.Fatalf("first run exit %d: %s", got, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if got := run(args, &stdout, &stderr); got != exitFailure {
		t.Fatalf("second run exit %d, want %d; stderr %s", got, exitFailure, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--force") {
		t.Errorf("stderr should point at --force: %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if got := run(append(args, "--force"), &stdout, &stderr); got != exitOK {
		t.Fatalf("forced run exit %d: %s", got, stderr.String())
	}
}

// TestRunRejectsDefectiveMaterial injects provisioners that hand back material the real one
// never would, to cover the failure paths after minting.
func TestRunRejectsDefectiveMaterial(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		corrupt    func(p *testidentity.Provisioned)
		wantStderr string
	}{
		{
			name:       "status token does not verify",
			corrupt:    func(p *testidentity.Provisioned) { p.Bundle.StatusToken = []byte("not a status token") },
			wantStderr: "does not verify",
		},
		{
			name: "certificate without an ans name",
			corrupt: func(p *testidentity.Provisioned) {
				p.Bundle.CertDER = certWithoutSAN(t, p.Bundle.Key)
			},
			wantStderr: "ans://",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			provision := func(ansName, agentID string) (*testidentity.Provisioned, error) {
				p, err := testidentity.Provision(ansName, agentID)
				if err != nil {
					return nil, err
				}
				tc.corrupt(p)
				return p, nil
			}
			dir := filepath.Join(t.TempDir(), "bundle")
			var stdout, stderr bytes.Buffer
			got := runWith([]string{"--out", dir, "--ans-name", "ans://v1.0.0.demo.example", "--agent-id", "demo-agent-1"}, &stdout, &stderr, provision)
			if got != exitFailure {
				t.Fatalf("exit %d, want %d; stderr %s", got, exitFailure, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}

func certWithoutSAN(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "no-san"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// rootKeyLine extracts the quoted C2SP line from the printed transparencyLogs snippet.
func rootKeyLine(t *testing.T, stdout string) string {
	t.Helper()
	for _, l := range strings.Split(stdout, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, `- "dev-tl+`) {
			return strings.Trim(strings.TrimPrefix(l, "- "), `"`)
		}
	}
	t.Fatalf("no root key line in stdout:\n%s", stdout)
	return ""
}
