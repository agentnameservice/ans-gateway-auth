//go:build e2e

package agentrouter

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

const (
	agentAName = "ans://v1.0.0.alpha.example"
	agentBName = "ans://v1.0.0.beta.example"
	agentCName = "ans://v1.0.0.gamma.example"
	agentAID   = "demo-agent-1"
	agentBID   = "agent-b"
	agentCID   = "agent-c"
)

// verifierBinary returns the ans-authz binary under test: ANS_AUTHZ_BIN when set, otherwise a
// fresh build of ./cmd/ans-authz, so the e2e always exercises the shipped composition root.
func verifierBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("ANS_AUTHZ_BIN"); bin != "" {
		return bin
	}
	out := filepath.Join(t.TempDir(), "ans-authz")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/ans-authz")
	cmd.Dir = repoRoot(t)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build ans-authz: %v\n%s", err, b)
	}
	return out
}

// identities provisions three dev identities: A and B are trusted by the verifier, C is not.
type identities struct {
	a, b, c *testidentity.Provisioned
}

func provisionIdentities(t *testing.T) identities {
	t.Helper()
	a, err := testidentity.Provision(agentAName, agentAID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testidentity.Provision(agentBName, agentBID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := testidentity.Provision(agentCName, agentCID)
	if err != nil {
		t.Fatal(err)
	}
	return identities{a: a, b: b, c: c}
}

// writeVerifierConfig derives the test configuration from the shipped
// examples/agent-router/ans-authz.yaml, so every key the recipe ships is the one under test:
// only the trusted log (the test's dev root keys), the gRPC listener and the HTTP listener are
// replaced.
func writeVerifierConfig(t *testing.T, rootKeys []string, grpcPort, httpPort int) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", "agent-router", "ans-authz.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("shipped ans-authz.yaml: %v", err)
	}
	keys := make([]any, len(rootKeys))
	for i, k := range rootKeys {
		keys[i] = k
	}
	cfg["transparencyLogs"] = []any{map[string]any{"name": "dev", "rootKeys": keys}}
	cfg["grpc"] = map[string]any{"listen": fmt.Sprintf("127.0.0.1:%d", grpcPort)}
	cfg["httpListen"] = fmt.Sprintf("127.0.0.1:%d", httpPort)
	cfg["logLevel"] = "debug"
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ans-authz.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startVerifier runs ans-authz with the given config and waits until /readyz answers 200.
func startVerifier(t *testing.T, bin, configPath string, httpPort int) *process {
	t.Helper()
	p := startProcess(t, "ans-authz", exec.Command(bin, "--config", configPath))
	ready := fmt.Sprintf("http://127.0.0.1:%d/readyz", httpPort)
	waitUntil(t, p, "ans-authz to report ready", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ready, nil)
		if err != nil {
			return err
		}
		return probe(req, http.StatusOK)
	})
	return p
}
