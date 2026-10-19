package agentrouter

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/agentnameservice/ans-gateway-auth/config"
	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

const (
	// rootKeyPlaceholder is what the ConfigMap ships in place of the log's root keys; the
	// verifier refuses it, so a deployment cannot start without pinned keys.
	rootKeyPlaceholder = "REPLACE_WITH_THE_LOG_ROOT_KEY_LINE"
	// distrolessNonroot is the uid and gid of the distroless nonroot user the image runs as.
	distrolessNonroot = 65532
)

// These tests need no gateway: they keep the shipped Agent Router recipes loadable and
// internally consistent in the ordinary unit suite.

func recipesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "examples", "agent-router")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func loadVerifierConfig(t *testing.T, path string) config.Config {
	t.Helper()
	cfg, err := config.Load(path, config.Overrides{})
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return cfg
}

func TestShippedVerifierConfigLoads(t *testing.T) {
	t.Parallel()
	cfg := loadVerifierConfig(t, filepath.Join(recipesDir(t), "ans-authz.yaml"))
	if got := cfg.TrustedHosts; len(got) != 1 || got[0] != "http://127.0.0.1:1975" {
		t.Errorf("trustedHosts = %v, want the aigw run listener", got)
	}
	if cfg.RequiredContext == nil || cfg.RequiredContext.Key != "ans-authz" || cfg.RequiredContext.Value != "body-forwarded" {
		t.Errorf("requiredContext = %+v, want the ans-authz: body-forwarded sentinel", cfg.RequiredContext)
	}
	if cfg.ExtraIdentityHeaders["x-ai-eg-mcp-subject"] != "agent_id" {
		t.Errorf("extraIdentityHeaders = %v, want x-ai-eg-mcp-subject: agent_id", cfg.ExtraIdentityHeaders)
	}
	if cfg.RequireTokenClaims {
		t.Error("requireTokenClaims must be false: Envoy Gateway forwards no token claims to ext_authz")
	}
	if !cfg.StripIdentityHeaders || !cfg.RequireReceipt {
		t.Error("stripIdentityHeaders and requireReceipt must stay on")
	}
}

// TestKubernetesConfigMapMatchesShippedConfig keeps the ConfigMap in ans-verifier.yaml a copy of
// the shipped config apart from the documented overrides: transparency log, trusted hosts and
// the two listeners.
func TestKubernetesConfigMapMatchesShippedConfig(t *testing.T) {
	t.Parallel()
	dir := recipesDir(t)
	shipped := loadVerifierConfig(t, filepath.Join(dir, "ans-authz.yaml"))

	k8s := loadVerifierConfig(t, writeConfigMapConfig(t, dir))

	if k8s.GRPC.Listen != "0.0.0.0:9191" || !k8s.GRPC.AllowInsecureListen || k8s.HTTPListen != "0.0.0.0:9192" {
		t.Errorf("ConfigMap listeners = grpc %q (insecure %v), http %q; want pod-wide 9191 and 9192", k8s.GRPC.Listen, k8s.GRPC.AllowInsecureListen, k8s.HTTPListen)
	}
	for _, c := range []*config.Config{&shipped, &k8s} {
		c.TransparencyLogs = nil
		c.TrustedHosts = nil
		c.GRPC = config.GRPCConfig{}
		c.HTTPListen = ""
	}
	if !reflect.DeepEqual(shipped, k8s) {
		t.Errorf("ConfigMap config drifted from examples/agent-router/ans-authz.yaml beyond the documented overrides:\nshipped: %+v\nconfigmap: %+v", shipped, k8s)
	}
}

// TestVerifierDeploymentHardening pins the Deployment settings the security review relies on:
// numeric non-root ids the kubelet can verify, a locked-down container, and a startup probe
// that outlasts the verifier's own startup retries so the kubelet never restarts it mid-fetch.
func TestVerifierDeploymentHardening(t *testing.T) {
	t.Parallel()
	dir := recipesDir(t)
	var deployment map[string]any
	for _, doc := range yamlDocs(t, filepath.Join(dir, "kubernetes", "ans-verifier.yaml")) {
		if doc["kind"] == "Deployment" {
			deployment = doc
		}
	}
	if deployment == nil {
		t.Fatal("kubernetes/ans-verifier.yaml has no Deployment")
	}
	podSpec := dig(t, deployment, "spec", "template", "spec")
	podSec := dig(t, podSpec, "securityContext")
	if podSec["runAsNonRoot"] != true || podSec["runAsUser"] != distrolessNonroot || podSec["runAsGroup"] != distrolessNonroot {
		t.Errorf("pod securityContext = %v, want runAsNonRoot with runAsUser and runAsGroup %d", podSec, distrolessNonroot)
	}
	if dig(t, podSec, "seccompProfile")["type"] != "RuntimeDefault" {
		t.Errorf("pod seccompProfile = %v, want RuntimeDefault", podSec["seccompProfile"])
	}

	containers, _ := podSpec["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("containers = %d, want the verifier alone", len(containers))
	}
	container, _ := containers[0].(map[string]any)
	sec := dig(t, container, "securityContext")
	drops, _ := dig(t, sec, "capabilities")["drop"].([]any)
	if sec["allowPrivilegeEscalation"] != false || sec["readOnlyRootFilesystem"] != true || len(drops) != 1 || drops[0] != "ALL" {
		t.Errorf("container securityContext = %v, want no privilege escalation, a read-only root and all capabilities dropped", sec)
	}

	probePath := func(name string) string {
		path, _ := dig(t, dig(t, container, name), "httpGet")["path"].(string)
		return path
	}
	if got := probePath("readinessProbe"); got != "/readyz" {
		t.Errorf("readinessProbe path = %q, want /readyz", got)
	}
	if got := probePath("livenessProbe"); got != "/healthz" {
		t.Errorf("livenessProbe path = %q, want /healthz", got)
	}
	if got := probePath("startupProbe"); got != "/readyz" {
		t.Errorf("startupProbe path = %q, want /readyz", got)
	}
	startup := dig(t, container, "startupProbe")
	period, _ := startup["periodSeconds"].(int)
	failures, _ := startup["failureThreshold"].(int)
	budget := time.Duration(period*failures) * time.Second
	k8s := loadVerifierConfig(t, writeConfigMapConfig(t, dir))
	// One startupTimeout per transparency log fetched without pinned keys, one more for the
	// HA variant's Redis connect.
	if need := k8s.StartupTimeout * time.Duration(len(k8s.TransparencyLogs)+1); budget < need {
		t.Errorf("startupProbe allows %s, want at least %s (startupTimeout %s x %d)", budget, need, k8s.StartupTimeout, len(k8s.TransparencyLogs)+1)
	}
}

// writeConfigMapConfig materialises the ConfigMap's config.yaml with a provisioned root key in
// place of the placeholder, so config.Load accepts it.
func writeConfigMapConfig(t *testing.T, dir string) string {
	t.Helper()
	var configMapYAML string
	for _, doc := range yamlDocs(t, filepath.Join(dir, "kubernetes", "ans-verifier.yaml")) {
		if doc["kind"] == "ConfigMap" {
			data, _ := doc["data"].(map[string]any)
			configMapYAML, _ = data["config.yaml"].(string)
		}
	}
	if configMapYAML == "" {
		t.Fatal("kubernetes/ans-verifier.yaml has no ConfigMap with data.config.yaml")
	}
	if !strings.Contains(configMapYAML, rootKeyPlaceholder) {
		t.Fatalf("ConfigMap must pin the log's root keys next to baseURL, shipped as %q", rootKeyPlaceholder)
	}
	p, err := testidentity.Provision("ans://v1.0.0.recipes.example", "recipes")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err = os.WriteFile(path, []byte(strings.Replace(configMapYAML, rootKeyPlaceholder, p.RootKeyC2SP, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dig(t *testing.T, m map[string]any, keys ...string) map[string]any {
	t.Helper()
	for _, k := range keys {
		next, ok := m[k].(map[string]any)
		if !ok {
			t.Fatalf("%q is missing or not a mapping", k)
		}
		m = next
	}
	return m
}

// TestRecipesCarryTheAuthorizerContract checks every extAuth block in the recipes for the
// settings the verifier and the triage table rely on, and every MCP authorization block for a
// deny-by-default posture.
func TestRecipesCarryTheAuthorizerContract(t *testing.T) {
	t.Parallel()
	var files []string
	if err := filepath.WalkDir(recipesDir(t), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	extAuthBlocks, authzBlocks := 0, 0
	for _, f := range files {
		for _, doc := range yamlDocs(t, f) {
			walk(doc, func(key string, value map[string]any) {
				switch key {
				case "extAuth":
					extAuthBlocks++
					checkExtAuth(t, f, value)
				case "authorization":
					if _, isMCP := value["rules"].([]any); isMCP && doc["kind"] == "MCPRoute" {
						authzBlocks++
						if value["defaultAction"] != "Deny" {
							t.Errorf("%s: MCPRoute authorization must set defaultAction: Deny", f)
						}
					}
				}
			})
		}
	}
	if extAuthBlocks < 4 || authzBlocks < 2 {
		t.Errorf("found %d extAuth and %d MCP authorization blocks; expected the LLM and MCP recipes for standalone and Kubernetes", extAuthBlocks, authzBlocks)
	}
}

func checkExtAuth(t *testing.T, file string, ext map[string]any) {
	t.Helper()
	if ext["failOpen"] != false {
		t.Errorf("%s: extAuth.failOpen must be false", file)
	}
	if status, _ := ext["statusOnError"].(int); status != 503 {
		t.Errorf("%s: extAuth.statusOnError must be 503, got %v", file, ext["statusOnError"])
	}
	body, _ := ext["bodyToExtAuth"].(map[string]any)
	if body == nil || body["maxRequestBytes"] == nil {
		t.Errorf("%s: extAuth.bodyToExtAuth.maxRequestBytes is required for content binding", file)
	}
	found := false
	if exts, _ := ext["contextExtensions"].([]any); exts != nil {
		for _, e := range exts {
			m, _ := e.(map[string]any)
			if m["name"] == "ans-authz" && m["value"] == "body-forwarded" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("%s: extAuth.contextExtensions must carry the ans-authz: body-forwarded sentinel", file)
	}
	grpc, _ := ext["grpc"].(map[string]any)
	settings, _ := grpc["backendSettings"].(map[string]any)
	breaker, _ := settings["circuitBreaker"].(map[string]any)
	if breaker == nil || breaker["maxParallelRequests"] == nil {
		t.Errorf("%s: extAuth.grpc.backendSettings.circuitBreaker.maxParallelRequests must bound in-flight checks", file)
	}
}

func yamlDocs(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	for _, chunk := range strings.Split(string(raw), "\n---") {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(chunk), &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(doc) > 0 {
			docs = append(docs, doc)
		}
	}
	return docs
}

func walk(node any, visit func(key string, value map[string]any)) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			if m, ok := child.(map[string]any); ok {
				visit(k, m)
			}
			walk(child, visit)
		}
	case []any:
		for _, child := range v {
			walk(child, visit)
		}
	}
}
