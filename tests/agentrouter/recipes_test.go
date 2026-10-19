package agentrouter

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/agentnameservice/ans-gateway-auth/config"
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
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(configMapYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	k8s := loadVerifierConfig(t, path)

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
