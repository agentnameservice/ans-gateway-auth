package config_test

import (
	"path/filepath"
	"testing"

	"github.com/agentnameservice/ans-gateway-auth/config"
)

// TestShippedExamplesLoad guards the verifier configurations under examples/:
// every ans-authz*.yaml must load and validate with the current schema.
func TestShippedExamplesLoad(t *testing.T) {
	t.Parallel()
	paths, err := filepath.Glob(filepath.Join("..", "examples", "*", "ans-authz*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no example verifier configurations found")
	}
	for _, p := range paths {
		name := filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Load(p, config.Overrides{}); err != nil {
				t.Fatalf("Load(%s): %v", p, err)
			}
		})
	}
}
