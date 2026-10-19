package testidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
)

func TestProvisionMintFailures(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tests := []struct {
		name    string
		mint    mintFunc
		wantErr string
	}{
		{
			name: "mint error",
			mint: func(string, string) (*ecdsa.PrivateKey, *demokit.Bundle, error) {
				return nil, nil, errors.New("mint failed")
			},
			wantErr: "mint failed",
		},
		{
			name: "log key without a curve",
			mint: func(string, string) (*ecdsa.PrivateKey, *demokit.Bundle, error) {
				return &ecdsa.PrivateKey{}, &demokit.Bundle{}, nil
			},
			wantErr: "elliptic curve",
		},
		{
			name: "log key is not P-256",
			mint: func(string, string) (*ecdsa.PrivateKey, *demokit.Bundle, error) {
				return p384, &demokit.Bundle{}, nil
			},
			wantErr: "P-256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := provision("ans://v1.0.0.caller.example", "caller-1", tt.mint)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if p != nil {
				t.Fatalf("provision returned %+v alongside error", p)
			}
		})
	}
}
