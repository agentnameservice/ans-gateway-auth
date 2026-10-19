// Command ans-authz is an Envoy ext_authz verifier for Agent Name Service
// identities: DPoP proofs (RFC 9449) bound to an identity certificate, with a
// SCITT receipt and status token, as specified by ANS-6 Method B.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// version is set by the linker (-X main.version=...).
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
