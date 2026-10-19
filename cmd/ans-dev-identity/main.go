// Command ans-dev-identity mints a development agent identity for testing ANS-6 Method B
// authentication: a self-signed identity certificate, a SCITT receipt and a status token
// issued by a throwaway transparency-log key. It writes the bundle for ans-curl and prints
// the root-key line a verifier needs to trust the identity. Development only; production
// agents obtain these artifacts from a registry and transparency log.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/agentnameservice/ans-gateway-auth/identity"
	"github.com/agentnameservice/ans-gateway-auth/testidentity"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

type provisionFunc func(ansName, agentID string) (*testidentity.Provisioned, error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWith(args, stdout, stderr, testidentity.Provision)
}

func runWith(args []string, stdout, stderr io.Writer, provision provisionFunc) int {
	fs := flag.NewFlagSet("ans-dev-identity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory to write the identity bundle into (required)")
	ansName := fs.String("ans-name", "", "the agent's ans:// name, for example ans://v1.0.0.demo.example (required)")
	agentID := fs.String("agent-id", "", "the agent id recorded in the status token (required)")
	force := fs.Bool("force", false, "overwrite an existing bundle")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *out == "" || *ansName == "" || *agentID == "" {
		fmt.Fprintln(stderr, "ans-dev-identity: --out, --ans-name and --agent-id are required")
		fs.Usage()
		return exitUsage
	}

	p, err := provision(*ansName, *agentID)
	if err != nil {
		fmt.Fprintln(stderr, "ans-dev-identity:", err)
		return exitFailure
	}
	status, err := p.Bundle.Status(p.KeyLookup, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "ans-dev-identity: minted status token does not verify:", err)
		return exitFailure
	}
	name, err := p.Bundle.AnsName()
	if err != nil {
		fmt.Fprintln(stderr, "ans-dev-identity:", err)
		return exitFailure
	}

	opts := []identity.WriteOption{identity.WithRootKeys(p.RootKeyC2SP)}
	if *force {
		opts = append(opts, identity.WithForce())
	}
	if err := p.Bundle.Write(*out, opts...); err != nil {
		if !*force && errors.Is(err, identity.ErrExists) {
			fmt.Fprintln(stderr, "ans-dev-identity:", err, "(use --force to overwrite)")
		} else {
			fmt.Fprintln(stderr, "ans-dev-identity:", err)
		}
		return exitFailure
	}

	expires := time.Unix(status.Payload.Exp, 0).UTC()
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	fmt.Fprintf(stdout, "agent:       %s (%s)\n", name, status.Payload.AgentID)
	fmt.Fprintf(stdout, "fingerprint: %s\n", p.Bundle.FingerprintHex())
	fmt.Fprintf(stdout, "status token expires %s\n", expires.Format(time.RFC3339))
	fmt.Fprintln(stdout, "verifier transparencyLogs entry (replace the shipped entry in ans-authz.yaml):")
	fmt.Fprintln(stdout, "  - name: dev")
	fmt.Fprintln(stdout, "    rootKeys:")
	fmt.Fprintf(stdout, "      - %q\n", p.RootKeyC2SP)
	fmt.Fprintln(stdout, "development identity: a fresh transparency-log key signs each run, so re-add the root key and restart the verifier after a refresh")
	return exitOK
}
