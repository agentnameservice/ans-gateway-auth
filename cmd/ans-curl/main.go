// Command ans-curl sends one HTTP request authenticated as an ANS agent: it attaches an RFC
// 9449 DPoP proof bound to the method, URL and body, plus the agent's SCITT receipt and
// status token, then prints the response. It works with any identity bundle in the on-disk
// layout ans-dev-identity writes, including registry-issued material copied into it.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/agentnameservice/ans-gateway-auth/identity"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2

	defaultTimeout = 30 * time.Second
)

type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ", ") }

func (h *headerFlags) Set(v string) error {
	if !strings.Contains(v, ":") {
		return fmt.Errorf("header %q must be Name: value", v)
	}
	*h = append(*h, v)
	return nil
}

type options struct {
	dir     string
	method  string
	data    string
	token   string
	replay  bool
	force   bool
	timeout time.Duration
	headers headerFlags
	url     string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, code := parseArgs(args, stderr)
	if code != exitOK {
		return code
	}
	bundle, err := identity.Load(opts.dir)
	if err != nil {
		fmt.Fprintln(stderr, "ans-curl:", err)
		return exitFailure
	}
	if err := checkStatus(bundle, opts.dir, time.Now(), stderr); err != nil {
		if !opts.force {
			fmt.Fprintln(stderr, "ans-curl:", err, "(use --force to send anyway)")
			return exitFailure
		}
		fmt.Fprintln(stderr, "ans-curl: warning:", err)
	}
	body, err := readBody(opts.data)
	if err != nil {
		fmt.Fprintln(stderr, "ans-curl:", err)
		return exitFailure
	}
	req, err := buildRequest(opts, body)
	if err != nil {
		fmt.Fprintln(stderr, "ans-curl:", err)
		return exitFailure
	}
	if err := bundle.Attach(req); err != nil {
		fmt.Fprintln(stderr, "ans-curl:", err)
		return exitFailure
	}
	client := &http.Client{Timeout: opts.timeout, CheckRedirect: noRedirect}
	if err := sendAll(client, req, body, opts.replay, stdout); err != nil {
		fmt.Fprintln(stderr, "ans-curl:", err)
		return exitFailure
	}
	return exitOK
}

func parseArgs(args []string, stderr io.Writer) (*options, int) {
	fs := flag.NewFlagSet("ans-curl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := &options{}
	fs.StringVar(&o.dir, "identity", "", "directory holding the identity bundle (required)")
	fs.StringVar(&o.method, "X", "", "HTTP method (default GET, or POST when -d is given)")
	fs.StringVar(&o.data, "d", "", "request body, or @file to read it from a file")
	fs.StringVar(&o.token, "token", "", "DPoP-bound OAuth access token to send as Authorization: DPoP <token>")
	fs.BoolVar(&o.replay, "replay", false, "send the identical signed request twice to show replay rejection")
	fs.BoolVar(&o.force, "force", false, "send even when the status token is expired or cannot be checked")
	fs.DurationVar(&o.timeout, "timeout", defaultTimeout, "request timeout")
	fs.Var(&o.headers, "H", "extra request header, repeatable (Name: value)")
	if err := fs.Parse(args); err != nil {
		return nil, exitUsage
	}
	if o.dir == "" || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "ans-curl: --identity <dir> and exactly one URL are required")
		fs.Usage()
		return nil, exitUsage
	}
	o.url = fs.Arg(0)
	return o, exitOK
}

// buildRequest assembles the unsigned request from the parsed options; the URL is the
// user's explicit target, exactly as with curl.
func buildRequest(o *options, body []byte) (*http.Request, error) {
	method := o.method
	if method == "" {
		method = http.MethodGet
		if body != nil {
			method = http.MethodPost
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), method, o.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, h := range o.headers {
		name, value, _ := strings.Cut(h, ":")
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if o.token != "" {
		req.Header.Set("Authorization", "DPoP "+o.token)
	}
	return req, nil
}

// sendAll sends the signed request once, or twice byte-for-byte when replay is set, so the
// second response shows the verifier rejecting the reused proof.
// noRedirect keeps the one signed request single, as curl does without -L: following a
// redirect would resend a proof bound to the original URL and carry the identity headers to
// whatever host the redirect names.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func sendAll(client *http.Client, req *http.Request, body []byte, replay bool, out io.Writer) error {
	attempts := 1
	if replay {
		attempts = 2
	}
	for i := range attempts {
		if i > 0 {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "--- replaying the identical signed request ---")
		}
		attempt := req.Clone(req.Context())
		attempt.Body = io.NopCloser(bytes.NewReader(body))
		if err := printResponse(client, attempt, out); err != nil {
			return err
		}
	}
	return nil
}

// checkStatus verifies the bundle's status token against root-keys.c2sp when the bundle has
// one; without it the expiry cannot be checked and the caller is told so.
func checkStatus(b *identity.Bundle, dir string, now time.Time, stderr io.Writer) error {
	keys, err := identity.LoadRootKeys(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(stderr, "ans-curl: no root-keys.c2sp in the bundle, status token expiry not checked")
			return nil
		}
		return err
	}
	if _, err := b.Status(keys, now); err != nil {
		return fmt.Errorf("status token is not valid: %w", err)
	}
	return nil
}

func readBody(data string) ([]byte, error) {
	switch {
	case data == "":
		return nil, nil
	case strings.HasPrefix(data, "@"):
		return os.ReadFile(data[1:]) //nolint:gosec // G703: the body file is the operator's own argument, as with curl -d @file
	default:
		return []byte(data), nil
	}
}

// printResponse writes the response the way curl -i does: status line, sorted headers, blank
// line, body. The output goes to the operator's terminal or file, never into a web page.
func printResponse(client *http.Client, req *http.Request, out io.Writer) error {
	resp, err := client.Do(req) //nolint:gosec // G704: the URL is the user's explicit target, as with curl
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Fprintf(out, "%s %s\n", resp.Proto, resp.Status) //nolint:gosec // G705: plain-text output, not HTML
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, v := range resp.Header[name] {
			fmt.Fprintf(out, "%s: %s\n", name, v) //nolint:gosec // G705: plain-text output, not HTML
		}
	}
	fmt.Fprintln(out)
	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	fmt.Fprintln(out)
	return nil
}
