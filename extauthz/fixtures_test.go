package extauthz

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

const (
	fixtureAnsName   = "ans://v1.0.0.caller.example"
	fixtureAuthority = "gw.example"
	fixtureBaseURL   = "http://" + fixtureAuthority
)

// fixture is a verifier over demokit-minted trust material plus a signer that
// produces valid requests for it.
type fixture struct {
	verifier *authz.Verifier
	signer   *pop.Signer
	scitt    http.Header
}

func newFixture(t *testing.T, cache replay.Cache) *fixture {
	t.Helper()
	tlKey, bundle, err := demokit.Provision(fixtureAnsName, "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := demokit.KeyLookup(&tlKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := authz.NewKeyring(authz.NoopObserver{}, authz.KeySource{Name: "demo", Lookup: lookup})
	if err != nil {
		t.Fatal(err)
	}
	if cache == nil {
		cache = replay.NewMemory(context.Background(), 1000, nil)
	}
	t.Cleanup(func() { _ = cache.Close() })
	cfg := authz.DefaultConfig()
	cfg.TrustedHosts = []string{fixtureBaseURL}
	v, err := authz.NewVerifier(cfg, keys, cache, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pop.NewSigner(bundle.AgentKey, bundle.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{verifier: v, signer: signer, scitt: scitt.GenerateHeaders(bundle.Receipt, bundle.StatusToken)}
}

// signedCheckRequest builds the CheckRequest agentgateway would send for a
// request carrying a valid identity.
func (f *fixture) signedCheckRequest(t *testing.T, method, path string, body []byte) *authv3.CheckRequest {
	t.Helper()
	req, err := http.NewRequest(method, fixtureBaseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if err := pop.AttachIdentity(req, f.signer, f.scitt); err != nil {
		t.Fatal(err)
	}
	return checkRequestFrom(req, body)
}

func checkRequestFrom(req *http.Request, body []byte) *authv3.CheckRequest {
	headers := map[string]string{
		":method":    req.Method,
		":path":      req.URL.RequestURI(),
		":authority": req.URL.Host,
		":scheme":    req.URL.Scheme,
	}
	for k, vs := range req.Header {
		headers[strings.ToLower(k)] = strings.Join(vs, ",")
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Method:  req.Method,
			Path:    req.URL.RequestURI(),
			Host:    req.URL.Host,
			Scheme:  req.URL.Scheme,
			Headers: headers,
			RawBody: body,
			Size:    int64(len(body)),
		}},
	}}
}
