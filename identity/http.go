package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// Headers returns the SCITT receipt and status-token headers for the bundle.
func (b *Bundle) Headers() http.Header {
	return scitt.GenerateHeaders(b.Receipt, b.StatusToken)
}

// Attach signs req with a fresh DPoP proof bound to its method, URL and body
// and adds the SCITT headers, replacing any DPoP or SCITT headers already on
// the request. An "Authorization: DPoP <token>" header already on req is bound
// into the proof's ath claim by the SDK.
func (b *Bundle) Attach(req *http.Request) error {
	if req == nil {
		return errors.New("identity: nil request")
	}
	signer, err := b.Signer()
	if err != nil {
		return err
	}
	for _, h := range []string{pop.DPoPHeader, scitt.HeaderReceipt, scitt.HeaderStatusToken} {
		req.Header.Del(h)
	}
	return pop.AttachIdentity(req, signer, b.Headers())
}

// Sign returns a header set carrying a DPoP proof for method, rawURL and body
// plus the SCITT headers, without an *http.Request. It exists for hand-built
// ext_authz CheckRequests in tests: each call mints one single-use proof, so
// presenting the same Sign output twice is the replay a verifier must reject.
// opts follow the content binding, so pop.WithAccessToken can add an ath.
func (b *Bundle) Sign(ctx context.Context, method, rawURL string, body []byte, opts ...pop.ProofOption) (http.Header, error) {
	signer, err := b.Signer()
	if err != nil {
		return nil, err
	}
	proof, err := signer.Sign(ctx, method, rawURL, append([]pop.ProofOption{pop.WithContent(body)}, opts...)...)
	if err != nil {
		return nil, err
	}
	h := b.Headers()
	h.Set(pop.DPoPHeader, proof)
	return h, nil
}

// Transport returns a RoundTripper that runs Attach on a clone of every request
// before handing the clone to base (http.DefaultTransport when nil). The
// caller's request is never modified; its body is buffered once so the proof
// binds the content digest and base can rewind the clone's body on a retry.
func (b *Bundle) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{bundle: b, base: base}
}

type transport struct {
	bundle *Bundle
	base   http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		content, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("identity: read request body: %w", err)
		}
		clone.Body = io.NopCloser(bytes.NewReader(content))
	}
	if err := t.bundle.Attach(clone); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(clone)
}
