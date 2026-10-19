package authz

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/examples/a2a-no-mtls/demokit"
	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/replay"
)

const (
	fixtureAnsName = "ans://v1.0.0.caller.example"
	fixtureAgentID = "agent-1"
	fixtureTarget  = "https://api.example/v1/resource"
)

type decisionRecord struct {
	result   string
	category string
	duration time.Duration
}

type refreshRecord struct {
	name string
	keys int
	err  error
}

// recObserver records every Observer call so tests can assert on telemetry.
type recObserver struct {
	mu        sync.Mutex
	decisions []decisionRecord
	refreshes []refreshRecord
	timeouts  int
	backend   int
}

func (o *recObserver) ReplayBackend(string, time.Duration, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.backend++
}

func (o *recObserver) Decision(result, category string, d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.decisions = append(o.decisions, decisionRecord{result: result, category: category, duration: d})
}

func (o *recObserver) KeyRefresh(name string, keys int, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refreshes = append(o.refreshes, refreshRecord{name: name, keys: keys, err: err})
}

func (o *recObserver) CheckTimeout() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.timeouts++
}

func (o *recObserver) refreshRecords() []refreshRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]refreshRecord(nil), o.refreshes...)
}

func (o *recObserver) decisionRecords() []decisionRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]decisionRecord(nil), o.decisions...)
}

func (o *recObserver) timeoutCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.timeouts
}

// mapLookup is a scitt.KeyLookup over a key set tests can grow at runtime; a
// miss returns a plain error, as demokit's lookup does.
type mapLookup struct {
	mu   sync.Mutex
	keys map[[4]byte]*scitt.TrustedKey
}

func newMapLookup(keys ...*scitt.TrustedKey) *mapLookup {
	m := &mapLookup{keys: make(map[[4]byte]*scitt.TrustedKey, len(keys))}
	for _, k := range keys {
		m.add(k)
	}
	return m
}

func (m *mapLookup) add(tk *scitt.TrustedKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[tk.Kid] = tk
}

func (m *mapLookup) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tk, ok := m.keys[kid]
	if !ok {
		return nil, errors.New("miss")
	}
	return tk, nil
}

func (m *mapLookup) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys)
}

func kidOf(b byte) [4]byte { return [4]byte{b, 0, 0, 0} }

func trustedKey(name string, b byte) *scitt.TrustedKey {
	return &scitt.TrustedKey{Name: name, Kid: kidOf(b)}
}

// fakeClock is an injectable time source for cooldown and rate-limit tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeCache is a replay.Cache whose behaviour each test scripts.
type fakeCache struct {
	check func(ctx context.Context, key string, exp time.Time) (bool, error)
}

func (c *fakeCache) CheckAndStore(ctx context.Context, key string, exp time.Time) (bool, error) {
	return c.check(ctx, key, exp)
}

func (c *fakeCache) Stats() replay.Stats { return replay.Stats{Backend: "fake"} }

func (c *fakeCache) Close() error { return nil }

// fixture is one provisioned caller identity: the transparency-log key that
// vouches for it, its credential bundle, signer and SCITT headers.
type fixture struct {
	tlKey  *ecdsa.PrivateKey
	bundle *demokit.Bundle
	lookup scitt.KeyLookup
	signer *pop.Signer
	hdrs   http.Header
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	tlKey, bundle, err := demokit.Provision(fixtureAnsName, fixtureAgentID)
	if err != nil {
		t.Fatalf("demokit.Provision: %v", err)
	}
	lookup, err := demokit.KeyLookup(&tlKey.PublicKey)
	if err != nil {
		t.Fatalf("demokit.KeyLookup: %v", err)
	}
	signer, err := pop.NewSigner(bundle.AgentKey, bundle.CertDER)
	if err != nil {
		t.Fatalf("pop.NewSigner: %v", err)
	}
	return &fixture{
		tlKey:  tlKey,
		bundle: bundle,
		lookup: lookup,
		signer: signer,
		hdrs:   scitt.GenerateHeaders(bundle.Receipt, bundle.StatusToken),
	}
}

func (f *fixture) keyring(t *testing.T) *Keyring {
	t.Helper()
	return mustKeyring(t, NoopObserver{}, KeySource{Name: "demo-tl", Lookup: f.lookup})
}

// token mints a DPoP-bound demo access token for the fixture's signing key.
func (f *fixture) token(t *testing.T) string {
	t.Helper()
	tok, err := demokit.MintUnsignedDemoToken("subject", "read", f.signer.JKT())
	if err != nil {
		t.Fatalf("MintUnsignedDemoToken: %v", err)
	}
	return tok
}

// signed builds a request for target carrying the fixture's identity. before,
// when set, edits the HTTP request before the proof is attached, so a DPoP
// access token set there is covered by ath.
func (f *fixture) signed(t *testing.T, method, target string, body []byte, before func(*http.Request)) *Request {
	t.Helper()
	req := newHTTPRequest(t, method, target, body)
	if before != nil {
		before(req)
	}
	if err := pop.AttachIdentity(req, f.signer, f.hdrs); err != nil {
		t.Fatalf("pop.AttachIdentity: %v", err)
	}
	return toRequest(t, req)
}

// bare builds a request for target without any identity material.
func bare(t *testing.T, method, target string, body []byte) *Request {
	t.Helper()
	return toRequest(t, newHTTPRequest(t, method, target, body))
}

func newHTTPRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, rd)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	return req
}

// toRequest converts an outbound HTTP request into the transport-neutral shape
// a gateway face would hand the verifier.
func toRequest(t *testing.T, req *http.Request) *Request {
	t.Helper()
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		body = b
	}
	return &Request{
		Method:    req.Method,
		Scheme:    req.URL.Scheme,
		Authority: req.URL.Host,
		Path:      req.URL.RequestURI(),
		Header:    req.Header.Clone(),
		Body:      body,
	}
}

func testConfig() Config {
	c := DefaultConfig()
	c.TrustedHosts = []string{"https://api.example"}
	return c
}

type verifierDeps struct {
	keys   *Keyring
	cache  replay.Cache
	obs    Observer
	logger *slog.Logger
}

func withKeys(k *Keyring) func(*verifierDeps)       { return func(d *verifierDeps) { d.keys = k } }
func withCache(c replay.Cache) func(*verifierDeps)  { return func(d *verifierDeps) { d.cache = c } }
func withObserver(o Observer) func(*verifierDeps)   { return func(d *verifierDeps) { d.obs = o } }
func withLogger(l *slog.Logger) func(*verifierDeps) { return func(d *verifierDeps) { d.logger = l } }

// verifier wires a Verifier over the fixture's keys and a fresh memory replay
// cache unless an option overrides them.
func (f *fixture) verifier(t *testing.T, cfg Config, opts ...func(*verifierDeps)) *Verifier {
	t.Helper()
	deps := verifierDeps{}
	for _, o := range opts {
		o(&deps)
	}
	if deps.keys == nil {
		deps.keys = f.keyring(t)
	}
	if deps.cache == nil {
		mem := replay.NewMemory(t.Context(), 1000, nil)
		t.Cleanup(func() { _ = mem.Close() })
		deps.cache = mem
	}
	v, err := NewVerifier(cfg, deps.keys, deps.cache, deps.obs, deps.logger)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}
