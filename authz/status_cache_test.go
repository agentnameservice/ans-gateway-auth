package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// The tests below drive the gateway-owned issuer status cache: tokens the
// verifier fetched from the TL in the background, compared by iat with the
// one the client presents. They reuse the cross-language "valid" vector's
// instance token and DPoP proof, and mint the status tokens themselves under
// a test TL key, so each case controls iat, exp and status exactly.

const testMaxStatusAge = 240 * time.Second

// Minimal CBOR encoding (RFC 8949) for minting status tokens in tests, so the
// module needs no direct CBOR dependency.
func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 0xff:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 0xffff:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = major<<5 | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}

func cborInt(v int64) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

func cborArray(items ...[]byte) []byte {
	out := cborHead(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// cborMap takes alternating encoded keys and values.
func cborMap(kv ...[]byte) []byte {
	out := cborHead(5, uint64(len(kv)/2))
	for _, it := range kv {
		out = append(out, it...)
	}
	return out
}

// statusHarness is one issuer, one test TL key and one shared status cache.
type statusHarness struct {
	t       *testing.T
	iv      *instanceVectors
	vec     instanceVector
	tlKey   *ecdsa.PrivateKey
	line    string
	kid     [4]byte
	keys    *countingKeys
	cache   *MemoryStatusCache
	ansName string
	certFP  [32]byte
}

func newStatusHarness(t *testing.T) *statusHarness {
	t.Helper()
	iv := loadInstanceVectors(t)
	vec := validInstanceVector(t, iv)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	var kid [4]byte
	copy(kid[:], sum[:4])
	line := "status-tl+" + hex.EncodeToString(kid[:]) + "+" + base64.StdEncoding.EncodeToString(spki)
	store, err := scitt.NewKeyStore(append([]string{line}, iv.RootKeys...))
	if err != nil {
		t.Fatal(err)
	}
	it, err := parseInstanceToken(vec.Token)
	if err != nil {
		t.Fatal(err)
	}
	return &statusHarness{
		t: t, iv: iv, vec: vec, tlKey: key, line: line, kid: kid,
		keys:    &countingKeys{inner: mustKeyring(t, NoopObserver{}, KeySource{Name: "test-tl", Lookup: store})},
		cache:   NewMemoryStatusCache(),
		ansName: vec.Expect.AnsName, certFP: sha256.Sum256(it.certDER),
	}
}

func (h *statusHarness) issuer() string { return h.iv.AllowedIssuers[0] }

// mintFor signs a status token under the harness TL key; iat and exp are
// offsets in seconds from the vectors' fixed clock.
func (h *statusHarness) mintFor(agentID, ansName string, status scitt.AgentStatus, iatOff, expOff int64) []byte {
	h.t.Helper()
	protected := cborMap(cborInt(1), cborInt(-7), cborInt(4), cborBytes(h.kid[:]))
	payload := cborMap(
		cborInt(1), cborText(agentID),
		cborInt(2), cborText(string(status)),
		cborInt(3), cborInt(h.iv.Now+iatOff),
		cborInt(4), cborInt(h.iv.Now+expOff),
		cborInt(5), cborText(ansName),
		cborInt(6), cborArray(cborMap(cborInt(1), cborBytes(h.certFP[:]))),
	)
	digest, err := scitt.ComputeSigStructureDigest(protected, payload)
	if err != nil {
		h.t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, h.tlKey, digest[:])
	if err != nil {
		h.t.Fatal(err)
	}
	sig := make([]byte, es256SigLen)
	r.FillBytes(sig[:p256CoordLen])
	s.FillBytes(sig[p256CoordLen:])
	return append(cborHead(6, 18), cborArray(cborBytes(protected), cborMap(), cborBytes(payload), cborBytes(sig))...)
}

func (h *statusHarness) mint(status scitt.AgentStatus, iatOff int64) []byte {
	return h.mintFor(h.iv.AgentID, h.ansName, status, iatOff, iatOff+3600)
}

func (h *statusHarness) config() Config {
	cfg := h.iv.config()
	cfg.InstanceMode.MaxStatusAge = testMaxStatusAge
	cfg.InstanceMode.Issuers = []InstanceIssuer{{Host: h.issuer(), AgentID: h.iv.AgentID, TL: "test-tl"}}
	return cfg
}

// verifier shares the harness cache, never reports a replay (so one vector
// request can be presented many times) and runs on the vectors' clock.
func (h *statusHarness) verifier() *Verifier {
	h.t.Helper()
	noReplay := &fakeCache{check: func(context.Context, string, time.Time) (bool, error) { return false, nil }}
	v, err := NewVerifier(h.config(), h.keys, noReplay, nil, nil, WithStatusCache(h.cache))
	if err != nil {
		h.t.Fatalf("NewVerifier: %v", err)
	}
	now := time.Unix(h.iv.Now, 0)
	v.now = func() time.Time { return now }
	return v
}

func (h *statusHarness) request(statusToken []byte) *Request {
	h.t.Helper()
	r := h.vec.request(h.t)
	r.Header.Set(scitt.HeaderStatusToken, base64.StdEncoding.EncodeToString(statusToken))
	return r
}

// fetcher is a scripted StatusFetcher that counts calls.
type fetcher struct {
	mu    sync.Mutex
	raw   []byte
	err   error
	calls atomic.Int64
}

func (f *fetcher) set(raw []byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.raw, f.err = raw, err
}

func (f *fetcher) fetch(context.Context, string) ([]byte, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.raw, nil
}

// refresher builds a StatusRefresher over the harness cache whose clock is
// the vectors' clock shifted by *offset seconds.
func (h *statusHarness) refresher(f StatusFetcher, offset *atomic.Int64, obs StatusObserver) *StatusRefresher {
	h.t.Helper()
	r, err := NewStatusRefresher(h.cache, h.keys, testMaxStatusAge, obs, nil,
		IssuerStatusSource{Host: h.issuer(), AgentID: h.iv.AgentID, Fetch: f, Timeout: time.Second})
	if err != nil {
		h.t.Fatalf("NewStatusRefresher: %v", err)
	}
	r.now = func() time.Time { return time.Unix(h.iv.Now+offset.Load(), 0) }
	return r
}

func requireAllowed(t *testing.T, d Decision, what string) {
	t.Helper()
	if !d.Allowed {
		t.Fatalf("%s: denied %+v", what, d.Deny)
	}
}

// TestMemoryStatusCacheWrites splits the two write paths. OfferPresented
// (a client's token) only moves a live entry forward and never replaces a
// terminal one, whatever its iat. Install (the TL's own current answer)
// replaces unconditionally, so a live TL token clears a terminal entry and a
// terminal answer replaces a newer-iat live one.
func TestMemoryStatusCacheWrites(t *testing.T) {
	t.Parallel()
	c := NewMemoryStatusCache()
	if _, ok := c.Get("a"); ok {
		t.Fatal("empty cache returned an entry")
	}
	if c.OfferPresented(IssuerStatus{AgentID: "a", Iat: 100}) {
		t.Fatal("a presented token populated an agent the TL never answered for")
	}
	c.Install(IssuerStatus{AgentID: "a", Iat: 100})
	if c.OfferPresented(IssuerStatus{AgentID: "a", Iat: 90}) || c.OfferPresented(IssuerStatus{AgentID: "a", Iat: 100}) {
		t.Fatal("an older or equal presented entry replaced the cached one")
	}
	if !c.OfferPresented(IssuerStatus{AgentID: "a", Iat: 101}) {
		t.Fatal("a newer presented entry refused")
	}
	c.Install(IssuerStatus{AgentID: "a", Iat: 50, Terminal: true})
	if got, _ := c.Get("a"); !got.Terminal {
		t.Fatal("Install of a terminal answer with a lower iat did not replace the live entry")
	}
	if c.OfferPresented(IssuerStatus{AgentID: "a", Iat: 1 << 40}) {
		t.Fatal("a presented entry with a higher iat replaced a terminal one")
	}
	if got, _ := c.Get("a"); !got.Terminal {
		t.Fatalf("terminal entry lost: %+v", got)
	}
	c.Install(IssuerStatus{AgentID: "a", Iat: 40})
	if got, _ := c.Get("a"); got.Terminal || got.Iat != 40 {
		t.Fatalf("Install of a live TL answer did not clear the terminal entry: %+v", got)
	}
	if c.OfferPresented(IssuerStatus{Iat: 1}) {
		t.Fatal("an entry without an agent id was accepted")
	}
	c.Install(IssuerStatus{Iat: 1})
	if _, ok := c.Get(""); ok {
		t.Fatal("Install stored an entry without an agent id")
	}
}

// raceCache installs a terminal entry from the TL right after the request
// path reads the cache, the window between Get and OfferPresented.
type raceCache struct {
	*MemoryStatusCache
	onGet func()
}

func (c *raceCache) Get(agentID string) (IssuerStatus, bool) {
	s, ok := c.MemoryStatusCache.Get(agentID)
	if c.onGet != nil {
		c.onGet()
	}
	return s, ok
}

// TestStatusCacheRevocationRaceKeepsTerminal: a request reads a live entry,
// the refresher then installs a 410 (dated by the gateway clock, here far
// below the presented token's TL iat), and the request offers its newer
// presented token. The terminal entry must survive, and the next request is
// refused revoked.
func TestStatusCacheRevocationRaceKeepsTerminal(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	race := &raceCache{MemoryStatusCache: h.cache}
	h.cache.Install(IssuerStatus{AgentID: h.iv.AgentID, Iat: h.iv.Now - 30, Token: mustVerify(t, h, h.mint(scitt.StatusActive, -30))})
	race.onGet = func() {
		race.onGet = nil
		h.cache.Install(IssuerStatus{AgentID: h.iv.AgentID, Iat: h.iv.Now - 1000, Terminal: true})
	}
	noReplay := &fakeCache{check: func(context.Context, string, time.Time) (bool, error) { return false, nil }}
	v, err := NewVerifier(h.config(), h.keys, noReplay, nil, nil, WithStatusCache(race))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(h.iv.Now, 0)
	v.now = func() time.Time { return now }
	// The in-flight request decided on the live entry it read; it is the
	// last one the race can admit.
	_ = v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -5)))
	if got, _ := h.cache.Get(h.iv.AgentID); !got.Terminal {
		t.Fatalf("a presented token overwrote the terminal entry: %+v", got)
	}
	requireInstanceDenial(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -1))), codeRevoked)
}

func mustVerify(t *testing.T, h *statusHarness, raw []byte) *scitt.VerifiedStatusToken {
	t.Helper()
	st, err := scitt.VerifyStatusTokenAt(raw, h.keys, 0, h.iv.Now)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestStatusCacheBackgroundRefreshReplacesStaleEntry: with only a stale cached
// token and a stale presented one, a background refresh installs a fresh
// token and the same request is then admitted.
func TestStatusCacheBackgroundRefreshReplacesStaleEntry(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	r := h.refresher(f.fetch, &offset, nil)
	f.set(h.mint(scitt.StatusActive, -400), nil)
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	v := h.verifier()
	stale := h.request(h.mint(scitt.StatusActive, -300))
	requireInstanceDenial(t, v.Verify(t.Context(), stale), codeStatusStale)

	f.set(h.mint(scitt.StatusActive, -5), nil)
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got, _ := h.cache.Get(h.iv.AgentID); got.Iat != h.iv.Now-5 {
		t.Fatalf("cached iat = %d, want %d", got.Iat, h.iv.Now-5)
	}
	requireAllowed(t, v.Verify(t.Context(), stale), "after a background refresh")
}

// TestStatusCacheClientNewerIsUsedAndCached: a fresh presented token newer
// than a stale cached one is used, and then replaces the cache entry.
func TestStatusCacheClientNewerIsUsedAndCached(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	f.set(h.mint(scitt.StatusActive, -400), nil)
	if err := h.refresher(f.fetch, &offset, nil).Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	v := h.verifier()
	requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -10))), "fresh presented token")
	if got, _ := h.cache.Get(h.iv.AgentID); got.Iat != h.iv.Now-10 || got.Token == nil || len(got.Raw) == 0 {
		t.Fatalf("presented token not cached: %+v", got)
	}
	// The cached copy now admits a request whose own token is stale.
	requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -500))), "stale presented token, fresh cache")
}

// TestStatusCacheClientOlderUsesCache: a presented token older than the
// cached one is ignored in favour of the cache, both when that admits (a stale
// presented token) and when it refuses (the newer cached token no longer
// lists the certificate).
func TestStatusCacheClientOlderUsesCache(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	r := h.refresher(f.fetch, &offset, nil)
	f.set(h.mint(scitt.StatusActive, -20), nil)
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	v := h.verifier()
	requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -300))), "stale presented, fresh cache")
	if got, _ := h.cache.Get(h.iv.AgentID); got.Iat != h.iv.Now-20 {
		t.Fatalf("an older presented token replaced the cache: iat %d", got.Iat)
	}

	// A newer cached token that rotated the certificate out wins over an
	// older presented one that still lists it.
	h.certFP = [32]byte{1}
	f.set(h.mint(scitt.StatusActive, -10), nil)
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	h.certFP = sha256.Sum256(mustCertDER(t, h.vec.Token))
	requireInstanceDenial(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -30))), codeCertNotCurrent)
}

func mustCertDER(t *testing.T, tok string) []byte {
	t.Helper()
	it, err := parseInstanceToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	return it.certDER
}

// TestStatusCachePresentedExpiredRefused: an expired presented token is
// refused status_expired even when the cache holds a fresh one. The request
// fails closed on any presented token that does not verify; it never falls
// back past a bad one.
func TestStatusCachePresentedExpiredRefused(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	f.set(h.mint(scitt.StatusActive, -5), nil)
	if err := h.refresher(f.fetch, &offset, nil).Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	expired := h.mintFor(h.iv.AgentID, h.ansName, scitt.StatusActive, -7200, -3600)
	requireInstanceDenial(t, h.verifier().Verify(t.Context(), h.request(expired)), codeStatusExpired)
}

// TestStatusCacheBothStale refuses when neither token is within maxStatusAge.
func TestStatusCacheBothStale(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	f.set(h.mint(scitt.StatusActive, -250), nil)
	if err := h.refresher(f.fetch, &offset, nil).Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	for _, iat := range []int64{-260, -241} { // older and newer than the cache, both stale
		d := h.verifier().Verify(t.Context(), h.request(h.mint(scitt.StatusActive, iat)))
		requireInstanceDenial(t, d, codeStatusStale)
		if d.Deny.Category != CategoryStatusInvalid {
			t.Fatalf("Category = %q", d.Deny.Category)
		}
	}
}

// TestStatusCacheNeverFetchedFailsClosed: until the first background fetch
// succeeds, every request for the issuer is status_stale, even one carrying a
// fresh token, and that token is not cached.
func TestStatusCacheNeverFetchedFailsClosed(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	requireInstanceDenial(t, h.verifier().Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -1))), codeStatusStale)
	if _, ok := h.cache.Get(h.iv.AgentID); ok {
		t.Fatal("a presented token populated an issuer the TL was never reached for")
	}
}

// TestStatusCacheRevokedCachedRefuses: once the TL reports the issuer
// terminal (a 410 or a signed REVOKED token), a presented ACTIVE token is
// refused revoked, whether older or newer than that report.
func TestStatusCacheRevokedCachedRefuses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		fetch func(h *statusHarness) ([]byte, error)
	}{
		{"TL answers 410 Gone", func(*statusHarness) ([]byte, error) {
			return nil, &scitt.TransportError{Type: scitt.TransportErrAgentTerminal, StatusCode: http.StatusGone}
		}},
		{"TL serves a signed REVOKED token", func(h *statusHarness) ([]byte, error) {
			return h.mint(scitt.StatusRevoked, -5), nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newStatusHarness(t)
			f := &fetcher{}
			var offset atomic.Int64
			r := h.refresher(f.fetch, &offset, nil)
			f.set(h.mint(scitt.StatusActive, -30), nil)
			if err := r.Refresh(t.Context(), h.issuer()); err != nil {
				t.Fatal(err)
			}
			v := h.verifier()
			requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -60))), "before revocation")

			f.set(tc.fetch(h))
			if err := r.Refresh(t.Context(), h.issuer()); err != nil {
				t.Fatalf("a terminal answer is not a refresh failure: %v", err)
			}
			for _, iat := range []int64{-60, -1} {
				d := v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, iat)))
				requireInstanceDenial(t, d, codeRevoked)
			}
			if got, _ := h.cache.Get(h.iv.AgentID); !got.Terminal {
				t.Fatalf("cache entry %+v is not terminal", got)
			}
			// Only the TL's own live answer clears the entry, even one whose
			// iat is below the gateway-clock date of the terminal entry (a
			// TL clock that lags ours).
			offset.Store(10)
			f.set(h.mint(scitt.StatusActive, -5), nil)
			if err := r.Refresh(t.Context(), h.issuer()); err != nil {
				t.Fatal(err)
			}
			requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -60))), "after the TL issued a newer token")
		})
	}
}

// TestStatusCachePresentedRevokedRefuses: a signed REVOKED token from the
// client is refused at once even while the cache holds a fresh ACTIVE one.
func TestStatusCachePresentedRevokedRefuses(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	f.set(h.mint(scitt.StatusActive, -5), nil)
	if err := h.refresher(f.fetch, &offset, nil).Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	requireInstanceDenial(t, h.verifier().Verify(t.Context(), h.request(h.mint(scitt.StatusRevoked, -100))), codeRevoked)
}

// TestStatusCachePresentedForAnotherAgent refuses a status token naming an
// agent other than the one the issuer is pinned to, so the cache always
// covers the token in use.
func TestStatusCachePresentedForAnotherAgent(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	f.set(h.mint(scitt.StatusActive, -5), nil)
	if err := h.refresher(f.fetch, &offset, nil).Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	other := h.mintFor("00000000-0000-4000-8000-0000000000ff", h.ansName, scitt.StatusActive, -1, 3600)
	d := h.verifier().Verify(t.Context(), h.request(other))
	requireInstanceDenial(t, d, codeIssMismatch)
	if d.Deny.Category != CategoryBindingFailed {
		t.Fatalf("Category = %q", d.Deny.Category)
	}
}

// TestStatusCachePresentedFutureIatNotCached: a presented token that fails a
// check is never cached, so a future-dated token cannot pin the cache ahead.
func TestStatusCachePresentedFutureIatNotCached(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	f.set(h.mint(scitt.StatusActive, -5), nil)
	if err := h.refresher(f.fetch, &offset, nil).Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	requireInstanceDenial(t, h.verifier().Verify(t.Context(), h.request(h.mint(scitt.StatusActive, 120))), codeClockSkew)
	if got, _ := h.cache.Get(h.iv.AgentID); got.Iat != h.iv.Now-5 {
		t.Fatalf("a refused presented token entered the cache: iat %d", got.Iat)
	}
}

// TestStatusCacheTLDownFailsClosedThenRecovers: the TL goes down after a
// successful fetch; once the cached token passes maxStatusAge every request
// is status_stale, and the first successful refresh after the TL returns
// admits again.
func TestStatusCacheTLDownFailsClosedThenRecovers(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	obs := &recStatusObserver{}
	r := h.refresher(f.fetch, &offset, obs)
	offset.Store(-300) // the last good fetch, five minutes before "now"
	f.set(h.mint(scitt.StatusActive, -300), nil)
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	v := h.verifier()
	presented := h.request(h.mint(scitt.StatusActive, -300))

	offset.Store(0)
	f.set(nil, &scitt.TransportError{Type: scitt.TransportErrHTTPError, StatusCode: http.StatusServiceUnavailable})
	if err := r.Refresh(t.Context(), h.issuer()); err == nil {
		t.Fatal("Refresh with the TL down succeeded")
	}
	requireInstanceDenial(t, v.Verify(t.Context(), presented), codeStatusStale)

	f.set(h.mint(scitt.StatusActive, 0), nil)
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	requireAllowed(t, v.Verify(t.Context(), presented), "after the TL returned")
	if got := obs.results(); strings.Join(got, ",") != "success,failure,success" {
		t.Fatalf("observed %v", got)
	}
}

// countingTL is a fake transparency log over HTTP that counts every request
// by path.
type countingTL struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  map[string]int
	token []byte
	code  int
}

func newCountingTL(t *testing.T, rootKey string, agentID string) *countingTL {
	t.Helper()
	tl := &countingTL{hits: map[string]int{}, code: http.StatusOK}
	tl.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tl.mu.Lock()
		defer tl.mu.Unlock()
		tl.hits[r.URL.Path]++
		switch r.URL.Path {
		case "/root-keys":
			_, _ = w.Write([]byte(rootKey + "\n"))
		case "/v1/agents/" + agentID + "/status-token":
			w.Header().Set("Content-Type", "application/ans-status-token+cbor")
			w.WriteHeader(tl.code)
			_, _ = w.Write(tl.token)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(tl.srv.Close)
	return tl
}

func (tl *countingTL) total() int {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	n := 0
	for _, c := range tl.hits {
		n += c
	}
	return n
}

func (tl *countingTL) set(code int, token []byte) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.code, tl.token = code, token
}

// TestStatusCacheNoTLCallOnRequestPath fetches through the SDK's HTTP client
// against a counting fake TL: the fetch hits it, and no Verify call does,
// whether the cache admits, the presented token is newer, nothing is cached
// yet, or the presented token names an unknown TL key.
func TestStatusCacheNoTLCallOnRequestPath(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	tl := newCountingTL(t, h.line, h.iv.AgentID)
	client, err := scitt.NewHTTPClient(tl.srv.URL, scitt.WithAllowInsecureTransport())
	if err != nil {
		t.Fatal(err)
	}
	var offset atomic.Int64
	r := h.refresher(client.FetchStatusToken, &offset, nil)
	tl.set(http.StatusOK, h.mint(scitt.StatusActive, -100))
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatal(err)
	}
	if n := tl.total(); n != 1 {
		t.Fatalf("fetch made %d TL requests, want 1", n)
	}
	v := h.verifier()
	before := tl.total()
	requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -200))), "cache admits")
	requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -10))), "newer presented")
	requireAllowed(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -600))), "stale presented, cache refreshed by the newer one")
	unknown := newStatusHarness(t) // a fresh harness: nothing fetched yet for its cache
	requireInstanceDenial(t, unknown.verifier().Verify(t.Context(), unknown.request(unknown.mint(scitt.StatusActive, -1))), codeStatusStale)
	// A presented token under a TL key the verifier lacks is refused without
	// an on-demand root-key refresh: the background refresher learns new keys.
	refreshes := h.keys.refreshes.Load()
	requireInstanceDenial(t, v.Verify(t.Context(), h.request(unknown.mint(scitt.StatusActive, -1))), codeBadStatusToken)
	if n := h.keys.refreshes.Load() - refreshes; n != 0 {
		t.Fatalf("Verify triggered %d root-key refreshes, want 0", n)
	}
	if n := tl.total() - before; n != 0 {
		t.Fatalf("Verify made %d TL requests, want 0", n)
	}
}

// TestStatusRefresherRejects keeps every unusable answer out of the cache.
func TestStatusRefresherRejects(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	other := newStatusHarness(t) // another TL key, not trusted by h
	for _, tc := range []struct {
		name string
		raw  []byte
		err  error
		want string
	}{
		{"fetch fails", nil, errors.New("connection refused"), "connection refused"},
		{"not a status token", []byte("junk"), nil, "status token"},
		{"unknown TL key", other.mint(scitt.StatusActive, -1), nil, "unknown key"},
		{"another agent", h.mintFor("00000000-0000-4000-8000-0000000000ff", h.ansName, scitt.StatusActive, -1, 3600), nil, "agent"},
		{"another host", h.mintFor(h.iv.AgentID, "ans://v1.0.0.other.example.test", scitt.StatusActive, -1, 3600), nil, "other.example.test"},
		{"unparseable name", h.mintFor(h.iv.AgentID, "not-a-name", scitt.StatusActive, -1, 3600), nil, "not-a-name"},
		{"future iat", h.mint(scitt.StatusActive, 61), nil, "ahead"},
		{"expired", h.mintFor(h.iv.AgentID, h.ansName, scitt.StatusActive, -7200, -3600), nil, "expired"},
	} {
		f := &fetcher{}
		f.set(tc.raw, tc.err)
		var offset atomic.Int64
		obs := &recStatusObserver{}
		err := h.refresher(f.fetch, &offset, obs).Refresh(t.Context(), h.issuer())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Refresh = %v, want an error containing %q", tc.name, err, tc.want)
		}
		if _, ok := h.cache.Get(h.iv.AgentID); ok {
			t.Fatalf("%s: rejected token cached", tc.name)
		}
		if got := obs.results(); len(got) != 1 || got[0] != StatusRefreshFailure {
			t.Errorf("%s: observed %v", tc.name, got)
		}
	}
	if err := h.refresher((&fetcher{}).fetch, new(atomic.Int64), nil).Refresh(t.Context(), "unknown.example.test"); err == nil {
		t.Fatal("Refresh for an unconfigured issuer succeeded")
	}
}

// TestStatusRefresherUnknownKidRefreshesKeys refreshes the root keys once in
// the background when a fetched token names a kid the keyring lacks.
func TestStatusRefresherUnknownKidRefreshesKeys(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	lookup := newMapLookup()
	ring := mustKeyring(t, NoopObserver{}, KeySource{Name: "tl", Lookup: lookup, Timeout: time.Second,
		Refresh: func(context.Context) error {
			tk, err := scitt.ParseC2SPKey(h.line)
			if err != nil {
				return err
			}
			lookup.add(tk)
			return nil
		}})
	f := &fetcher{}
	f.set(h.mint(scitt.StatusActive, -1), nil)
	r, err := NewStatusRefresher(h.cache, ring, testMaxStatusAge, nil, nil,
		IssuerStatusSource{Host: h.issuer(), AgentID: h.iv.AgentID, Fetch: f.fetch})
	if err != nil {
		t.Fatal(err)
	}
	r.now = func() time.Time { return time.Unix(h.iv.Now, 0) }
	if err := r.Refresh(t.Context(), h.issuer()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if lookup.Len() != 1 {
		t.Fatal("root keys were not refreshed")
	}
}

// TestStatusRefresherRun refreshes in the background every maxStatusAge/2
// (jittered, never later), backs off after failures, recovers, and stops with
// its context.
func TestStatusRefresherRun(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	f := &fetcher{}
	var offset atomic.Int64
	obs := &recStatusObserver{}
	r := h.refresher(f.fetch, &offset, obs)
	if r.interval != testMaxStatusAge/2 {
		t.Fatalf("interval = %s, want maxStatusAge/2", r.interval)
	}
	for range 100 {
		if w := r.jittered(); w > r.interval || w < r.interval*8/10 {
			t.Fatalf("jittered wait %s outside [0.8, 1] x %s", w, r.interval)
		}
	}
	if got := r.backoff(1); got != r.backoffInitial {
		t.Fatalf("backoff(1) = %s", got)
	}
	if got := r.backoff(64); got != r.backoffMax {
		t.Fatalf("backoff(64) = %s, want the cap %s", got, r.backoffMax)
	}
	r.interval, r.backoffInitial, r.backoffMax = 20*time.Millisecond, 5*time.Millisecond, 10*time.Millisecond

	f.set(nil, errors.New("down"))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	waitFor(t, "failed attempts", func() bool { return f.calls.Load() >= 3 })
	f.set(h.mint(scitt.StatusActive, -1), nil)
	waitFor(t, "a successful refresh", func() bool { _, ok := h.cache.Get(h.iv.AgentID); return ok })
	n := f.calls.Load()
	waitFor(t, "scheduled refreshes", func() bool { return f.calls.Load() >= n+2 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	stopped := f.calls.Load()
	time.Sleep(50 * time.Millisecond)
	if f.calls.Load() != stopped {
		t.Fatal("Run kept fetching after its context ended")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestNewStatusRefresherErrors validates the refresher's wiring.
func TestNewStatusRefresherErrors(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	fetch := (&fetcher{}).fetch
	src := IssuerStatusSource{Host: h.issuer(), AgentID: h.iv.AgentID, Fetch: fetch}
	for _, tc := range []struct {
		name    string
		cache   StatusCache
		keys    KeyProvider
		age     time.Duration
		sources []IssuerStatusSource
		want    string
	}{
		{"no cache", nil, h.keys, time.Minute, []IssuerStatusSource{src}, "cache"},
		{"no keys", h.cache, nil, time.Minute, []IssuerStatusSource{src}, "key provider"},
		{"no max age", h.cache, h.keys, 0, []IssuerStatusSource{src}, "maxStatusAge"},
		{"no sources", h.cache, h.keys, time.Minute, nil, "at least one"},
		{"no host", h.cache, h.keys, time.Minute, []IssuerStatusSource{{AgentID: "a", Fetch: fetch}}, "host"},
		{"no agent", h.cache, h.keys, time.Minute, []IssuerStatusSource{{Host: "a", Fetch: fetch}}, "agent"},
		{"no fetch", h.cache, h.keys, time.Minute, []IssuerStatusSource{{Host: "a", AgentID: "a"}}, "fetch"},
		{"duplicate host", h.cache, h.keys, time.Minute, []IssuerStatusSource{src, src}, "duplicate"},
	} {
		if _, err := NewStatusRefresher(tc.cache, tc.keys, tc.age, nil, nil, tc.sources...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	r, err := NewStatusRefresher(h.cache, h.keys, time.Minute, nil, nil, src)
	if err != nil {
		t.Fatal(err)
	}
	if hosts := r.Hosts(); len(hosts) != 1 || hosts[0] != h.issuer() {
		t.Fatalf("Hosts = %v", hosts)
	}
	if r.sources[0].Timeout != DefaultKeyFetchTimeout || r.backoffMax != 30*time.Second {
		t.Fatalf("defaults: timeout %s, backoff cap %s", r.sources[0].Timeout, r.backoffMax)
	}
}

// TestVerifierDefaultStatusCache: without WithStatusCache a verifier with
// issuers configured holds its own empty cache, so it fails closed.
func TestVerifierDefaultStatusCache(t *testing.T) {
	t.Parallel()
	h := newStatusHarness(t)
	v, err := NewVerifier(h.config(), h.keys, &fakeCache{check: func(context.Context, string, time.Time) (bool, error) { return false, nil }}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(h.iv.Now, 0)
	v.now = func() time.Time { return now }
	requireInstanceDenial(t, v.Verify(t.Context(), h.request(h.mint(scitt.StatusActive, -1))), codeStatusStale)
}

type recStatusObserver struct {
	mu   sync.Mutex
	seen []string
}

func (o *recStatusObserver) IssuerStatusRefresh(_, result string, _ time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, result)
}

func (o *recStatusObserver) results() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.seen...)
}
