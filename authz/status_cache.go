package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// The gateway-owned issuer status cache. With instanceMode.maxStatusAge set,
// the verifier keeps each allowed issuer's TL status token itself, refreshed
// in the background every maxStatusAge/2, so revocation latency depends on
// the gateway alone: at most maxStatusAge plus the TL's publish delay,
// whatever status token a client chooses to present. A presented token is
// used only when it is newer (a later iat) than the cached one and verifies
// under the TL root keys; it then replaces the cache entry. No request ever
// calls the TL.

// Results a StatusObserver receives.
const (
	StatusRefreshSuccess  = "success"
	StatusRefreshFailure  = "failure"
	StatusRefreshTerminal = "terminal"
)

const (
	// statusRefreshBackoffInitial and statusRefreshBackoffMax bound the
	// retry wait after a failed background refresh; the cap never exceeds
	// the regular interval.
	statusRefreshBackoffInitial = time.Second
	statusRefreshBackoffMax     = 30 * time.Second
	// statusRefreshJitter is the largest fraction the regular interval is
	// shortened by, so replicas do not refresh in lockstep. It only ever
	// shortens the wait, keeping the refresh within maxStatusAge/2.
	statusRefreshJitter = 0.2
	// statusRefreshDivisor sets the regular interval to maxStatusAge/2, so a
	// single missed refresh still leaves the cached token within the bound.
	statusRefreshDivisor = 2
)

// IssuerStatus is one issuer's newest known TL status.
type IssuerStatus struct {
	// AgentID is the issuer's ANS agent id, the cache key.
	AgentID string
	// Iat orders entries: a later iat replaces an earlier one.
	Iat int64
	// Terminal records that the TL reported the issuer REVOKED, EXPIRED or
	// superseded (410, or a signed terminal token); every request for it is
	// refused for the life of the process. Under ANS such an agent id does
	// not return to ACTIVE, and a later ACTIVE answer may be a stale replica
	// or a replayed response.
	Terminal bool
	// Raw is the status token as the TL signed it, for a shared store that
	// re-verifies; nil for a terminal entry learned from a 410.
	Raw []byte
	// Token is the verified token; nil for a terminal entry.
	Token *scitt.VerifiedStatusToken
}

// StatusCache holds the current IssuerStatus per issuer agent id. It has two
// write paths, kept apart so a client can never undo what the TL said:
//
//   - Install records the TL's own current answer, from the background
//     refresher only. It replaces a live entry unconditionally, so a terminal
//     answer replaces any live one, and never replaces a terminal entry.
//     Entries from the two clocks (a 410 dated by the gateway, a token dated
//     by the TL) are never compared.
//   - OfferPresented records a token a client presented after it verified.
//     It never creates an entry, never replaces a terminal one, and replaces
//     a live one only when its iat is later; it reports whether it did.
//
// The in-memory implementation serves one verifier process; a shared store
// can replace it, but must make each write a compare-and-set, since
// MemoryStatusCache relies on its lock for that.
type StatusCache interface {
	Get(agentID string) (IssuerStatus, bool)
	Install(s IssuerStatus)
	OfferPresented(s IssuerStatus) bool
}

// MemoryStatusCache is the in-memory StatusCache.
type MemoryStatusCache struct {
	mu      sync.RWMutex
	entries map[string]IssuerStatus
}

var _ StatusCache = (*MemoryStatusCache)(nil)

// NewMemoryStatusCache returns an empty in-memory cache.
func NewMemoryStatusCache() *MemoryStatusCache {
	return &MemoryStatusCache{entries: make(map[string]IssuerStatus)}
}

// Get implements StatusCache.
func (c *MemoryStatusCache) Get(agentID string) (IssuerStatus, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.entries[agentID]
	return s, ok
}

// Install implements StatusCache.
func (c *MemoryStatusCache) Install(s IssuerStatus) {
	if s.AgentID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, ok := c.entries[s.AgentID]; ok && cur.Terminal {
		return
	}
	c.entries[s.AgentID] = s
}

// OfferPresented implements StatusCache. The check and the write share one
// lock, so a terminal entry installed after the request read the cache still
// wins.
func (c *MemoryStatusCache) OfferPresented(s IssuerStatus) bool {
	if s.AgentID == "" || s.Terminal {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cur, ok := c.entries[s.AgentID]
	if !ok || cur.Terminal || s.Iat <= cur.Iat {
		return false
	}
	c.entries[s.AgentID] = s
	return true
}

// StatusObserver receives every background refresh outcome per issuer host:
// StatusRefreshSuccess, StatusRefreshFailure or StatusRefreshTerminal.
type StatusObserver interface {
	IssuerStatusRefresh(issuer, result string, at time.Time)
}

// StatusFetcher fetches an agent's status token from its TL;
// scitt.HTTPClient.FetchStatusToken is one.
type StatusFetcher func(ctx context.Context, agentID string) ([]byte, error)

// IssuerStatusSource is one issuer the refresher keeps warm.
type IssuerStatusSource struct {
	// Host is the issuer as allowedIssuers names it.
	Host string
	// AgentID is the issuer's ANS agent id.
	AgentID string
	// TL names the transparencyLogs entry whose keys must sign the issuer's
	// status token (issuers[].tl); a token another configured log signed is
	// refused.
	TL string
	// Fetch reads the status token from the issuer's TL.
	Fetch StatusFetcher
	// Timeout bounds one fetch; zero selects DefaultKeyFetchTimeout.
	Timeout time.Duration
}

// StatusRefresher fetches each issuer's status token in the background,
// verifies it with the same checks and keys as the request path, and offers
// it to the cache.
type StatusRefresher struct {
	cache   StatusCache
	keys    KeyProvider
	obs     StatusObserver
	logger  *slog.Logger
	sources []IssuerStatusSource
	byHost  map[string]int

	interval       time.Duration
	backoffInitial time.Duration
	backoffMax     time.Duration
	now            func() time.Time
}

// NewStatusRefresher validates its wiring. maxStatusAge sets the refresh
// interval (half of it). A nil observer or logger discards.
func NewStatusRefresher(cache StatusCache, keys KeyProvider, maxStatusAge time.Duration, obs StatusObserver,
	logger *slog.Logger, sources ...IssuerStatusSource) (*StatusRefresher, error) {
	switch {
	case cache == nil:
		return nil, errors.New("authz: status refresher needs a status cache")
	case keys == nil:
		return nil, errors.New("authz: status refresher needs a key provider")
	case maxStatusAge <= 0:
		return nil, errors.New("authz: status refresher needs a positive maxStatusAge")
	case len(sources) == 0:
		return nil, errors.New("authz: status refresher needs at least one issuer")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	r := &StatusRefresher{
		cache: cache, keys: keys, obs: obs, logger: logger, byHost: make(map[string]int, len(sources)),
		interval: maxStatusAge / statusRefreshDivisor, backoffInitial: statusRefreshBackoffInitial, now: time.Now,
	}
	r.backoffMax = min(statusRefreshBackoffMax, r.interval)
	for _, s := range sources {
		switch {
		case s.Host == "":
			return nil, errors.New("authz: status source needs a host")
		case s.AgentID == "":
			return nil, fmt.Errorf("authz: status source %q needs an agent id", s.Host)
		case s.TL == "":
			return nil, fmt.Errorf("authz: status source %q needs a transparency log", s.Host)
		case s.Fetch == nil:
			return nil, fmt.Errorf("authz: status source %q needs a fetch function", s.Host)
		}
		if _, dup := r.byHost[s.Host]; dup {
			return nil, fmt.Errorf("authz: duplicate status source %q", s.Host)
		}
		if s.Timeout <= 0 {
			s.Timeout = DefaultKeyFetchTimeout
		}
		// A UUID's case carries no meaning; the cache is keyed, and the TL
		// asked, by its canonical lower-case form.
		s.AgentID = strings.ToLower(s.AgentID)
		r.byHost[s.Host] = len(r.sources)
		r.sources = append(r.sources, s)
	}
	return r, nil
}

// Hosts lists the issuers the refresher serves, in configuration order.
func (r *StatusRefresher) Hosts() []string {
	hosts := make([]string, len(r.sources))
	for i, s := range r.sources {
		hosts[i] = s.Host
	}
	return hosts
}

// Refresh fetches, verifies and caches one issuer's status token. A 410 from
// the TL, or a validly signed REVOKED or EXPIRED token, caches a terminal
// entry and is not an error. Any other failure leaves the cache unchanged.
// A 410 is unsigned and trusted on the TL connection's TLS alone.
func (r *StatusRefresher) Refresh(ctx context.Context, host string) error {
	i, ok := r.byHost[host]
	if !ok {
		return fmt.Errorf("authz: no status source for issuer %q", host)
	}
	src := &r.sources[i]
	result, err := r.refresh(ctx, src)
	if r.obs != nil {
		r.obs.IssuerStatusRefresh(src.Host, result, r.now())
	}
	if err != nil {
		r.logger.WarnContext(ctx, "issuer status refresh failed", "issuer", src.Host, "agent_id", src.AgentID, "error", err)
		return err
	}
	if result == StatusRefreshTerminal {
		r.logger.WarnContext(ctx, "issuer status is revoked, expired or superseded at its TL (HTTP 410); if this issuer re-registered, update issuers[].agentId",
			"issuer", src.Host, "agent_id", src.AgentID)
	}
	return nil
}

func (r *StatusRefresher) refresh(ctx context.Context, src *IssuerStatusSource) (string, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, src.Timeout)
	defer cancel()
	raw, err := src.Fetch(fetchCtx, src.AgentID)
	now := r.now().Unix()
	var te *scitt.TransportError
	if errors.As(err, &te) && te.Type == scitt.TransportErrAgentTerminal {
		r.cache.Install(IssuerStatus{AgentID: src.AgentID, Iat: now, Terminal: true})
		return StatusRefreshTerminal, nil
	}
	if err != nil {
		return StatusRefreshFailure, fmt.Errorf("issuer %s: fetch status token: %w", src.Host, err)
	}
	st, err := scitt.VerifyStatusTokenAt(raw, r.keys, 0, now)
	if _, unknown := unknownKeyID(err); unknown && r.keys.RefreshFor(ctx) {
		st, err = scitt.VerifyStatusTokenAt(raw, r.keys, 0, now)
	}
	var tokErr *scitt.TokenError
	if errors.As(err, &tokErr) && tokErr.Type == scitt.TokenErrTerminalStatus {
		// The SDK checks the signature before the status, so this is a
		// configured TL's own statement. It withholds the payload, so the
		// agent id and host are not checked here (doing so needs a CBOR
		// decoder this module does not depend on directly): a wrong agent's
		// terminal token fails closed, no worse than the unsigned 410 above.
		// The entry is dated by our clock.
		r.cache.Install(IssuerStatus{AgentID: src.AgentID, Iat: now, Terminal: true})
		return StatusRefreshTerminal, nil
	}
	if err != nil {
		return StatusRefreshFailure, fmt.Errorf("issuer %s: status token: %w", src.Host, err)
	}
	if !holdsKey(r.keys, src.TL, st.KeyID) {
		return StatusRefreshFailure, fmt.Errorf("issuer %s: status token is not signed by transparency log %q", src.Host, src.TL)
	}
	if err := checkFetchedStatus(&st.Payload, src, now); err != nil {
		return StatusRefreshFailure, err
	}
	r.cache.Install(IssuerStatus{AgentID: src.AgentID, Iat: st.Payload.Iat, Raw: raw, Token: st})
	return StatusRefreshSuccess, nil
}

// checkFetchedStatus requires the token the TL served to be about this
// issuer, and not dated ahead of our clock, so it cannot pin the cache.
func checkFetchedStatus(p *scitt.StatusTokenPayload, src *IssuerStatusSource, now int64) error {
	if !strings.EqualFold(p.AgentID, src.AgentID) {
		return fmt.Errorf("issuer %s: status token names agent %q, want %q", src.Host, p.AgentID, src.AgentID)
	}
	name, err := verify.ParseAnsName(p.AnsName)
	if err != nil || name.Host != src.Host {
		return fmt.Errorf("issuer %s: status token names %q", src.Host, p.AnsName)
	}
	if p.Iat > now+boundedStatusIATSkew {
		return fmt.Errorf("issuer %s: status token iat %d is %ds ahead", src.Host, p.Iat, p.Iat-now)
	}
	return nil
}

// holdsKey reports whether the named key source holds kid, the key a status
// token verified under. A provider that cannot say (not a Keyring) fails
// closed: issuers[].tl cannot be enforced, so no token is trusted.
func holdsKey(keys KeyProvider, source string, kid [4]byte) bool {
	h, ok := keys.(interface{ HoldsKey(string, [4]byte) bool })
	return ok && h.HoldsKey(source, kid)
}

// firstWait is how long Run waits before an issuer's first refresh: at once
// when nothing live is cached, otherwise the jittered interval measured from
// the cached token's iat, not from Run, so a slow startup (a replay backend
// that took startupTimeout to come up) does not leave the startup token past
// maxStatusAge.
func (r *StatusRefresher) firstWait(agentID string) time.Duration {
	cached, ok := r.cache.Get(agentID)
	if !ok || cached.Terminal {
		return 0
	}
	// Compare before converting: an ancient iat's age overflows
	// time.Duration, and a far-future one is held to one interval.
	now, interval := r.now().Unix(), int64(r.interval/time.Second)
	if cached.Iat <= now-interval {
		return 0
	}
	age := max(now-cached.Iat, -interval)
	return max(0, r.jittered()-time.Duration(age)*time.Second)
}

// Run refreshes every issuer until ctx ends: one goroutine per issuer, each
// refreshing at once when nothing is cached for it, then every
// maxStatusAge/2 shortened by up to 20% jitter, and after a failure with
// exponential backoff capped at that interval. It never touches the request
// path.
func (r *StatusRefresher) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, s := range r.sources {
		wg.Go(func() { r.runOne(ctx, s.Host, s.AgentID) })
	}
	wg.Wait()
}

func (r *StatusRefresher) runOne(ctx context.Context, host, agentID string) {
	failures := 0
	timer := time.NewTimer(r.firstWait(agentID))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := r.Refresh(ctx, host); err != nil {
			failures++
			timer.Reset(r.backoff(failures))
			continue
		}
		failures = 0
		timer.Reset(r.jittered())
	}
}

// jittered is the regular interval shortened by a random 0-20%.
func (r *StatusRefresher) jittered() time.Duration {
	cut := time.Duration(rand.Float64() * statusRefreshJitter * float64(r.interval)) //nolint:gosec // jitter, not a secret
	return r.interval - cut
}

// backoff is the wait after the n-th consecutive failure.
func (r *StatusRefresher) backoff(n int) time.Duration {
	wait := r.backoffInitial
	for i := 1; i < n && wait < r.backoffMax; i++ {
		wait *= 2
	}
	return min(wait, r.backoffMax)
}

// cachedIssuerStatus picks the status token a cache-mode request is judged
// on. The presented token must verify under the cached root keys of the
// issuer's own transparency log (issuers[].tl; no on-demand refresh: no TL
// call on the request path), be unexpired, not
// lead our clock by more than 60 s, and name the issuer's configured agent.
// A terminal entry refuses at once, as does a REVOKED presented token.
// Until the first background fetch succeeds the issuer is status_stale.
// The newer of the cached and presented tokens wins and must be within
// maxStatusAge; a presented winner replaces the cache entry.
func (v *Verifier) cachedIssuerStatus(ctx context.Context, raw []byte, it *instanceToken,
	now int64) (*scitt.VerifiedStatusToken, error) {
	agentID := v.issuerAgents[it.claims.iss]
	presented, err := scitt.VerifyStatusTokenAt(raw, v.keys, 0, now)
	if err != nil {
		return nil, statusFailure(ctx, err, raw, it, agentID)
	}
	if tl := v.issuerLogs[it.claims.iss]; !holdsKey(v.keys, tl, presented.KeyID) {
		return nil, refuse(codeBadStatusToken, CategoryStatusInvalid, "status token is not signed by issuer "+
			echoValue(it.claims.iss)+"'s transparency log "+echoValue(tl))
	}
	if err := checkStatusClock(&presented.Payload, now, boundedStatusIATSkew); err != nil {
		return nil, err
	}
	if !strings.EqualFold(presented.Payload.AgentID, agentID) {
		return nil, refuse(codeIssMismatch, CategoryBindingFailed, "status token names agent "+
			echoValue(presented.Payload.AgentID)+", not issuer "+echoValue(it.claims.iss)+"'s configured agent")
	}
	cached, ok := v.statusCache.Get(agentID)
	switch {
	case !ok:
		return nil, refuse(codeStatusStale, CategoryStatusInvalid, "no status for issuer "+
			echoValue(it.claims.iss)+" from its transparency log yet")
	case cached.Terminal:
		return nil, refuse(codeRevoked, CategoryStatusInvalid, "issuer "+echoValue(it.claims.iss)+
			" is revoked, expired or superseded at its transparency log")
	}
	chosen, fromClient := cached.Token, false
	if presented.Payload.Iat > cached.Iat {
		chosen, fromClient = presented, true
	}
	p := &chosen.Payload
	if now >= p.Exp {
		return nil, refuse(codeStatusExpired, CategoryStatusInvalid, fmt.Sprintf("status token expired at %d", p.Exp))
	}
	// p.Iat < now-maxAge, not now-p.Iat > maxAge: the subtraction wraps for
	// an iat near the int64 minimum and would read as fresh.
	if maxAge := int64(v.cfg.InstanceMode.MaxStatusAge / time.Second); p.Iat < now-maxAge {
		return nil, refuse(codeStatusStale, CategoryStatusInvalid, fmt.Sprintf(
			"newest status token for issuer %s was issued at %d, over maxStatusAge %ds before %d",
			echoValue(it.claims.iss), p.Iat, maxAge, now))
	}
	if fromClient {
		v.statusCache.OfferPresented(IssuerStatus{AgentID: agentID, Iat: p.Iat, Raw: slices.Clone(raw), Token: chosen})
	}
	return chosen, nil
}
