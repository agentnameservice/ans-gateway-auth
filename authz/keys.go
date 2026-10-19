package authz

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

const (
	// DefaultKeyFetchTimeout bounds one root-key fetch when KeySource.Timeout
	// is zero.
	DefaultKeyFetchTimeout = time.Second
	// FailureCooldown is the minimum interval between refresh attempts,
	// measured from the start of the previous attempt.
	FailureCooldown = 30 * time.Second
	// SuccessCooldown is the minimum interval between refresh attempts after a
	// successful one, whether the keyring or a source's own background
	// refresher performed it.
	SuccessCooldown = 5 * time.Minute
	// waitMargin is the part of a caller's remaining budget that is never spent
	// waiting for a refresh, so the request can still be answered afterwards.
	waitMargin = 100 * time.Millisecond
)

// KeySource is one transparency log's trusted keys with optional refresh
// hooks; the verifier binary supplies its per-log key store's methods.
type KeySource struct {
	// Name labels the source in telemetry and status; it must be unique.
	Name string
	// Lookup resolves kids against the source's current snapshot. Required.
	Lookup scitt.KeyLookup
	// Refresh fetches new keys. Nil means the source is static.
	Refresh func(ctx context.Context) error
	// LastRefreshed reports the source's own last successful refresh, so a
	// background refresher's success also satisfies the success cooldown.
	LastRefreshed func() *time.Time
	// KeyCount reports the number of trusted keys for status and telemetry.
	KeyCount func() int
	// Timeout bounds one Refresh call; zero selects DefaultKeyFetchTimeout.
	Timeout time.Duration
}

// SourceStatus is the point-in-time view of one KeySource.
type SourceStatus struct {
	Name        string
	Keys        int
	LastSuccess *time.Time
	LastFailure *time.Time
	LastError   string
}

type sourceState struct {
	lastSuccess time.Time
	lastFailure time.Time
	lastError   string
}

// refreshRun is one in-flight fetch; ok is written before done is closed. all
// makes the run refresh every refreshable source regardless of freshness.
type refreshRun struct {
	done chan struct{}
	ok   bool
	all  bool
}

// Keyring is a scitt.KeyLookup over several KeySources with single-flight,
// cooldown-gated refresh on demand.
type Keyring struct {
	obs     Observer
	sources []KeySource
	now     func() time.Time
	maxWait time.Duration

	mu          sync.Mutex
	inflight    *refreshRun
	lastAttempt time.Time
	states      []sourceState
}

// NewKeyring validates the sources and returns a Keyring. A nil Observer
// selects NoopObserver.
func NewKeyring(obs Observer, sources ...KeySource) (*Keyring, error) {
	if len(sources) == 0 {
		return nil, errors.New("authz: keyring needs at least one key source")
	}
	if obs == nil {
		obs = NoopObserver{}
	}
	k := &Keyring{
		obs:     obs,
		sources: make([]KeySource, 0, len(sources)),
		now:     time.Now,
		states:  make([]sourceState, len(sources)),
	}
	names := make(map[string]struct{}, len(sources))
	for _, s := range sources {
		if s.Name == "" {
			return nil, errors.New("authz: key source needs a name")
		}
		if s.Lookup == nil {
			return nil, fmt.Errorf("authz: key source %q has no lookup", s.Name)
		}
		if _, dup := names[s.Name]; dup {
			return nil, fmt.Errorf("authz: duplicate key source name %q", s.Name)
		}
		names[s.Name] = struct{}{}
		if s.Timeout <= 0 {
			s.Timeout = DefaultKeyFetchTimeout
		}
		if s.Refresh != nil && s.Timeout > k.maxWait {
			k.maxWait = s.Timeout
		}
		k.sources = append(k.sources, s)
	}
	return k, nil
}

// Get implements scitt.KeyLookup: the first source holding the kid wins, and
// a miss everywhere is the SDK's unknown-key-ID error.
func (k *Keyring) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	for i := range k.sources {
		if tk, err := k.sources[i].Lookup.Get(kid); err == nil && tk != nil {
			return tk, nil
		}
	}
	return nil, &scitt.SignatureError{Type: scitt.SigErrUnknownKeyID, Kid: kid, Message: "unknown key ID"}
}

// RefreshFor refreshes the stale refreshable sources on behalf of a request
// whose kid is unknown. One fetch runs at a time, on a background context
// bounded by each source's Timeout, so a cancelled caller cannot fail it for
// others. It reports true only when a fetch completed successfully while this
// caller waited; a caller never waits past min(remaining budget - waitMargin,
// the largest source Timeout), and inside a cooldown it returns false at once.
// Cooldowns are per source: a log that failed while another succeeded stays
// eligible once FailureCooldown has passed.
func (k *Keyring) RefreshFor(ctx context.Context) bool {
	run := k.joinOrStart()
	if run == nil {
		return false
	}
	wait := k.waitBudget(ctx)
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-run.done:
		return run.ok
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// RunPeriodic refreshes every refreshable source each interval until ctx
// ends, ignoring cooldowns, so scheduled refreshes report through the
// Observer and Status like on-demand ones. It joins an in-flight on-demand
// run instead of starting a second one.
func (k *Keyring) RunPeriodic(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			k.refreshAll(ctx)
		}
	}
}

func (k *Keyring) refreshAll(ctx context.Context) {
	k.mu.Lock()
	run := k.inflight
	if run == nil {
		if k.maxWait == 0 {
			k.mu.Unlock()
			return
		}
		run = k.startLocked(true)
	}
	k.mu.Unlock()
	select {
	case <-run.done:
	case <-ctx.Done():
	}
}

// Status reports every source; LastSuccess includes refreshes the source's
// own background refresher performed.
func (k *Keyring) Status() []SourceStatus {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]SourceStatus, len(k.sources))
	for i := range k.sources {
		s := &k.sources[i]
		st := SourceStatus{Name: s.Name, Keys: keyCount(s), LastError: k.states[i].lastError}
		if success := k.effectiveSuccessLocked(i); !success.IsZero() {
			st.LastSuccess = &success
		}
		if failure := k.states[i].lastFailure; !failure.IsZero() {
			st.LastFailure = &failure
		}
		out[i] = st
	}
	return out
}

// joinOrStart returns the in-flight run, starts one when no cooldown applies,
// or returns nil when nothing should run.
func (k *Keyring) joinOrStart() *refreshRun {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.inflight != nil {
		return k.inflight
	}
	if k.maxWait == 0 || k.inCooldownLocked() {
		return nil
	}
	return k.startLocked(false)
}

func (k *Keyring) startLocked(all bool) *refreshRun {
	run := &refreshRun{done: make(chan struct{}), all: all}
	k.inflight = run
	k.lastAttempt = k.now()
	go k.fetch(run)
	return run
}

// inCooldownLocked reports whether a failure cooldown is running or every
// refreshable source succeeded within SuccessCooldown.
func (k *Keyring) inCooldownLocked() bool {
	now := k.now()
	if !k.lastAttempt.IsZero() && now.Sub(k.lastAttempt) < FailureCooldown {
		return true
	}
	return len(k.staleLocked(now)) == 0
}

// staleLocked lists the refreshable sources that never succeeded or whose
// last success, including the source's own background refreshes, is older
// than SuccessCooldown.
func (k *Keyring) staleLocked(now time.Time) []int {
	var stale []int
	for i := range k.sources {
		if k.sources[i].Refresh == nil {
			continue
		}
		success := k.effectiveSuccessLocked(i)
		if success.IsZero() || now.Sub(success) >= SuccessCooldown {
			stale = append(stale, i)
		}
	}
	return stale
}

// effectiveSuccessLocked is the later of the keyring's own record and the
// source's LastRefreshed.
func (k *Keyring) effectiveSuccessLocked(i int) time.Time {
	success := k.states[i].lastSuccess
	if lr := k.sources[i].LastRefreshed; lr != nil {
		if t := lr(); t != nil && t.After(success) {
			success = *t
		}
	}
	return success
}

func (k *Keyring) waitBudget(ctx context.Context) time.Duration {
	wait := k.maxWait
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := deadline.Sub(k.now()) - waitMargin; remaining < wait {
			wait = remaining
		}
	}
	return wait
}

// fetch refreshes the selected sources concurrently (the stale ones, or all
// of them for a periodic run), records the outcome and releases the waiters.
// Observers are notified before the release so a caller that saw the result
// also sees its telemetry.
func (k *Keyring) fetch(run *refreshRun) {
	k.mu.Lock()
	targets := k.staleLocked(k.now())
	if run.all {
		targets = targets[:0]
		for i := range k.sources {
			if k.sources[i].Refresh != nil {
				targets = append(targets, i)
			}
		}
	}
	k.mu.Unlock()

	results := make([]error, len(k.sources))
	var wg sync.WaitGroup
	for _, i := range targets {
		s := &k.sources[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
			defer cancel()
			results[i] = s.Refresh(ctx)
		}()
	}
	wg.Wait()
	run.ok = k.record(targets, results)
	for _, i := range targets {
		s := &k.sources[i]
		k.obs.KeyRefresh(s.Name, keyCount(s), results[i])
	}
	close(run.done)
}

// record stores the outcome of the attempted sources and reports whether any
// of them refreshed successfully.
func (k *Keyring) record(targets []int, results []error) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	ok := false
	for _, i := range targets {
		if err := results[i]; err != nil {
			k.states[i].lastFailure = now
			k.states[i].lastError = err.Error()
			continue
		}
		ok = true
		k.states[i].lastSuccess = now
	}
	k.inflight = nil
	return ok
}

func keyCount(s *KeySource) int {
	if s.KeyCount == nil {
		return 0
	}
	return s.KeyCount()
}
