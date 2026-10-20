package authz

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

func mustKeyring(t *testing.T, obs Observer, sources ...KeySource) *Keyring {
	t.Helper()
	k, err := NewKeyring(obs, sources...)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	return k
}

func TestNewKeyringErrors(t *testing.T) {
	t.Parallel()
	lookup := newMapLookup()
	tests := []struct {
		name    string
		sources []KeySource
		wantErr string
	}{
		{name: "no sources", wantErr: "at least one"},
		{name: "nil lookup", sources: []KeySource{{Name: "a"}}, wantErr: "no lookup"},
		{name: "empty name", sources: []KeySource{{Lookup: lookup}}, wantErr: "name"},
		{name: "duplicate name", sources: []KeySource{
			{Name: "a", Lookup: lookup}, {Name: "a", Lookup: lookup},
		}, wantErr: "duplicate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k, err := NewKeyring(NoopObserver{}, tc.sources...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewKeyring() = %v, %v; want error containing %q", k, err, tc.wantErr)
			}
		})
	}
}

func TestNewKeyringDefaults(t *testing.T) {
	t.Parallel()
	k, err := NewKeyring(nil, KeySource{Name: "a", Lookup: newMapLookup(), Refresh: func(context.Context) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if got := k.sources[0].Timeout; got != DefaultKeyFetchTimeout {
		t.Fatalf("Timeout defaulted to %v, want %v", got, DefaultKeyFetchTimeout)
	}
	if k.obs == nil {
		t.Fatal("nil observer must default to NoopObserver")
	}
}

func TestKeyringGet(t *testing.T) {
	t.Parallel()
	first := newMapLookup(trustedKey("first", 1))
	second := newMapLookup(trustedKey("second", 2), trustedKey("second-too", 1))
	k := mustKeyring(t, NoopObserver{}, KeySource{Name: "one", Lookup: first}, KeySource{Name: "two", Lookup: second})

	tests := []struct {
		name     string
		kid      [4]byte
		wantName string
	}{
		{name: "first source wins", kid: kidOf(1), wantName: "first"},
		{name: "falls through to the second source", kid: kidOf(2), wantName: "second"},
		{name: "unknown everywhere", kid: kidOf(9)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tk, err := k.Get(tc.kid)
			if tc.wantName != "" {
				if err != nil || tk.Name != tc.wantName {
					t.Fatalf("Get() = %v, %v; want key %q", tk, err, tc.wantName)
				}
				return
			}
			var sigErr *scitt.SignatureError
			if !errors.As(err, &sigErr) {
				t.Fatalf("Get() error %T %v, want *scitt.SignatureError", err, err)
			}
			if sigErr.Type != scitt.SigErrUnknownKeyID || sigErr.Kid != tc.kid {
				t.Fatalf("Get() error = %+v, want SigErrUnknownKeyID for kid %x", sigErr, tc.kid)
			}
		})
	}
}

func TestKeyringRefreshForSingleFlight(t *testing.T) {
	const (
		timeout       = 50 * time.Millisecond
		fetchDuration = 300 * time.Millisecond
		callers       = 200
	)
	var started, finished atomic.Int32
	obs := &recObserver{}
	baseline := runtime.NumGoroutine()
	k := mustKeyring(t, obs, KeySource{
		Name:    "slow",
		Lookup:  newMapLookup(),
		Timeout: timeout,
		Refresh: func(context.Context) error {
			started.Add(1)
			time.Sleep(fetchDuration)
			finished.Add(1)
			return nil
		},
	})

	results := make([]bool, callers)
	elapsed := make([]time.Duration, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			begin := time.Now()
			results[i] = k.RefreshFor(t.Context())
			elapsed[i] = time.Since(begin)
		}()
	}
	wg.Wait()
	for i := range callers {
		if results[i] {
			t.Fatalf("caller %d reported a refresh, but the fetch outlives every caller's wait", i)
		}
		if elapsed[i] >= fetchDuration {
			t.Fatalf("caller %d waited %v, must give up at the source timeout (%v)", i, elapsed[i], timeout)
		}
	}
	if got := started.Load(); got != 1 {
		t.Fatalf("%d fetches started, want exactly one", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (finished.Load() != 1 || runtime.NumGoroutine() > baseline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := finished.Load(); got != 1 {
		t.Fatalf("%d fetches finished, want 1", got)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		t.Fatalf("%d goroutines alive after the fetch, baseline %d", got, baseline)
	}
	refreshes := obs.refreshRecords()
	if len(refreshes) != 1 || refreshes[0].name != "slow" || refreshes[0].err != nil {
		t.Fatalf("observer saw %+v, want one successful refresh for slow", refreshes)
	}
}

func TestKeyringRefreshForCooldowns(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	var failing atomic.Bool
	obs := &recObserver{}
	k := mustKeyring(t, obs, KeySource{
		Name:   "tl",
		Lookup: newMapLookup(),
		Refresh: func(context.Context) error {
			attempts.Add(1)
			if failing.Load() {
				return errors.New("boom")
			}
			return nil
		},
	})
	clock := newFakeClock()
	k.now = clock.now
	start := clock.now()

	steps := []struct {
		name         string
		advance      time.Duration
		failing      bool
		want         bool
		wantAttempts int32
	}{
		{name: "first attempt fails", failing: true, want: false, wantAttempts: 1},
		{name: "inside the failure cooldown", advance: 10 * time.Second, failing: true, want: false, wantAttempts: 1},
		{name: "after the failure cooldown", advance: 21 * time.Second, want: true, wantAttempts: 2},
		{name: "inside the success cooldown", advance: time.Minute, want: false, wantAttempts: 2},
		{name: "after the success cooldown", advance: 5 * time.Minute, want: true, wantAttempts: 3},
	}
	for _, s := range steps {
		clock.advance(s.advance)
		failing.Store(s.failing)
		if got := k.RefreshFor(t.Context()); got != s.want {
			t.Fatalf("%s: RefreshFor() = %v, want %v", s.name, got, s.want)
		}
		if got := attempts.Load(); got != s.wantAttempts {
			t.Fatalf("%s: %d attempts, want %d", s.name, got, s.wantAttempts)
		}
	}

	status := k.Status()
	if len(status) != 1 {
		t.Fatalf("Status() has %d entries, want 1", len(status))
	}
	st := status[0]
	if st.Name != "tl" || st.LastError == nil || st.LastError.Error() != "boom" {
		t.Fatalf("Status() = %+v, want name tl and the last failure message", st)
	}
	if st.LastFailure == nil || !st.LastFailure.Equal(start) {
		t.Fatalf("LastFailure = %v, want %v", st.LastFailure, start)
	}
	wantSuccess := start.Add(10*time.Second + 21*time.Second + time.Minute + 5*time.Minute)
	if st.LastSuccess == nil || !st.LastSuccess.Equal(wantSuccess) {
		t.Fatalf("LastSuccess = %v, want %v", st.LastSuccess, wantSuccess)
	}
	refreshes := obs.refreshRecords()
	if len(refreshes) != 3 || refreshes[0].err == nil || refreshes[1].err != nil || refreshes[2].err != nil {
		t.Fatalf("observer saw %+v, want one failure then two successes", refreshes)
	}
}

func TestKeyringRefreshForHonoursSourceLastRefreshed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		lastRefresh  func(now time.Time) *time.Time
		want         bool
		wantAttempts int32
	}{
		{name: "fresh background refresh", lastRefresh: func(now time.Time) *time.Time {
			t := now.Add(-time.Minute)
			return &t
		}, want: false, wantAttempts: 0},
		{name: "stale background refresh", lastRefresh: func(now time.Time) *time.Time {
			t := now.Add(-10 * time.Minute)
			return &t
		}, want: true, wantAttempts: 1},
		{name: "never refreshed", lastRefresh: func(time.Time) *time.Time { return nil }, want: true, wantAttempts: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var attempts atomic.Int32
			clock := newFakeClock()
			k := mustKeyring(t, NoopObserver{}, KeySource{
				Name:          "tl",
				Lookup:        newMapLookup(),
				Refresh:       func(context.Context) error { attempts.Add(1); return nil },
				LastRefreshed: func() *time.Time { return tc.lastRefresh(clock.now()) },
			})
			k.now = clock.now
			if got := k.RefreshFor(t.Context()); got != tc.want {
				t.Fatalf("RefreshFor() = %v, want %v", got, tc.want)
			}
			if got := attempts.Load(); got != tc.wantAttempts {
				t.Fatalf("%d attempts, want %d", got, tc.wantAttempts)
			}
			st := k.Status()[0]
			if tc.wantAttempts == 0 && (st.LastSuccess == nil || !st.LastSuccess.Equal(clock.now().Add(-time.Minute))) {
				t.Fatalf("Status().LastSuccess = %v, want the source's own last refresh", st.LastSuccess)
			}
		})
	}
}

func TestKeyringRefreshForSkipsStaticSourcesInCooldownCheck(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	clock := newFakeClock()
	fresh := clock.now().Add(-time.Minute)
	k := mustKeyring(t, NoopObserver{},
		KeySource{Name: "static", Lookup: newMapLookup()},
		KeySource{
			Name:          "tl",
			Lookup:        newMapLookup(),
			Refresh:       func(context.Context) error { attempts.Add(1); return nil },
			LastRefreshed: func() *time.Time { return &fresh },
		},
	)
	k.now = clock.now
	if k.RefreshFor(t.Context()) || attempts.Load() != 0 {
		t.Fatalf("RefreshFor() refreshed (%d attempts) although the only refreshable source is fresh", attempts.Load())
	}
}

func TestKeyringRefreshForWaitBudget(t *testing.T) {
	t.Parallel()
	const fetchDuration = 400 * time.Millisecond
	tests := []struct {
		name       string
		budget     time.Duration
		maxElapsed time.Duration
	}{
		{name: "deadline shorter than the source timeout", budget: 150 * time.Millisecond, maxElapsed: 150 * time.Millisecond},
		{name: "deadline below the wait margin returns at once", budget: 50 * time.Millisecond, maxElapsed: 50 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var attempts atomic.Int32
			finished := make(chan struct{})
			k := mustKeyring(t, NoopObserver{}, KeySource{
				Name:   "tl",
				Lookup: newMapLookup(),
				Refresh: func(ctx context.Context) error {
					defer close(finished)
					attempts.Add(1)
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(fetchDuration):
						return nil
					}
				},
			})
			ctx, cancel := context.WithTimeout(t.Context(), tc.budget)
			defer cancel()
			begin := time.Now()
			got := k.RefreshFor(ctx)
			elapsed := time.Since(begin)
			if got {
				t.Fatal("RefreshFor() = true, the fetch cannot finish inside the budget")
			}
			if elapsed >= tc.maxElapsed {
				t.Fatalf("RefreshFor() took %v, must return before %v", elapsed, tc.maxElapsed)
			}
			<-finished
			if attempts.Load() != 1 {
				t.Fatalf("%d attempts, want the fetch to start even when the caller cannot wait", attempts.Load())
			}
		})
	}
}

func TestKeyringRefreshForCancelledCaller(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var sawLiveContext atomic.Bool
	k := mustKeyring(t, NoopObserver{}, KeySource{
		Name:   "tl",
		Lookup: newMapLookup(),
		Refresh: func(ctx context.Context) error {
			sawLiveContext.Store(ctx.Err() == nil)
			<-release
			return nil
		},
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if k.RefreshFor(ctx) {
		t.Fatal("a cancelled caller must not report a refresh")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && !sawLiveContext.Load() {
		time.Sleep(5 * time.Millisecond)
	}
	if !sawLiveContext.Load() {
		t.Fatal("the fetch must run on a context the caller cannot cancel")
	}
}

func TestKeyringRefreshForSourceTimeout(t *testing.T) {
	t.Parallel()
	const timeout = 20 * time.Millisecond
	obs := &recObserver{}
	k := mustKeyring(t, obs, KeySource{
		Name:    "tl",
		Lookup:  newMapLookup(),
		Timeout: timeout,
		Refresh: func(ctx context.Context) error {
			if _, ok := ctx.Deadline(); !ok {
				return errors.New("fetch context carries no deadline")
			}
			<-ctx.Done()
			return ctx.Err()
		},
	})
	if k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() = true for a fetch that timed out")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(obs.refreshRecords()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	refreshes := obs.refreshRecords()
	if len(refreshes) != 1 || !errors.Is(refreshes[0].err, context.DeadlineExceeded) {
		t.Fatalf("observer saw %+v, want one deadline-exceeded refresh", refreshes)
	}
	st := k.Status()[0]
	if st.LastFailure == nil || st.LastError == nil || st.LastSuccess != nil {
		t.Fatalf("Status() = %+v, want a failure and no success", st)
	}
}

func TestKeyringRefreshForGainsKey(t *testing.T) {
	t.Parallel()
	lookup := newMapLookup()
	key := trustedKey("tl", 7)
	obs := &recObserver{}
	k := mustKeyring(t, obs, KeySource{
		Name:     "tl",
		Lookup:   lookup,
		Refresh:  func(context.Context) error { lookup.add(key); return nil },
		KeyCount: lookup.Len,
	})
	if _, err := k.Get(key.Kid); err == nil {
		t.Fatal("Get() found the key before any refresh")
	}
	if !k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() = false, want true after a successful fetch")
	}
	tk, err := k.Get(key.Kid)
	if err != nil || tk.Name != "tl" {
		t.Fatalf("Get() after refresh = %v, %v", tk, err)
	}
	st := k.Status()[0]
	if st.Keys != 1 || st.LastSuccess == nil || st.LastFailure != nil || st.LastError != nil {
		t.Fatalf("Status() = %+v, want 1 key and a clean success", st)
	}
	refreshes := obs.refreshRecords()
	if len(refreshes) != 1 || refreshes[0].name != "tl" || refreshes[0].keys != 1 || refreshes[0].err != nil {
		t.Fatalf("observer saw %+v, want one success reporting 1 key", refreshes)
	}
}

func TestKeyringRefreshForWithoutRefreshFuncs(t *testing.T) {
	t.Parallel()
	obs := &recObserver{}
	k := mustKeyring(t, obs, KeySource{Name: "static", Lookup: newMapLookup(trustedKey("static", 1))})
	begin := time.Now()
	if k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() = true with nothing to refresh")
	}
	if time.Since(begin) > 100*time.Millisecond {
		t.Fatal("RefreshFor() waited although no source can refresh")
	}
	if got := obs.refreshRecords(); len(got) != 0 {
		t.Fatalf("observer saw %+v, want nothing", got)
	}
	st := k.Status()[0]
	if st.Name != "static" || st.Keys != 0 || st.LastSuccess != nil || st.LastFailure != nil {
		t.Fatalf("Status() = %+v, want an untouched static source", st)
	}
}

func TestKeyringRefreshForPartialFailure(t *testing.T) {
	t.Parallel()
	obs := &recObserver{}
	k := mustKeyring(t, obs,
		KeySource{Name: "good", Lookup: newMapLookup(), Refresh: func(context.Context) error { return nil }},
		KeySource{Name: "bad", Lookup: newMapLookup(), Refresh: func(context.Context) error { return errors.New("down") }},
		KeySource{Name: "static", Lookup: newMapLookup()},
	)
	if !k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() = false, want true when at least one source refreshed")
	}
	refreshes := obs.refreshRecords()
	if len(refreshes) != 2 {
		t.Fatalf("observer saw %d refreshes, want 2 (static sources are skipped)", len(refreshes))
	}
	byName := map[string]error{}
	for _, r := range refreshes {
		byName[r.name] = r.err
	}
	if byName["good"] != nil || byName["bad"] == nil {
		t.Fatalf("observer saw %+v", refreshes)
	}
	status := k.Status()
	if status[0].LastSuccess == nil || status[0].LastFailure != nil {
		t.Fatalf("good status = %+v", status[0])
	}
	if status[1].LastSuccess != nil || status[1].LastFailure == nil || status[1].LastError == nil || status[1].LastError.Error() != "down" {
		t.Fatalf("bad status = %+v", status[1])
	}
	if status[2].LastSuccess != nil || status[2].LastFailure != nil {
		t.Fatalf("static status = %+v", status[2])
	}
}

func TestKeyringRefreshForRetriesOnlyFailedSource(t *testing.T) {
	t.Parallel()
	obs := &recObserver{}
	var failing atomic.Bool
	failing.Store(true)
	k := mustKeyring(t, obs,
		KeySource{Name: "good", Lookup: newMapLookup(), Refresh: func(context.Context) error { return nil }},
		KeySource{Name: "bad", Lookup: newMapLookup(), Refresh: func(context.Context) error {
			if failing.Load() {
				return errors.New("down")
			}
			return nil
		}},
	)
	clock := newFakeClock()
	k.now = clock.now
	if !k.RefreshFor(t.Context()) {
		t.Fatal("first RefreshFor() = false")
	}
	if k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() inside the failure cooldown must be false")
	}
	clock.advance(FailureCooldown + time.Second)
	failing.Store(false)
	if !k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() after the failure cooldown = false, want a retry of the failed source")
	}
	refreshes := obs.refreshRecords()
	if len(refreshes) != 3 || refreshes[2].name != "bad" || refreshes[2].err != nil {
		t.Fatalf("observer saw %+v, want good+bad then bad alone", refreshes)
	}
	clock.advance(time.Second)
	if k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() with every source fresh must be false")
	}
	clock.advance(SuccessCooldown)
	if !k.RefreshFor(t.Context()) {
		t.Fatal("RefreshFor() after the success cooldown = false")
	}
	if got := len(obs.refreshRecords()); got != 5 {
		t.Fatalf("observer saw %d refreshes, want 5 (both sources stale again)", got)
	}
}

func TestKeyringRunPeriodic(t *testing.T) {
	t.Parallel()
	obs := &recObserver{}
	var calls atomic.Int32
	k := mustKeyring(t, obs,
		KeySource{Name: "tl", Lookup: newMapLookup(), Refresh: func(context.Context) error { calls.Add(1); return nil }},
		KeySource{Name: "static", Lookup: newMapLookup()},
	)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		k.RunPeriodic(ctx, 5*time.Millisecond)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for calls.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("periodic refresh ran %d times", calls.Load())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	for _, r := range obs.refreshRecords() {
		if r.name != "tl" || r.err != nil {
			t.Fatalf("observer saw %+v", r)
		}
	}
	if st := k.Status(); st[0].LastSuccess == nil {
		t.Fatalf("status after periodic refresh = %+v", st[0])
	}

	static := mustKeyring(t, obs, KeySource{Name: "only-static", Lookup: newMapLookup()})
	staticCtx, staticCancel := context.WithCancel(t.Context())
	staticCancel()
	static.RunPeriodic(staticCtx, time.Millisecond)
}
