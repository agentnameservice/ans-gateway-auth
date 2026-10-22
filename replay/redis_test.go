package replay

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/alicebob/miniredis/v2"
)

const (
	testSkew   = 10 * time.Second
	testWindow = 2*testSkew + resetGrace

	infoGood = "# Server\r\nrun_id:run-1\r\n# Memory\r\nused_memory:1024\r\nmaxmemory:4096\r\nmaxmemory_policy:noeviction\r\n" +
		"# Persistence\r\naof_enabled:1\r\n# Stats\r\nevicted_keys:0\r\n"
	infoDrift = "# Server\r\nrun_id:run-2\r\n# Memory\r\nused_memory:2048\r\nmaxmemory:4096\r\nmaxmemory_policy:allkeys-lru\r\n" +
		"# Persistence\r\naof_enabled:0\r\n# Stats\r\nevicted_keys:3\r\n"
	infoAOFOff = "# Server\r\nrun_id:run-1\r\n# Memory\r\nused_memory:1024\r\nmaxmemory:4096\r\nmaxmemory_policy:noeviction\r\n" +
		"# Persistence\r\naof_enabled:0\r\n# Stats\r\nevicted_keys:0\r\n"
	infoNoLimit  = "# Memory\r\nmaxmemory:0\r\nmaxmemory_policy:noeviction\r\n"
	infoEvicting = "# Memory\r\nmaxmemory:4096\r\nmaxmemory_policy:volatile-lru\r\n"
	oomMessage   = "OOM command not allowed when used memory > 'maxmemory'."
)

// clock is a settable time source shared by a test's backends.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// infoSeam stands in for the INFO round trip.
type infoSeam struct {
	mu  sync.Mutex
	doc string
	err error
}

func (s *infoSeam) fetch(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc, s.err
}

func (s *infoSeam) set(doc string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doc, s.err = doc, err
}

// recObserver records backend observations.
type recObserver struct {
	mu   sync.Mutex
	errs map[string][]error
}

func (o *recObserver) ReplayBackend(op string, _ time.Duration, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.errs == nil {
		o.errs = make(map[string][]error)
	}
	o.errs[op] = append(o.errs[op], err)
}

// last reports whether op was observed and the error its latest call carried.
func (o *recObserver) last(op string) (bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	errs := o.errs[op]
	if len(errs) == 0 {
		return false, nil
	}
	return true, errs[len(errs)-1]
}

// recordHandler keeps slog records.
type recordHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordHandler) WithGroup(string) slog.Handler      { return h }
func (h *recordHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

func startMini(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	m, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

// seedOldSentinel plants a sentinel created long ago, so no window is open.
func seedOldSentinel(t *testing.T, m *miniredis.Miniredis, clk *clock) {
	t.Helper()
	if err := m.Set(sentinelKey, strconv.FormatInt(clk.now().Add(-time.Hour).UnixMilli(), 10)+":seed"); err != nil {
		t.Fatal(err)
	}
}

func testConfig(addr string) RedisConfig {
	return RedisConfig{Addr: addr, Timeout: 500 * time.Millisecond, PoPSkew: testSkew}
}

type backend struct {
	r    *Redis
	info *infoSeam
	obs  *recObserver
	log  *recordHandler
}

func newBackend(t *testing.T, m *miniredis.Miniredis, clk *clock, extra ...RedisOption) *backend {
	t.Helper()
	b := &backend{info: &infoSeam{doc: infoGood}, obs: &recObserver{}, log: &recordHandler{}}
	opts := append([]RedisOption{
		withRedisClock(clk.now), withRedisInfo(b.info.fetch), WithRedisLogger(slog.New(b.log)),
	}, extra...)
	r, err := NewRedis(context.Background(), testConfig(m.Addr()), b.obs, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	b.r = r
	return b
}

func (b *backend) check(t *testing.T, key string, exp time.Time) (bool, error) {
	t.Helper()
	return b.r.CheckAndStore(context.Background(), key, exp)
}

func TestRedisConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cfg  RedisConfig
		want string
	}{
		{name: "valid", cfg: RedisConfig{Addr: "127.0.0.1:6379", PoPSkew: time.Minute}},
		{name: "missing addr", cfg: RedisConfig{PoPSkew: time.Minute}, want: "addr is required"},
		{name: "zero skew", cfg: RedisConfig{Addr: "127.0.0.1:6379"}, want: "popSkew must be positive"},
		{name: "negative timeout", cfg: RedisConfig{Addr: "127.0.0.1:6379", PoPSkew: time.Minute, Timeout: -1}, want: "timeout must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("validate() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate() = %v, want %q", err, tt.want)
			}
			if _, err := NewRedis(context.Background(), tt.cfg, nil); err == nil {
				t.Fatal("NewRedis accepted an invalid config")
			}
		})
	}
}

func TestRedisConfigOptions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		cfg         RedisConfig
		wantTimeout time.Duration
		wantTLS     bool
	}{
		{name: "defaults", cfg: RedisConfig{Addr: "a:1", PoPSkew: time.Minute}, wantTimeout: DefaultRedisTimeout},
		{name: "explicit timeout and tls", cfg: RedisConfig{Addr: "a:1", PoPSkew: time.Minute, Timeout: 250 * time.Millisecond, TLS: true, Username: "u", Password: "p", DB: 3}, wantTimeout: 250 * time.Millisecond, wantTLS: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			o := tt.cfg.options()
			for name, got := range map[string]time.Duration{"dial": o.DialTimeout, "read": o.ReadTimeout, "write": o.WriteTimeout, "pool": o.PoolTimeout} {
				if got != tt.wantTimeout {
					t.Errorf("%s timeout = %s, want %s", name, got, tt.wantTimeout)
				}
			}
			if o.DialerRetries != 1 || o.MaxRetries != -1 || !o.ContextTimeoutEnabled || o.PoolSize != RedisPoolSize {
				t.Errorf("retry/pool options = %+v", o)
			}
			if o.Addr != tt.cfg.Addr || o.Username != tt.cfg.Username || o.Password != tt.cfg.Password || o.DB != tt.cfg.DB {
				t.Errorf("connection options = %+v", o)
			}
			if tt.wantTLS != (o.TLSConfig != nil) {
				t.Fatalf("TLSConfig present = %v, want %v", o.TLSConfig != nil, tt.wantTLS)
			}
			if tt.wantTLS && o.TLSConfig.MinVersion != tls.VersionTLS13 {
				t.Fatalf("TLS MinVersion = %x", o.TLSConfig.MinVersion)
			}
		})
	}
}

func TestNewRedisGuards(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  string
		err  error
		want string
	}{
		{name: "healthy store", doc: infoGood},
		{name: "no memory limit", doc: infoNoLimit, want: "maxmemory is 0"},
		{name: "evicting policy", doc: infoEvicting, want: "requires noeviction"},
		{name: "appendonly off", doc: infoAOFOff, want: "appendonly is off"},
		{name: "info unavailable", err: errors.New("connection refused"), want: "info: connection refused"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := startMini(t)
			clk := newClock()
			seedOldSentinel(t, m, clk)
			seam := &infoSeam{doc: tt.doc, err: tt.err}
			r, err := NewRedis(context.Background(), testConfig(m.Addr()), nil, withRedisClock(clk.now), withRedisInfo(seam.fetch))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("NewRedis = %v", err)
				}
				_ = r.Close()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewRedis = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRedisCheckAndStore(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	seedOldSentinel(t, m, clk)
	b := newBackend(t, m, clk)
	exp := clk.now().Add(testSkew)

	if seen, err := b.check(t, "jti-a", exp); err != nil || seen {
		t.Fatalf("first use: seen=%v err=%v", seen, err)
	}
	if seen, err := b.check(t, "jti-a", exp); err != nil || !seen {
		t.Fatalf("replay: seen=%v err=%v", seen, err)
	}
	if seen, err := b.check(t, "jti-b", exp); err != nil || seen {
		t.Fatalf("other key: seen=%v err=%v", seen, err)
	}
	if ttl := m.TTL(jtiKeyPrefix + "jti-a"); ttl < 9*time.Second || ttl > testSkew {
		t.Fatalf("ttl = %s, want about %s", ttl, testSkew)
	}
	m.FastForward(testSkew + time.Second)
	if seen, err := b.check(t, "jti-a", exp); err != nil || seen {
		t.Fatalf("after expiry: seen=%v err=%v", seen, err)
	}
	if _, err := b.check(t, "jti-past", clk.now().Add(-time.Minute)); err != nil {
		t.Fatalf("expiry in the past must clamp, got %v", err)
	}
	if st := b.r.Stats(); st.Backend != "redis" || !st.Up || st.MaxMemory != 4096 || st.EvictionPolicy != noEvictionPolicy || !st.AOFEnabled || st.KeyspaceResets != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if ok, err := b.obs.last(opCheckAndStore); !ok || err != nil {
		t.Fatalf("observer last = %v, %v", ok, err)
	}
}

func TestRedisBackendErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		message  string
		wantKind error
		notKind  error
		wantMsg  string
	}{
		{name: "out of memory is capacity", message: oomMessage, wantKind: ErrFull, notKind: ErrUnavailable, wantMsg: "replay cache full"},
		{name: "other errors are outages", message: "ERR boom", wantKind: ErrUnavailable, notKind: ErrFull, wantMsg: "replay cache unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := startMini(t)
			clk := newClock()
			seedOldSentinel(t, m, clk)
			b := newBackend(t, m, clk)
			m.SetError(tt.message)
			_, err := b.check(t, "jti", clk.now().Add(testSkew))
			var pe *pop.ProofError
			if !errors.As(err, &pe) || pe.Type != pop.ErrReplayCacheFull || pe.Message != tt.wantMsg {
				t.Fatalf("err = %v, want ProofError %s %q", err, pop.ErrReplayCacheFull, tt.wantMsg)
			}
			if !errors.Is(err, tt.wantKind) || errors.Is(err, tt.notKind) {
				t.Fatalf("err = %v, want kind %v and not %v", err, tt.wantKind, tt.notKind)
			}
			if !strings.Contains(err.Error(), tt.message) && !strings.Contains(pe.Cause.Error(), tt.message) {
				t.Fatalf("backend text missing from cause: %v", pe.Cause)
			}
			if ok, got := b.obs.last(opCheckAndStore); !ok || got == nil {
				t.Fatal("observer did not see the failure")
			}
			m.SetError("")
			if seen, err := b.check(t, "jti", clk.now().Add(testSkew)); err != nil || seen {
				t.Fatalf("after recovery: seen=%v err=%v", seen, err)
			}
		})
	}
}

func assertKeyspaceReset(t *testing.T, err error, wantUntil time.Time) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want keyspace reset matching ErrUnavailable", err)
	}
	var kre *KeyspaceResetError
	if !errors.As(err, &kre) || !kre.Until.Equal(wantUntil) {
		t.Fatalf("err = %v, want KeyspaceResetError until %s", err, wantUntil)
	}
	var pe *pop.ProofError
	if !errors.As(err, &pe) || pe.Type != pop.ErrReplayCacheFull {
		t.Fatalf("err = %v, want the SDK replay cache error type", err)
	}
}

func TestRedisKeyspaceReset(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	seedOldSentinel(t, m, clk)
	b := newBackend(t, m, clk)
	exp := func() time.Time { return clk.now().Add(testSkew) }

	if _, err := b.check(t, "before", exp()); err != nil {
		t.Fatal(err)
	}
	m.FlushAll()
	_, err := b.check(t, "after", exp())
	assertKeyspaceReset(t, err, clk.now().Add(testWindow))
	if st := b.r.Stats(); st.KeyspaceResets != 1 || !st.KeyspaceResetUntil.Equal(clk.now().Add(testWindow)) {
		t.Fatalf("stats = %+v", st)
	}
	if !m.Exists(sentinelKey) {
		t.Fatal("sentinel was not re-created")
	}
	clk.advance(testWindow / 2)
	_, err = b.check(t, "midway", exp())
	assertKeyspaceReset(t, err, clk.now().Add(testWindow/2))
	if st := b.r.Stats(); st.KeyspaceResets != 1 {
		t.Fatalf("a present sentinel must not count as another reset: %+v", st)
	}
	clk.advance(testWindow/2 + time.Second)
	if seen, checkErr := b.check(t, "after-window", exp()); checkErr != nil || seen {
		t.Fatalf("after the window: seen=%v err=%v", seen, checkErr)
	}
	if st := b.r.Stats(); !st.KeyspaceResetUntil.IsZero() {
		t.Fatalf("an elapsed window must not be reported: %+v", st)
	}

	m.FlushAll()
	_, err = b.check(t, "second-flush", exp())
	assertKeyspaceReset(t, err, clk.now().Add(testWindow))
	if st := b.r.Stats(); st.KeyspaceResets != 2 {
		t.Fatalf("stats after second flush = %+v", st)
	}
	if got := b.log.count(); got != 1 {
		t.Fatalf("keyspace-loss logs = %d, want 1 within the rate limit", got)
	}
}

func TestRedisFreshStoreFailsClosedForWindow(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	b := newBackend(t, m, clk)
	until := clk.now().Add(testWindow)
	if st := b.r.Stats(); !st.KeyspaceResetUntil.Equal(until) {
		t.Fatalf("fresh store must open the window: %+v", st)
	}
	_, err := b.check(t, "jti", clk.now().Add(testSkew))
	assertKeyspaceReset(t, err, until)
	clk.advance(testWindow + time.Second)
	// The denied proof's identifier was still recorded (SET runs before the
	// sentinel read), so its replay stays denied; a new identifier is admitted.
	if seen, err := b.check(t, "jti", clk.now().Add(testSkew)); err != nil || !seen {
		t.Fatalf("recorded identifier after the window: seen=%v err=%v", seen, err)
	}
	if seen, err := b.check(t, "jti-2", clk.now().Add(testSkew)); err != nil || seen {
		t.Fatalf("new identifier after the window: seen=%v err=%v", seen, err)
	}
}

func TestRedisUnreadableSentinelHeals(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value func(*clock) string
	}{
		{name: "garbage", value: func(*clock) string { return "garbage" }},
		{name: "non-numeric timestamp", value: func(*clock) string { return "soon:abcd" }},
		{name: "timestamp beyond one window ahead", value: func(clk *clock) string {
			return strconv.FormatInt(clk.now().Add(2*testWindow).UnixMilli(), 10) + ":x"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := startMini(t)
			clk := newClock()
			seedOldSentinel(t, m, clk)
			b := newBackend(t, m, clk)
			bad := tt.value(clk)
			if err := m.Set(sentinelKey, bad); err != nil {
				t.Fatal(err)
			}
			_, err := b.check(t, "jti", clk.now().Add(testSkew))
			assertKeyspaceReset(t, err, clk.now().Add(testWindow))
			if got, err := m.Get(sentinelKey); err != nil || got == bad {
				t.Fatalf("sentinel not replaced: %q, %v", got, err)
			}
			if got := b.log.count(); got != 1 {
				t.Fatalf("logs = %d, want one unreadable-sentinel line", got)
			}
			clk.advance(testWindow + time.Second)
			if seen, err := b.check(t, "jti-2", clk.now().Add(testSkew)); err != nil || seen {
				t.Fatalf("after the window: seen=%v err=%v", seen, err)
			}
		})
	}
}

func TestNewRedisReplacesUnreadableSentinel(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	if err := m.Set(sentinelKey, "garbage"); err != nil {
		t.Fatal(err)
	}
	b := newBackend(t, m, clk)
	if st := b.r.Stats(); !st.KeyspaceResetUntil.Equal(clk.now().Add(testWindow)) {
		t.Fatalf("startup with an unreadable sentinel must open one window: %+v", st)
	}
	if got, err := m.Get(sentinelKey); err != nil || got == "garbage" {
		t.Fatalf("sentinel not replaced: %q, %v", got, err)
	}
}

func TestRedisSharedSentinel(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	seedOldSentinel(t, m, clk)
	a := newBackend(t, m, clk)
	b := newBackend(t, m, clk)
	exp := func() time.Time { return clk.now().Add(testSkew) }

	for name, be := range map[string]*backend{"a": a, "b": b} {
		if _, err := be.check(t, "warm-"+name, exp()); err != nil {
			t.Fatalf("%s before flush: %v", name, err)
		}
	}
	m.FlushAll()
	_, err := a.check(t, "x", exp())
	assertKeyspaceReset(t, err, clk.now().Add(testWindow))
	_, err = b.check(t, "y", exp())
	assertKeyspaceReset(t, err, clk.now().Add(testWindow))
	if a.r.Stats().KeyspaceResets+b.r.Stats().KeyspaceResets != 1 {
		t.Fatalf("exactly one replica should record the loss: a=%d b=%d", a.r.Stats().KeyspaceResets, b.r.Stats().KeyspaceResets)
	}

	clk.advance(testWindow / 2)
	c := newBackend(t, m, clk)
	_, err = c.check(t, "z", exp())
	assertKeyspaceReset(t, err, clk.now().Add(testWindow/2))

	clk.advance(testWindow/2 + time.Second)
	for name, be := range map[string]*backend{"a": a, "b": b, "c": c} {
		if seen, err := be.check(t, "done-"+name, exp()); err != nil || seen {
			t.Fatalf("%s after the window: seen=%v err=%v", name, seen, err)
		}
	}
}

func waitStats(t *testing.T, r *Redis, ok func(Stats) bool) Stats {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := r.Stats()
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("stats never reached the expected state: %+v", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRedisSamplerAndPolicyDrift(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	seedOldSentinel(t, m, clk)
	b := newBackend(t, m, clk, withRedisSampleInterval(5*time.Millisecond))
	exp := clk.now().Add(testSkew)

	b.info.set(infoDrift, nil)
	st := waitStats(t, b.r, func(s Stats) bool { return s.EvictionPolicy == "allkeys-lru" })
	if st.Restarts != 1 || st.AOFEnabled || st.EvictedKeys != 3 || st.UsedMemory != 2048 || !st.Up {
		t.Fatalf("drifted stats = %+v", st)
	}
	_, err := b.check(t, "jti", exp)
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "drifted") {
		t.Fatalf("drift must fail closed: %v", err)
	}

	b.info.set("", errors.New("timeout"))
	waitStats(t, b.r, func(s Stats) bool { return !s.Up })
	if ok, err := b.obs.last(opInfo); !ok || err == nil {
		t.Fatal("observer did not see the INFO failure")
	}

	b.info.set(infoGood, nil)
	st = waitStats(t, b.r, func(s Stats) bool { return s.Up && s.EvictionPolicy == noEvictionPolicy })
	if st.Restarts != 2 {
		t.Fatalf("run_id change back must count: %+v", st)
	}
	if seen, err := b.check(t, "jti", exp); err != nil || seen {
		t.Fatalf("after restoring the policy: seen=%v err=%v", seen, err)
	}
}

func TestRedisAOFDriftFailsClosed(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	seedOldSentinel(t, m, clk)
	b := newBackend(t, m, clk, withRedisSampleInterval(5*time.Millisecond))
	b.info.set(infoAOFOff, nil)
	waitStats(t, b.r, func(s Stats) bool { return !s.AOFEnabled })
	_, err := b.check(t, "jti", clk.now().Add(testSkew))
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "appendonly") {
		t.Fatalf("appendonly drift must fail closed: %v", err)
	}
}

func TestNewRedisBoundedByTimeout(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	tests := []struct {
		name string
		opts []RedisOption
	}{
		{name: "server accepts but never answers"},
		{name: "dialer blocks", opts: []RedisOption{withRedisDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := RedisConfig{Addr: lis.Addr().String(), Timeout: 150 * time.Millisecond, PoPSkew: testSkew}
			start := time.Now()
			_, err := NewRedis(context.Background(), cfg, nil, tt.opts...)
			if err == nil {
				t.Fatal("NewRedis succeeded against a stalled store")
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Fatalf("NewRedis took %s, want a single bounded attempt", elapsed)
			}
		})
	}
}

func TestRedisCancelledContext(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	seedOldSentinel(t, m, clk)
	b := newBackend(t, m, clk)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := b.r.CheckAndStore(ctx, "jti", clk.now().Add(testSkew))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want the cancellation wrapped as unavailable", err)
	}
	if got := b.log.count(); got != 0 {
		t.Fatalf("logs = %d; the caller's cancellation is not a backend failure", got)
	}
}

func TestRedisClose(t *testing.T) {
	t.Parallel()
	m := startMini(t)
	clk := newClock()
	seedOldSentinel(t, m, clk)
	seam := &infoSeam{doc: infoGood}
	r, err := NewRedis(context.Background(), testConfig(m.Addr()), nil, withRedisClock(clk.now), withRedisInfo(seam.fetch))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if _, err := r.CheckAndStore(context.Background(), "jti", clk.now().Add(testSkew)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("after Close: %v", err)
	}
}

func TestKeyspaceResetErrorText(t *testing.T) {
	t.Parallel()
	until := time.Date(2026, 10, 13, 12, 30, 0, 0, time.UTC)
	err := &KeyspaceResetError{Until: until}
	if got := err.Error(); !strings.Contains(got, "failing closed until 2026-10-13T12:30:00Z") {
		t.Fatalf("Error() = %q", got)
	}
	NoopObserver{}.ReplayBackend(opInfo, 0, err)
}

func TestParseInfo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  string
		want map[string]string
	}{
		{name: "crlf with sections", doc: "# Memory\r\nmaxmemory:1\r\nmaxmemory_policy:noeviction\r\n", want: map[string]string{"maxmemory": "1", "maxmemory_policy": "noeviction"}},
		{name: "values containing colons keep the remainder", doc: "run_id:ab:cd\n", want: map[string]string{"run_id": "ab:cd"}},
		{name: "blank and malformed lines are skipped", doc: "\n\nnocolon\n# c\nk:v\n", want: map[string]string{"k": "v"}},
		{name: "empty", doc: "", want: map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseInfo(tt.doc)
			if len(got) != len(tt.want) {
				t.Fatalf("parseInfo = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Fatalf("parseInfo[%s] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
