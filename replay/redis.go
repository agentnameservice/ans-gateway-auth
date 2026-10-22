package replay

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/redis/go-redis/v9"
)

const (
	// DefaultRedisTimeout bounds each connect, write, read and pool wait when
	// RedisConfig.Timeout is zero.
	DefaultRedisTimeout = 500 * time.Millisecond
	// RedisPoolSize caps connections to the store. It is also the number of
	// consecutive dial failures after which pool waits fail fast.
	RedisPoolSize = 64
	// RedisSampleInterval is how often INFO is sampled into Stats.
	RedisSampleInterval = 15 * time.Second
	// resetGrace matches the SDK's replay retention grace (iat + skew + 5 s), so
	// the fail-closed window after a keyspace loss covers every proof the lost
	// keyspace could have held, including one with iat one skew in the future.
	resetGrace = 5 * time.Second
	// sentinelKey holds "<created_unix_ms>:<random>"; its absence proves the
	// keyspace was lost.
	sentinelKey = "ans-authz:epoch"
	// jtiKeyPrefix namespaces the proof identifiers next to the sentinel, so a
	// store ACL can be limited to ~ans-authz:* .
	jtiKeyPrefix        = "ans-authz:jti:"
	sentinelRandomBytes = 8
	noEvictionPolicy    = "noeviction"
	opCheckAndStore     = "check_and_store"
	opInfo              = "info"
	backendErrorLogGap  = time.Minute
	minTTL              = time.Millisecond
	infoFieldParts      = 2
)

// RedisConfig configures the shared replay backend: one standalone Redis 6.2+
// instance dedicated to replay protection, with maxmemory set and
// maxmemory-policy noeviction.
type RedisConfig struct {
	Addr     string
	Username string
	// Password is resolved by the caller at startup (the service reads it from
	// an environment variable) and never serialized.
	Password string //nolint:gosec // G117: runtime credential, not a hardcoded secret
	DB       int
	// TLS connects with TLS 1.3 or newer.
	TLS bool
	// Timeout bounds each connect, write, read and pool wait, as a single
	// attempt; zero selects DefaultRedisTimeout.
	Timeout time.Duration
	// PoPSkew is the verifier's proof skew. After a keyspace loss every replica
	// fails closed for 2*PoPSkew + 5 s.
	PoPSkew time.Duration
}

func (c RedisConfig) validate() error {
	if c.Addr == "" {
		return errors.New("replay: redis: addr is required")
	}
	if c.PoPSkew <= 0 {
		return errors.New("replay: redis: popSkew must be positive")
	}
	if c.Timeout < 0 {
		return errors.New("replay: redis: timeout must not be negative")
	}
	return nil
}

func (c RedisConfig) timeout() time.Duration {
	if c.Timeout == 0 {
		return DefaultRedisTimeout
	}
	return c.Timeout
}

// options builds the client options: every network step is a single attempt
// bounded by Timeout, and the request context bounds the whole call.
func (c RedisConfig) options() *redis.Options {
	t := c.timeout()
	o := &redis.Options{
		Addr:                  c.Addr,
		Username:              c.Username,
		Password:              c.Password,
		DB:                    c.DB,
		DialTimeout:           t,
		ReadTimeout:           t,
		WriteTimeout:          t,
		PoolTimeout:           t,
		PoolSize:              RedisPoolSize,
		DialerRetries:         1,
		MaxRetries:            -1,
		ContextTimeoutEnabled: true,
	}
	if c.TLS {
		o.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	return o
}

// redisInfo fetches the INFO document; a test seam replaces the client call.
type redisInfo func(ctx context.Context) (string, error)

// RedisOption configures a Redis backend.
type RedisOption func(*Redis)

// WithRedisLogger sets the logger for rate-limited backend errors.
func WithRedisLogger(l *slog.Logger) RedisOption {
	return func(r *Redis) { r.logger = l }
}

func withRedisClock(now func() time.Time) RedisOption {
	return func(r *Redis) { r.now = now }
}

func withRedisInfo(fn redisInfo) RedisOption {
	return func(r *Redis) { r.info = fn }
}

func withRedisDialer(d func(ctx context.Context, network, addr string) (net.Conn, error)) RedisOption {
	return func(r *Redis) { r.dialer = d }
}

func withRedisSampleInterval(d time.Duration) RedisOption {
	return func(r *Redis) { r.sampleEvery = d }
}

// Redis is the shared replay cache. Every CheckAndStore is one pipelined
// round trip: SET NX PX for the proof identifier followed by GET of the
// keyspace sentinel, in that order, so a flush before or between the two
// commands is always detected.
type Redis struct {
	client      *redis.Client
	obs         Observer
	logger      *slog.Logger
	now         func() time.Time
	info        redisInfo
	dialer      func(ctx context.Context, network, addr string) (net.Conn, error)
	window      time.Duration
	sampleEvery time.Duration

	mu      sync.Mutex
	stats   Stats
	runID   string
	lastLog map[string]time.Time

	stop     context.CancelFunc
	sampling chan struct{}
}

// NewRedis connects to the store, enforces its guard rails (maxmemory set,
// maxmemory-policy noeviction, appendonly on), establishes the keyspace
// sentinel and starts the INFO sampler. A fresh or flushed store opens the
// fail-closed window.
func NewRedis(ctx context.Context, cfg RedisConfig, obs Observer, opts ...RedisOption) (*Redis, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if obs == nil {
		obs = NoopObserver{}
	}
	r := &Redis{
		obs:         obs,
		logger:      slog.New(slog.DiscardHandler),
		now:         time.Now,
		window:      2*cfg.PoPSkew + resetGrace,
		sampleEvery: RedisSampleInterval,
		stats:       Stats{Backend: BackendRedis},
		lastLog:     make(map[string]time.Time),
	}
	for _, opt := range opts {
		opt(r)
	}
	o := cfg.options()
	if r.dialer != nil {
		o.Dialer = r.dialer
	}
	r.client = redis.NewClient(o)
	if r.info == nil {
		r.info = func(ctx context.Context) (string, error) { return r.client.Info(ctx).Result() }
	}
	if err := r.start(ctx); err != nil {
		_ = r.client.Close()
		return nil, err
	}
	return r, nil
}

func (r *Redis) start(ctx context.Context) error {
	if err := r.refreshInfo(ctx); err != nil {
		return fmt.Errorf("replay: redis: %w", err)
	}
	if err := r.checkGuards(); err != nil {
		return err
	}
	if _, err := r.ensureSentinel(ctx); err != nil {
		return fmt.Errorf("replay: redis: sentinel: %w", err)
	}
	samplerCtx, cancel := context.WithCancel(context.Background())
	r.stop = cancel
	r.sampling = make(chan struct{})
	go r.sample(samplerCtx)
	return nil
}

// checkGuards rejects a store that cannot refuse writes (maxmemory 0), that
// would evict replay records silently (any policy but noeviction) or that
// would lose them at a restart (appendonly off).
func (r *Redis) checkGuards() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stats.MaxMemory == 0 {
		return errors.New("replay: redis: maxmemory is 0 (unlimited); set maxmemory so the store refuses writes instead of growing without bound")
	}
	if r.stats.EvictionPolicy != noEvictionPolicy {
		return fmt.Errorf("replay: redis: maxmemory-policy is %q; replay protection requires noeviction", r.stats.EvictionPolicy)
	}
	if !r.stats.AOFEnabled {
		return errors.New("replay: redis: appendonly is off; replay records would not survive a restart")
	}
	return nil
}

// driftError reports a guard rail that held at startup and has since been
// changed on the store.
func (r *Redis) driftError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stats.EvictionPolicy != noEvictionPolicy {
		return fmt.Errorf("maxmemory-policy drifted to %q", r.stats.EvictionPolicy)
	}
	if !r.stats.AOFEnabled {
		return errors.New("appendonly drifted to off")
	}
	return nil
}

// CheckAndStore implements Cache.
func (r *Redis) CheckAndStore(ctx context.Context, key string, exp time.Time) (bool, error) {
	start := r.now()
	seen, err := r.checkAndStore(ctx, key, exp, start)
	r.obs.ReplayBackend(opCheckAndStore, r.now().Sub(start), err)
	if err != nil {
		return false, err
	}
	return seen, nil
}

func (r *Redis) checkAndStore(ctx context.Context, key string, exp time.Time, now time.Time) (bool, error) {
	if err := r.driftError(); err != nil {
		return false, r.failure(ErrUnavailable, err)
	}
	ttl := max(exp.Sub(now), minTTL)
	var setCmd *redis.BoolCmd
	var getCmd *redis.StringCmd
	_, _ = r.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		setCmd = p.SetNX(ctx, jtiKeyPrefix+key, 1, ttl)
		getCmd = p.Get(ctx, sentinelKey)
		return nil
	})
	if err := setCmd.Err(); err != nil {
		if redis.IsOOMError(err) {
			return false, r.failure(ErrFull, err)
		}
		return false, r.failure(ErrUnavailable, err)
	}
	sentinel, err := getCmd.Result()
	switch {
	case errors.Is(err, redis.Nil):
		return false, r.keyspaceLost(ctx)
	case err != nil:
		return false, r.failure(ErrUnavailable, err)
	}
	window, ok := r.windowFor(sentinel, now)
	switch {
	case !ok:
		until, err := r.sentinelUnreadable(ctx)
		if err != nil {
			return false, r.failure(ErrUnavailable, err)
		}
		return false, r.failClosed(until)
	case window.open:
		return false, r.failClosed(window.until)
	}
	return !setCmd.Val(), nil
}

// keyspaceLost records the loss, re-creates the sentinel and fails closed for
// the window that the new sentinel defines.
func (r *Redis) keyspaceLost(ctx context.Context) error {
	r.mu.Lock()
	r.stats.KeyspaceResets++
	r.mu.Unlock()
	r.logLimited(ctx, "replay store lost its keyspace (flush or restart without persistence); every replica fails closed for the replay window",
		slog.Duration("window", r.window))
	until, err := r.ensureSentinel(ctx)
	if err != nil {
		return r.failure(ErrUnavailable, err)
	}
	return r.failClosed(until)
}

// ensureSentinel writes a fresh sentinel if none exists and returns the end of
// the fail-closed window implied by the sentinel that is now in place. A
// sentinel this version cannot read is replaced.
func (r *Redis) ensureSentinel(ctx context.Context) (time.Time, error) {
	now := r.now()
	value, err := newSentinelValue(now)
	if err != nil {
		return time.Time{}, err
	}
	created, err := r.client.SetNX(ctx, sentinelKey, value, 0).Result()
	if err != nil {
		return time.Time{}, fmt.Errorf("set sentinel: %w", err)
	}
	current := value
	if !created {
		if current, err = r.client.Get(ctx, sentinelKey).Result(); err != nil {
			return time.Time{}, fmt.Errorf("read sentinel: %w", err)
		}
	}
	window, ok := r.windowFor(current, now)
	if !ok {
		return r.sentinelUnreadable(ctx)
	}
	return r.recordWindow(window.until), nil
}

// sentinelUnreadable replaces a sentinel in another format, or one stamped
// more than a window ahead of this clock, with a fresh value and opens one
// window from now, so the store heals instead of failing closed for good.
func (r *Redis) sentinelUnreadable(ctx context.Context) (time.Time, error) {
	r.logLimited(ctx, "replay store sentinel is unreadable; replacing it and failing closed for the replay window",
		slog.Duration("window", r.window))
	now := r.now()
	value, err := newSentinelValue(now)
	if err != nil {
		return time.Time{}, err
	}
	if err := r.client.Set(ctx, sentinelKey, value, 0).Err(); err != nil {
		return time.Time{}, fmt.Errorf("replace sentinel: %w", err)
	}
	return r.recordWindow(now.Add(r.window)), nil
}

// sentinelWindow is a readable sentinel's fail-closed window.
type sentinelWindow struct {
	until time.Time
	open  bool
}

// windowFor interprets a sentinel. The second result is false for a value in
// another format or created more than one window ahead of now.
func (r *Redis) windowFor(sentinel string, now time.Time) (sentinelWindow, bool) {
	ms, _, ok := strings.Cut(sentinel, ":")
	if !ok {
		return sentinelWindow{}, false
	}
	n, err := strconv.ParseInt(ms, 10, 64)
	if err != nil {
		return sentinelWindow{}, false
	}
	created := time.UnixMilli(n)
	if created.After(now.Add(r.window)) {
		return sentinelWindow{}, false
	}
	until := created.Add(r.window)
	return sentinelWindow{until: until, open: now.Before(until)}, true
}

// recordWindow publishes the latest window end in Stats and returns it.
func (r *Redis) recordWindow(until time.Time) time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if until.After(r.stats.KeyspaceResetUntil) {
		r.stats.KeyspaceResetUntil = until
	}
	return until
}

func (r *Redis) failClosed(until time.Time) error {
	r.recordWindow(until)
	return &pop.ProofError{
		Type:    pop.ErrReplayCacheFull,
		Message: "replay cache keyspace reset",
		Cause:   &KeyspaceResetError{Until: until},
	}
}

// failure wraps a backend fault as the SDK error the verifier maps, with kind
// (ErrFull or ErrUnavailable) and the backend's own error both reachable
// through errors.Is and errors.As. Capacity and the caller's own cancellation
// are not backend failures and are not logged.
func (r *Redis) failure(kind, err error) error {
	message := "replay cache unavailable"
	switch {
	case errors.Is(kind, ErrFull):
		message = "replay cache full"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
	default:
		r.logLimited(context.Background(), "replay store call failed", slog.String("error", err.Error()))
	}
	return &pop.ProofError{Type: pop.ErrReplayCacheFull, Message: message, Cause: fmt.Errorf("%w: %w", kind, err)}
}

func newSentinelValue(now time.Time) (string, error) {
	random := make([]byte, sentinelRandomBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("sentinel randomness: %w", err)
	}
	return strconv.FormatInt(now.UnixMilli(), 10) + ":" + hex.EncodeToString(random), nil
}

// sample refreshes Stats until the backend is closed.
func (r *Redis) sample(ctx context.Context) {
	defer close(r.sampling)
	ticker := time.NewTicker(r.sampleEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.refreshInfo(ctx)
		}
	}
}

// refreshInfo issues INFO (every section, so Redis 6.2 is supported) and
// records memory, policy, eviction, persistence and restart state.
func (r *Redis) refreshInfo(ctx context.Context) error {
	start := r.now()
	doc, err := r.info(ctx)
	r.obs.ReplayBackend(opInfo, r.now().Sub(start), err)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.stats.Up = false
		return fmt.Errorf("info: %w", err)
	}
	fields := parseInfo(doc)
	r.stats.Up = true
	r.stats.UsedMemory = infoInt(fields, "used_memory")
	r.stats.MaxMemory = infoInt(fields, "maxmemory")
	r.stats.EvictionPolicy = fields["maxmemory_policy"]
	r.stats.EvictedKeys = infoInt(fields, "evicted_keys")
	r.stats.AOFEnabled = fields["aof_enabled"] == "1"
	if runID := fields["run_id"]; runID != "" {
		if r.runID != "" && runID != r.runID {
			r.stats.Restarts++
		}
		r.runID = runID
	}
	return nil
}

func parseInfo(doc string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if parts := strings.SplitN(line, ":", infoFieldParts); len(parts) == infoFieldParts {
			fields[parts[0]] = parts[1]
		}
	}
	return fields
}

func infoInt(fields map[string]string, key string) int64 {
	n, _ := strconv.ParseInt(fields[key], 10, 64)
	return n
}

// Stats implements Cache. A fail-closed window that has elapsed is reported
// as closed.
func (r *Redis) Stats() Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stats
	if !st.KeyspaceResetUntil.IsZero() && !r.now().Before(st.KeyspaceResetUntil) {
		st.KeyspaceResetUntil = time.Time{}
	}
	return st
}

// Close stops the sampler and closes the client.
func (r *Redis) Close() error {
	if r.stop != nil {
		r.stop()
		<-r.sampling
	}
	return r.client.Close()
}

// logLimited emits one ERROR per message per minute.
func (r *Redis) logLimited(ctx context.Context, msg string, attrs ...slog.Attr) {
	now := r.now()
	r.mu.Lock()
	last, ok := r.lastLog[msg]
	if ok && now.Sub(last) < backendErrorLogGap {
		r.mu.Unlock()
		return
	}
	r.lastLog[msg] = now
	r.mu.Unlock()
	r.logger.LogAttrs(ctx, slog.LevelError, msg, attrs...)
}
