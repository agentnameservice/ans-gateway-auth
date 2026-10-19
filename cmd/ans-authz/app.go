package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/config"
	"github.com/agentnameservice/ans-gateway-auth/extauthz"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteTimeout      = 10 * time.Second
	httpIdleTimeout       = 60 * time.Second
	httpShutdownTimeout   = 5 * time.Second
	startupBackoffInitial = 250 * time.Millisecond
	startupBackoffMax     = 2 * time.Second
	startupBackoffFactor  = 2
)

type lifecycle int32

const (
	stateStarting lifecycle = iota
	stateServing
	stateDraining
)

// app wires configuration into the verifier, the ext_authz server and the
// health, readiness and metrics endpoint.
type app struct {
	cfg     config.Config
	logger  *slog.Logger
	metrics *extauthz.Metrics
	keyring *authz.Keyring
	cache   replay.Cache
	server  *extauthz.Server

	// refreshable counts transparency logs with a baseURL, which the keyring
	// refreshes every keyRefreshInterval.
	refreshable int

	grpcLis net.Listener
	httpLis net.Listener
	httpSrv *http.Server

	state    atomic.Int32
	cancel   context.CancelFunc
	grpcDone chan error
	httpDone chan error
}

// newApp loads trust material (retrying transparency-log fetches until
// startupTimeout) and builds the verifier. Nothing listens yet.
func newApp(ctx context.Context, cfg config.Config, logger *slog.Logger) (*app, error) {
	a := &app{cfg: cfg, logger: logger, metrics: extauthz.NewMetrics()}

	sources := make([]authz.KeySource, 0, len(cfg.TransparencyLogs))
	for _, tl := range cfg.TransparencyLogs {
		store, refreshable, err := a.loadKeys(ctx, tl)
		if err != nil {
			return nil, err
		}
		src := authz.KeySource{
			Name:          tl.Name,
			Lookup:        store,
			LastRefreshed: store.LastRefreshed,
			KeyCount:      store.Len,
			Timeout:       tl.Timeout,
		}
		if refreshable {
			src.Refresh = store.DoRefresh
			a.refreshable++
		}
		sources = append(sources, src)
	}
	keyring, err := authz.NewKeyring(a.metrics, sources...)
	if err != nil {
		return nil, err
	}
	a.keyring = keyring

	a.cache, err = a.newReplayCache(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.buildServer(logger); err != nil {
		_ = a.cache.Close()
		return nil, err
	}
	return a, nil
}

// buildServer wires the verifier and the ext_authz server over the loaded
// keys and replay cache.
func (a *app) buildServer(logger *slog.Logger) error {
	verifier, err := authz.NewVerifier(a.cfg.Config, a.keyring, a.cache, a.metrics, logger)
	if err != nil {
		return err
	}
	if err := a.metrics.RegisterStatus(a.keyring, a.cache); err != nil {
		return fmt.Errorf("register status metrics: %w", err)
	}
	opts := []extauthz.Option{
		extauthz.WithLogger(logger),
		extauthz.WithMaxContentBytes(a.cfg.MaxContentBytes),
	}
	tlsCfg, err := serverTLS(a.cfg)
	if err != nil {
		return err
	}
	if tlsCfg != nil {
		opts = append(opts, extauthz.WithTLS(tlsCfg))
	}
	a.server = extauthz.NewServer(verifier, opts...)
	return nil
}

// serverTLS loads the gRPC listener's TLS material up front, so unusable
// certificates fail --check and startup instead of the first accept.
func serverTLS(cfg config.Config) (*tls.Config, error) {
	t := cfg.GRPC.TLS
	if t == nil {
		return nil, nil //nolint:nilnil // no TLS configured is a valid outcome
	}
	return extauthz.ServerTLS{CertFile: t.CertFile, KeyFile: t.KeyFile, ClientCAFile: t.ClientCAFile}.Config()
}

// loadKeys builds the key store for one transparency log. Pinned keys load
// immediately; a baseURL is fetched with retries until startupTimeout, and a
// failed fetch is fatal only when no pinned key is available either.
func (a *app) loadKeys(ctx context.Context, tl config.TransparencyLog) (*keyStore, bool, error) {
	pinned, err := scitt.NewKeyStore(tl.RootKeys)
	if err != nil {
		return nil, false, fmt.Errorf("transparency log %q: root keys: %w", tl.Name, err)
	}
	logger := a.logger.With("tl", tl.Name)
	if tl.BaseURL == "" {
		return newKeyStore(tl.Name, pinned, nil, logger), false, nil
	}
	clientOpts := []scitt.HTTPClientOption{scitt.WithTimeout(tl.Timeout)}
	if tl.AllowInsecure {
		clientOpts = append(clientOpts, scitt.WithAllowInsecureTransport())
	}
	client, err := scitt.NewHTTPClient(tl.BaseURL, clientOpts...)
	if err != nil {
		return nil, false, fmt.Errorf("transparency log %q: client: %w", tl.Name, err)
	}
	store := newKeyStore(tl.Name, pinned, client, logger)
	if pinned.IsEmpty() {
		if err := retryUntil(ctx, a.cfg.StartupTimeout, store.DoRefresh); err != nil {
			return nil, false, fmt.Errorf("transparency log %q: no root keys after %s: %w", tl.Name, a.cfg.StartupTimeout, err)
		}
	} else if err := store.DoRefresh(ctx); err != nil {
		logger.WarnContext(ctx, "initial root-key fetch failed, continuing with pinned keys", "error", err)
	}
	return store, true, nil
}

// retryUntil calls fn with exponential backoff until it succeeds, ctx ends or
// timeout elapses, and returns the last error.
func retryUntil(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	deadline := time.Now().Add(timeout)
	backoff := startupBackoffInitial
	for {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || ctx.Err() != nil {
			return err
		}
		wait := min(backoff, remaining)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		backoff = min(backoff*startupBackoffFactor, startupBackoffMax)
	}
}

func (a *app) newReplayCache(ctx context.Context) (replay.Cache, error) {
	switch a.cfg.Replay.Type {
	case config.ReplayTypeMemory:
		a.logger.WarnContext(ctx, "in-memory replay cache: valid for a single verifier replica only (ANS-6 section 7.6)",
			"max_entries", a.cfg.Replay.MaxEntries)
		return replay.NewMemory(ctx, a.cfg.Replay.MaxEntries, a.metrics), nil
	case config.ReplayTypeRedis:
		return a.newRedisCache(ctx)
	default:
		return nil, fmt.Errorf("replay backend %q is not supported", a.cfg.Replay.Type)
	}
}

// newRedisCache connects to the shared store, retrying until startupTimeout
// so a store that is still starting does not fail the verifier.
func (a *app) newRedisCache(ctx context.Context) (replay.Cache, error) {
	rc := a.cfg.Replay.Redis
	rcfg := replay.RedisConfig{
		Addr: rc.Addr, Username: rc.Username, DB: rc.DB, TLS: rc.TLS,
		Timeout: rc.Timeout, PoPSkew: a.cfg.PoPSkew,
	}
	if rc.PasswordEnv != "" {
		rcfg.Password = os.Getenv(rc.PasswordEnv)
	}
	var cache *replay.Redis
	err := retryUntil(ctx, a.cfg.StartupTimeout, func(ctx context.Context) error {
		c, err := replay.NewRedis(ctx, rcfg, a.metrics, replay.WithRedisLogger(a.logger))
		if err != nil {
			return err
		}
		cache = c
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("replay backend: %w", err)
	}
	a.logger.InfoContext(ctx, "shared replay cache connected", "addr", rc.Addr,
		"fail_closed_until", cache.Stats().KeyspaceResetUntil)
	return cache, nil
}

// Start binds the listeners and serves. It returns once both listeners are
// bound; Wait reports how serving ended.
func (a *app) Start(ctx context.Context) error {
	var err error
	var lc net.ListenConfig
	if a.grpcLis, err = lc.Listen(ctx, "tcp", a.cfg.GRPC.Listen); err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	if a.httpLis, err = lc.Listen(ctx, "tcp", a.cfg.HTTPListen); err != nil {
		_ = a.grpcLis.Close()
		return fmt.Errorf("http listen: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	// Readiness flips the moment shutdown begins, before the gRPC drain.
	context.AfterFunc(runCtx, func() { a.state.Store(int32(stateDraining)) })
	if a.refreshable > 0 {
		go a.keyring.RunPeriodic(runCtx, a.cfg.KeyRefreshInterval)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", a.readyz)
	mux.Handle("GET /metrics", a.metrics.Handler())
	a.httpSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
	}

	a.grpcDone = make(chan error, 1)
	a.httpDone = make(chan error, 1)
	go func() { a.grpcDone <- a.server.Serve(runCtx, a.grpcLis) }()
	go func() {
		if err := a.httpSrv.Serve(a.httpLis); !errors.Is(err, http.ErrServerClosed) {
			a.httpDone <- err
			return
		}
		a.httpDone <- nil
	}()
	a.state.Store(int32(stateServing))
	return nil
}

// Wait blocks until the servers stop: after ctx cancellation (graceful) or a
// server failure. It then closes the replay cache.
func (a *app) Wait() error {
	var err error
	select {
	case err = <-a.grpcDone:
		a.grpcDone = nil
	case err = <-a.httpDone:
		a.httpDone = nil
	}
	a.state.Store(int32(stateDraining))
	a.logger.InfoContext(context.Background(), "shutdown: readiness now 503, draining")
	a.cancel()
	if a.grpcDone != nil {
		if grpcErr := <-a.grpcDone; err == nil {
			err = grpcErr
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	_ = a.httpSrv.Shutdown(shutdownCtx)
	if a.httpDone != nil {
		<-a.httpDone
	}
	if closeErr := a.cache.Close(); err == nil {
		err = closeErr
	}
	return err
}

// GRPCAddr is the bound ext_authz address, available after Start.
func (a *app) GRPCAddr() string { return a.grpcLis.Addr().String() }

// HTTPAddr is the bound health and metrics address, available after Start.
func (a *app) HTTPAddr() string { return a.httpLis.Addr().String() }

// readiness is the /readyz document.
type readiness struct {
	Ready            bool         `json:"ready"`
	Reasons          []string     `json:"reasons,omitempty"`
	Replay           replayStatus `json:"replay"`
	TransparencyLogs []keyStatus  `json:"transparencyLogs"`
}

type replayStatus struct {
	Backend            string     `json:"backend"`
	Up                 bool       `json:"up"`
	Entries            int64      `json:"entries,omitempty"`
	Capacity           int64      `json:"capacity,omitempty"`
	UsedMemory         int64      `json:"usedMemory,omitempty"`
	MaxMemory          int64      `json:"maxMemory,omitempty"`
	EvictionPolicy     string     `json:"evictionPolicy,omitempty"`
	EvictedKeys        int64      `json:"evictedKeys,omitempty"`
	KeyspaceResets     int64      `json:"keyspaceResets,omitempty"`
	Restarts           int64      `json:"restarts,omitempty"`
	AOFEnabled         bool       `json:"aofEnabled,omitempty"`
	KeyspaceResetUntil *time.Time `json:"keyspaceResetUntil,omitempty"`
}

type keyStatus struct {
	Name        string     `json:"name"`
	Keys        int        `json:"keys"`
	LastSuccess *time.Time `json:"lastSuccess,omitempty"`
	LastFailure *time.Time `json:"lastFailure,omitempty"`
	LastError   string     `json:"lastError,omitempty"`
}

func replayStatusOf(st replay.Stats) replayStatus {
	out := replayStatus{
		Backend: st.Backend, Up: st.Up, Entries: st.Entries, Capacity: st.Capacity,
		UsedMemory: st.UsedMemory, MaxMemory: st.MaxMemory, EvictionPolicy: st.EvictionPolicy,
		EvictedKeys: st.EvictedKeys, KeyspaceResets: st.KeyspaceResets, Restarts: st.Restarts, AOFEnabled: st.AOFEnabled,
	}
	if !st.KeyspaceResetUntil.IsZero() {
		until := st.KeyspaceResetUntil
		out.KeyspaceResetUntil = &until
	}
	return out
}

func keyStatusOf(sources []authz.SourceStatus) []keyStatus {
	out := make([]keyStatus, 0, len(sources))
	for _, s := range sources {
		out = append(out, keyStatus{Name: s.Name, Keys: s.Keys, LastSuccess: s.LastSuccess, LastFailure: s.LastFailure, LastError: s.LastError})
	}
	return out
}

// readyz is 200 only while serving with keys for every transparency log and,
// when required, a reachable replay backend.
func (a *app) readyz(w http.ResponseWriter, _ *http.Request) {
	r := readiness{Replay: replayStatusOf(a.cache.Stats()), TransparencyLogs: keyStatusOf(a.keyring.Status())}
	switch lifecycle(a.state.Load()) {
	case stateStarting:
		r.Reasons = append(r.Reasons, "starting")
	case stateDraining:
		r.Reasons = append(r.Reasons, "draining")
	case stateServing:
	}
	for _, tl := range r.TransparencyLogs {
		if tl.Keys == 0 {
			r.Reasons = append(r.Reasons, fmt.Sprintf("transparency log %q has no root keys", tl.Name))
		}
	}
	if a.cfg.Readiness.RequireReplayBackend && !r.Replay.Up {
		r.Reasons = append(r.Reasons, "replay backend is down")
	}
	r.Ready = len(r.Reasons) == 0
	w.Header().Set("Content-Type", "application/json")
	if !r.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(r)
}
