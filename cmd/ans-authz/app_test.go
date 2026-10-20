package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/config"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

func loadConfig(t *testing.T, yaml string) config.Config {
	t.Helper()
	cfg, err := config.Load(writeConfig(t, yaml), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func httpGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func readyState(t *testing.T, base string) (int, readiness) {
	t.Helper()
	code, body := httpGet(t, base+"/readyz")
	var r readiness
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("readyz body %q: %v", body, err)
	}
	return code, r
}

func startApp(t *testing.T, cfg config.Config) (*app, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := a.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	return a, cancel
}

func TestAppLifecycle(t *testing.T) {
	tr := newTrust(t)
	tl := rootKeysServer(t, 200, tr.line+"\n")
	a, cancel := startApp(t, loadConfig(t, configYAML(remoteTL(tl.URL))))
	base := "http://" + a.HTTPAddr()

	if code, body := httpGet(t, base+"/healthz"); code != 200 || string(body) != "ok\n" {
		t.Fatalf("healthz = %d %q", code, body)
	}
	code, r := readyState(t, base)
	if code != 200 || !r.Ready || len(r.TransparencyLogs) != 1 || r.TransparencyLogs[0].Keys != 1 || r.Replay.Backend != "memory" {
		t.Fatalf("readyz = %d %+v", code, r)
	}
	if _, body := httpGet(t, base+"/metrics"); !strings.Contains(string(body), `ans_authz_root_keys{tl="remote"} 1`) {
		t.Fatalf("metrics lack root key gauge:\n%s", body)
	}

	conn, err := grpc.NewClient(a.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := authv3.NewAuthorizationClient(conn)
	ctx := context.Background()

	resp, err := client.Check(ctx, checkRequestFrom(httptest.NewRequest(http.MethodGet, "http://"+testAuthority+"/echo", nil), nil))
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.Unauthenticated {
		t.Fatalf("unsigned: %v %v", resp.GetStatus(), err)
	}
	signed := tr.signedCheckRequest(t, http.MethodPost, "/echo", []byte(`{"a":1}`))
	resp, err = client.Check(ctx, signed)
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("signed: %v %v body %s", resp.GetStatus(), err, resp.GetDeniedResponse().GetBody())
	}
	var name string
	for _, h := range resp.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetKey() == "X-ANS-Name" {
			name = h.GetHeader().GetValue()
		}
	}
	if name != testAnsName {
		t.Fatalf("X-ANS-Name = %q", name)
	}
	resp, err = client.Check(ctx, signed)
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.Unauthenticated || !strings.Contains(resp.GetDeniedResponse().GetBody(), "REPLAY") {
		t.Fatalf("replay: %v %v body %s", resp.GetStatus(), err, resp.GetDeniedResponse().GetBody())
	}
	if _, body := httpGet(t, base+"/metrics"); !strings.Contains(string(body), `ans_authz_decisions_total{category="REPLAY",result="deny"} 1`) {
		t.Fatalf("metrics lack replay decision:\n%s", body)
	}

	cancel()
	if err := a.Wait(); err != nil {
		t.Fatalf("Wait = %v", err)
	}
	if _, err := http.Get(base + "/readyz"); err == nil {
		t.Fatal("readyz still answers after shutdown")
	}
}

func TestAppReadinessReasons(t *testing.T) {
	tr := newTrust(t)
	cfg := loadConfig(t, configYAML(pinnedTL(tr.line)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, err := newApp(ctx, cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	probe := func() (int, readiness) {
		rec := httptest.NewRecorder()
		a.readyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		var r readiness
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		return rec.Code, r
	}
	if code, r := probe(); code != 503 || r.Ready || !strings.Contains(strings.Join(r.Reasons, ","), "starting") {
		t.Fatalf("before Start: %d %+v", code, r)
	}

	a.cache = downCache{}
	empty, err := authz.NewKeyring(authz.NoopObserver{}, authz.KeySource{
		Name: "empty", Lookup: a.keyring, KeyCount: func() int { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	a.keyring = empty
	a.state.Store(int32(stateServing))
	code, r := probe()
	reasons := strings.Join(r.Reasons, ",")
	if code != 503 || !strings.Contains(reasons, `transparency log "empty" has no root keys`) || !strings.Contains(reasons, "replay backend is down") {
		t.Fatalf("degraded: %d %+v", code, r)
	}

	a.cfg.Readiness.RequireReplayBackend = false
	if _, r := probe(); strings.Contains(strings.Join(r.Reasons, ","), "replay backend") {
		t.Fatalf("replay reason reported although not required: %+v", r)
	}
	a.state.Store(int32(stateDraining))
	if _, r := probe(); !strings.Contains(strings.Join(r.Reasons, ","), "draining") {
		t.Fatalf("draining not reported: %+v", r)
	}
}

type downCache struct{}

func (downCache) CheckAndStore(context.Context, string, time.Time) (bool, error) {
	return false, replay.ErrUnavailable
}
func (downCache) Stats() replay.Stats { return replay.Stats{Backend: "redis", Up: false} }
func (downCache) Close() error        { return nil }

func TestNewAppKeyLoading(t *testing.T) {
	tr := newTrust(t)
	good := rootKeysServer(t, 200, tr.line+"\n")
	failing := rootKeysServer(t, 500, "")
	empty := rootKeysServer(t, 200, "\n")
	other := newTrust(t)
	redirecting := redirectServer(t, rootKeysServer(t, 200, other.line+"\n").URL+"/root-keys")
	tests := []struct {
		name           string
		tl             string
		wantErr        string
		wantRefreshers int
	}{
		{name: "pinned only runs static", tl: pinnedTL(tr.line)},
		{name: "remote fetch", tl: remoteTL(good.URL), wantRefreshers: 1},
		{name: "remote failure falls back to pinned keys", tl: remoteTLWithPin(failing.URL, tr.line), wantRefreshers: 1},
		{name: "remote failure without pins is fatal", tl: remoteTL(failing.URL), wantErr: "no root keys after"},
		{name: "remote without keys is fatal", tl: remoteTL(empty.URL), wantErr: "no root keys after"},
		{name: "redirect without pins is fatal", tl: remoteTL(redirecting.URL), wantErr: "no root keys after"},
		{name: "redirect is not followed and pinned keys stay the only trust", tl: remoteTLWithPin(redirecting.URL, tr.line), wantRefreshers: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadConfig(t, configYAML(tt.tl))
			a, err := newApp(context.Background(), cfg, discardLogger())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if a.refreshable != tt.wantRefreshers {
				t.Fatalf("refreshable = %d, want %d", a.refreshable, tt.wantRefreshers)
			}
			if st := a.keyring.Status(); len(st) != 1 || st[0].Keys != 1 {
				t.Fatalf("status = %+v", st)
			}
		})
	}
}

func TestNewAppRejectsUnknownReplayBackend(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Replay.Type = "bogus"
	a := &app{cfg: cfg, logger: discardLogger()}
	if _, err := a.newReplayCache(context.Background()); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v", err)
	}
}

func TestAppStartListenerErrors(t *testing.T) {
	tr := newTrust(t)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	tests := []struct {
		name string
		mut  func(*config.Config)
		want string
	}{
		{name: "grpc", mut: func(c *config.Config) { c.GRPC.Listen = taken.Addr().String() }, want: "grpc listen"},
		{name: "http", mut: func(c *config.Config) { c.HTTPListen = taken.Addr().String() }, want: "http listen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadConfig(t, configYAML(pinnedTL(tr.line)))
			tt.mut(&cfg)
			a, err := newApp(context.Background(), cfg, discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			if err := a.Start(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Start = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestAppWaitReportsServerFailures(t *testing.T) {
	tr := newTrust(t)
	t.Run("http listener closed underneath", func(t *testing.T) {
		a, cancel := startApp(t, loadConfig(t, configYAML(pinnedTL(tr.line))))
		defer cancel()
		_ = a.httpLis.Close()
		if err := a.Wait(); err == nil {
			t.Fatal("Wait = nil, want the http accept error")
		}
	})
}

func TestNewAppLoadsTLSUpFront(t *testing.T) {
	tr := newTrust(t)
	bogus := writeConfig(t, "not a certificate")
	yaml := strings.Replace(configYAML(pinnedTL(tr.line)), `grpc: {listen: "127.0.0.1:0"}`,
		`grpc: {listen: "127.0.0.1:0", tls: {certFile: `+bogus+`, keyFile: `+bogus+`}}`, 1)
	_, err := newApp(context.Background(), loadConfig(t, yaml), discardLogger())
	if err == nil || !strings.Contains(err.Error(), "load server certificate") {
		t.Fatalf("newApp = %v, want the TLS load failure", err)
	}
}

func TestAppDrainingFlipsReadinessBeforeWait(t *testing.T) {
	tr := newTrust(t)
	a, cancel := startApp(t, loadConfig(t, configYAML(pinnedTL(tr.line))))
	base := "http://" + a.HTTPAddr()
	if code, _ := readyState(t, base); code != 200 {
		t.Fatalf("readyz before shutdown = %d", code)
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, r := readyState(t, base)
		if code == 503 && strings.Contains(strings.Join(r.Reasons, ","), "draining") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readyz never reported draining: %d %+v", code, r)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := a.Wait(); err != nil {
		t.Fatalf("Wait = %v", err)
	}
}

func TestNewAppRedisBackend(t *testing.T) {
	tr := newTrust(t)
	m, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	t.Setenv("ANS_TEST_REDIS_PASSWORD", "secret")
	yaml := strings.Replace(configYAML(pinnedTL(tr.line)), "replay: {type: memory, maxEntries: 100}",
		"replay: {type: redis, redis: {addr: \""+m.Addr()+"\", timeout: 100ms, passwordEnv: ANS_TEST_REDIS_PASSWORD}}", 1)
	cfg := loadConfig(t, yaml)
	start := time.Now()
	_, err = newApp(context.Background(), cfg, discardLogger())
	if err == nil || !strings.Contains(err.Error(), "replay backend") || !strings.Contains(err.Error(), "maxmemory") {
		t.Fatalf("newApp = %v, want the store's guard-rail failure", err)
	}
	if elapsed := time.Since(start); elapsed < cfg.StartupTimeout || elapsed > cfg.StartupTimeout+5*time.Second {
		t.Fatalf("retry window was %s, want about startupTimeout %s", elapsed, cfg.StartupTimeout)
	}
}

func TestAppRedisBackendServes(t *testing.T) {
	tr := newTrust(t)
	store := startFakeRedis(t, fakeRedisInfo)
	yaml := strings.Replace(configYAML(pinnedTL(tr.line)), "replay: {type: memory, maxEntries: 100}",
		"replay: {type: redis, redis: {addr: \""+store.addr()+"\", timeout: 100ms}}", 1)
	a, cancel := startApp(t, loadConfig(t, yaml))
	defer cancel()
	code, r := readyState(t, "http://"+a.HTTPAddr())
	if code != 200 || r.Replay.Backend != "redis" || !r.Replay.Up || r.Replay.MaxMemory != 4096 || r.Replay.KeyspaceResetUntil == nil {
		t.Fatalf("readyz = %d %+v (a fresh store must report its fail-closed window)", code, r.Replay)
	}
	conn, err := grpc.NewClient(a.GRPCAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	resp, err := authv3.NewAuthorizationClient(conn).Check(context.Background(), tr.signedCheckRequest(t, http.MethodGet, "/echo", nil))
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.Unavailable || !strings.Contains(resp.GetDeniedResponse().GetBody(), "REPLAY_CACHE_UNAVAILABLE") {
		t.Fatalf("check inside the fresh-store window: %v %v body %s", resp.GetStatus(), err, resp.GetDeniedResponse().GetBody())
	}
	cancel()
	if err := a.Wait(); err != nil {
		t.Fatalf("Wait = %v", err)
	}
}

func TestReplayStatusOf(t *testing.T) {
	t.Parallel()
	until := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		stats     replay.Stats
		wantUntil bool
	}{
		{name: "memory", stats: replay.Stats{Backend: "memory", Entries: 1, Capacity: 2, Up: true}},
		{name: "redis in a reset window", stats: replay.Stats{Backend: "redis", Up: true, KeyspaceResetUntil: until}, wantUntil: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := replayStatusOf(tt.stats)
			if got.Backend != tt.stats.Backend || got.Entries != tt.stats.Entries || got.Capacity != tt.stats.Capacity {
				t.Fatalf("replayStatusOf = %+v", got)
			}
			if (got.KeyspaceResetUntil != nil) != tt.wantUntil || (tt.wantUntil && !got.KeyspaceResetUntil.Equal(until)) {
				t.Fatalf("KeyspaceResetUntil = %v, want present=%v", got.KeyspaceResetUntil, tt.wantUntil)
			}
		})
	}
}

func TestRetryUntil(t *testing.T) {
	t.Parallel()
	t.Run("succeeds after retries", func(t *testing.T) {
		t.Parallel()
		attempts := 0
		err := retryUntil(context.Background(), 5*time.Second, func(context.Context) error {
			attempts++
			if attempts < 3 {
				return errors.New("not yet")
			}
			return nil
		})
		if err != nil || attempts != 3 {
			t.Fatalf("err = %v attempts = %d", err, attempts)
		}
	})
	t.Run("gives up at the deadline", func(t *testing.T) {
		t.Parallel()
		start := time.Now()
		err := retryUntil(context.Background(), 300*time.Millisecond, func(context.Context) error { return errors.New("down") })
		if err == nil || err.Error() != "down" {
			t.Fatalf("err = %v", err)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("took %s", elapsed)
		}
	})
	t.Run("stops when the context ends during the backoff wait", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
		start := time.Now()
		err := retryUntil(ctx, time.Minute, func(context.Context) error { return errors.New("down") })
		if err == nil || time.Since(start) > 5*time.Second {
			t.Fatalf("err = %v after %s", err, time.Since(start))
		}
	})
	t.Run("stops when the context ends", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		err := retryUntil(ctx, time.Minute, func(context.Context) error {
			calls++
			cancel()
			return errors.New("down")
		})
		if err == nil || calls != 1 {
			t.Fatalf("err = %v calls = %d", err, calls)
		}
	})
}

// TestNewAppRejectsInvalidWiring covers constructor failures that config.Load
// would normally reject before newApp sees them.
func TestNewAppRejectsInvalidWiring(t *testing.T) {
	tr := newTrust(t)
	tests := []struct {
		name string
		mut  func(*config.Config)
		want string
	}{
		{name: "unparseable pinned key", mut: func(c *config.Config) { c.TransparencyLogs[0].RootKeys = []string{"garbage"} }, want: "root keys"},
		{name: "unusable base URL", mut: func(c *config.Config) { c.TransparencyLogs[0].BaseURL = "::not-a-url" }, want: "client"},
		{
			name: "duplicate transparency log names",
			mut:  func(c *config.Config) { c.TransparencyLogs = append(c.TransparencyLogs, c.TransparencyLogs[0]) },
			want: "duplicate key source name",
		},
		{name: "invalid verifier policy", mut: func(c *config.Config) { c.MaxContentBytes = 0 }, want: "maxContentBytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadConfig(t, configYAML(pinnedTL(tr.line)))
			tt.mut(&cfg)
			_, err := newApp(context.Background(), cfg, discardLogger())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}
