package extauthz

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

type fakeStatus []authz.SourceStatus

func (f fakeStatus) Status() []authz.SourceStatus { return f }

type fakeCache struct{ stats replay.Stats }

func (f fakeCache) CheckAndStore(context.Context, string, time.Time) (bool, error) { return false, nil }
func (f fakeCache) Stats() replay.Stats                                            { return f.stats }
func (fakeCache) Close() error                                                     { return nil }

func TestRegisterStatus(t *testing.T) {
	t.Parallel()
	refreshed := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name   string
		keys   fakeStatus
		stats  replay.Stats
		want   []string
		absent []string
	}{
		{
			name:  "memory backend exposes occupancy",
			keys:  fakeStatus{{Name: "tl-a", Keys: 2, LastSuccess: &refreshed}, {Name: "tl-b", Keys: 0}},
			stats: replay.Stats{Backend: "memory", Entries: 5, Capacity: 100, Up: true},
			want: []string{
				`ans_authz_root_keys{tl="tl-a"} 2`,
				`ans_authz_root_keys{tl="tl-b"} 0`,
				`ans_authz_root_keys_last_refresh_timestamp_seconds{tl="tl-a"} 1.7e+09`,
				"ans_authz_replay_cache_entries 5",
				"ans_authz_replay_cache_capacity 100",
				`ans_authz_replay_backend_up{backend="memory"} 1`,
			},
			absent: []string{`last_refresh_timestamp_seconds{tl="tl-b"}`, "ans_authz_replay_backend_maxmemory_bytes"},
		},
		{
			name: "redis backend exposes guard rails",
			keys: fakeStatus{{Name: "tl-a", Keys: 1}},
			stats: replay.Stats{
				Backend: "redis", UsedMemory: 1024, MaxMemory: 4096, EvictionPolicy: "noeviction",
				EvictedKeys: 0, KeyspaceResets: 1, Restarts: 2, AOFEnabled: true, Up: true,
			},
			want: []string{
				"ans_authz_replay_backend_used_memory_bytes 1024",
				"ans_authz_replay_backend_maxmemory_bytes 4096",
				"ans_authz_replay_backend_noeviction 1",
				"ans_authz_replay_backend_evicted_keys_total 0",
				"ans_authz_replay_backend_keyspace_resets_total 1",
				"ans_authz_replay_backend_restarts_total 2",
				"ans_authz_replay_backend_aof_enabled 1",
				`ans_authz_replay_backend_up{backend="redis"} 1`,
			},
			absent: []string{"ans_authz_replay_cache_entries"},
		},
		{
			name:  "redis down with a wrong policy",
			keys:  fakeStatus{},
			stats: replay.Stats{Backend: "redis", EvictionPolicy: "allkeys-lru", Up: false},
			want: []string{
				"ans_authz_replay_backend_noeviction 0",
				`ans_authz_replay_backend_up{backend="redis"} 0`,
				"ans_authz_replay_backend_aof_enabled 0",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewMetrics()
			if err := m.RegisterStatus(tt.keys, fakeCache{stats: tt.stats}); err != nil {
				t.Fatal(err)
			}
			if err := m.RegisterStatus(tt.keys, fakeCache{stats: tt.stats}); err == nil {
				t.Fatal("second registration must fail")
			}
			rec := httptest.NewRecorder()
			m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			body, _ := io.ReadAll(rec.Body)
			for _, want := range tt.want {
				if !strings.Contains(string(body), want) {
					t.Errorf("exposition lacks %q", want)
				}
			}
			for _, absent := range tt.absent {
				if strings.Contains(string(body), absent) {
					t.Errorf("exposition must not contain %q", absent)
				}
			}
			if t.Failed() {
				t.Logf("exposition:\n%s", body)
			}
		})
	}
}
