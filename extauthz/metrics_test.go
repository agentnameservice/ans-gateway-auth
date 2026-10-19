package extauthz

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/agentnameservice/ans-gateway-auth/replay"
)

func TestMetricsDecision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		calls    [][2]string
		want     map[[2]string]float64
		wantObs  uint64
		timeouts int
	}{
		{
			name:    "allow and deny are counted by result and category",
			calls:   [][2]string{{"allow", ""}, {"deny", "REPLAY"}, {"deny", "REPLAY"}, {"deny", "MISSING_HEADERS"}},
			want:    map[[2]string]float64{{"allow", ""}: 1, {"deny", "REPLAY"}: 2, {"deny", "MISSING_HEADERS"}: 1},
			wantObs: 4,
		},
		{
			name:     "timeouts are counted separately",
			calls:    [][2]string{{"deny", "TIMEOUT"}},
			want:     map[[2]string]float64{{"deny", "TIMEOUT"}: 1},
			wantObs:  1,
			timeouts: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewMetrics()
			for _, c := range tt.calls {
				m.Decision(c[0], c[1], 5*time.Millisecond)
			}
			for range tt.timeouts {
				m.CheckTimeout()
			}
			for labels, want := range tt.want {
				if got := testutil.ToFloat64(m.decisions.WithLabelValues(labels[0], labels[1])); got != want {
					t.Errorf("decisions%v = %v, want %v", labels, got, want)
				}
			}
			if got := histogramCount(t, m, "ans_authz_check_duration_seconds"); got != tt.wantObs {
				t.Errorf("check duration observations = %d, want %d", got, tt.wantObs)
			}
			if got := testutil.ToFloat64(m.checkTimeouts); got != float64(tt.timeouts) {
				t.Errorf("check timeouts = %v, want %d", got, tt.timeouts)
			}
		})
	}
}

func TestMetricsKeyRefresh(t *testing.T) {
	t.Parallel()
	m := NewMetrics()
	m.KeyRefresh("tl-a", 3, nil)
	m.KeyRefresh("tl-a", 0, errors.New("boom"))
	m.KeyRefresh("tl-b", 1, nil)

	tests := []struct {
		tl, result string
		want       float64
	}{
		{"tl-a", "success", 1},
		{"tl-a", "failure", 1},
		{"tl-b", "success", 1},
		{"tl-b", "failure", 0},
	}
	for _, tt := range tests {
		if got := testutil.ToFloat64(m.keyRefresh.WithLabelValues(tt.tl, tt.result)); got != tt.want {
			t.Errorf("key_refresh{tl=%s,result=%s} = %v, want %v", tt.tl, tt.result, got, tt.want)
		}
	}
}

func TestMetricsReplayBackend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		wantErrors float64
	}{
		{name: "success is not an error", err: nil},
		{name: "capacity error is counted", err: replay.ErrFull, wantErrors: 1},
		{name: "outage is counted", err: replay.ErrUnavailable, wantErrors: 1},
		{name: "wrapped outage is counted", err: errors.Join(errors.New("set"), replay.ErrUnavailable), wantErrors: 1},
		{name: "keyspace reset is not a backend error", err: &replay.KeyspaceResetError{}},
		{name: "cancellation is excluded", err: context.Canceled},
		{name: "deadline is excluded", err: context.DeadlineExceeded},
		{name: "wrapped deadline is excluded", err: errors.Join(errors.New("get"), context.DeadlineExceeded)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := NewMetrics()
			m.ReplayBackend("check_and_store", 2*time.Millisecond, tt.err)
			if got := testutil.ToFloat64(m.replayErrors.WithLabelValues("check_and_store")); got != tt.wantErrors {
				t.Errorf("replay errors = %v, want %v", got, tt.wantErrors)
			}
			if got := histogramCount(t, m, "ans_authz_replay_backend_duration_seconds"); got != 1 {
				t.Errorf("replay duration observations = %d, want 1", got)
			}
		})
	}
}

func TestMetricsHandler(t *testing.T) {
	t.Parallel()
	m := NewMetrics()
	m.Decision("allow", "", time.Millisecond)
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	for _, want := range []string{
		`ans_authz_decisions_total{category="",result="allow"} 1`,
		"ans_authz_check_duration_seconds_count 1",
		"ans_authz_check_timeouts_total 0",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("exposition lacks %q:\n%s", want, body)
		}
	}
}

func histogramCount(t *testing.T, m *Metrics, name string) uint64 {
	t.Helper()
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, metric := range f.GetMetric() {
			total += metric.GetHistogram().GetSampleCount()
		}
	}
	return total
}
