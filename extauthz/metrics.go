package extauthz

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

const metricsNamespace = "ans_authz"

// Metrics is the Prometheus implementation of authz.Observer. It owns its
// registry so a process can expose the verifier's metrics without the
// default registry's process and Go collectors leaking into tests.
type Metrics struct {
	registry *prometheus.Registry

	decisions     *prometheus.CounterVec
	checkDuration prometheus.Histogram
	checkTimeouts prometheus.Counter
	keyRefresh    *prometheus.CounterVec
	replayLatency *prometheus.HistogramVec
	replayErrors  *prometheus.CounterVec

	issuerRefresh     *prometheus.CounterVec
	issuerLastSuccess *prometheus.GaugeVec
}

var (
	_ authz.Observer       = (*Metrics)(nil)
	_ authz.StatusObserver = (*Metrics)(nil)
)

// NewMetrics creates the verifier metrics and registers them, together with
// the Go runtime and process collectors, on a fresh registry.
func NewMetrics() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "decisions_total",
			Help:      "Verification decisions by result (allow, deny) and deny category.",
		}, []string{"result", "category"}),
		checkDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "check_duration_seconds",
			Help:      "Wall time of one verification, from request receipt to decision.",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 12),
		}),
		checkTimeouts: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "check_timeouts_total",
			Help:      "Verifications that exhausted the configured checkTimeout budget.",
		}),
		keyRefresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "key_refresh_total",
			Help:      "Transparency-log root key refresh attempts by log and result.",
		}, []string{"tl", "result"}),
		replayLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "replay_backend_duration_seconds",
			Help:      "Replay-cache backend call latency by operation.",
			Buckets:   prometheus.ExponentialBuckets(0.0005, 2, 12),
		}, []string{"op"}),
		replayErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "replay_backend_errors_total",
			Help:      "Replay-cache backend failures by operation; request cancellations and deadlines are excluded.",
		}, []string{"op"}),
		issuerRefresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "issuer_status_refresh_total",
			Help:      "Background issuer status-token fetches by issuer and result (success, failure, terminal).",
		}, []string{"issuer", "result"}),
		issuerLastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "issuer_status_last_success_timestamp_seconds",
			Help:      "Unix time of the last issuer status fetch the TL answered (a token or a terminal 410).",
		}, []string{"issuer"}),
	}
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.decisions, m.checkDuration, m.checkTimeouts, m.keyRefresh, m.replayLatency, m.replayErrors,
		m.issuerRefresh, m.issuerLastSuccess,
	)
	// Pre-create the series operators alert on so they exist at zero.
	m.replayErrors.WithLabelValues("check_and_store")
	return m
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Decision implements authz.Observer.
func (m *Metrics) Decision(result, category string, d time.Duration) {
	m.decisions.WithLabelValues(result, category).Inc()
	m.checkDuration.Observe(d.Seconds())
}

// KeyRefresh implements authz.Observer.
func (m *Metrics) KeyRefresh(tl string, _ int, err error) {
	result := "success"
	if err != nil {
		result = "failure"
	}
	m.keyRefresh.WithLabelValues(tl, result).Inc()
}

// IssuerStatusRefresh implements authz.StatusObserver. A terminal answer is a
// successful contact with the TL, so it moves the success timestamp.
func (m *Metrics) IssuerStatusRefresh(issuer, result string, at time.Time) {
	m.issuerRefresh.WithLabelValues(issuer, result).Inc()
	if result != authz.StatusRefreshFailure {
		m.issuerLastSuccess.WithLabelValues(issuer).Set(float64(at.Unix()))
	}
}

// PreregisterIssuer creates an issuer's refresh counters and its
// last-success gauge at zero, so a staleness alert fires for an issuer the
// TL never answered.
func (m *Metrics) PreregisterIssuer(issuer string) {
	for _, r := range []string{authz.StatusRefreshSuccess, authz.StatusRefreshFailure, authz.StatusRefreshTerminal} {
		m.issuerRefresh.WithLabelValues(issuer, r)
	}
	m.issuerLastSuccess.WithLabelValues(issuer)
}

// CheckTimeout implements authz.Observer.
func (m *Metrics) CheckTimeout() {
	m.checkTimeouts.Inc()
}

// ReplayBackend implements replay.Observer. A keyspace reset is reported
// through its own counter by the status collector, not as a backend error.
func (m *Metrics) ReplayBackend(op string, d time.Duration, err error) {
	m.replayLatency.WithLabelValues(op).Observe(d.Seconds())
	if err == nil || isContextError(err) || isKeyspaceReset(err) {
		return
	}
	m.replayErrors.WithLabelValues(op).Inc()
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func isKeyspaceReset(err error) bool {
	var reset *replay.KeyspaceResetError
	return errors.As(err, &reset)
}
