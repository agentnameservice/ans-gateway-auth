package extauthz

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

// StatusSource reports per-transparency-log key status; *authz.Keyring
// satisfies it.
type StatusSource interface {
	Status() []authz.SourceStatus
}

// RegisterStatus adds a collector that samples key-store and replay-backend
// status at scrape time.
func (m *Metrics) RegisterStatus(keys StatusSource, cache replay.Cache) error {
	return m.registry.Register(&statusCollector{keys: keys, cache: cache, d: newStatusDescs()})
}

type statusCollector struct {
	keys  StatusSource
	cache replay.Cache
	d     statusDescs
}

type statusDescs struct {
	descRootKeys             *prometheus.Desc
	descRootKeysRefreshed    *prometheus.Desc
	descReplayEntries        *prometheus.Desc
	descReplayCapacity       *prometheus.Desc
	descReplayUp             *prometheus.Desc
	descReplayUsedMemory     *prometheus.Desc
	descReplayMaxMemory      *prometheus.Desc
	descReplayNoEviction     *prometheus.Desc
	descReplayEvicted        *prometheus.Desc
	descReplayKeyspaceResets *prometheus.Desc
	descReplayRestarts       *prometheus.Desc
	descReplayAOF            *prometheus.Desc
}

func newStatusDescs() statusDescs {
	return statusDescs{descRootKeys: prometheus.NewDesc(metricsNamespace+"_root_keys",
		"Trusted root keys currently held per transparency log.", []string{"tl"}, nil),
		descRootKeysRefreshed: prometheus.NewDesc(metricsNamespace+"_root_keys_last_refresh_timestamp_seconds",
			"Unix time of the last successful root-key fetch per transparency log.", []string{"tl"}, nil),
		descReplayEntries: prometheus.NewDesc(metricsNamespace+"_replay_cache_entries",
			"Entries held by the in-memory replay cache.", nil, nil),
		descReplayCapacity: prometheus.NewDesc(metricsNamespace+"_replay_cache_capacity",
			"Capacity of the in-memory replay cache.", nil, nil),
		descReplayUp: prometheus.NewDesc(metricsNamespace+"_replay_backend_up",
			"1 when the replay backend answered its last probe.", []string{"backend"}, nil),
		descReplayUsedMemory: prometheus.NewDesc(metricsNamespace+"_replay_backend_used_memory_bytes",
			"Memory used by the shared replay backend.", nil, nil),
		descReplayMaxMemory: prometheus.NewDesc(metricsNamespace+"_replay_backend_maxmemory_bytes",
			"Configured memory limit of the shared replay backend; 0 means unlimited and is a misconfiguration.", nil, nil),
		descReplayNoEviction: prometheus.NewDesc(metricsNamespace+"_replay_backend_noeviction",
			"1 when the shared replay backend's eviction policy is noeviction.", nil, nil),
		descReplayEvicted: prometheus.NewDesc(metricsNamespace+"_replay_backend_evicted_keys_total",
			"Keys the shared replay backend evicted; any increase compromises replay protection.", nil, nil),
		descReplayKeyspaceResets: prometheus.NewDesc(metricsNamespace+"_replay_backend_keyspace_resets_total",
			"Times the shared replay backend lost its keyspace.", nil, nil),
		descReplayRestarts: prometheus.NewDesc(metricsNamespace+"_replay_backend_restarts_total",
			"Shared replay backend restarts observed.", nil, nil),
		descReplayAOF: prometheus.NewDesc(metricsNamespace+"_replay_backend_aof_enabled",
			"1 when the shared replay backend persists with an append-only file.", nil, nil),
	}
}

func (c *statusCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.d.descRootKeys, c.d.descRootKeysRefreshed, c.d.descReplayEntries, c.d.descReplayCapacity, c.d.descReplayUp,
		c.d.descReplayUsedMemory, c.d.descReplayMaxMemory, c.d.descReplayNoEviction, c.d.descReplayEvicted,
		c.d.descReplayKeyspaceResets, c.d.descReplayRestarts, c.d.descReplayAOF,
	} {
		ch <- d
	}
}

func (c *statusCollector) Collect(ch chan<- prometheus.Metric) {
	for _, s := range c.keys.Status() {
		ch <- prometheus.MustNewConstMetric(c.d.descRootKeys, prometheus.GaugeValue, float64(s.Keys), s.Name)
		if s.LastSuccess != nil {
			ch <- prometheus.MustNewConstMetric(c.d.descRootKeysRefreshed, prometheus.GaugeValue, float64(s.LastSuccess.Unix()), s.Name)
		}
	}
	st := c.cache.Stats()
	ch <- prometheus.MustNewConstMetric(c.d.descReplayUp, prometheus.GaugeValue, boolValue(st.Up), st.Backend)
	switch st.Backend {
	case replay.BackendMemory:
		ch <- prometheus.MustNewConstMetric(c.d.descReplayEntries, prometheus.GaugeValue, float64(st.Entries))
		ch <- prometheus.MustNewConstMetric(c.d.descReplayCapacity, prometheus.GaugeValue, float64(st.Capacity))
	case replay.BackendRedis:
		ch <- prometheus.MustNewConstMetric(c.d.descReplayUsedMemory, prometheus.GaugeValue, float64(st.UsedMemory))
		ch <- prometheus.MustNewConstMetric(c.d.descReplayMaxMemory, prometheus.GaugeValue, float64(st.MaxMemory))
		ch <- prometheus.MustNewConstMetric(c.d.descReplayNoEviction, prometheus.GaugeValue, boolValue(st.EvictionPolicy == "noeviction"))
		ch <- prometheus.MustNewConstMetric(c.d.descReplayEvicted, prometheus.CounterValue, float64(st.EvictedKeys))
		ch <- prometheus.MustNewConstMetric(c.d.descReplayKeyspaceResets, prometheus.CounterValue, float64(st.KeyspaceResets))
		ch <- prometheus.MustNewConstMetric(c.d.descReplayRestarts, prometheus.CounterValue, float64(st.Restarts))
		ch <- prometheus.MustNewConstMetric(c.d.descReplayAOF, prometheus.GaugeValue, boolValue(st.AOFEnabled))
	}
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
