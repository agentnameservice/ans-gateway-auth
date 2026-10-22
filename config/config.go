// Package config loads and validates the ans-authz service configuration: the
// verification policy from package authz plus the transparency logs, replay
// backend, listeners and operational settings.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

// Service defaults.
const (
	DefaultReplayMaxEntries                     = 100000
	DefaultGRPCListen                           = "127.0.0.1:9191"
	DefaultHTTPListen                           = "127.0.0.1:9192"
	DefaultLogLevel                             = "info"
	DefaultKeyRefreshInterval     time.Duration = 24 * time.Hour
	DefaultStartupTimeout         time.Duration = 30 * time.Second
	DefaultTransparencyLogTimeout time.Duration = time.Second
	// DefaultTokenClaimsNamespace is the filter_metadata namespace the gateway
	// recipes write validated access-token claims to.
	DefaultTokenClaimsNamespace = "ans-authz"
)

// Replay backend types.
const (
	ReplayTypeMemory = replay.BackendMemory
	ReplayTypeRedis  = replay.BackendRedis
)

// Config is the complete service configuration. The authz policy is inline so
// one YAML document lists policy and service keys at the same level.
type Config struct {
	authz.Config       `yaml:",inline"`
	TransparencyLogs   []TransparencyLog `yaml:"transparencyLogs"`
	Replay             ReplayConfig      `yaml:"replay"`
	GRPC               GRPCConfig        `yaml:"grpc"`
	HTTPListen         string            `yaml:"httpListen"`
	LogLevel           string            `yaml:"logLevel"`
	KeyRefreshInterval time.Duration     `yaml:"keyRefreshInterval"`
	StartupTimeout     time.Duration     `yaml:"startupTimeout"`
	Readiness          ReadinessConfig   `yaml:"readiness"`
}

// TransparencyLog names one SCITT transparency log whose root keys sign the
// receipts and status tokens this verifier accepts. Keys come from RootKeys,
// from the log's /root-keys endpoint under BaseURL, or both.
type TransparencyLog struct {
	Name string `yaml:"name"`
	// BaseURL is the log's base URL; the SDK client appends /root-keys.
	BaseURL string `yaml:"baseURL"`
	// RootKeys lists pinned root keys as C2SP lines (name+kid+base64 SPKI).
	RootKeys []string `yaml:"rootKeys"`
	// AllowInsecure permits an http BaseURL, for loopback development only.
	AllowInsecure bool `yaml:"allowInsecure"`
	// Timeout bounds one root-key fetch. It must stay below checkTimeout so a
	// refresh wait can never consume the whole verification budget. Load
	// applies DefaultTransparencyLogTimeout when it is unset.
	Timeout time.Duration `yaml:"timeout"`
}

// ReplayConfig selects the replay-cache backend.
type ReplayConfig struct {
	// Type is "memory" (one replica only, ANS-6 section 7.6) or "redis" (a
	// shared store for every replica behind one authority).
	Type string `yaml:"type"`
	// MaxEntries caps the memory backend; the cache fails closed when full.
	MaxEntries int `yaml:"maxEntries"`
	// Redis configures the shared backend; required when Type is "redis".
	Redis *RedisConfig `yaml:"redis"`
}

// RedisConfig names the shared replay store. The password is never in the
// file: PasswordEnv names the environment variable that carries it.
type RedisConfig struct {
	Addr        string `yaml:"addr"`
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"passwordEnv"`
	DB          int    `yaml:"db"`
	TLS         bool   `yaml:"tls"`
	// Timeout bounds each connect, write, read and pool wait as a single
	// attempt; it must stay below checkTimeout. Load applies
	// replay.DefaultRedisTimeout when it is unset.
	Timeout time.Duration `yaml:"timeout"`
}

// GRPCConfig configures the ext_authz listener.
type GRPCConfig struct {
	Listen string `yaml:"listen"`
	// TLS is required unless Listen binds loopback or AllowInsecureListen is
	// set.
	TLS *TLSConfig `yaml:"tls"`
	// AllowInsecureListen admits a plaintext non-loopback listener, for
	// deployments where a mesh provides mutual TLS.
	AllowInsecureListen bool `yaml:"allowInsecureListen"`
	// TokenClaimsNamespace is the filter_metadata namespace forwarded
	// access-token claims are read from; no other namespace is consulted.
	TokenClaimsNamespace string `yaml:"tokenClaimsNamespace"`
}

// TLSConfig names the server certificate and, for mutual TLS, the client CA.
type TLSConfig struct {
	CertFile     string `yaml:"certFile"`
	KeyFile      string `yaml:"keyFile"`
	ClientCAFile string `yaml:"clientCAFile"`
}

// ReadinessConfig tunes the /readyz endpoint.
type ReadinessConfig struct {
	// RequireReplayBackend fails readiness while the replay backend is down.
	// A sidecar sharing pod readiness with the gateway sets it to false.
	RequireReplayBackend bool `yaml:"requireReplayBackend"`
}

// Overrides carries the operational settings flags and environment variables
// may set. An empty field leaves the loaded value in place.
type Overrides struct {
	GRPCListen string
	HTTPListen string
	LogLevel   string
}

// Default returns the service defaults. They are not a complete configuration:
// the authorities and at least one transparency log must come from the
// document.
func Default() Config {
	return Config{
		Config:             authz.DefaultConfig(),
		Replay:             ReplayConfig{Type: ReplayTypeMemory, MaxEntries: DefaultReplayMaxEntries},
		GRPC:               GRPCConfig{Listen: DefaultGRPCListen, TokenClaimsNamespace: DefaultTokenClaimsNamespace},
		HTTPListen:         DefaultHTTPListen,
		LogLevel:           DefaultLogLevel,
		KeyRefreshInterval: DefaultKeyRefreshInterval,
		StartupTimeout:     DefaultStartupTimeout,
		Readiness:          ReadinessConfig{RequireReplayBackend: true},
	}
}

// Load builds the configuration from the defaults, the YAML document at path
// when path is not empty, and the overrides, in that order, then validates
// the result. Unknown YAML keys are errors.
func Load(path string, ov Overrides) (Config, error) {
	cfg := Default()
	if path != "" {
		if err := decodeFile(path, &cfg); err != nil {
			return Config{}, err
		}
	}
	for i := range cfg.TransparencyLogs {
		if cfg.TransparencyLogs[i].Timeout == 0 {
			cfg.TransparencyLogs[i].Timeout = DefaultTransparencyLogTimeout
		}
	}
	if cfg.Replay.Redis != nil && cfg.Replay.Redis.Timeout == 0 {
		cfg.Replay.Redis.Timeout = replay.DefaultRedisTimeout
	}
	ov.apply(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func decodeFile(path string, cfg *Config) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}

func (o Overrides) apply(c *Config) {
	if o.GRPCListen != "" {
		c.GRPC.Listen = o.GRPCListen
	}
	if o.HTTPListen != "" {
		c.HTTPListen = o.HTTPListen
	}
	if o.LogLevel != "" {
		c.LogLevel = o.LogLevel
	}
}
