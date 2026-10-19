package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// GatewayExtAuthzBudget is the client-side timeout agentgateway applies to
// every ext_authz call. A checkTimeout at or above it lets the gateway give up
// before the verifier answers.
const GatewayExtAuthzBudget time.Duration = 2 * time.Second

// Validate reports the first configuration error, starting with the authz
// policy rules.
func (c Config) Validate() error {
	if err := c.Config.Validate(); err != nil {
		return err
	}
	if err := c.validateTransparencyLogs(); err != nil {
		return err
	}
	if err := c.Replay.validate(c.CheckTimeout); err != nil {
		return err
	}
	if err := c.GRPC.validate(); err != nil {
		return err
	}
	if _, err := validateListen("httpListen", c.HTTPListen); err != nil {
		return err
	}
	if err := validateLogLevel(c.LogLevel); err != nil {
		return err
	}
	if c.KeyRefreshInterval <= 0 {
		return errors.New("config: keyRefreshInterval must be positive")
	}
	if c.StartupTimeout <= 0 {
		return errors.New("config: startupTimeout must be positive")
	}
	return nil
}

// Warnings reports settings that are legal but likely to misbehave in
// production.
func (c Config) Warnings() []string {
	var warnings []string
	if c.CheckTimeout >= GatewayExtAuthzBudget {
		warnings = append(warnings, fmt.Sprintf(
			"checkTimeout %s is not below the gateway's %s ext_authz budget", c.CheckTimeout, GatewayExtAuthzBudget))
	}
	for _, tl := range c.TransparencyLogs {
		if u, err := url.Parse(tl.BaseURL); err == nil && u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			warnings = append(warnings, fmt.Sprintf(
				"transparencyLogs %q fetches root keys over plaintext from non-loopback %s; an on-path host can inject trust, pin rootKeys", tl.Name, u.Host))
		}
	}
	if c.RequiredContext == nil {
		warnings = append(warnings, "requiredContext is not set; a route that stops forwarding the request body cannot be detected for body-less requests")
	}
	return warnings
}

func (c Config) validateTransparencyLogs() error {
	if len(c.TransparencyLogs) == 0 {
		return errors.New("config: at least one transparencyLogs entry is required")
	}
	names := make(map[string]bool, len(c.TransparencyLogs))
	for i, tl := range c.TransparencyLogs {
		if err := tl.validate(c.CheckTimeout); err != nil {
			return fmt.Errorf("config: transparencyLogs[%d]: %w", i, err)
		}
		if names[tl.Name] {
			return fmt.Errorf("config: transparencyLogs[%d]: name %q is already used", i, tl.Name)
		}
		names[tl.Name] = true
	}
	return nil
}

func (tl TransparencyLog) validate(checkTimeout time.Duration) error {
	if tl.Name == "" {
		return errors.New("name is required")
	}
	if tl.BaseURL == "" && len(tl.RootKeys) == 0 {
		return errors.New("baseURL or rootKeys is required")
	}
	for i, line := range tl.RootKeys {
		if _, err := scitt.ParseC2SPKey(line); err != nil {
			return fmt.Errorf("rootKeys[%d]: %w", i, err)
		}
	}
	if _, err := scitt.NewKeyStore(tl.RootKeys); err != nil {
		return fmt.Errorf("rootKeys: %w", err)
	}
	if tl.BaseURL != "" {
		if err := validateBaseURL(tl.BaseURL, tl.AllowInsecure); err != nil {
			return fmt.Errorf("baseURL %q: %w", tl.BaseURL, err)
		}
	}
	if tl.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if tl.Timeout >= checkTimeout {
		return fmt.Errorf("timeout %s must be below checkTimeout %s", tl.Timeout, checkTimeout)
	}
	return nil
}

// validateBaseURL accepts an http or https URL with a host and no query or
// fragment; http needs the explicit insecure opt-in, as in the SDK client.
func validateBaseURL(raw string, allowInsecure bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecure {
			return errors.New("http scheme requires allowInsecure")
		}
	default:
		return errors.New("scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("host is required")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("query and fragment are not allowed")
	}
	return nil
}

func (r ReplayConfig) validate(checkTimeout time.Duration) error {
	switch r.Type {
	case ReplayTypeMemory:
		if r.MaxEntries <= 0 {
			return errors.New("config: replay.maxEntries must be positive")
		}
		return nil
	case ReplayTypeRedis:
		if r.Redis == nil {
			return errors.New("config: replay.redis is required when replay.type is redis")
		}
		return r.Redis.validate(checkTimeout)
	default:
		return fmt.Errorf("config: replay.type %q is unknown, use %s or %s", r.Type, ReplayTypeMemory, ReplayTypeRedis)
	}
}

func (r RedisConfig) validate(checkTimeout time.Duration) error {
	if r.Addr == "" {
		return errors.New("config: replay.redis.addr is required")
	}
	if _, _, err := net.SplitHostPort(r.Addr); err != nil {
		return fmt.Errorf("config: replay.redis.addr %q: %w", r.Addr, err)
	}
	if r.DB < 0 {
		return errors.New("config: replay.redis.db must not be negative")
	}
	if r.Timeout <= 0 {
		return errors.New("config: replay.redis.timeout must be positive")
	}
	if r.Timeout >= checkTimeout {
		return fmt.Errorf("config: replay.redis.timeout %s must be below checkTimeout %s", r.Timeout, checkTimeout)
	}
	if r.PasswordEnv != "" {
		if _, ok := os.LookupEnv(r.PasswordEnv); !ok {
			return fmt.Errorf("config: replay.redis.passwordEnv names %s, which is not set", r.PasswordEnv)
		}
	}
	return nil
}

func (g GRPCConfig) validate() error {
	host, err := validateListen("grpc.listen", g.Listen)
	if err != nil {
		return err
	}
	if g.TLS != nil {
		return g.TLS.validate()
	}
	if !isLoopbackHost(host) && !g.AllowInsecureListen {
		return fmt.Errorf("config: grpc.listen %q is not loopback and requires grpc.tls or allowInsecureListen", g.Listen)
	}
	return nil
}

func (tc TLSConfig) validate() error {
	if tc.CertFile == "" {
		return errors.New("config: grpc.tls.certFile is required")
	}
	if tc.KeyFile == "" {
		return errors.New("config: grpc.tls.keyFile is required")
	}
	files := []struct{ key, path string }{
		{"certFile", tc.CertFile},
		{"keyFile", tc.KeyFile},
		{"clientCAFile", tc.ClientCAFile},
	}
	for _, f := range files {
		if f.path == "" {
			continue
		}
		if _, err := os.Stat(f.path); err != nil {
			return fmt.Errorf("config: grpc.tls.%s: %w", f.key, err)
		}
	}
	return nil
}

// validateListen parses a host:port listen address and returns the host,
// which is empty for a wildcard bind.
func validateListen(key, addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("config: %s is required", key)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("config: %s %q: %w", key, addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("config: %s %q: port is required", key, addr)
	}
	return host, nil
}

// isLoopbackHost reports whether a listener on host only accepts connections
// from the same machine: localhost or a loopback IP address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func validateLogLevel(level string) error {
	switch level {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return fmt.Errorf("config: logLevel %q must be one of debug, info, warn, error", level)
	}
}
