package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agentnameservice/ans-gateway-auth/authz"
)

// C2SP root-key line layout: name+hexkid+base64(0x02||SPKI DER), the kid
// being the first four bytes of SHA-256 over the SPKI DER.
const (
	c2spTypeByte = 0x02
	c2spKidLen   = 4
)

func mintRootKey(t *testing.T, name string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(spki)
	kid := hex.EncodeToString(sum[:c2spKidLen])
	body := base64.StdEncoding.EncodeToString(append([]byte{c2spTypeByte}, spki...))
	return name + "+" + kid + "+" + body
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return path
}

// tlsFiles holds placeholder certificate, key and CA files, which only need
// to exist, plus the path of a file that does not.
type tlsFiles struct{ cert, key, ca, missing string }

func newTLSFiles(t *testing.T, dir string) tlsFiles {
	t.Helper()
	return tlsFiles{
		cert:    writeFile(t, dir, "cert.pem", "cert"),
		key:     writeFile(t, dir, "key.pem", "key"),
		ca:      writeFile(t, dir, "ca.pem", "ca"),
		missing: filepath.Join(dir, "missing.pem"),
	}
}

func validConfig() Config {
	c := Default()
	c.TrustedHosts = []string{"https://gw.example.com"}
	c.TransparencyLogs = []TransparencyLog{{
		Name:    "tl",
		BaseURL: "https://tl.example.com",
		Timeout: DefaultTransparencyLogTimeout,
	}}
	return c
}

func TestDefault(t *testing.T) {
	t.Parallel()
	want := Config{
		Config:             authz.DefaultConfig(),
		Replay:             ReplayConfig{Type: "memory", MaxEntries: 100000},
		GRPC:               GRPCConfig{Listen: "127.0.0.1:9191"},
		HTTPListen:         "127.0.0.1:9192",
		LogLevel:           "info",
		KeyRefreshInterval: 24 * time.Hour,
		StartupTimeout:     30 * time.Second,
		Readiness:          ReadinessConfig{RequireReplayBackend: true},
	}
	got := Default()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Default() = %+v\nwant %+v", got, want)
	}
	if DefaultTransparencyLogTimeout != time.Second {
		t.Fatalf("DefaultTransparencyLogTimeout = %s, want 1s", DefaultTransparencyLogTimeout)
	}
	if err := got.Validate(); err == nil {
		t.Fatal("Default().Validate() = nil, want an error: defaults alone name no authority or transparency log")
	}
}

func TestLoad(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	files := newTLSFiles(t, dir)
	rootKey := mintRootKey(t, "pinned")

	const minimal = "trustedHosts: [https://gw.example.com]\n" +
		"transparencyLogs:\n  - name: tl\n    baseURL: https://tl.example.com\n"
	const listens = "grpc:\n  listen: 127.0.0.1:1111\nhttpListen: 127.0.0.1:2222\nlogLevel: warn\n"

	full := fmt.Sprintf(`trustedHosts:
  - https://gw.example.com
  - http://gw.internal:8080
externalAuthority: https://public.example.com
maxContentBytes: 2048
requireReceipt: false
allowedAnsNames:
  - ans://v1.0.0.caller.example
popSkew: 60s
stripIdentityHeaders: false
checkTimeout: 1200ms
requiredContext:
  key: ans-authz
  value: body-forwarded
requireTokenClaims: false
transparencyLogs:
  - name: local
    baseURL: http://127.0.0.1:18081
    allowInsecure: true
    timeout: 500ms
  - name: pinned
    rootKeys:
      - %s
replay:
  type: memory
  maxEntries: 5000
grpc:
  listen: ":9191"
  tls:
    certFile: %s
    keyFile: %s
    clientCAFile: %s
httpListen: 0.0.0.0:9192
logLevel: debug
keyRefreshInterval: 1h
startupTimeout: 10s
readiness:
  requireReplayBackend: false
`, rootKey, files.cert, files.key, files.ca)

	wantFull := Config{
		Config: authz.Config{
			TrustedHosts:         []string{"https://gw.example.com", "http://gw.internal:8080"},
			ExternalAuthority:    "https://public.example.com",
			MaxContentBytes:      2048,
			RequireReceipt:       false,
			AllowedAnsNames:      []string{"ans://v1.0.0.caller.example"},
			PoPSkew:              60 * time.Second,
			StripIdentityHeaders: false,
			CheckTimeout:         1200 * time.Millisecond,
			RequiredContext:      &authz.RequiredContext{Key: "ans-authz", Value: "body-forwarded"},
			RequireTokenClaims:   false,
		},
		TransparencyLogs: []TransparencyLog{
			{Name: "local", BaseURL: "http://127.0.0.1:18081", AllowInsecure: true, Timeout: 500 * time.Millisecond},
			{Name: "pinned", RootKeys: []string{rootKey}, Timeout: time.Second},
		},
		Replay:             ReplayConfig{Type: "memory", MaxEntries: 5000},
		GRPC:               GRPCConfig{Listen: ":9191", TLS: &TLSConfig{CertFile: files.cert, KeyFile: files.key, ClientCAFile: files.ca}},
		HTTPListen:         "0.0.0.0:9192",
		LogLevel:           "debug",
		KeyRefreshInterval: time.Hour,
		StartupTimeout:     10 * time.Second,
		Readiness:          ReadinessConfig{RequireReplayBackend: false},
	}

	wantMinimal := Default()
	wantMinimal.TrustedHosts = []string{"https://gw.example.com"}
	wantMinimal.TransparencyLogs = []TransparencyLog{{Name: "tl", BaseURL: "https://tl.example.com", Timeout: time.Second}}
	minimalWith := func(grpcListen, httpListen, logLevel string) Config {
		c := wantMinimal
		c.GRPC.Listen = grpcListen
		c.HTTPListen = httpListen
		c.LogLevel = logLevel
		return c
	}

	tests := []struct {
		name    string
		yaml    string
		usePath bool   // pass path verbatim instead of writing yaml to a file
		path    string // used when usePath is set
		ov      Overrides
		want    Config
		wantErr string
	}{
		{name: "full document round trip", yaml: full, want: wantFull},
		{name: "sparse document keeps defaults", yaml: minimal, want: wantMinimal},
		{
			name: "overrides beat the document",
			yaml: minimal + listens,
			ov:   Overrides{GRPCListen: "127.0.0.1:3333", HTTPListen: "127.0.0.1:4444", LogLevel: "error"},
			want: minimalWith("127.0.0.1:3333", "127.0.0.1:4444", "error"),
		},
		{
			name: "partial overrides keep document values",
			yaml: minimal + listens,
			ov:   Overrides{LogLevel: "error"},
			want: minimalWith("127.0.0.1:1111", "127.0.0.1:2222", "error"),
		},
		{name: "overrides are validated", yaml: minimal, ov: Overrides{LogLevel: "verbose"}, wantErr: "logLevel"},
		{name: "unknown top-level key", yaml: minimal + "bogus: 1\n", wantErr: "field bogus not found"},
		{name: "unknown nested key", yaml: minimal + "grpc:\n  port: 9191\n", wantErr: "field port not found"},
		{name: "bare integer duration", yaml: minimal + "checkTimeout: 1500\n", wantErr: "time.Duration"},
		{name: "malformed document", yaml: "trustedHosts: [\n", wantErr: "parse"},
		{name: "empty document keeps defaults", yaml: "", wantErr: "trustedHosts or externalAuthority"},
		{name: "document failing validation", yaml: minimal + "replay:\n  type: redis\n", wantErr: "replay.redis is required"},
		{name: "missing file", usePath: true, path: filepath.Join(dir, "absent.yaml"), wantErr: "no such file"},
		{name: "empty path uses defaults", usePath: true, wantErr: "trustedHosts or externalAuthority"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := tc.path
			if !tc.usePath {
				path = writeFile(t, dir, fmt.Sprintf("%d.yaml", i), tc.yaml)
			}
			got, err := Load(path, tc.ov)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load() error = %v, want containing %q", err, tc.wantErr)
				}
				if !reflect.DeepEqual(got, Config{}) {
					t.Fatalf("Load() = %+v alongside an error, want the zero Config", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load(): %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Load() = %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	files := newTLSFiles(t, t.TempDir())
	rootKey := mintRootKey(t, "tl")
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "valid baseline", mutate: func(*Config) {}},
		{name: "authz policy errors propagate", mutate: func(c *Config) {
			c.TrustedHosts = nil
		}, wantErr: "trustedHosts or externalAuthority"},
		{name: "no transparency logs", mutate: func(c *Config) {
			c.TransparencyLogs = nil
		}, wantErr: "at least one transparencyLogs"},
		{name: "transparency log without name", mutate: func(c *Config) {
			c.TransparencyLogs[0].Name = ""
		}, wantErr: "transparencyLogs[0]: name"},
		{name: "duplicate transparency log names", mutate: func(c *Config) {
			c.TransparencyLogs = append(c.TransparencyLogs, c.TransparencyLogs[0])
		}, wantErr: "transparencyLogs[1]: name \"tl\" is already used"},
		{name: "transparency log without baseURL or rootKeys", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = ""
		}, wantErr: "baseURL or rootKeys"},
		{name: "root keys alone", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = ""
			c.TransparencyLogs[0].RootKeys = []string{rootKey}
		}},
		{name: "root keys with baseURL", mutate: func(c *Config) {
			c.TransparencyLogs[0].RootKeys = []string{rootKey}
		}},
		{name: "root key malformed", mutate: func(c *Config) {
			c.TransparencyLogs[0].RootKeys = []string{rootKey, "tl+00000000+AAAA"}
		}, wantErr: "rootKeys[1]"},
		{name: "baseURL unparseable", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "https://tl.example.com:bad port"
		}, wantErr: "baseURL"},
		{name: "baseURL scheme unsupported", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "ftp://tl.example.com"
		}, wantErr: "scheme must be http or https"},
		{name: "baseURL without host", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "https://"
		}, wantErr: "host"},
		{name: "baseURL with query", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "https://tl.example.com/?x=1"
		}, wantErr: "query"},
		{name: "baseURL with fragment", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "https://tl.example.com/#frag"
		}, wantErr: "fragment"},
		{name: "baseURL with path", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "https://tl.example.com/api"
		}},
		{name: "baseURL uppercase scheme", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "HTTPS://tl.example.com"
		}},
		{name: "http baseURL without allowInsecure", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "http://127.0.0.1:18081"
		}, wantErr: "allowInsecure"},
		{name: "http baseURL with allowInsecure", mutate: func(c *Config) {
			c.TransparencyLogs[0].BaseURL = "http://127.0.0.1:18081"
			c.TransparencyLogs[0].AllowInsecure = true
		}},
		{name: "transparency log timeout zero", mutate: func(c *Config) {
			c.TransparencyLogs[0].Timeout = 0
		}, wantErr: "timeout must be positive"},
		{name: "transparency log timeout negative", mutate: func(c *Config) {
			c.TransparencyLogs[0].Timeout = -time.Second
		}, wantErr: "timeout must be positive"},
		{name: "transparency log timeout equal to checkTimeout", mutate: func(c *Config) {
			c.TransparencyLogs[0].Timeout = c.CheckTimeout
		}, wantErr: "below checkTimeout"},
		{name: "transparency log timeout above checkTimeout", mutate: func(c *Config) {
			c.TransparencyLogs[0].Timeout = c.CheckTimeout + time.Second
		}, wantErr: "below checkTimeout"},
		{name: "checkTimeout at the gateway budget is only a warning", mutate: func(c *Config) {
			c.CheckTimeout = 2 * time.Second
		}},
		{name: "replay redis without a block", mutate: func(c *Config) {
			c.Replay.Type = "redis"
		}, wantErr: "replay.redis is required"},
		{name: "replay redis valid", mutate: func(c *Config) {
			c.Replay.Type = "redis"
			c.Replay.Redis = &RedisConfig{Addr: "127.0.0.1:6379", Timeout: 500 * time.Millisecond}
		}},
		{name: "replay redis missing addr", mutate: func(c *Config) {
			c.Replay.Type = "redis"
			c.Replay.Redis = &RedisConfig{Timeout: 500 * time.Millisecond}
		}, wantErr: "replay.redis.addr is required"},
		{name: "replay redis addr without port", mutate: func(c *Config) {
			c.Replay.Type = "redis"
			c.Replay.Redis = &RedisConfig{Addr: "redis.internal", Timeout: 500 * time.Millisecond}
		}, wantErr: "replay.redis.addr"},
		{name: "replay redis negative db", mutate: func(c *Config) {
			c.Replay.Type = "redis"
			c.Replay.Redis = &RedisConfig{Addr: "127.0.0.1:6379", Timeout: 500 * time.Millisecond, DB: -1}
		}, wantErr: "replay.redis.db"},
		{name: "replay redis zero timeout", mutate: func(c *Config) {
			c.Replay.Type = "redis"
			c.Replay.Redis = &RedisConfig{Addr: "127.0.0.1:6379"}
		}, wantErr: "replay.redis.timeout must be positive"},
		{name: "replay redis timeout at checkTimeout", mutate: func(c *Config) {
			c.Replay.Type = "redis"
			c.Replay.Redis = &RedisConfig{Addr: "127.0.0.1:6379", Timeout: c.CheckTimeout}
		}, wantErr: "below checkTimeout"},
		{name: "replay redis password env unset", mutate: func(c *Config) {
			c.Replay.Type = "redis"
			c.Replay.Redis = &RedisConfig{Addr: "127.0.0.1:6379", Timeout: 500 * time.Millisecond, PasswordEnv: "ANS_TEST_REDIS_PASSWORD_UNSET_FOR_TEST"}
		}, wantErr: "is not set"},
		{name: "duplicate pinned key ids", mutate: func(c *Config) {
			line := mintRootKey(t, "dup")
			c.TransparencyLogs[0].RootKeys = []string{line, line}
		}, wantErr: "duplicate key ID"},
		{name: "replay type unknown", mutate: func(c *Config) {
			c.Replay.Type = "disk"
		}, wantErr: "replay.type"},
		{name: "replay maxEntries zero", mutate: func(c *Config) {
			c.Replay.MaxEntries = 0
		}, wantErr: "replay.maxEntries"},
		{name: "grpc listen empty", mutate: func(c *Config) {
			c.GRPC.Listen = ""
		}, wantErr: "grpc.listen is required"},
		{name: "grpc listen without port", mutate: func(c *Config) {
			c.GRPC.Listen = "127.0.0.1"
		}, wantErr: "grpc.listen"},
		{name: "grpc listen with empty port", mutate: func(c *Config) {
			c.GRPC.Listen = "127.0.0.1:"
		}, wantErr: "port is required"},
		{name: "grpc listen ipv4 loopback", mutate: func(c *Config) {
			c.GRPC.Listen = "127.0.0.1:9191"
		}},
		{name: "grpc listen other ipv4 loopback address", mutate: func(c *Config) {
			c.GRPC.Listen = "127.0.0.2:9191"
		}},
		{name: "grpc listen ipv6 loopback", mutate: func(c *Config) {
			c.GRPC.Listen = "[::1]:9191"
		}},
		{name: "grpc listen localhost", mutate: func(c *Config) {
			c.GRPC.Listen = "localhost:9191"
		}},
		{name: "grpc listen localhost uppercase", mutate: func(c *Config) {
			c.GRPC.Listen = "LOCALHOST:9191"
		}},
		{name: "grpc listen wildcard without tls", mutate: func(c *Config) {
			c.GRPC.Listen = ":9191"
		}, wantErr: "requires grpc.tls or allowInsecureListen"},
		{name: "grpc listen any address without tls", mutate: func(c *Config) {
			c.GRPC.Listen = "0.0.0.0:9191"
		}, wantErr: "requires grpc.tls or allowInsecureListen"},
		{name: "grpc listen ipv6 any address without tls", mutate: func(c *Config) {
			c.GRPC.Listen = "[::]:9191"
		}, wantErr: "requires grpc.tls or allowInsecureListen"},
		{name: "grpc listen hostname without tls", mutate: func(c *Config) {
			c.GRPC.Listen = "gw.internal:9191"
		}, wantErr: "requires grpc.tls or allowInsecureListen"},
		{name: "grpc listen wildcard with allowInsecureListen", mutate: func(c *Config) {
			c.GRPC.Listen = ":9191"
			c.GRPC.AllowInsecureListen = true
		}},
		{name: "grpc listen any address with tls", mutate: func(c *Config) {
			c.GRPC.Listen = "0.0.0.0:9191"
			c.GRPC.TLS = &TLSConfig{CertFile: files.cert, KeyFile: files.key}
		}},
		{name: "grpc tls with client CA", mutate: func(c *Config) {
			c.GRPC.TLS = &TLSConfig{CertFile: files.cert, KeyFile: files.key, ClientCAFile: files.ca}
		}},
		{name: "grpc tls without certFile", mutate: func(c *Config) {
			c.GRPC.TLS = &TLSConfig{KeyFile: files.key}
		}, wantErr: "certFile is required"},
		{name: "grpc tls without keyFile", mutate: func(c *Config) {
			c.GRPC.TLS = &TLSConfig{CertFile: files.cert}
		}, wantErr: "keyFile is required"},
		{name: "grpc tls certFile missing", mutate: func(c *Config) {
			c.GRPC.TLS = &TLSConfig{CertFile: files.missing, KeyFile: files.key}
		}, wantErr: "certFile: stat"},
		{name: "grpc tls keyFile missing", mutate: func(c *Config) {
			c.GRPC.TLS = &TLSConfig{CertFile: files.cert, KeyFile: files.missing}
		}, wantErr: "keyFile: stat"},
		{name: "grpc tls clientCAFile missing", mutate: func(c *Config) {
			c.GRPC.TLS = &TLSConfig{CertFile: files.cert, KeyFile: files.key, ClientCAFile: files.missing}
		}, wantErr: "clientCAFile: stat"},
		{name: "httpListen empty", mutate: func(c *Config) {
			c.HTTPListen = ""
		}, wantErr: "httpListen is required"},
		{name: "httpListen without port", mutate: func(c *Config) {
			c.HTTPListen = "127.0.0.1"
		}, wantErr: "httpListen"},
		{name: "httpListen any address", mutate: func(c *Config) {
			c.HTTPListen = "0.0.0.0:9192"
		}},
		{name: "logLevel debug", mutate: func(c *Config) { c.LogLevel = "debug" }},
		{name: "logLevel info", mutate: func(c *Config) { c.LogLevel = "info" }},
		{name: "logLevel warn", mutate: func(c *Config) { c.LogLevel = "warn" }},
		{name: "logLevel error", mutate: func(c *Config) { c.LogLevel = "error" }},
		{name: "logLevel unknown", mutate: func(c *Config) {
			c.LogLevel = "verbose"
		}, wantErr: "logLevel"},
		{name: "logLevel uppercase", mutate: func(c *Config) {
			c.LogLevel = "INFO"
		}, wantErr: "logLevel"},
		{name: "keyRefreshInterval zero", mutate: func(c *Config) {
			c.KeyRefreshInterval = 0
		}, wantErr: "keyRefreshInterval"},
		{name: "startupTimeout zero", mutate: func(c *Config) {
			c.StartupTimeout = 0
		}, wantErr: "startupTimeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := validConfig()
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestConfigWarnings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		checkTimeout time.Duration
		mutate       func(*Config)
		want         []string
	}{
		{name: "below the gateway budget", checkTimeout: 1500 * time.Millisecond},
		{
			name:         "at the gateway budget",
			checkTimeout: 2 * time.Second,
			want:         []string{"checkTimeout 2s is not below the gateway's 2s ext_authz budget"},
		},
		{
			name:         "above the gateway budget",
			checkTimeout: 3 * time.Second,
			want:         []string{"checkTimeout 3s is not below the gateway's 2s ext_authz budget"},
		},
		{
			name: "plaintext transparency log on a non-loopback host", checkTimeout: 1500 * time.Millisecond,
			mutate: func(c *Config) {
				c.TransparencyLogs[0].BaseURL = "http://tl.internal:18081"
				c.TransparencyLogs[0].AllowInsecure = true
			},
			want: []string{`transparencyLogs "tl" fetches root keys over plaintext from non-loopback tl.internal:18081; an on-path host can inject trust, pin rootKeys`},
		},
		{
			name: "plaintext transparency log on loopback is fine", checkTimeout: 1500 * time.Millisecond,
			mutate: func(c *Config) {
				c.TransparencyLogs[0].BaseURL = "http://localhost:18081"
				c.TransparencyLogs[0].AllowInsecure = true
			},
		},
		{
			name: "missing requiredContext", checkTimeout: 1500 * time.Millisecond,
			mutate: func(c *Config) { c.RequiredContext = nil },
			want:   []string{"requiredContext is not set; a route that stops forwarding the request body cannot be detected for body-less requests"},
		},
		{
			name: "token claims not required", checkTimeout: 1500 * time.Millisecond,
			mutate: func(c *Config) { c.RequireTokenClaims = false },
			want:   []string{"requireTokenClaims is false; an opaque DPoP-bound access token is forwarded without its cnf.jkt check, which the upstream must then enforce (RFC 9449 section 7.1)"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := validConfig()
			c.CheckTimeout = tc.checkTimeout
			c.RequiredContext = &authz.RequiredContext{Key: "ans-authz", Value: "body-forwarded"}
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			got := c.Warnings()
			if len(got) != len(tc.want) {
				t.Fatalf("Warnings() = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Warnings()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
