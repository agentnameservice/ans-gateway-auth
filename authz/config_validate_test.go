package authz

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	c := DefaultConfig()
	c.TrustedHosts = []string{"https://gw.example.com"}
	return c
}

func validIssuer() InstanceIssuer {
	return InstanceIssuer{Host: "issuer.example.test", AgentID: "00000000-0000-4000-8000-000000000001", TL: "tl"}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "defaults with a trusted host", mutate: func(*Config) {}},
		{name: "external authority alone", mutate: func(c *Config) {
			c.TrustedHosts = nil
			c.ExternalAuthority = "https://gw.example.com"
		}},
		{name: "both trusted hosts and external authority", mutate: func(c *Config) {
			c.ExternalAuthority = "https://public.example.com:8443"
		}},
		{name: "same authority under one scheme twice", mutate: func(c *Config) {
			c.TrustedHosts = []string{"https://gw.example.com", "https://GW.example.com:443"}
		}},
		{name: "allowed ans names parse", mutate: func(c *Config) {
			c.AllowedAnsNames = []string{"ans://v1.0.0.caller.example"}
		}},
		{name: "required context complete", mutate: func(c *Config) {
			c.RequiredContext = &RequiredContext{Key: "ans-authz", Value: "body-forwarded"}
		}},
		{name: "extra identity headers", mutate: func(c *Config) {
			c.ExtraIdentityHeaders = map[string]string{"x-ai-eg-mcp-subject": "agent_id", "X-Caller": "ans_name"}
		}},
		{name: "extra identity header with an unknown attribute", mutate: func(c *Config) {
			c.ExtraIdentityHeaders = map[string]string{"x-caller": "status"}
		}, wantErr: "unknown attribute"},
		{name: "extra identity header with an invalid name", mutate: func(c *Config) {
			c.ExtraIdentityHeaders = map[string]string{"x caller": "ans_name"}
		}, wantErr: "not a valid header name"},
		{name: "extra identity header colliding with a standard one", mutate: func(c *Config) {
			c.ExtraIdentityHeaders = map[string]string{"x-ans-name": "agent_id"}
		}, wantErr: "collides"},
		{name: "extra identity headers colliding by case", mutate: func(c *Config) {
			c.ExtraIdentityHeaders = map[string]string{"x-caller": "agent_id", "X-Caller": "ans_name"}
		}, wantErr: "collides"},
		{name: "instance mode with issuers", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				ExpectedAud: "gw.example.com", MaxInstancesPerSub: 3}
		}},
		{name: "instance mode off ignores its other fields", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{AllowedIssuers: []string{"Not A Host"}}
		}},
		{name: "instance mode without issuers", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true}
		}, wantErr: "instanceMode.allowedIssuers"},
		{name: "instance issuer not lowercase", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"Issuer.example.test"}}
		}, wantErr: "bare lowercase host"},
		{name: "instance issuer as a URL", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"https://issuer.example.test"}}
		}, wantErr: "bare lowercase host"},
		{name: "instance issuer with a port", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test:443"}}
		}, wantErr: "bare lowercase host"},
		{name: "instance expected aud as a URL", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				ExpectedAud: "https://gw.example.com"}
		}, wantErr: "instanceMode.expectedAud"},
		{name: "instance max status age negative", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: -time.Second}
		}, wantErr: "maxStatusAge"},
		{name: "instance max status age set", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{validIssuer()}}
		}},
		{name: "instance max status age without issuers", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute}
		}, wantErr: `instanceMode.issuers has no entry for allowedIssuers host "issuer.example.test"`},
		{name: "instance max status age below the minimum", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 9 * time.Second, Issuers: []InstanceIssuer{validIssuer()}}
		}, wantErr: "maxStatusAge must be at least 10s"},
		{name: "instance issuers without max status age", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				Issuers: []InstanceIssuer{validIssuer()}}
		}, wantErr: "instanceMode.issuers needs maxStatusAge"},
		{name: "instance issuer entry not allowlisted", mutate: func(c *Config) {
			other := validIssuer()
			other.Host = "other.example.test"
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{validIssuer(), other}}
		}, wantErr: `instanceMode.issuers[1]: host "other.example.test" is not in allowedIssuers`},
		{name: "instance issuer entry duplicated", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{validIssuer(), validIssuer()}}
		}, wantErr: "instanceMode.issuers[1]: host \"issuer.example.test\" is listed twice"},
		{name: "instance issuer agent id not a UUID", mutate: func(c *Config) {
			bad := validIssuer()
			bad.AgentID = "../root-keys"
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{bad}}
		}, wantErr: "instanceMode.issuers[0]: agentId"},
		{name: "instance issuer agent id with a misplaced dash", mutate: func(c *Config) {
			bad := validIssuer()
			bad.AgentID = "000000000-000-4000-8000-000000000001"
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{bad}}
		}, wantErr: "instanceMode.issuers[0]: agentId"},
		{name: "instance issuer agent id with a non-hex digit", mutate: func(c *Config) {
			bad := validIssuer()
			bad.AgentID = "0000000g-0000-4000-8000-000000000001"
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{bad}}
		}, wantErr: "instanceMode.issuers[0]: agentId"},
		{name: "instance issuer agent id in upper case", mutate: func(c *Config) {
			ok := validIssuer()
			ok.AgentID = "ABCDEF00-0000-4000-8000-000000000001"
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{ok}}
		}},
		{name: "instance issuer without a TL", mutate: func(c *Config) {
			bad := validIssuer()
			bad.TL = ""
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxStatusAge: 5 * time.Minute, Issuers: []InstanceIssuer{bad}}
		}, wantErr: "instanceMode.issuers[0]: tl"},
		{name: "instance cap negative", mutate: func(c *Config) {
			c.InstanceMode = InstanceMode{Enabled: true, AllowedIssuers: []string{"issuer.example.test"},
				MaxInstancesPerSub: -1}
		}, wantErr: "maxInstancesPerSub"},
		{name: "neither trusted hosts nor external authority", mutate: func(c *Config) {
			c.TrustedHosts = nil
		}, wantErr: "trustedHosts or externalAuthority"},
		{name: "trusted host without scheme", mutate: func(c *Config) {
			c.TrustedHosts = []string{"gw.example.com"}
		}, wantErr: "scheme must be http or https"},
		{name: "trusted host with unsupported scheme", mutate: func(c *Config) {
			c.TrustedHosts = []string{"grpc://gw.example.com"}
		}, wantErr: "scheme must be http or https"},
		{name: "trusted host with path", mutate: func(c *Config) {
			c.TrustedHosts = []string{"https://gw.example.com/api"}
		}, wantErr: "no path"},
		{name: "trusted host with query", mutate: func(c *Config) {
			c.TrustedHosts = []string{"https://gw.example.com?x=1"}
		}, wantErr: "no path"},
		{name: "trusted host with userinfo", mutate: func(c *Config) {
			c.TrustedHosts = []string{"https://user@gw.example.com"}
		}, wantErr: "no path"},
		{name: "trusted host unparseable", mutate: func(c *Config) {
			c.TrustedHosts = []string{"https://gw.example.com:bad port"}
		}, wantErr: "trustedHosts entry"},
		{name: "authority under two schemes", mutate: func(c *Config) {
			c.TrustedHosts = []string{"https://gw.example.com", "http://gw.example.com"}
		}, wantErr: "under both"},
		{name: "external authority with path", mutate: func(c *Config) {
			c.ExternalAuthority = "https://gw.example.com/x"
		}, wantErr: "externalAuthority"},
		{name: "allowed ans name malformed", mutate: func(c *Config) {
			c.AllowedAnsNames = []string{"not-an-ans-name"}
		}, wantErr: "allowedAnsNames entry"},
		{name: "max content bytes zero", mutate: func(c *Config) {
			c.MaxContentBytes = 0
		}, wantErr: "maxContentBytes"},
		{name: "pop skew zero", mutate: func(c *Config) {
			c.PoPSkew = 0
		}, wantErr: "popSkew"},
		{name: "check timeout negative", mutate: func(c *Config) {
			c.CheckTimeout = -time.Second
		}, wantErr: "checkTimeout"},
		{name: "required context missing value", mutate: func(c *Config) {
			c.RequiredContext = &RequiredContext{Key: "ans-authz"}
		}, wantErr: "requiredContext"},
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

func TestParseAuthority(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in            string
		wantScheme    string
		wantAuthority string
		wantErr       bool
	}{
		{in: "https://GW.Example.com:443", wantScheme: "https", wantAuthority: "gw.example.com"},
		{in: "http://gw.example.com:80", wantScheme: "http", wantAuthority: "gw.example.com"},
		{in: "http://gw.example.com:443", wantScheme: "http", wantAuthority: "gw.example.com:443"},
		{in: "HTTPS://127.0.0.1:8080", wantScheme: "https", wantAuthority: "127.0.0.1:8080"},
		{in: " https://gw.example.com ", wantScheme: "https", wantAuthority: "gw.example.com"},
		{in: "https://", wantErr: true},
		{in: "ftp://gw.example.com", wantErr: true},
		{in: "https://gw.example.com#frag", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			scheme, authority, err := parseAuthority(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAuthority(%q) = %q %q, want error", tc.in, scheme, authority)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAuthority(%q): %v", tc.in, err)
			}
			if scheme != tc.wantScheme || authority != tc.wantAuthority {
				t.Fatalf("parseAuthority(%q) = %q %q, want %q %q", tc.in, scheme, authority, tc.wantScheme, tc.wantAuthority)
			}
		})
	}
}

func TestHeaderFieldChecks(t *testing.T) {
	t.Parallel()
	names := []struct {
		name string
		ok   bool
	}{
		{name: "x-ai-eg-mcp-subject", ok: true}, {name: "X_Caller.v2", ok: true},
		{name: "", ok: false}, {name: "x caller", ok: false}, {name: "x:caller", ok: false}, {name: "héader", ok: false},
	}
	for _, tc := range names {
		if got := validHeaderName(tc.name); got != tc.ok {
			t.Errorf("validHeaderName(%q) = %v, want %v", tc.name, got, tc.ok)
		}
	}
	values := []struct {
		value string
		ok    bool
	}{
		{value: "ans://v1.0.0.caller.example", ok: true}, {value: "with space\tand tab", ok: true}, {value: "", ok: true},
		{value: "bad\r\nx-injected: 1", ok: false}, {value: "nul\x00", ok: false}, {value: "del\x7f", ok: false},
	}
	for _, tc := range values {
		if got := validHeaderValue(tc.value); got != tc.ok {
			t.Errorf("validHeaderValue(%q) = %v, want %v", tc.value, got, tc.ok)
		}
	}
}
