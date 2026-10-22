package authz

import "time"

// Policy defaults.
const (
	DefaultMaxContentBytes int64         = 1 << 20
	DefaultPoPSkew         time.Duration = 120 * time.Second
	DefaultCheckTimeout    time.Duration = 1500 * time.Millisecond
)

// Config holds the verification policy. It is a plain struct so embedders can
// build it without YAML; the config package embeds it inline and validates it
// together with the service settings.
type Config struct {
	// TrustedHosts lists the externally visible authorities this verifier
	// answers for, each as scheme://authority. The scheme of the matching entry
	// builds the htu the proof is compared against; the request's own scheme is
	// never trusted. Required unless ExternalAuthority is set.
	TrustedHosts []string `yaml:"trustedHosts"`
	// ExternalAuthority, when set as scheme://authority, is joined with the
	// request path to form htu regardless of the request authority.
	ExternalAuthority string `yaml:"externalAuthority"`
	// MaxContentBytes caps the request body the verifier will hash.
	MaxContentBytes int64 `yaml:"maxContentBytes"`
	// RequireReceipt demands the SCITT receipt header on every request.
	RequireReceipt bool `yaml:"requireReceipt"`
	// AllowedAnsNames optionally pins the callers that may pass.
	AllowedAnsNames []string `yaml:"allowedAnsNames"`
	// PoPSkew is the accepted clock skew for the proof's iat.
	PoPSkew time.Duration `yaml:"popSkew"`
	// StripIdentityHeaders removes the SCITT headers (and the DPoP header when
	// no DPoP-bound access token is present) before the upstream sees them.
	StripIdentityHeaders bool `yaml:"stripIdentityHeaders"`
	// CheckTimeout bounds one verification, including any key refresh wait and
	// the replay-cache call. The gateway sends no deadline of its own.
	CheckTimeout time.Duration `yaml:"checkTimeout"`
	// RequiredContext, when set, must appear among the gateway's context
	// extensions; its absence means the route is misconfigured.
	RequiredContext *RequiredContext `yaml:"requiredContext"`
	// RequireTokenClaims demands gateway-validated token claims whenever a
	// DPoP-bound access token is presented, so the cnf.jkt binding is always
	// completed somewhere.
	RequireTokenClaims bool `yaml:"requireTokenClaims"`
	// ExtraIdentityHeaders maps additional header names to an identity
	// attribute (ans_name, agent_id, fingerprint or jkt) set on every allow
	// with the same overwrite semantics as the standard X-ANS-* headers, for
	// gateways or upstreams that key on their own header name.
	ExtraIdentityHeaders map[string]string `yaml:"extraIdentityHeaders"`
}

// RequiredContext names a context-extension key and value the gateway must
// forward with every check.
type RequiredContext struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

// DefaultConfig returns the policy defaults.
func DefaultConfig() Config {
	return Config{
		MaxContentBytes:      DefaultMaxContentBytes,
		RequireReceipt:       true,
		PoPSkew:              DefaultPoPSkew,
		StripIdentityHeaders: true,
		CheckTimeout:         DefaultCheckTimeout,
		RequireTokenClaims:   true,
	}
}
