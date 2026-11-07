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
	// InstanceMode admits callers that hold no ANS certificate of their own:
	// a local agent instance presenting a short-lived instance token signed by
	// an ANS-registered issuer's identity-certificate key. Off by default.
	InstanceMode InstanceMode `yaml:"instanceMode"`
}

// InstanceMode configures the second caller mode. A request selects it by
// presenting `Authorization: DPoP <JWS whose header typ is "instance+jwt">`
// with no X-SCITT-Receipt; every other request takes the certificate path.
type InstanceMode struct {
	// Enabled turns instance mode on. When false an instance request is
	// refused (MISSING_HEADERS, reason instance_disabled).
	Enabled bool `yaml:"enabled"`
	// AllowedIssuers lists the issuers whose instance tokens are accepted, as
	// bare lowercase hosts (the host inside the issuer's ans:// name, e.g.
	// "authority.example.com"). A token's iss is checked against this list
	// before any key or transparency-log lookup. Required when Enabled.
	AllowedIssuers []string `yaml:"allowedIssuers"`
	// ExpectedAud is the aud an instance token must carry, as a bare lowercase
	// host. Empty means the host of the authority the request matched
	// (externalAuthority, or the matching trustedHosts entry).
	ExpectedAud string `yaml:"expectedAud"`
	// MaxInstancesPerSub caps how many distinct instance keys (cnf.jkt) one
	// issuer's sub may present while their tokens are live; the next distinct
	// key is refused (EXPECTED_PEER_MISMATCH, reason instance_cap). Zero turns
	// the cap off. The count is per verifier process, not shared across
	// replicas.
	MaxInstancesPerSub int `yaml:"maxInstancesPerSub"`
	// MaxStatusAge, when positive, refuses an issuer status token issued
	// longer ago than this (STATUS_INVALID, reason status_stale), and lets
	// its iat lead the verifier's clock by at most 60 s so a future-dated
	// token cannot extend its freshness. Zero means the token is accepted
	// until its own exp.
	MaxStatusAge time.Duration `yaml:"maxStatusAge"`
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
