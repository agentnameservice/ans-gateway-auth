package authz

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/agentnameservice/ans-sdk-go/verify"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// Validate reports the first policy error. It enforces ANS-6 section 7.7:
// a verifier must know its external authorities from configuration and must
// never derive them from the request.
func (c Config) Validate() error {
	if len(c.TrustedHosts) == 0 && c.ExternalAuthority == "" {
		return errors.New("authz: trustedHosts or externalAuthority is required (ANS-6 section 7.7)")
	}
	seen := make(map[string]string, len(c.TrustedHosts))
	for _, h := range c.TrustedHosts {
		scheme, authority, err := parseAuthority(h)
		if err != nil {
			return fmt.Errorf("authz: trustedHosts entry %q: %w", h, err)
		}
		if prev, dup := seen[authority]; dup && prev != scheme {
			return fmt.Errorf("authz: trustedHosts lists %q under both %s and %s", authority, prev, scheme)
		}
		seen[authority] = scheme
	}
	if c.ExternalAuthority != "" {
		if _, _, err := parseAuthority(c.ExternalAuthority); err != nil {
			return fmt.Errorf("authz: externalAuthority %q: %w", c.ExternalAuthority, err)
		}
	}
	for _, n := range c.AllowedAnsNames {
		if _, err := verify.ParseAnsName(n); err != nil {
			return fmt.Errorf("authz: allowedAnsNames entry %q: %w", n, err)
		}
	}
	if c.MaxContentBytes <= 0 {
		return errors.New("authz: maxContentBytes must be positive")
	}
	if c.PoPSkew <= 0 {
		return errors.New("authz: popSkew must be positive")
	}
	if c.CheckTimeout <= 0 {
		return errors.New("authz: checkTimeout must be positive")
	}
	if rc := c.RequiredContext; rc != nil && (rc.Key == "" || rc.Value == "") {
		return errors.New("authz: requiredContext needs both key and value")
	}
	return validateExtraIdentityHeaders(c.ExtraIdentityHeaders)
}

// validateExtraIdentityHeaders requires token header names that do not
// collide with the standard identity headers or each other, each mapped to a
// known identity attribute.
func validateExtraIdentityHeaders(extra map[string]string) error {
	seen := map[string]string{
		strings.ToLower(HeaderANSName):        HeaderANSName,
		strings.ToLower(HeaderANSAgentID):     HeaderANSAgentID,
		strings.ToLower(HeaderANSFingerprint): HeaderANSFingerprint,
		strings.ToLower(HeaderANSJKT):         HeaderANSJKT,
	}
	for name, attribute := range extra {
		if !validHeaderName(name) {
			return fmt.Errorf("authz: extraIdentityHeaders: %q is not a valid header name", name)
		}
		if other, dup := seen[strings.ToLower(name)]; dup {
			return fmt.Errorf("authz: extraIdentityHeaders: %q collides with %q", name, other)
		}
		seen[strings.ToLower(name)] = name
		if !identityAttributes[attribute] {
			return fmt.Errorf("authz: extraIdentityHeaders: %q maps to unknown attribute %q (use %s, %s, %s or %s)",
				name, attribute, MetadataANSName, MetadataAgentID, MetadataFingerprint, MetadataJKT)
		}
	}
	return nil
}

// identityAttributes are the values extraIdentityHeaders may name.
var identityAttributes = map[string]bool{ //nolint:gochecknoglobals // immutable lookup set
	MetadataANSName: true, MetadataAgentID: true, MetadataFingerprint: true, MetadataJKT: true,
}

// validHeaderName reports whether name is an RFC 9110 token.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		b := name[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0:
		default:
			return false
		}
	}
	return true
}

// validHeaderValue reports whether value may be sent as an HTTP field value:
// visible characters, spaces and tabs only (RFC 9110 section 5.5).
func validHeaderValue(value string) bool {
	for i := range len(value) {
		b := value[i]
		if (b < 0x20 && b != '\t') || b == 0x7f {
			return false
		}
	}
	return true
}

// parseAuthority accepts scheme://authority with an http or https scheme and
// no path, query or fragment. It returns the lowercased scheme and the
// authority with the scheme's default port removed.
func parseAuthority(s string) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return "", "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != schemeHTTP && scheme != schemeHTTPS {
		return "", "", errors.New("scheme must be http or https")
	}
	if u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", "", errors.New("must be scheme://authority with no path, query, fragment or userinfo")
	}
	return scheme, normalizeAuthority(scheme, u.Host), nil
}

// normalizeAuthority lowercases an authority and drops the scheme's default
// port, the same rule the SDK applies when it normalizes htu.
func normalizeAuthority(scheme, authority string) string {
	authority = strings.ToLower(strings.TrimSpace(authority))
	switch scheme {
	case schemeHTTPS:
		authority = strings.TrimSuffix(authority, ":443")
	case schemeHTTP:
		authority = strings.TrimSuffix(authority, ":80")
	}
	return authority
}
