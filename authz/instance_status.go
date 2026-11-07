package authz

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/agentnameservice/ans-sdk-go/verify"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// issuerStatus picks and checks the status token a request is judged on:
// with the status cache on (maxStatusAge set), the newer of the cached and
// presented tokens; otherwise the presented token, verified against the
// cached TL root keys (refreshing once for an unknown kid, as certificate
// mode does). Either way it must vouch for the x5c certificate under the
// token's name.
func (v *Verifier) issuerStatus(ctx context.Context, raw []byte, it *instanceToken,
	now int64) (*scitt.VerifiedStatusToken, error) {
	var st *scitt.VerifiedStatusToken
	var err error
	if v.statusCache != nil {
		st, err = v.cachedIssuerStatus(ctx, raw, it, now)
	} else {
		st, err = v.presentedIssuerStatus(ctx, raw, now)
	}
	if err != nil {
		return nil, err
	}
	p := &st.Payload
	if err := checkIssuerNames(p, it); err != nil {
		return nil, err
	}
	if p.Status != scitt.StatusActive && p.Status != scitt.StatusWarning {
		return nil, refuse(codeRevoked, CategoryStatusInvalid, "issuer registration is "+echoValue(string(p.Status)))
	}
	if now < it.cert.NotBefore.Unix() || now >= it.cert.NotAfter.Unix() {
		return nil, refuse(codeCertNotCurrent, CategoryCertInvalid, "identity certificate is outside its validity dates")
	}
	if !scitt.MatchesIdentityCert(p, sha256.Sum256(it.certDER)) {
		return nil, refuse(codeCertNotCurrent, CategoryBindingFailed, "x5c certificate is not in the issuer's validIdentityCerts")
	}
	return st, nil
}

// presentedIssuerStatus is the maxStatusAge-0 path: the presented token
// alone, bounded only by its own exp.
func (v *Verifier) presentedIssuerStatus(ctx context.Context, raw []byte, now int64) (*scitt.VerifiedStatusToken, error) {
	st, err := scitt.VerifyStatusTokenAt(raw, v.keys, 0, now)
	if kid, unknown := unknownKeyID(err); unknown && v.keyAvailable(ctx, kid) {
		st, err = scitt.VerifyStatusTokenAt(raw, v.keys, 0, now)
	}
	if err != nil {
		return nil, statusFailure(ctx, err)
	}
	if err := checkStatusClock(&st.Payload, now, statusIATSkew); err != nil {
		return nil, err
	}
	return st, nil
}

// checkStatusClock refuses an expired status token or one whose iat leads
// our clock by more than skew seconds.
func checkStatusClock(p *scitt.StatusTokenPayload, now, skew int64) error {
	if now >= p.Exp {
		return refuse(codeStatusExpired, CategoryStatusInvalid, fmt.Sprintf("status token expired at %d", p.Exp))
	}
	if p.Iat > now+skew {
		return refuse(codeClockSkew, CategoryStatusInvalid, fmt.Sprintf("status token iat %d is %ds ahead", p.Iat, p.Iat-now))
	}
	return nil
}

func statusFailure(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return err
	}
	var te *scitt.TokenError
	if errors.As(err, &te) {
		switch te.Type {
		case scitt.TokenErrExpired:
			return refuse(codeStatusExpired, CategoryStatusInvalid, err.Error())
		case scitt.TokenErrTerminalStatus:
			return refuse(codeRevoked, CategoryStatusInvalid, err.Error())
		case scitt.TokenErrMissingField, scitt.TokenErrPayloadInvalid, scitt.TokenErrPayloadEmpty:
		}
	}
	return refuse(codeBadStatusToken, CategoryStatusInvalid, err.Error())
}

// checkIssuerNames binds the token's iss and ans_name to the status token and
// the certificate: the status token names this ans_name, whose host is iss,
// and the certificate carries it as a URI SAN.
func checkIssuerNames(p *scitt.StatusTokenPayload, it *instanceToken) error {
	stName, err := verify.ParseAnsName(p.AnsName)
	if err != nil || stName.Host != it.claims.iss || p.AnsName != it.claims.ansName {
		return refuse(codeIssMismatch, CategoryBindingFailed, "status token names "+echoValue(p.AnsName)+
			", token says "+echoValue(it.claims.iss)+" "+echoValue(it.claims.ansName))
	}
	for _, u := range it.cert.URIs {
		if u.String() == it.claims.ansName {
			return nil
		}
	}
	return refuse(codeIssMismatch, CategoryBindingFailed, "identity certificate does not name "+echoValue(it.claims.ansName))
}

// checkIssuerAllowed applies allowedAnsNames to the issuer, compared on
// version and host as the SDK compares certificate-mode callers.
func (v *Verifier) checkIssuerAllowed(it *instanceToken) error {
	if len(v.allowedNames) == 0 {
		return nil
	}
	name, err := verify.ParseAnsName(it.claims.ansName)
	if err == nil && v.allowedNames[canonicalAnsName(name)] {
		return nil
	}
	return refusePolicy(codeIssMismatch, "issuer "+echoValue(it.claims.ansName)+" is not in allowedAnsNames")
}

// canonicalAnsName spells an ans:// name by version and host only, the SDK's
// rule for allowedAnsNames.
func canonicalAnsName(n *verify.AnsName) string {
	return "ans://" + n.Version.String() + "." + n.Host
}

// checkAudience requires aud to be this verifier: instanceMode.expectedAud,
// or the host of the authority the request matched.
func (v *Verifier) checkAudience(it *instanceToken, base string) error {
	want := v.cfg.InstanceMode.ExpectedAud
	if want == "" {
		if u, err := url.Parse(base); err == nil {
			want = u.Hostname()
		}
	}
	var aud string
	if json.Unmarshal(it.claims.aud, &aud) != nil || want == "" || aud != want {
		return refuse(codeAudMismatch, CategoryTokenBindingMismatch, "token aud is not "+echoValue(want))
	}
	return nil
}
