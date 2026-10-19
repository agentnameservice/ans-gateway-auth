package authz

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/replay"
)

// Decision results reported to the Observer.
const (
	ResultAllow = "allow"
	ResultDeny  = "deny"
)

// Denial categories. SDK categories keep their pop.ErrorType spelling so deny
// bodies, metrics and the SDK's own vocabulary agree.
const (
	CategoryMalformedRequest       = "MALFORMED_REQUEST"
	CategoryTimeout                = "TIMEOUT"
	CategoryReplayCacheUnavailable = "REPLAY_CACHE_UNAVAILABLE"
	CategoryInternalError          = "INTERNAL_ERROR"
	CategoryMalformedProof         = string(pop.ErrMalformedProof)
	CategoryHTTPBindingMismatch    = string(pop.ErrHTTPBindingMismatch)
	CategorySCITTHeaderInvalid     = string(pop.ErrScittHeaderInvalid)
	CategoryContentUnreadable      = string(pop.ErrContentUnreadable)
	CategoryMissingHeaders         = string(pop.ErrMissingHeaders)
	CategoryReplay                 = string(pop.ErrReplay)
	CategoryReplayCacheFull        = string(pop.ErrReplayCacheFull)
	CategoryTokenBindingMismatch   = string(pop.ErrTokenBindingMismatch)
	CategoryMisconfigured          = string(pop.ErrMisconfigured)
	CategoryClientGone             = string(pop.ErrClientGone)
)

// Identity headers and metadata keys an allow decision carries.
const (
	HeaderANSName        = "X-ANS-Name"
	HeaderANSAgentID     = "X-ANS-Agent-Id"
	HeaderANSFingerprint = "X-ANS-Fingerprint"
	HeaderANSJKT         = "X-ANS-JKT"

	MetadataANSName     = "ans_name"
	MetadataAgentID     = "agent_id"
	MetadataFingerprint = "fingerprint"
	MetadataJKT         = "jkt"
)

const (
	headerAuthorization = "Authorization"
	headerContentLength = "Content-Length"
	claimConfirmation   = "cnf"
	claimThumbprint     = "jkt"
	jwsSegments         = 3
	// replayRetryAfter is the Retry-After offered when the replay cache is
	// saturated or unreachable.
	replayRetryAfter = time.Second
	// misconfigurationLogInterval spaces the operator-facing ERROR logs per
	// reason and authority.
	misconfigurationLogInterval = time.Minute
)

// Request is the transport-neutral view of one gateway check. Scheme is
// informational only: the htu scheme always comes from configuration.
type Request struct {
	Method      string
	Scheme      string
	Authority   string
	Path        string
	Header      http.Header
	Body        []byte
	Partial     bool
	Context     map[string]string
	TokenClaims map[string]any
	RequestID   string
	// RequestIDFromClient marks a RequestID taken from a client-supplied
	// header because the gateway sent none; logs label it so it is never
	// mistaken for a gateway-minted correlation id.
	RequestIDFromClient bool
}

// Denial describes a rejected request by a stable category. Detail is the
// verifier-side reason for logs; it never reaches the response.
type Denial struct {
	HTTPStatus int
	Category   string
	RetryAfter time.Duration
	Detail     string
}

// KeyProvider resolves transparency-log keys and refreshes them on demand;
// *Keyring implements it.
type KeyProvider interface {
	scitt.KeyLookup
	RefreshFor(ctx context.Context) bool
}

// Decision is the outcome of Verify. Headers, Metadata and RemoveHeaders are
// set only on an allow.
type Decision struct {
	Allowed       bool
	Identity      *pop.CallerIdentity
	Headers       map[string]string
	RemoveHeaders []string
	Metadata      map[string]any
	Deny          *Denial
}

type trustedHost struct {
	scheme    string
	authority string
}

// Verifier runs the ANS-6 section 7.4 pipeline over transport-neutral requests.
type Verifier struct {
	cfg      Config
	keys     KeyProvider
	cache    replay.Cache
	obs      Observer
	logger   *slog.Logger
	now      func() time.Time
	trusted  []trustedHost
	external string
	extra    []extraHeader
	baseOpts []pop.CallerOption
	limiter  *logLimiter
}

// extraHeader is one configured extraIdentityHeaders entry.
type extraHeader struct {
	name      string
	attribute string
}

// NewVerifier validates cfg and wires the verifier. A nil Observer selects
// NoopObserver and a nil logger discards the rate-limited misconfiguration
// logs.
func NewVerifier(cfg Config, keys KeyProvider, cache replay.Cache, obs Observer, logger *slog.Logger) (*Verifier, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if k, isKeyring := keys.(*Keyring); keys == nil || (isKeyring && k == nil) {
		return nil, errors.New("authz: keyring is required")
	}
	if cache == nil {
		return nil, errors.New("authz: replay cache is required")
	}
	if obs == nil {
		obs = NoopObserver{}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	v := &Verifier{cfg: cfg, keys: keys, cache: cache, obs: obs, logger: logger, now: time.Now}
	// Validate already parsed every entry, so the errors cannot recur here.
	for _, h := range cfg.TrustedHosts {
		scheme, authority, _ := parseAuthority(h)
		v.trusted = append(v.trusted, trustedHost{scheme: scheme, authority: authority})
	}
	if cfg.ExternalAuthority != "" {
		scheme, authority, _ := parseAuthority(cfg.ExternalAuthority)
		v.external = scheme + "://" + authority
	}
	for name, attribute := range cfg.ExtraIdentityHeaders {
		v.extra = append(v.extra, extraHeader{name: name, attribute: attribute})
	}
	slices.SortFunc(v.extra, func(a, b extraHeader) int { return strings.Compare(a.name, b.name) })
	v.baseOpts = []pop.CallerOption{
		pop.WithRequireReceipt(cfg.RequireReceipt),
		pop.WithPoPSkew(cfg.PoPSkew),
		pop.WithLogger(slog.New(slog.DiscardHandler)),
	}
	if len(cfg.AllowedAnsNames) > 0 {
		v.baseOpts = append(v.baseOpts, pop.WithAllowedAnsNames(cfg.AllowedAnsNames...))
	}
	v.limiter = &logLimiter{
		interval: misconfigurationLogInterval,
		now:      func() time.Time { return v.now() },
		last:     make(map[string]time.Time),
	}
	return v, nil
}

// Verify decides one request within cfg.CheckTimeout. It never returns an
// error: every fault is a Denial, so nothing this verifier emits can be
// admitted by a gateway's failure mode.
func (v *Verifier) Verify(ctx context.Context, r *Request) Decision {
	start := v.now()
	ctx, cancel := context.WithTimeout(ctx, v.cfg.CheckTimeout)
	defer cancel()
	d := v.verify(ctx, r)
	result, category := ResultAllow, ""
	if !d.Allowed {
		result, category = ResultDeny, d.Deny.Category
	}
	v.obs.Decision(result, category, v.now().Sub(start))
	return d
}

func (v *Verifier) verify(ctx context.Context, r *Request) Decision {
	if d := checkShape(r); d != nil {
		return denied(d)
	}
	if d := checkHeaderMultiplicity(r.Header); d != nil {
		return denied(d)
	}
	base, ok := v.htuBase(r.Authority)
	if !ok {
		return denied(deny(http.StatusUnauthorized, CategoryHTTPBindingMismatch))
	}
	if d := v.checkContext(ctx, r, base); d != nil {
		return denied(d)
	}
	if d := v.checkContent(ctx, r, base); d != nil {
		return denied(d)
	}
	hdrs, err := scitt.ExtractHeaders(r.Header)
	if err != nil {
		return denied(deny(http.StatusUnauthorized, CategorySCITTHeaderInvalid))
	}
	tok, tokenPresented := pop.AccessTokenFromAuthorization(r.Header.Get(headerAuthorization))
	id, err := v.authenticate(ctx, r, hdrs, base+pathOnly(r.Path), tok, tokenPresented)
	if err != nil {
		return denied(v.mapError(ctx, err))
	}
	if d := v.completeTokenBinding(ctx, r, id, tok, tokenPresented, base); d != nil {
		return denied(d)
	}
	headers, err := v.identityHeaders(id)
	if err != nil {
		return denied(withDetail(deny(http.StatusServiceUnavailable, CategoryInternalError), err))
	}
	return v.allow(id, headers, tokenPresented)
}

// htuBase returns the scheme://authority the proof must have been minted for,
// or false when the request authority is not one this verifier answers for
// (ANS-6 section 7.7). The request scheme is never consulted.
func (v *Verifier) htuBase(authority string) (string, bool) {
	if authority == "" {
		return "", false
	}
	if len(v.trusted) == 0 {
		return v.external, true
	}
	scheme, ok := v.matchTrusted(authority)
	if !ok {
		return "", false
	}
	if v.external != "" {
		return v.external, true
	}
	return scheme + "://" + normalizeAuthority(scheme, authority), true
}

// matchTrusted compares the request authority against each entry under that
// entry's own default-port rule; the first match in list order wins.
func (v *Verifier) matchTrusted(authority string) (string, bool) {
	for _, h := range v.trusted {
		if normalizeAuthority(h.scheme, authority) == h.authority {
			return h.scheme, true
		}
	}
	return "", false
}

func (v *Verifier) checkContext(ctx context.Context, r *Request, authority string) *Denial {
	rc := v.cfg.RequiredContext
	if rc == nil || r.Context[rc.Key] == rc.Value {
		return nil
	}
	v.logMisconfiguration(ctx, "required context extension missing; forward it next to includeRequestBody",
		authority, slog.String("key", rc.Key))
	return deny(http.StatusServiceUnavailable, CategoryMisconfigured)
}

func (v *Verifier) checkContent(ctx context.Context, r *Request, authority string) *Denial {
	if r.Partial || int64(len(r.Body)) > v.cfg.MaxContentBytes {
		return deny(http.StatusRequestEntityTooLarge, CategoryContentUnreadable)
	}
	declared, err := strconv.ParseInt(r.Header.Get(headerContentLength), 10, 64)
	if err == nil && declared > 0 && len(r.Body) == 0 {
		v.logMisconfiguration(ctx, "request declares a body the gateway did not forward; enable includeRequestBody", authority)
		return deny(http.StatusServiceUnavailable, CategoryMisconfigured)
	}
	return nil
}

// authenticate runs the SDK's three-proof verification, refreshing the root
// keys and retrying once when the proof names a key the keyring does not hold.
func (v *Verifier) authenticate(ctx context.Context, r *Request, hdrs *scitt.Headers, rawURL, tok string,
	tokenPresented bool) (*pop.CallerIdentity, error) {
	verifyOpts := []pop.VerifyOption{pop.WithReceivedContent(func() ([]byte, error) { return r.Body, nil })}
	if tokenPresented {
		verifyOpts = append(verifyOpts, pop.WithBoundAccessToken(tok))
	}
	opts := make([]pop.CallerOption, 0, len(v.baseOpts)+1)
	opts = append(opts, v.baseOpts...)
	opts = append(opts, pop.WithVerifyOptions(verifyOpts...))
	proof := r.Header.Get(pop.DPoPHeader)
	cache := boundReplay{ctx: ctx, cache: v.cache}
	id, err := pop.VerifyCaller(ctx, proof, hdrs, r.Method, rawURL, v.keys, cache, opts...)
	if err != nil && isUnknownKeyID(err) && v.keys.RefreshFor(ctx) {
		id, err = pop.VerifyCaller(ctx, proof, hdrs, r.Method, rawURL, v.keys, cache, opts...)
	}
	return id, err
}

// completeTokenBinding finishes RFC 9449 section 7 token binding: a DPoP-bound
// token's cnf.jkt must name the proof key, and a token carrying cnf.jkt must
// not arrive under another scheme (section 7.2). When the presented token is
// itself a JWS, its own cnf.jkt is read too (unverified, so a match grants
// nothing on its own, but a mismatch is a certain rejection). Opaque tokens
// can only be checked through gateway-forwarded claims, which is what
// RequireTokenClaims demands.
func (v *Verifier) completeTokenBinding(ctx context.Context, r *Request, id *pop.CallerIdentity,
	tok string, tokenPresented bool, authority string) *Denial {
	if !tokenPresented {
		if r.TokenClaims[claimConfirmation] != nil {
			return deny(http.StatusUnauthorized, CategoryTokenBindingMismatch)
		}
		if _, other, found := strings.Cut(r.Header.Get(headerAuthorization), " "); found {
			if jkt, ok := tokenThumbprint(strings.TrimSpace(other)); ok && jkt != "" {
				return deny(http.StatusUnauthorized, CategoryTokenBindingMismatch)
			}
		}
		return nil
	}
	if jkt, ok := tokenThumbprint(tok); ok && jkt != "" && subtle.ConstantTimeCompare([]byte(jkt), []byte(id.JKT)) != 1 {
		return deny(http.StatusUnauthorized, CategoryTokenBindingMismatch)
	}
	if r.TokenClaims == nil {
		if !v.cfg.RequireTokenClaims {
			return nil
		}
		v.logMisconfiguration(ctx, "DPoP-bound access token presented without gateway-validated claims; "+
			"forward the token claims or set requireTokenClaims to false", authority)
		return deny(http.StatusServiceUnavailable, CategoryMisconfigured)
	}
	jkt := confirmationThumbprint(r.TokenClaims)
	if jkt == "" || subtle.ConstantTimeCompare([]byte(jkt), []byte(id.JKT)) != 1 {
		return deny(http.StatusUnauthorized, CategoryTokenBindingMismatch)
	}
	return nil
}

// mapError classifies a verification failure. Context errors are inspected
// first so a budget expiry or a gateway cancellation is never reported as a
// backend fault. The failure text is kept as Detail for the decision log.
func (v *Verifier) mapError(ctx context.Context, err error) *Denial {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			v.obs.CheckTimeout()
			return withDetail(deny(http.StatusServiceUnavailable, CategoryTimeout), err)
		}
		return withDetail(deny(http.StatusServiceUnavailable, CategoryClientGone), err)
	}
	var pe *pop.ProofError
	isProofError := errors.As(err, &pe)
	switch {
	case errors.Is(err, replay.ErrUnavailable):
		return withDetail(&Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheUnavailable, RetryAfter: v.replayRetryAfter(err)}, err)
	case errors.Is(err, replay.ErrFull), isProofError && pe.Type == pop.ErrReplayCacheFull:
		return withDetail(&Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheFull, RetryAfter: replayRetryAfter}, err)
	case !isProofError:
		return withDetail(deny(http.StatusServiceUnavailable, CategoryMisconfigured), err)
	case pe.Type == pop.ErrMisconfigured, pe.Type == pop.ErrClientGone:
		return withDetail(deny(http.StatusServiceUnavailable, string(pe.Type)), err)
	default:
		return withDetail(deny(http.StatusUnauthorized, string(pe.Type)), err)
	}
}

// replayRetryAfter advises the caller to wait out a keyspace-loss window when
// the backend reports one, else the fixed backend-retry hint.
func (v *Verifier) replayRetryAfter(err error) time.Duration {
	var reset *replay.KeyspaceResetError
	if errors.As(err, &reset) {
		if remaining := reset.Until.Sub(v.now()); remaining > replayRetryAfter {
			return remaining
		}
	}
	return replayRetryAfter
}

func withDetail(d *Denial, err error) *Denial {
	var pe *pop.ProofError
	switch {
	case errors.As(err, &pe):
		d.Detail = pe.Message
		if pe.Cause != nil {
			d.Detail += ": " + pe.Cause.Error()
		}
	case err != nil:
		d.Detail = err.Error()
	}
	return d
}

// identityHeaders renders the standard X-ANS-* headers plus the configured
// extra ones. Every value is checked as an HTTP field value even though it
// comes from signed material, so a defective issuer cannot inject header
// framing.
func (v *Verifier) identityHeaders(id *pop.CallerIdentity) (map[string]string, error) {
	attributes := map[string]string{
		MetadataANSName: id.AnsName, MetadataAgentID: id.AgentID,
		MetadataFingerprint: id.FingerprintHex(), MetadataJKT: id.JKT,
	}
	headers := map[string]string{
		HeaderANSName: attributes[MetadataANSName], HeaderANSAgentID: attributes[MetadataAgentID],
		HeaderANSFingerprint: attributes[MetadataFingerprint], HeaderANSJKT: attributes[MetadataJKT],
	}
	for _, e := range v.extra {
		headers[e.name] = attributes[e.attribute]
	}
	for name, value := range headers {
		if !validHeaderValue(value) {
			return nil, fmt.Errorf("identity attribute for header %s is not a valid header field value", name)
		}
	}
	return headers, nil
}

// allow builds the identity contract. The identity headers are set with
// overwrite semantics, which replaces any client-supplied value; they are
// deliberately not listed for removal, because Envoy applies removals after
// additions and would strip them again.
func (v *Verifier) allow(id *pop.CallerIdentity, headers map[string]string, tokenPresented bool) Decision {
	fingerprint := id.FingerprintHex()
	var remove []string
	if v.cfg.StripIdentityHeaders {
		remove = append(remove, strings.ToLower(scitt.HeaderReceipt), strings.ToLower(scitt.HeaderStatusToken))
		if !tokenPresented {
			remove = append(remove, strings.ToLower(pop.DPoPHeader))
		}
	}
	return Decision{
		Allowed:  true,
		Identity: id,
		Headers:  headers,
		Metadata: map[string]any{
			MetadataANSName: id.AnsName, MetadataAgentID: id.AgentID,
			MetadataFingerprint: fingerprint, MetadataJKT: id.JKT,
		},
		RemoveHeaders: remove,
	}
}

// logMisconfiguration emits one ERROR per reason and authority per interval.
// Header values are never logged.
func (v *Verifier) logMisconfiguration(ctx context.Context, msg, authority string, attrs ...slog.Attr) {
	if !v.limiter.allow(msg + "|" + authority) {
		return
	}
	v.logger.LogAttrs(ctx, slog.LevelError, msg, append([]slog.Attr{slog.String("authority", authority)}, attrs...)...)
}

func checkShape(r *Request) *Denial {
	if r == nil || r.Method == "" || !strings.HasPrefix(r.Path, "/") {
		return deny(http.StatusBadRequest, CategoryMalformedRequest)
	}
	return nil
}

// checkHeaderMultiplicity rejects a request carrying more than one value for a
// header a decision reads (RFC 9449 section 4.3 for DPoP; the same reasoning
// covers Authorization and the SCITT headers), since a downstream hop could
// otherwise act on a different value than this verifier did. A comma inside a
// value is rejected too: none of these grammars admits one, and a gateway
// that folds duplicate headers into one comma-joined value would otherwise
// hide the duplicate.
func checkHeaderMultiplicity(h http.Header) *Denial {
	for _, name := range []string{pop.DPoPHeader, headerAuthorization, scitt.HeaderReceipt, scitt.HeaderStatusToken} {
		values := h.Values(name)
		if len(values) > 1 {
			return deny(http.StatusUnauthorized, CategoryMalformedProof)
		}
		for _, value := range values {
			if strings.Contains(value, ",") {
				return deny(http.StatusUnauthorized, CategoryMalformedProof)
			}
		}
	}
	return nil
}

// tokenThumbprint reads cnf.jkt from an access token that is a JWS compact
// serialization, without verifying it. ok is false for opaque tokens. Padding
// is tolerated so a re-encoded payload cannot dodge the check.
func tokenThumbprint(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != jwsSegments {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	return confirmationThumbprint(claims), true
}

func confirmationThumbprint(claims map[string]any) string {
	cnf, ok := claims[claimConfirmation].(map[string]any)
	if !ok {
		return ""
	}
	jkt, ok := cnf[claimThumbprint].(string)
	if !ok {
		return ""
	}
	return jkt
}

func isUnknownKeyID(err error) bool {
	var sigErr *scitt.SignatureError
	return errors.As(err, &sigErr) && sigErr.Type == scitt.SigErrUnknownKeyID
}

func pathOnly(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

func deny(status int, category string) *Denial {
	return &Denial{HTTPStatus: status, Category: category}
}

func denied(d *Denial) Decision { return Decision{Deny: d} }

// boundReplay satisfies pop.ReplayCache for one request so the check budget
// and the gateway's cancellation reach the backend.
type boundReplay struct {
	ctx   context.Context
	cache replay.Cache
}

func (b boundReplay) CheckAndStore(key string, exp time.Time) (bool, error) {
	return b.cache.CheckAndStore(b.ctx, key, exp)
}

// logLimiter admits one event per key per interval. Keys derive from
// configuration, so the map stays bounded.
type logLimiter struct {
	interval time.Duration
	now      func() time.Time
	mu       sync.Mutex
	last     map[string]time.Time
}

func (l *logLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if last, ok := l.last[key]; ok && now.Sub(last) < l.interval {
		return false
	}
	l.last[key] = now
	return true
}
