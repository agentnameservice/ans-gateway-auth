// Package extauthz exposes the ANS verifier as an Envoy ext_authz gRPC
// service, the extension point agentgateway, Agent Router and other
// Envoy-family gateways share.
package extauthz

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-gateway-auth/authz"
)

const (
	// MetadataNamespace is the filter_metadata namespace the gateway recipe
	// uses to forward validated access-token claims
	// (protocol.grpc.metadata: {ans-authz: '{"jwt_payload": jwt}'}).
	MetadataNamespace = "ans-authz"
	// CompatMetadataNamespace is the Envoy jwt_authn namespace agentgateway
	// fills when no explicit metadata expression is configured.
	CompatMetadataNamespace = "envoy.filters.http.jwt_authn"
	jwtPayloadKey           = "jwt_payload"

	partialBodyHeader = "X-Envoy-Auth-Partial-Body"
	requestIDHeader   = "X-Request-Id"
	traceparentHeader = "Traceparent"

	// DPoPChallenge is the WWW-Authenticate value on every 401 (RFC 9449 §7.1).
	DPoPChallenge = `DPoP algs="ES256"`

	maxHTTPStatus = 599
)

// ErrMalformedCheckRequest reports a CheckRequest without HTTP attributes.
var ErrMalformedCheckRequest = errors.New("extauthz: CheckRequest has no HTTP request attributes")

// FromCheckRequest maps an Envoy CheckRequest to the transport-neutral
// request. The scheme is carried for logging only; the verifier never trusts
// it.
func FromCheckRequest(req *authv3.CheckRequest) (*authz.Request, error) {
	attrs := req.GetAttributes()
	hr := attrs.GetRequest().GetHttp()
	if hr == nil {
		return nil, ErrMalformedCheckRequest
	}
	header := headersFrom(hr)
	partial := hr.GetSize() < 0 || strings.EqualFold(header.Get(partialBodyHeader), "true")
	header.Del(partialBodyHeader)

	authority := hr.GetHost()
	if authority == "" {
		authority = pseudoHeader(hr, ":authority")
	}
	if authority == "" {
		authority = header.Get("Host")
	}

	body := hr.GetRawBody()
	if len(body) == 0 && hr.GetBody() != "" {
		body = []byte(hr.GetBody())
	}

	id, fromClient := requestID(hr, header)
	return &authz.Request{
		Method:              hr.GetMethod(),
		Scheme:              strings.ToLower(hr.GetScheme()),
		Authority:           authority,
		Path:                hr.GetPath(),
		Header:              header,
		Body:                body,
		Partial:             partial,
		Context:             attrs.GetContextExtensions(),
		TokenClaims:         tokenClaims(attrs.GetMetadataContext()),
		RequestID:           id,
		RequestIDFromClient: fromClient,
	}, nil
}

// headersFrom prefers header_map, which preserves duplicate names, over the
// comma-joined headers map. Pseudo-headers are not request headers.
func headersFrom(hr *authv3.AttributeContext_HttpRequest) http.Header {
	header := http.Header{}
	if entries := hr.GetHeaderMap().GetHeaders(); len(entries) > 0 {
		for _, hv := range entries {
			if strings.HasPrefix(hv.GetKey(), ":") {
				continue
			}
			value := hv.GetValue()
			if raw := hv.GetRawValue(); len(raw) > 0 {
				value = string(raw)
			}
			header.Add(hv.GetKey(), value)
		}
		return header
	}
	for k, v := range hr.GetHeaders() {
		if strings.HasPrefix(k, ":") {
			continue
		}
		header.Add(k, v)
	}
	return header
}

func pseudoHeader(hr *authv3.AttributeContext_HttpRequest, name string) string {
	for _, hv := range hr.GetHeaderMap().GetHeaders() {
		if hv.GetKey() == name {
			if raw := hv.GetRawValue(); len(raw) > 0 {
				return string(raw)
			}
			return hv.GetValue()
		}
	}
	return hr.GetHeaders()[name]
}

// tokenClaims returns the validated access-token claims the gateway forwarded,
// from the recipe's explicit namespace first, else the jwt_authn namespace.
func tokenClaims(md *corev3.Metadata) map[string]any {
	for _, ns := range []string{MetadataNamespace, CompatMetadataNamespace} {
		payload := md.GetFilterMetadata()[ns].GetFields()[jwtPayloadKey]
		if s := payload.GetStructValue(); s != nil {
			return s.AsMap()
		}
	}
	return nil
}

// requestID prefers the gateway's own request id; the client-supplied headers
// are fallbacks for gateways that send none, reported as such.
func requestID(hr *authv3.AttributeContext_HttpRequest, header http.Header) (string, bool) {
	if id := hr.GetId(); id != "" {
		return id, false
	}
	if id := header.Get(requestIDHeader); id != "" {
		return id, true
	}
	if id := header.Get(traceparentHeader); id != "" {
		return id, true
	}
	return "", false
}

// ToCheckResponse maps a decision to the Envoy response. Allowed decisions
// overwrite the identity headers, remove the headers the verifier names and
// publish the identity as dynamic metadata (CEL `extauthz.<key>`). Denials
// carry a fixed JSON body naming only the category.
func ToCheckResponse(d authz.Decision) *authv3.CheckResponse {
	if d.Allowed {
		return &authv3.CheckResponse{
			Status: &status.Status{Code: statusCode(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
				Headers:         headerOptions(d.Headers, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD),
				HeadersToRemove: removalsNotSet(d.RemoveHeaders, d.Headers),
			}},
			DynamicMetadata: metadataStruct(d.Metadata),
		}
	}
	// A decision that is neither allowed nor carries a denial violates the
	// verifier contract; failing closed is cheaper than trusting it.
	denial := authz.Denial{HTTPStatus: http.StatusServiceUnavailable, Category: authz.CategoryMisconfigured}
	if d.Deny != nil {
		denial = *d.Deny
	}
	headers := map[string]string{
		"Content-Type":  "application/json",
		"Cache-Control": "no-store",
	}
	if denial.HTTPStatus == http.StatusUnauthorized {
		headers["WWW-Authenticate"] = DPoPChallenge
	}
	if denial.RetryAfter > 0 {
		headers["Retry-After"] = retryAfterSeconds(denial.RetryAfter)
	}
	body, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: denial.Category})
	return &authv3.CheckResponse{
		Status: &status.Status{Code: statusCode(grpcCode(denial.HTTPStatus)), Message: denial.Category},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status:  &typev3.HttpStatus{Code: httpStatusCode(denial.HTTPStatus)},
			Headers: headerOptions(headers, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD),
			Body:    string(body),
		}},
	}
}

// httpStatusCode narrows an HTTP status for the denied response; anything
// outside the HTTP range becomes 503 so the gateway never admits the request.
func httpStatusCode(n int) typev3.StatusCode {
	if n < http.StatusContinue || n > maxHTTPStatus {
		return typev3.StatusCode_ServiceUnavailable
	}
	return typev3.StatusCode(n)
}

// statusCode narrows a gRPC code for the proto Status; codes are 0..16.
func statusCode(c codes.Code) int32 {
	if c > math.MaxInt32 {
		return int32(codes.Unknown)
	}
	return int32(c)
}

func grpcCode(httpStatus int) codes.Code {
	switch httpStatus {
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusRequestEntityTooLarge:
		return codes.ResourceExhausted
	case http.StatusServiceUnavailable:
		return codes.Unavailable
	case http.StatusBadRequest:
		return codes.InvalidArgument
	default:
		return codes.PermissionDenied
	}
}

// removalsNotSet drops removals that name a header the decision also sets.
// Envoy applies removals after additions, so such an entry would strip the
// value just written; overwrite semantics already replace client values.
func removalsNotSet(removals []string, set map[string]string) []string {
	if len(removals) == 0 {
		return nil
	}
	out := make([]string, 0, len(removals))
	for _, name := range removals {
		if _, dup := set[http.CanonicalHeaderKey(name)]; dup {
			continue
		}
		clash := false
		for setName := range set {
			if strings.EqualFold(setName, name) {
				clash = true
				break
			}
		}
		if !clash {
			out = append(out, name)
		}
	}
	return out
}

// headerOptions renders headers in name order so responses are deterministic.
func headerOptions(headers map[string]string, action corev3.HeaderValueOption_HeaderAppendAction) []*corev3.HeaderValueOption {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	opts := make([]*corev3.HeaderValueOption, 0, len(names))
	for _, name := range names {
		opts = append(opts, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: name, Value: headers[name]},
			AppendAction: action,
		})
	}
	return opts
}

// metadataStruct converts the identity metadata; a value structpb cannot
// represent is dropped rather than failing the whole decision.
func metadataStruct(md map[string]any) *structpb.Struct {
	fields := make(map[string]*structpb.Value, len(md))
	for k, v := range md {
		if val, err := structpb.NewValue(v); err == nil {
			fields[k] = val
		}
	}
	return &structpb.Struct{Fields: fields}
}

func retryAfterSeconds(d time.Duration) string {
	return strconv.FormatInt(int64(math.Ceil(d.Seconds())), 10)
}
