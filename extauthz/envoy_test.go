package extauthz

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/agentnameservice/ans-gateway-auth/authz"
)

func httpRequest(mutate func(*authv3.AttributeContext_HttpRequest)) *authv3.CheckRequest {
	hr := &authv3.AttributeContext_HttpRequest{
		Method: http.MethodPost,
		Path:   "/echo?x=1",
		Host:   "127.0.0.1:8080",
		Scheme: "HTTP",
		Headers: map[string]string{
			":method":      "POST",
			":path":        "/echo?x=1",
			":authority":   "127.0.0.1:8080",
			"dpop":         "proof",
			"x-request-id": "req-1",
		},
		RawBody: []byte(`{"a":1}`),
		Size:    7,
	}
	if mutate != nil {
		mutate(hr)
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Request: &authv3.AttributeContext_Request{Http: hr},
	}}
}

func claimsMetadata(ns string, payload *structpb.Value) *corev3.Metadata {
	return &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
		ns: {Fields: map[string]*structpb.Value{jwtPayloadKey: payload}},
	}}
}

func TestFromCheckRequestRejectsMissingHTTP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  *authv3.CheckRequest
	}{
		{name: "nil request", req: nil},
		{name: "no attributes", req: &authv3.CheckRequest{}},
		{name: "no request", req: &authv3.CheckRequest{Attributes: &authv3.AttributeContext{}}},
		{name: "no http", req: &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := FromCheckRequest(tt.req); !errors.Is(err, ErrMalformedCheckRequest) {
				t.Fatalf("err = %v, want ErrMalformedCheckRequest", err)
			}
		})
	}
}

func TestFromCheckRequestMapping(t *testing.T) {
	t.Parallel()
	runMappingCases(t, []mappingCase{
		{
			name: "basic fields, pseudo-headers dropped, scheme lowercased",
			check: func(t *testing.T, r *authz.Request) {
				if r.Method != http.MethodPost || r.Path != "/echo?x=1" || r.Authority != "127.0.0.1:8080" || r.Scheme != "http" {
					t.Fatalf("basic fields = %+v", r)
				}
				if got := r.Header.Get("Dpop"); got != "proof" {
					t.Fatalf("Dpop = %q", got)
				}
				for k := range r.Header {
					if k[0] == ':' {
						t.Fatalf("pseudo-header %q leaked", k)
					}
				}
				if string(r.Body) != `{"a":1}` || r.Partial {
					t.Fatalf("body = %q partial = %v", r.Body, r.Partial)
				}
				if r.RequestID != "req-1" {
					t.Fatalf("RequestID = %q", r.RequestID)
				}
				if r.TokenClaims != nil || r.Context != nil {
					t.Fatalf("claims = %v context = %v, want nil", r.TokenClaims, r.Context)
				}
			},
		},
		{
			name: "header_map wins and preserves duplicates",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) {
				hr.HeaderMap = &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
					{Key: ":authority", Value: "ignored"},
					{Key: "dpop", Value: "one"},
					{Key: "dpop", RawValue: []byte("two")},
				}}
			},
			check: func(t *testing.T, r *authz.Request) {
				if got := r.Header.Values("Dpop"); !reflect.DeepEqual(got, []string{"one", "two"}) {
					t.Fatalf("Dpop values = %v", got)
				}
				if r.Header.Get("X-Request-Id") != "" {
					t.Fatal("headers map must be ignored when header_map is present")
				}
			},
		},
		{
			name:   "authority falls back to :authority then Host header",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) { hr.Host = "" },
			check: func(t *testing.T, r *authz.Request) {
				if r.Authority != "127.0.0.1:8080" {
					t.Fatalf("Authority = %q", r.Authority)
				}
			},
		},
		{
			name: "authority from header_map :authority",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) {
				hr.Host = ""
				hr.HeaderMap = &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: ":authority", RawValue: []byte("gw.example:443")}}}
			},
			check: func(t *testing.T, r *authz.Request) {
				if r.Authority != "gw.example:443" {
					t.Fatalf("Authority = %q", r.Authority)
				}
			},
		},
		{
			name: "authority from Host header when no pseudo-header",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) {
				hr.Host = ""
				hr.Headers = map[string]string{"host": "legacy.example"}
			},
			check: func(t *testing.T, r *authz.Request) {
				if r.Authority != "legacy.example" {
					t.Fatalf("Authority = %q", r.Authority)
				}
			},
		},
		{
			name: "string body used when raw body is empty",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) {
				hr.RawBody = nil
				hr.Body = "text"
			},
			check: func(t *testing.T, r *authz.Request) {
				if string(r.Body) != "text" {
					t.Fatalf("Body = %q", r.Body)
				}
			},
		},
		{
			name:   "negative size marks a partial body",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) { hr.Size = -1 },
			check: func(t *testing.T, r *authz.Request) {
				if !r.Partial {
					t.Fatal("Partial = false")
				}
			},
		},
		{
			name:   "envoy partial-body header marks a partial body and is consumed",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) { hr.GetHeaders()["x-envoy-auth-partial-body"] = "TRUE" },
			check: func(t *testing.T, r *authz.Request) {
				if !r.Partial || r.Header.Get(partialBodyHeader) != "" {
					t.Fatalf("Partial = %v header = %q", r.Partial, r.Header.Get(partialBodyHeader))
				}
			},
		},
		{
			name:   "partial-body header false is not partial",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) { hr.GetHeaders()["x-envoy-auth-partial-body"] = "false" },
			check: func(t *testing.T, r *authz.Request) {
				if r.Partial {
					t.Fatal("Partial = true")
				}
			},
		},
	})
}

type mappingCase struct {
	name   string
	mutate func(*authv3.AttributeContext_HttpRequest)
	attrs  func(*authv3.AttributeContext)
	check  func(t *testing.T, r *authz.Request)
}

func runMappingCases(t *testing.T, tests []mappingCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httpRequest(tt.mutate)
			if tt.attrs != nil {
				tt.attrs(req.GetAttributes())
			}
			r, err := FromCheckRequest(req)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, r)
		})
	}
}

func TestFromCheckRequestMetadata(t *testing.T) {
	t.Parallel()
	jkt := structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
		"cnf": structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{"jkt": structpb.NewStringValue("thumb")}}),
	}})
	runMappingCases(t, []mappingCase{
		{
			name: "context extensions are carried",
			attrs: func(a *authv3.AttributeContext) {
				a.ContextExtensions = map[string]string{"ans-authz": "body-forwarded"}
			},
			check: func(t *testing.T, r *authz.Request) {
				if r.Context["ans-authz"] != "body-forwarded" {
					t.Fatalf("Context = %v", r.Context)
				}
			},
		},
		{
			name:  "claims from the recipe namespace",
			attrs: func(a *authv3.AttributeContext) { a.MetadataContext = claimsMetadata(MetadataNamespace, jkt) },
			check: func(t *testing.T, r *authz.Request) {
				cnf, _ := r.TokenClaims["cnf"].(map[string]any)
				if cnf["jkt"] != "thumb" {
					t.Fatalf("TokenClaims = %v", r.TokenClaims)
				}
			},
		},
		{
			name:  "claims from the compat namespace",
			attrs: func(a *authv3.AttributeContext) { a.MetadataContext = claimsMetadata(CompatMetadataNamespace, jkt) },
			check: func(t *testing.T, r *authz.Request) {
				if r.TokenClaims == nil {
					t.Fatal("TokenClaims = nil")
				}
			},
		},
		{
			name: "non-struct payload yields no claims",
			attrs: func(a *authv3.AttributeContext) {
				a.MetadataContext = claimsMetadata(MetadataNamespace, structpb.NewStringValue("opaque"))
			},
			check: func(t *testing.T, r *authz.Request) {
				if r.TokenClaims != nil {
					t.Fatalf("TokenClaims = %v, want nil", r.TokenClaims)
				}
			},
		},
		{
			name:   "gateway request id wins over the client header",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) { hr.Id = "attr-id" },
			check: func(t *testing.T, r *authz.Request) {
				if r.RequestID != "attr-id" {
					t.Fatalf("RequestID = %q", r.RequestID)
				}
			},
		},
		{
			name: "request id from traceparent",
			mutate: func(hr *authv3.AttributeContext_HttpRequest) {
				delete(hr.GetHeaders(), "x-request-id")
				hr.GetHeaders()["traceparent"] = "00-trace-span-01"
			},
			check: func(t *testing.T, r *authz.Request) {
				if r.RequestID != "00-trace-span-01" {
					t.Fatalf("RequestID = %q", r.RequestID)
				}
			},
		},
	})
}

func TestToCheckResponseAllow(t *testing.T) {
	t.Parallel()
	resp := ToCheckResponse(authz.Decision{
		Allowed:       true,
		Headers:       map[string]string{"X-ANS-Name": "ans://v1.0.0.caller.example", "X-ANS-JKT": "thumb"},
		RemoveHeaders: []string{"x-ans-name", "dpop"},
		Metadata:      map[string]any{"ans_name": "ans://v1.0.0.caller.example", "jkt": "thumb", "bad": make(chan int)},
	})
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("status = %d", resp.GetStatus().GetCode())
	}
	ok := resp.GetOkResponse()
	if ok == nil {
		t.Fatal("no OkResponse")
	}
	names := make([]string, 0, len(ok.GetHeaders()))
	for _, h := range ok.GetHeaders() {
		names = append(names, h.GetHeader().GetKey())
		if h.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Fatalf("append action = %v", h.GetAppendAction())
		}
	}
	if !reflect.DeepEqual(names, []string{"X-ANS-JKT", "X-ANS-Name"}) {
		t.Fatalf("header order = %v", names)
	}
	if !reflect.DeepEqual(ok.GetHeadersToRemove(), []string{"dpop"}) {
		t.Fatalf("headers to remove = %v, want the set header dropped from the removals", ok.GetHeadersToRemove())
	}
	md := resp.GetDynamicMetadata().AsMap()
	if md["ans_name"] != "ans://v1.0.0.caller.example" || md["jkt"] != "thumb" {
		t.Fatalf("dynamic metadata = %v", md)
	}
	if _, present := md["bad"]; present {
		t.Fatal("unrepresentable metadata value must be dropped")
	}
}

func TestToCheckResponseDeny(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		deny          *authz.Denial
		wantGRPC      codes.Code
		wantHTTP      int
		wantCategory  string
		wantChallenge bool
		wantRetry     string
	}{
		{
			name: "401 carries the DPoP challenge", deny: &authz.Denial{HTTPStatus: 401, Category: "REPLAY"},
			wantGRPC: codes.Unauthenticated, wantHTTP: 401, wantCategory: "REPLAY", wantChallenge: true,
		},
		{
			name: "413 is resource exhausted", deny: &authz.Denial{HTTPStatus: 413, Category: "CONTENT_UNREADABLE"},
			wantGRPC: codes.ResourceExhausted, wantHTTP: 413, wantCategory: "CONTENT_UNREADABLE",
		},
		{
			name: "503 with retry-after rounds up", deny: &authz.Denial{HTTPStatus: 503, Category: "REPLAY_CACHE_FULL", RetryAfter: 1500 * time.Millisecond},
			wantGRPC: codes.Unavailable, wantHTTP: 503, wantCategory: "REPLAY_CACHE_FULL", wantRetry: "2",
		},
		{
			name: "400 is invalid argument", deny: &authz.Denial{HTTPStatus: 400, Category: "MALFORMED_REQUEST"},
			wantGRPC: codes.InvalidArgument, wantHTTP: 400, wantCategory: "MALFORMED_REQUEST",
		},
		{
			name: "other statuses are permission denied", deny: &authz.Denial{HTTPStatus: 403, Category: "FORBIDDEN"},
			wantGRPC: codes.PermissionDenied, wantHTTP: 403, wantCategory: "FORBIDDEN",
		},
		{
			name: "status outside the HTTP range becomes 503", deny: &authz.Denial{HTTPStatus: 7, Category: "WEIRD"},
			wantGRPC: codes.PermissionDenied, wantHTTP: 503, wantCategory: "WEIRD",
		},
		{
			name: "missing denial fails closed", deny: nil,
			wantGRPC: codes.Unavailable, wantHTTP: 503, wantCategory: authz.CategoryMisconfigured,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := ToCheckResponse(authz.Decision{Deny: tt.deny})
			if got := codes.Code(resp.GetStatus().GetCode()); got != tt.wantGRPC {
				t.Fatalf("grpc code = %v, want %v", got, tt.wantGRPC)
			}
			denied := resp.GetDeniedResponse()
			if denied == nil {
				t.Fatal("no DeniedResponse")
			}
			if int(denied.GetStatus().GetCode()) != tt.wantHTTP {
				t.Fatalf("http status = %d, want %d", denied.GetStatus().GetCode(), tt.wantHTTP)
			}
			headers := map[string]string{}
			for _, h := range denied.GetHeaders() {
				headers[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
			}
			if headers["Content-Type"] != "application/json" || headers["Cache-Control"] != "no-store" {
				t.Fatalf("headers = %v", headers)
			}
			if challenge, ok := headers["WWW-Authenticate"]; ok != tt.wantChallenge || (ok && challenge != DPoPChallenge) {
				t.Fatalf("WWW-Authenticate = %q present=%v, want present=%v", challenge, ok, tt.wantChallenge)
			}
			if headers["Retry-After"] != tt.wantRetry {
				t.Fatalf("Retry-After = %q, want %q", headers["Retry-After"], tt.wantRetry)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(denied.GetBody()), &body); err != nil || body.Error != tt.wantCategory {
				t.Fatalf("body = %q (%v), want category %q", denied.GetBody(), err, tt.wantCategory)
			}
		})
	}
}

func TestRemovalsNotSet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		removals []string
		set      map[string]string
		want     []string
	}{
		{name: "nil removals", set: map[string]string{"X-ANS-Name": "a"}},
		{name: "set header dropped case-insensitively", removals: []string{"x-ans-name", "X-ANS-JKT", "dpop"},
			set: map[string]string{"X-ANS-Name": "a", "X-ANS-JKT": "b"}, want: []string{"dpop"}},
		{name: "nothing set keeps all", removals: []string{"dpop", "x-scitt-receipt"}, want: []string{"dpop", "x-scitt-receipt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := removalsNotSet(tt.removals, tt.set)
			if len(got) != len(tt.want) || (len(got) > 0 && !reflect.DeepEqual(got, tt.want)) {
				t.Fatalf("removalsNotSet = %v, want %v", got, tt.want)
			}
		})
	}
}
