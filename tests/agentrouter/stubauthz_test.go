//go:build e2e

package agentrouter

import (
	"context"
	"net"
	"sync"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type stubMode int

const (
	stubAllowWithIdentity stubMode = iota
	stubAllowWithoutIdentity
	stubDeny
)

// stubAuthz is an allow-all ext_authz server used by the wiring spike. It stands in for the
// ANS verifier only to prove the Envoy Gateway plumbing: body forwarding, context extensions,
// header overwrite, authorization on verifier-set headers, denial passthrough and
// statusOnError.
type stubAuthz struct {
	mu       sync.Mutex
	mode     stubMode
	requests []*authv3.CheckRequest
	server   *grpc.Server
	addr     string
}

func startStubAuthz(t *testing.T) *stubAuthz {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	s := &stubAuthz{server: srv, addr: lis.Addr().String()}
	authv3.RegisterAuthorizationServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(s.Stop)
	return s
}

func (s *stubAuthz) Stop() {
	s.mu.Lock()
	srv := s.server
	s.server = nil
	s.mu.Unlock()
	if srv != nil {
		srv.Stop()
	}
}

func (s *stubAuthz) setMode(m stubMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

func (s *stubAuthz) lastRequest() *authv3.CheckRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return nil
	}
	return s.requests[len(s.requests)-1]
}

func (s *stubAuthz) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	s.mu.Lock()
	s.requests = append(s.requests, req)
	mode := s.mode
	s.mu.Unlock()

	switch mode {
	case stubDeny:
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Unauthorized},
				Headers: []*corev3.HeaderValueOption{headerOption("WWW-Authenticate", `DPoP algs="ES256"`)},
				Body:    `{"error":"MISSING_HEADERS"}`,
			}},
		}, nil
	case stubAllowWithoutIdentity:
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{headerOption("x-ans-spike", "ok")},
			}},
		}, nil
	case stubAllowWithIdentity:
		fallthrough
	default:
		return &authv3.CheckResponse{
			Status: &status.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					headerOption("x-ans-spike", "ok"),
					headerOption("x-ans-agent-id", spikeAgentID),
				},
			}},
		}, nil
	}
}

func headerOption(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: key, Value: value},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}
