package extauthz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/agentnameservice/ans-gateway-auth/authz"
)

const (
	// DefaultDrainTimeout bounds GracefulStop before in-flight checks are cut.
	DefaultDrainTimeout = 10 * time.Second
	// recvHeadroom is added to the content cap for proof, receipt and status
	// token headers plus protobuf framing.
	recvHeadroom = 1 << 20
	// logFieldLimit bounds client-influenced strings in the decision log.
	logFieldLimit = 256
	// maxConcurrentStreams bounds the HTTP/2 streams one gateway connection
	// may hold open; grpc-go's default is unlimited.
	maxConcurrentStreams = 1024
)

// Decider makes the verification decision; *authz.Verifier implements it.
type Decider interface {
	Verify(ctx context.Context, r *authz.Request) authz.Decision
}

// ServerTLS names the listener certificate and, for mutual TLS, the CA that
// must have issued the gateway's client certificate.
type ServerTLS struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

// Server is the ext_authz Authorization service.
type Server struct {
	authv3.UnimplementedAuthorizationServer

	decider         Decider
	logger          *slog.Logger
	tls             *tls.Config
	maxRecv         int
	drain           time.Duration
	claimsNamespace string
}

// Option configures a Server.
type Option func(*Server)

// WithTLS serves TLS on the listener with cfg, typically from
// ServerTLS.Config, so unusable material fails at startup rather than at
// the first accept.
func WithTLS(cfg *tls.Config) Option {
	return func(s *Server) { s.tls = cfg }
}

// WithLogger sets the decision logger; the default discards.
func WithLogger(l *slog.Logger) Option {
	return func(s *Server) { s.logger = l }
}

// WithMaxContentBytes sizes the gRPC receive limit from the verifier's
// content cap, so a body the gateway may forward always fits.
func WithMaxContentBytes(n int64) Option {
	return func(s *Server) { s.maxRecv = int(n) + recvHeadroom }
}

// WithTokenClaimsNamespace names the filter_metadata namespace forwarded
// access-token claims are read from; the default is MetadataNamespace.
func WithTokenClaimsNamespace(ns string) Option {
	return func(s *Server) {
		if ns != "" {
			s.claimsNamespace = ns
		}
	}
}

// WithDrainTimeout bounds the graceful stop at shutdown.
func WithDrainTimeout(d time.Duration) Option {
	return func(s *Server) { s.drain = d }
}

// NewServer wraps a decider. Telemetry is wired through the verifier's
// Observer; the server is transport only.
func NewServer(v Decider, opts ...Option) *Server {
	s := &Server{
		decider:         v,
		logger:          slog.New(slog.DiscardHandler),
		maxRecv:         int(authz.DefaultMaxContentBytes) + recvHeadroom,
		claimsNamespace: MetadataNamespace,
		drain:           DefaultDrainTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Check implements the ext_authz Authorization service. Every fault is a
// denial in the response, including a panic while verifying client-supplied
// material; the only gRPC error Check returns is the caller's own
// cancellation. The transport rejects a message above the receive limit before
// Check runs, which the gateway's failure mode must turn into a denial.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	var resp *authv3.CheckResponse
	var err error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.LogAttrs(ctx, slog.LevelError, "panic during check",
					slog.Any("panic", recovered), slog.String("stack", string(debug.Stack())))
				resp = ToCheckResponse(authz.Decision{Deny: &authz.Denial{
					HTTPStatus: http.StatusServiceUnavailable,
					Category:   authz.CategoryInternalError,
				}})
				err = nil
			}
		}()
		resp, err = s.check(ctx, req)
	}()
	return resp, err
}

func (s *Server) check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := time.Now()
	r, err := FromCheckRequest(req, s.claimsNamespace)
	if err != nil {
		s.logger.LogAttrs(ctx, slog.LevelWarn, "malformed CheckRequest", slog.String("error", err.Error()))
		return ToCheckResponse(authz.Decision{Deny: &authz.Denial{
			HTTPStatus: http.StatusBadRequest,
			Category:   authz.CategoryMalformedRequest,
		}}), nil
	}
	d := s.decider.Verify(ctx, r)
	if ctx.Err() != nil {
		return nil, grpcstatus.FromContextError(ctx.Err()).Err()
	}
	s.logDecision(ctx, r, d, time.Since(start))
	return ToCheckResponse(d), nil
}

// logDecision writes one line per check. Server-side faults (5xx denials)
// log at WARN so they survive a warn-level production log; header values are
// never logged and client-influenced fields are bounded.
func (s *Server) logDecision(ctx context.Context, r *authz.Request, d authz.Decision, elapsed time.Duration) {
	result, category, ansName, reason := "allow", "", "", ""
	status := http.StatusOK
	level := slog.LevelInfo
	if d.Identity != nil {
		ansName = d.Identity.AnsName
	}
	if !d.Allowed {
		result = "deny"
		if d.Deny != nil {
			category, reason, status = d.Deny.Category, d.Deny.Detail, d.Deny.HTTPStatus
		}
		if status >= http.StatusInternalServerError {
			level = slog.LevelWarn
		}
	}
	path, _, _ := strings.Cut(r.Path, "?")
	idSource := "gateway"
	switch {
	case r.RequestID == "":
		idSource = "none"
	case r.RequestIDFromClient:
		idSource = "client"
	}
	s.logger.LogAttrs(ctx, level, "decision",
		slog.String("request_id", truncate(r.RequestID)),
		slog.String("request_id_source", idSource),
		slog.String("method", truncate(r.Method)),
		slog.String("authority", truncate(r.Authority)),
		slog.String("path", truncate(path)),
		slog.String("result", result),
		slog.Int("status", status),
		slog.String("category", category),
		slog.String("reason", truncate(reason)),
		slog.String("ans_name", ansName),
		slog.Int64("duration_ms", elapsed.Milliseconds()),
	)
}

func truncate(s string) string {
	if len(s) <= logFieldLimit {
		return s
	}
	return s[:logFieldLimit] + "..."
}

// Register adds the Authorization service to a gRPC server, for embedding.
func (s *Server) Register(reg grpc.ServiceRegistrar) {
	authv3.RegisterAuthorizationServer(reg, s)
}

// Serve runs the gRPC server on lis until ctx is cancelled, then flips the
// health service to NOT_SERVING and drains in-flight checks for at most the
// drain timeout. It returns nil after a clean shutdown.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	opts := []grpc.ServerOption{grpc.MaxRecvMsgSize(s.maxRecv), grpc.MaxConcurrentStreams(maxConcurrentStreams)}
	if s.tls != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(s.tls)))
	}
	gs := grpc.NewServer(opts...)
	s.Register(gs)

	hs := health.NewServer()
	healthpb.RegisterHealthServer(gs, hs)
	hs.SetServingStatus(authv3.Authorization_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)

	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()

	select {
	case err := <-served:
		if err != nil {
			return fmt.Errorf("extauthz: serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo, "shutdown started; health NOT_SERVING, draining in-flight checks",
		slog.Duration("drain_timeout", s.drain))
	hs.Shutdown()
	drained := make(chan struct{})
	go func() {
		gs.GracefulStop()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(s.drain):
		s.logger.LogAttrs(ctx, slog.LevelWarn, "drain deadline exceeded; forcing stop")
		gs.Stop()
		<-drained
	}
	<-served
	s.logger.LogAttrs(ctx, slog.LevelInfo, "ext_authz listener stopped")
	return nil
}

// Config loads the TLS material: TLS 1.3 minimum, mutual TLS when a client
// CA is named. Load it at startup so bad material fails before serving.
func (t ServerTLS) Config() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("extauthz: load server certificate: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
	if t.ClientCAFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(t.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("extauthz: read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("extauthz: client CA file holds no certificates")
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = pool
	return cfg, nil
}
