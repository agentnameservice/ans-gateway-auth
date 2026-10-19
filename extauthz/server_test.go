package extauthz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/agentnameservice/ans-gateway-auth/authz"
	"github.com/agentnameservice/ans-gateway-auth/replay"
)

// serve starts s on lis and returns a stop function that cancels the server
// context and waits for Serve to return, reporting its error. It is safe to
// call more than once; the cleanup calls it too.
func serve(t *testing.T, s *Server, lis net.Listener) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()
	var once sync.Once
	var result error
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case result = <-done:
			case <-time.After(10 * time.Second):
				result = errors.New("Serve did not return after cancellation")
			}
		})
		return result
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Error(err)
		}
	})
	return stop
}

func bufconnClient(t *testing.T, lis *bufconn.Listener) authv3.AuthorizationClient {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return authv3.NewAuthorizationClient(conn)
}

func headerValue(opts []*corev3HeaderValueOption, name string) string {
	for _, o := range opts {
		if strings.EqualFold(o.GetHeader().GetKey(), name) {
			return o.GetHeader().GetValue()
		}
	}
	return ""
}

func TestServerCheck(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	lis := bufconn.Listen(1 << 20)
	serve(t, NewServer(f.verifier), lis)
	client := bufconnClient(t, lis)
	ctx := context.Background()

	t.Run("signed request is allowed with identity headers and metadata", func(t *testing.T) {
		t.Parallel()
		resp, err := client.Check(ctx, f.signedCheckRequest(t, http.MethodPost, "/echo", []byte(`{"a":1}`)))
		if err != nil {
			t.Fatal(err)
		}
		if codes.Code(resp.GetStatus().GetCode()) != codes.OK {
			t.Fatalf("status = %v body %s", resp.GetStatus(), resp.GetDeniedResponse().GetBody())
		}
		if got := headerValue(resp.GetOkResponse().GetHeaders(), "X-ANS-Name"); got != fixtureAnsName {
			t.Fatalf("X-ANS-Name = %q", got)
		}
		if got := resp.GetDynamicMetadata().AsMap()["ans_name"]; got != fixtureAnsName {
			t.Fatalf("metadata ans_name = %v", got)
		}
	})

	t.Run("request without identity is denied with a challenge", func(t *testing.T) {
		t.Parallel()
		req, _ := http.NewRequest(http.MethodGet, fixtureBaseURL+"/echo", nil)
		resp, err := client.Check(ctx, checkRequestFrom(req, nil))
		if err != nil {
			t.Fatal(err)
		}
		if codes.Code(resp.GetStatus().GetCode()) != codes.Unauthenticated {
			t.Fatalf("status = %v", resp.GetStatus())
		}
		denied := resp.GetDeniedResponse()
		if denied.GetStatus().GetCode() != 401 || headerValue(denied.GetHeaders(), "WWW-Authenticate") != DPoPChallenge {
			t.Fatalf("denied = %v", denied)
		}
	})

	t.Run("malformed CheckRequest is a 400 denial", func(t *testing.T) {
		t.Parallel()
		resp, err := client.Check(ctx, &authv3.CheckRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if codes.Code(resp.GetStatus().GetCode()) != codes.InvalidArgument || resp.GetDeniedResponse().GetStatus().GetCode() != 400 {
			t.Fatalf("resp = %v", resp)
		}
		if !strings.Contains(resp.GetDeniedResponse().GetBody(), authz.CategoryMalformedRequest) {
			t.Fatalf("body = %q", resp.GetDeniedResponse().GetBody())
		}
	})

	t.Run("health reports serving", func(t *testing.T) {
		t.Parallel()
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hc := healthpb.NewHealthClient(conn)
		for _, svc := range []string{"", authv3.Authorization_ServiceDesc.ServiceName} {
			resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{Service: svc})
			if err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
				t.Fatalf("health %q = %v, %v", svc, resp.GetStatus(), err)
			}
		}
	})
}

func TestServerCancelledCallerGetsContextError(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	s := NewServer(f.verifier)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Check(ctx, f.signedCheckRequest(t, http.MethodGet, "/echo", nil))
	if status.Code(err) != codes.Canceled {
		t.Fatalf("err = %v, want Canceled", err)
	}
}

func TestServerShutdownStopsServing(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	lis := bufconn.Listen(1 << 20)
	stop := serve(t, NewServer(f.verifier), lis)
	client := bufconnClient(t, lis)
	if _, err := client.Check(context.Background(), &authv3.CheckRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v after cancellation", err)
	}
	ctx, cancelProbe := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelProbe()
	if _, err := client.Check(ctx, &authv3.CheckRequest{}); err == nil {
		t.Fatal("Check succeeded after shutdown")
	}
}

// blockingCache parks CheckAndStore until the request context ends, so an
// in-flight check can be observed during shutdown.
type blockingCache struct {
	entered chan struct{}
}

func (b *blockingCache) CheckAndStore(ctx context.Context, _ string, _ time.Time) (bool, error) {
	close(b.entered)
	<-ctx.Done()
	return false, ctx.Err()
}
func (*blockingCache) Stats() replay.Stats { return replay.Stats{Backend: "blocking", Up: true} }
func (*blockingCache) Close() error        { return nil }

func TestServerDrainTimeoutForcesStop(t *testing.T) {
	t.Parallel()
	cache := &blockingCache{entered: make(chan struct{})}
	f := newFixture(t, cache)
	lis := bufconn.Listen(1 << 20)
	stop := serve(t, NewServer(f.verifier, WithDrainTimeout(50*time.Millisecond)), lis)
	client := bufconnClient(t, lis)

	checkDone := make(chan error, 1)
	go func() {
		_, err := client.Check(context.Background(), f.signedCheckRequest(t, http.MethodGet, "/echo", nil))
		checkDone <- err
	}()
	select {
	case <-cache.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("check never reached the replay cache")
	}
	start := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("Serve returned %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("shutdown took %s, drain timeout was not enforced", elapsed)
	}
	if err := <-checkDone; err == nil {
		t.Fatal("in-flight check completed successfully after a forced stop")
	}
}

func TestServerMaxRecvMsgSize(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	lis := bufconn.Listen(1 << 20)
	serve(t, NewServer(f.verifier, WithMaxContentBytes(1024)), lis)
	client := bufconnClient(t, lis)

	big := make([]byte, recvHeadroom+2048)
	_, err := client.Check(context.Background(), f.signedCheckRequest(t, http.MethodPost, "/echo", big))
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want ResourceExhausted", err)
	}
	small := make([]byte, 512)
	resp, err := client.Check(context.Background(), f.signedCheckRequest(t, http.MethodPost, "/echo", small))
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("small body: resp %v err %v", resp.GetStatus(), err)
	}
}

func TestServerServeListenerError(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = lis.Close()
	if err := NewServer(f.verifier).Serve(context.Background(), lis); err == nil || !strings.Contains(err.Error(), "extauthz: serve") {
		t.Fatalf("err = %v", err)
	}
}

// pki holds a throwaway CA with one server and one client leaf on disk.
type pki struct {
	dir                   string
	caPEM                 []byte
	serverCert, serverKey string
	clientCert, clientKey string
	pool                  *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	dir := t.TempDir()
	caKey, caTmpl := newKeyAndTemplate(t, "ans-authz test CA", nil)
	caTmpl.IsCA = true
	caTmpl.KeyUsage |= x509.KeyUsageCertSign
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	p := &pki{dir: dir, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pool: x509.NewCertPool()}
	p.pool.AddCert(caCert)
	p.serverCert, p.serverKey = p.issue(t, "server", caCert, caKey, x509.ExtKeyUsageServerAuth, net.ParseIP("127.0.0.1"))
	p.clientCert, p.clientKey = p.issue(t, "client", caCert, caKey, x509.ExtKeyUsageClientAuth, nil)
	writeFile(t, filepath.Join(dir, "ca.pem"), p.caPEM)
	return p
}

func (p *pki) issue(t *testing.T, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage, ip net.IP) (string, string) {
	t.Helper()
	key, tmpl := newKeyAndTemplate(t, name, []x509.ExtKeyUsage{usage})
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(p.dir, name+".pem")
	keyPath := filepath.Join(p.dir, name+".key")
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func newKeyAndTemplate(t *testing.T, cn string, usages []x509.ExtKeyUsage) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return key, &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
		BasicConstraintsValid: true,
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestServerMutualTLS(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	f := newFixture(t, nil)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := ServerTLS{CertFile: p.serverCert, KeyFile: p.serverKey, ClientCAFile: filepath.Join(p.dir, "ca.pem")}.Config()
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert || tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("tls config = %+v", tlsCfg)
	}
	serve(t, NewServer(f.verifier, WithTLS(tlsCfg)), lis)

	clientCert, err := tls.LoadX509KeyPair(p.clientCert, p.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		tlsCfg  *tls.Config
		wantErr bool
	}{
		{name: "client certificate accepted", tlsCfg: &tls.Config{RootCAs: p.pool, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13}},
		{name: "missing client certificate rejected", tlsCfg: &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS13}, wantErr: true},
		{name: "TLS 1.2 rejected", tlsCfg: &tls.Config{RootCAs: p.pool, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn, dialErr := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(tt.tlsCfg)))
			if dialErr != nil {
				t.Fatal(dialErr)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := authv3.NewAuthorizationClient(conn).Check(ctx, &authv3.CheckRequest{})
			if tt.wantErr {
				if err == nil {
					t.Fatal("Check succeeded, want a transport error")
				}
				return
			}
			if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.InvalidArgument {
				t.Fatalf("resp %v err %v", resp.GetStatus(), err)
			}
		})
	}
}

func TestServerTLSConfigErrors(t *testing.T) {
	t.Parallel()
	p := newPKI(t)
	empty := filepath.Join(p.dir, "empty.pem")
	writeFile(t, empty, []byte("not a certificate"))
	tests := []struct {
		name string
		tls  ServerTLS
		want string
	}{
		{name: "missing certificate", tls: ServerTLS{CertFile: filepath.Join(p.dir, "nope.pem"), KeyFile: p.serverKey}, want: "load server certificate"},
		{name: "missing client CA", tls: ServerTLS{CertFile: p.serverCert, KeyFile: p.serverKey, ClientCAFile: filepath.Join(p.dir, "nope-ca.pem")}, want: "read client CA"},
		{name: "client CA without certificates", tls: ServerTLS{CertFile: p.serverCert, KeyFile: p.serverKey, ClientCAFile: empty}, want: "holds no certificates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := tt.tls.Config()
			if err == nil || cfg != nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Config() = %v, %v, want %q", cfg, err, tt.want)
			}
		})
	}
	t.Run("server-only material", func(t *testing.T) {
		t.Parallel()
		cfg, err := ServerTLS{CertFile: p.serverCert, KeyFile: p.serverKey}.Config()
		if err != nil || cfg.ClientAuth != tls.NoClientCert || len(cfg.Certificates) != 1 {
			t.Fatalf("Config() = %+v, %v", cfg, err)
		}
	})
}

func TestServerLogsDecisions(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	rec := &recordingHandler{}
	s := NewServer(f.verifier, WithLogger(slogNew(rec)))
	resp, err := s.Check(context.Background(), f.signedCheckRequest(t, http.MethodPost, "/echo?secret=1", []byte("x")))
	if err != nil || codes.Code(resp.GetStatus().GetCode()) != codes.OK {
		t.Fatalf("resp %v err %v", resp.GetStatus(), err)
	}
	record := rec.last()
	if record["msg"] != "decision" || record["result"] != "allow" || record["ans_name"] != fixtureAnsName || record["path"] != "/echo" ||
		record["level"] != slog.LevelInfo.String() || record["status"] != int64(200) || record["reason"] != "" {
		t.Fatalf("decision log = %v", record)
	}
	if _, err := s.Check(context.Background(), checkRequestFrom(httptest.NewRequest(http.MethodGet, fixtureBaseURL+"/echo", nil), nil)); err != nil {
		t.Fatal(err)
	}
	if record := rec.last(); record["result"] != "deny" || record["status"] != int64(401) || record["category"] != authz.CategoryMissingHeaders ||
		record["level"] != slog.LevelInfo.String() || record["reason"] == "" {
		t.Fatalf("401 decision log = %v", record)
	}
	if _, malformedErr := s.Check(context.Background(), &authv3.CheckRequest{}); malformedErr != nil {
		t.Fatal(malformedErr)
	}
	if record := rec.last(); record["msg"] != "malformed CheckRequest" {
		t.Fatalf("malformed log = %v", record)
	}
}

// scriptedDecider returns a fixed decision, or panics when told to.
type scriptedDecider struct {
	decision authz.Decision
	panics   bool
}

func (d scriptedDecider) Verify(context.Context, *authz.Request) authz.Decision {
	if d.panics {
		panic("sdk parser bug")
	}
	return d.decision
}

func TestServerLogsServerFaultsAtWarn(t *testing.T) {
	t.Parallel()
	rec := &recordingHandler{}
	s := NewServer(scriptedDecider{decision: authz.Decision{Deny: &authz.Denial{
		HTTPStatus: http.StatusServiceUnavailable, Category: authz.CategoryReplayCacheUnavailable, Detail: "dial tcp: refused",
	}}}, WithLogger(slogNew(rec)))
	long := strings.Repeat("a", 2*logFieldLimit)
	req := checkRequestFrom(httptest.NewRequest(http.MethodGet, "http://"+long+"/echo?x=1", nil), nil)
	req.GetAttributes().GetRequest().GetHttp().Id = long
	if _, err := s.Check(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	record := rec.last()
	if record["level"] != slog.LevelWarn.String() || record["status"] != int64(503) || record["reason"] != "dial tcp: refused" {
		t.Fatalf("5xx decision log = %v", record)
	}
	for _, field := range []string{"request_id", "authority"} {
		if got, _ := record[field].(string); len(got) > logFieldLimit+3 || !strings.HasSuffix(got, "...") {
			t.Fatalf("%s = %q, want it truncated to %d bytes", field, got, logFieldLimit)
		}
	}
}

func TestServerRecoversFromPanic(t *testing.T) {
	t.Parallel()
	rec := &recordingHandler{}
	s := NewServer(scriptedDecider{panics: true}, WithLogger(slogNew(rec)))
	resp, err := s.Check(context.Background(), checkRequestFrom(httptest.NewRequest(http.MethodGet, fixtureBaseURL+"/echo", nil), nil))
	if err != nil {
		t.Fatal(err)
	}
	if codes.Code(resp.GetStatus().GetCode()) != codes.Unavailable || resp.GetDeniedResponse().GetStatus().GetCode() != 503 ||
		!strings.Contains(resp.GetDeniedResponse().GetBody(), authz.CategoryInternalError) {
		t.Fatalf("resp = %v", resp)
	}
	record := rec.last()
	if record["msg"] != "panic during check" || record["level"] != slog.LevelError.String() || record["panic"] != "sdk parser bug" {
		t.Fatalf("panic log = %v", record)
	}
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "short unchanged", in: "abc", want: "abc"},
		{name: "exact limit unchanged", in: strings.Repeat("x", logFieldLimit), want: strings.Repeat("x", logFieldLimit)},
		{name: "over limit marked", in: strings.Repeat("x", logFieldLimit+1), want: strings.Repeat("x", logFieldLimit) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := truncate(tt.in); got != tt.want {
				t.Fatalf("truncate = %q, want %q", got, tt.want)
			}
		})
	}
}
