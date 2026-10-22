package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestErrorKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil"},
		{name: "deadline", err: fmt.Errorf("fetch root keys: %w", context.DeadlineExceeded), want: errKindTimeout},
		{name: "network timeout", err: &url.Error{Op: "Get", URL: "https://tl.example/root-keys", Err: timeoutError{}}, want: errKindTimeout},
		{name: "dns", err: &url.Error{Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "tl.example"}}}, want: errKindDNS},
		{name: "certificate verification", err: &url.Error{Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}}, want: errKindTLS},
		{name: "unknown authority", err: x509.UnknownAuthorityError{}, want: errKindTLS},
		{name: "hostname mismatch", err: x509.HostnameError{Host: "tl.example"}, want: errKindTLS},
		{name: "connection refused", err: &url.Error{Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}, want: errKindConnection},
		{name: "http status", err: fmt.Errorf("fetch root keys: %w", &scitt.TransportError{StatusCode: 302, Message: "redirect"}), want: errKindHTTP},
		{name: "unparseable payload", err: errors.New("none of 3 lines parsed"), want: errKindOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := errorKind(tt.err); got != tt.want {
				t.Fatalf("errorKind(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
