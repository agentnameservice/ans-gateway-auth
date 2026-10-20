package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// Kinds of root-key fetch failure reported on /readyz.
const (
	errKindTimeout    = "timeout"
	errKindDNS        = "dns_error"
	errKindTLS        = "tls_error"
	errKindConnection = "connection_error"
	errKindHTTP       = "http_error"
	errKindOther      = "other"
)

// errorKind classifies a fetch failure without reproducing its text.
func errorKind(err error) string {
	var (
		netErr   net.Error
		dnsErr   *net.DNSError
		opErr    *net.OpError
		tlsErr   *tls.CertificateVerificationError
		recErr   tls.RecordHeaderError
		alertErr tls.AlertError
		authErr  x509.UnknownAuthorityError
		certErr  x509.CertificateInvalidError
		hostErr  x509.HostnameError
		httpErr  *scitt.TransportError
	)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return errKindTimeout
	case errors.As(err, &dnsErr):
		return errKindDNS
	case errors.As(err, &tlsErr), errors.As(err, &recErr), errors.As(err, &alertErr),
		errors.As(err, &authErr), errors.As(err, &certErr), errors.As(err, &hostErr):
		return errKindTLS
	case errors.As(err, &opErr):
		return errKindConnection
	case errors.As(err, &httpErr):
		return errKindHTTP
	default:
		return errKindOther
	}
}
