package authz

import (
	"time"

	"github.com/agentnameservice/ans-gateway-auth/replay"
)

// Observer receives verifier and key-store outcomes. Implementations live
// outside this package (the Prometheus implementation is in extauthz); the
// default is NoopObserver.
type Observer interface {
	replay.Observer
	// Decision is called once per verified request with the outcome.
	Decision(result, category string, d time.Duration)
	// KeyRefresh is called after every root-key refresh attempt for a
	// transparency log.
	KeyRefresh(tl string, keys int, err error)
	// CheckTimeout is called when a request exhausted the verifier's budget.
	CheckTimeout()
}

// NoopObserver discards every observation.
type NoopObserver struct {
	replay.NoopObserver
}

// Decision implements Observer.
func (NoopObserver) Decision(string, string, time.Duration) {}

// KeyRefresh implements Observer.
func (NoopObserver) KeyRefresh(string, int, error) {}

// CheckTimeout implements Observer.
func (NoopObserver) CheckTimeout() {}
