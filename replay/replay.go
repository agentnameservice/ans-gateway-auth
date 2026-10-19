// Package replay defines the replay-cache contract the verifier uses to make
// every DPoP proof single-use, and the backends that implement it.
//
// The contract is context-aware so a request budget and the gateway's
// cancellation reach the backend; the SDK's own interface has no context and
// is satisfied per request by an adapter in the authz package.
package replay

import (
	"context"
	"errors"
	"time"
)

// Cache records proof identifiers and reports whether one was seen before.
type Cache interface {
	// CheckAndStore atomically records key with the given expiry and reports
	// whether it was already present. Any error means the request must be
	// rejected; a replay cache never fails open.
	CheckAndStore(ctx context.Context, key string, exp time.Time) (seen bool, err error)
	// Stats reports the backend's current occupancy and health for readiness
	// and metrics.
	Stats() Stats
	// Close releases backend resources.
	Close() error
}

// Stats is a point-in-time view of a backend. Memory backends fill Entries and
// Capacity; the Redis backend fills the remaining fields from its sampler.
type Stats struct {
	Backend        string
	Entries        int64
	Capacity       int64
	UsedMemory     int64
	MaxMemory      int64
	EvictionPolicy string
	EvictedKeys    int64
	KeyspaceResets int64
	Restarts       int64
	AOFEnabled     bool
	Up             bool
	// KeyspaceResetUntil is the end of the current fail-closed window after a
	// keyspace loss; zero when no window is open.
	KeyspaceResetUntil time.Time
}

// Observer receives backend outcomes. The authz package embeds it in its own
// Observer so one telemetry implementation serves both packages.
type Observer interface {
	ReplayBackend(op string, d time.Duration, err error)
}

// NoopObserver discards every observation.
type NoopObserver struct{}

// ReplayBackend implements Observer.
func (NoopObserver) ReplayBackend(string, time.Duration, error) {}

var (
	// ErrFull reports that the backend refused a record because it is at
	// capacity. The verifier maps it to the REPLAY_CACHE_FULL category.
	ErrFull = errors.New("replay cache full")
	// ErrUnavailable reports that the backend could not be consulted. The
	// verifier maps it to the REPLAY_CACHE_UNAVAILABLE category.
	ErrUnavailable = errors.New("replay cache unavailable")
)

// Backend names, reported in Stats.Backend and used as the configured replay
// type.
const (
	BackendMemory = "memory"
	BackendRedis  = "redis"
)

// KeyspaceResetError reports that the shared backend lost its keyspace and
// every replica is failing closed until Until, so a verifier can advise the
// caller when to retry. It matches ErrUnavailable under errors.Is.
type KeyspaceResetError struct {
	Until time.Time
}

func (e *KeyspaceResetError) Error() string {
	return "replay cache keyspace reset; failing closed until " + e.Until.UTC().Format(time.RFC3339)
}

// Is reports a match for ErrUnavailable.
func (*KeyspaceResetError) Is(target error) bool { return target == ErrUnavailable }
