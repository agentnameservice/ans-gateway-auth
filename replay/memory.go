package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
)

// Memory is the in-process backend. It wraps the SDK's bounded cache, so it
// fails closed when full and its scope is one verifier process.
type Memory struct {
	cache *pop.MemoryReplayCache
	obs   Observer
}

// NewMemory returns a Memory holding at most maxEntries live records; a value
// at or below zero selects the SDK default. The cache's janitor stops when ctx
// ends or Close is called.
func NewMemory(ctx context.Context, maxEntries int, obs Observer) *Memory {
	if obs == nil {
		obs = NoopObserver{}
	}
	return &Memory{cache: pop.NewMemoryReplayCache(ctx, maxEntries), obs: obs}
}

// CheckAndStore implements Cache. The context is accepted for interface
// symmetry; the in-process cache cannot block.
func (m *Memory) CheckAndStore(_ context.Context, key string, exp time.Time) (bool, error) {
	start := time.Now()
	seen, err := m.cache.CheckAndStore(key, exp)
	if err != nil {
		err = &pop.ProofError{Type: pop.ErrReplayCacheFull, Message: "replay cache full", Cause: fmt.Errorf("%w: %w", ErrFull, err)}
	}
	m.obs.ReplayBackend("check_and_store", time.Since(start), err)
	return seen, err
}

// Stats implements Cache.
func (m *Memory) Stats() Stats {
	return Stats{
		Backend:  BackendMemory,
		Entries:  int64(m.cache.Len()),
		Capacity: int64(m.cache.Cap()),
		Up:       true,
	}
}

// Close implements Cache.
func (m *Memory) Close() error {
	m.cache.Close()
	return nil
}
