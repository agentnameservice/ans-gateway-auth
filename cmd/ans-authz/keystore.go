package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// keyStore is one transparency log's trusted keys: the pinned set from the
// configuration plus whatever the log served at the last successful fetch.
// Every refresh replaces the fetched set instead of accumulating, so a key
// the log withdraws stops being trusted at the next refresh rather than
// surviving until a restart. Pinned keys are never dropped.
type keyStore struct {
	name   string
	pinned *scitt.KeyStore
	client scitt.Client
	logger *slog.Logger

	mu            sync.RWMutex
	current       *scitt.KeyStore
	lastRefreshed *time.Time
}

func newKeyStore(name string, pinned *scitt.KeyStore, client scitt.Client, logger *slog.Logger) *keyStore {
	return &keyStore{name: name, pinned: pinned, client: client, logger: logger, current: pinned}
}

// Get implements scitt.KeyLookup over the current snapshot.
func (s *keyStore) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	return current.Get(kid)
}

// DoRefresh fetches the log's root keys and installs pinned ∪ fetched as the
// new snapshot. A static store (no client) is a no-op; a failed fetch keeps
// the previous snapshot and does not count as a refresh.
func (s *keyStore) DoRefresh(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	lines, err := s.client.FetchRootKeys(ctx)
	if err != nil {
		return fmt.Errorf("fetch root keys: %w", err)
	}
	merged, result := s.pinned.MergeFrom(lines)
	now := time.Now()
	s.mu.Lock()
	previous := s.current
	s.current = merged
	s.lastRefreshed = &now
	s.mu.Unlock()
	if previous.Len() != merged.Len() || result.SkippedUnparseable > 0 || len(result.Collisions) > 0 {
		s.logger.InfoContext(ctx, "root keys refreshed",
			"keys_before", previous.Len(), "keys_after", merged.Len(), "fetched", len(lines),
			"unparseable", result.SkippedUnparseable, "collisions", len(result.Collisions))
	}
	return nil
}

// LastRefreshed reports the last successful fetch, nil before the first.
func (s *keyStore) LastRefreshed() *time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRefreshed
}

// Len is the number of keys in the current snapshot.
func (s *keyStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current.Len()
}

// IsEmpty reports whether the current snapshot holds no keys.
func (s *keyStore) IsEmpty() bool { return s.Len() == 0 }
