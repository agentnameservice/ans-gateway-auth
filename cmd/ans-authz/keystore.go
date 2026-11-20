package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// keyStore is one transparency log's trusted keys: the pinned set from the
// configuration plus every key the log has served since startup. Refreshes
// merge additively and never drop a cached key, even one a later response
// omits (ANS-6 section 4.5, ANS-4 section 5.1).
type keyStore struct {
	name   string
	client scitt.Client
	logger *slog.Logger

	mu            sync.RWMutex
	current       *scitt.KeyStore
	fetched       map[[4]byte]string
	lastRefreshed *time.Time
}

func newKeyStore(name string, pinned *scitt.KeyStore, client scitt.Client, logger *slog.Logger) *keyStore {
	return &keyStore{name: name, client: client, logger: logger, current: pinned}
}

// Get implements scitt.KeyLookup over the current snapshot.
func (s *keyStore) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	return current.Get(kid)
}

// DoRefresh fetches the log's root keys and merges them into the current
// snapshot. A static store (no client) is a no-op; a failed fetch, or one in
// which no line parsed, keeps the previous snapshot and does not count as a
// refresh. Every change to the served set is logged, at WARN when the response
// omits a previously served key (which stays trusted) or a kid collided with a
// key of another name.
func (s *keyStore) DoRefresh(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	lines, err := s.client.FetchRootKeys(ctx)
	if err != nil {
		s.logger.WarnContext(ctx, "root-key fetch failed", "error", err)
		return fmt.Errorf("fetch root keys: %w", err)
	}
	fetched := parseKids(lines)
	s.mu.Lock()
	previous, previousFetched := s.current, s.fetched
	merged, result := previous.MergeFrom(lines)
	if result.Added+result.SkippedDuplicate == 0 {
		s.mu.Unlock()
		return fmt.Errorf("fetch root keys: none of %d lines parsed", len(lines))
	}
	now := time.Now()
	s.current, s.fetched, s.lastRefreshed = merged, fetched, &now
	s.mu.Unlock()
	added, removed := onlyIn(fetched, previousFetched), onlyIn(previousFetched, fetched)
	if len(added)+len(removed)+result.SkippedUnparseable+len(result.Collisions) == 0 {
		return nil
	}
	level := slog.LevelInfo
	if len(removed) > 0 || len(result.Collisions) > 0 {
		level = slog.LevelWarn
	}
	s.logger.Log(ctx, level, "root keys refreshed",
		"log", s.name, "keys_before", previous.Len(), "keys_after", merged.Len(), "fetched", len(lines),
		"added", added, "removed", removed, "unparseable", result.SkippedUnparseable, "collisions", result.Collisions)
	return nil
}

// parseKids maps every parseable line's kid to its key name.
func parseKids(lines []string) map[[4]byte]string {
	kids := make(map[[4]byte]string, len(lines))
	for _, line := range lines {
		if tk, err := scitt.ParseC2SPKey(line); err == nil {
			kids[tk.Kid] = tk.Name
		}
	}
	return kids
}

// onlyIn lists the keys of set absent from other as "name/kid", sorted.
func onlyIn(set, other map[[4]byte]string) []string {
	out := make([]string, 0, len(set))
	for kid, name := range set {
		if _, ok := other[kid]; !ok {
			out = append(out, fmt.Sprintf("%s/%x", name, kid))
		}
	}
	slices.Sort(out)
	return out
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
