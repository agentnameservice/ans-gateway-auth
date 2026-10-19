package replay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
)

type recordingObserver struct {
	ops  []string
	errs []error
}

func (r *recordingObserver) ReplayBackend(op string, _ time.Duration, err error) {
	r.ops = append(r.ops, op)
	r.errs = append(r.errs, err)
}

func TestMemoryCheckAndStore(t *testing.T) {
	t.Parallel()
	exp := time.Now().Add(time.Minute)
	tests := []struct {
		name       string
		maxEntries int
		keys       []string
		wantSeen   []bool
		wantErrAt  int // index of the call that must fail, -1 for none
		wantErrIs  error
		wantType   pop.ErrorType
	}{
		{
			name:       "first sight then replay",
			maxEntries: 10,
			keys:       []string{"a", "a"},
			wantSeen:   []bool{false, true},
			wantErrAt:  -1,
		},
		{
			name:       "distinct keys are unseen",
			maxEntries: 10,
			keys:       []string{"a", "b", "c"},
			wantSeen:   []bool{false, false, false},
			wantErrAt:  -1,
		},
		{
			name:       "full of live entries fails closed",
			maxEntries: 1,
			keys:       []string{"a", "b"},
			wantSeen:   []bool{false, false},
			wantErrAt:  1,
			wantErrIs:  ErrFull,
			wantType:   pop.ErrReplayCacheFull,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			obs := &recordingObserver{}
			m := NewMemory(ctx, tc.maxEntries, obs)
			defer func() {
				if err := m.Close(); err != nil {
					t.Errorf("Close() = %v", err)
				}
			}()
			for i, key := range tc.keys {
				seen, err := m.CheckAndStore(ctx, key, exp)
				if i == tc.wantErrAt {
					if err == nil {
						t.Fatalf("call %d: expected error", i)
					}
					if !errors.Is(err, tc.wantErrIs) {
						t.Fatalf("call %d: error %v does not match %v", i, err, tc.wantErrIs)
					}
					var pe *pop.ProofError
					if !errors.As(err, &pe) || pe.Type != tc.wantType {
						t.Fatalf("call %d: error %v is not a %s ProofError", i, err, tc.wantType)
					}
					continue
				}
				if err != nil {
					t.Fatalf("call %d: unexpected error %v", i, err)
				}
				if seen != tc.wantSeen[i] {
					t.Fatalf("call %d: seen = %v, want %v", i, seen, tc.wantSeen[i])
				}
			}
			if len(obs.ops) != len(tc.keys) {
				t.Fatalf("observer saw %d ops, want %d", len(obs.ops), len(tc.keys))
			}
			for i, op := range obs.ops {
				if op != "check_and_store" {
					t.Fatalf("op %d = %q", i, op)
				}
				if (obs.errs[i] != nil) != (i == tc.wantErrAt) {
					t.Fatalf("op %d: observed error %v, failing call index %d", i, obs.errs[i], tc.wantErrAt)
				}
			}
		})
	}
}

func TestMemoryStats(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMemory(ctx, 5, nil)
	defer m.Close()
	if _, err := m.CheckAndStore(ctx, "a", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got := m.Stats()
	want := Stats{Backend: "memory", Entries: 1, Capacity: 5, Up: true}
	if got != want {
		t.Fatalf("Stats() = %+v, want %+v", got, want)
	}
}

func TestMemoryDefaultCapacity(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMemory(ctx, 0, nil)
	defer m.Close()
	if got := m.Stats().Capacity; got != int64(pop.DefaultReplayMaxEntries) {
		t.Fatalf("Capacity = %d, want SDK default %d", got, pop.DefaultReplayMaxEntries)
	}
}

func TestKeyspaceResetErrorMatchesUnavailable(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrKeyspaceReset, ErrUnavailable) {
		t.Fatal("ErrKeyspaceReset must satisfy errors.Is(err, ErrUnavailable)")
	}
	if errors.Is(ErrKeyspaceReset, ErrFull) {
		t.Fatal("ErrKeyspaceReset must not match ErrFull")
	}
	if ErrKeyspaceReset.Error() == "" {
		t.Fatal("ErrKeyspaceReset must have a message")
	}
}
