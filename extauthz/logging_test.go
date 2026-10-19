package extauthz

import (
	"context"
	"log/slog"
	"sync"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

type corev3HeaderValueOption = corev3.HeaderValueOption

// recordingHandler keeps every slog record as a flat map for assertions.
type recordingHandler struct {
	mu      sync.Mutex
	records []map[string]any
}

func slogNew(h slog.Handler) *slog.Logger { return slog.New(h) }

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	m := map[string]any{"msg": r.Message, "level": r.Level.String()}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, m)
	h.mu.Unlock()
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) last() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.records) == 0 {
		return nil
	}
	return h.records[len(h.records)-1]
}
