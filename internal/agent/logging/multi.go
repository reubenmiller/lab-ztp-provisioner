// Package logging provides a small slog.Handler that fans out every log
// record to multiple child handlers. It exists so the agent can keep
// printing to stderr (so journald / interactive runs see live output) while
// also persisting the same log lines to a file — useful on devices where
// journald lives in tmpfs and log history is otherwise lost across reboots.
package logging

import (
	"context"
	"log/slog"
)

// MultiHandler dispatches each Record to every wrapped handler.
//
// The slog.Handler contract requires implementations to be safe for
// concurrent use; this is satisfied as long as each child handler is
// goroutine-safe (the stdlib TextHandler / JSONHandler are).
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMulti wraps one or more handlers. nil entries are dropped so callers
// can write `NewMulti(stderr, maybeFile)` without checking for the empty
// case explicitly.
func NewMulti(handlers ...slog.Handler) slog.Handler {
	out := make([]slog.Handler, 0, len(handlers))
	for _, h := range handlers {
		if h != nil {
			out = append(out, h)
		}
	}
	if len(out) == 1 {
		// No need to pay for the fan-out when there's only one sink.
		return out[0]
	}
	return &MultiHandler{handlers: out}
}

func (m *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	var firstErr error
	for _, h := range m.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		// Clone so handlers that mutate (e.g. add their own attrs) cannot
		// disturb the next handler in the chain.
		if err := h.Handle(ctx, r.Clone()); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: out}
}

func (m *MultiHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		out[i] = h.WithGroup(name)
	}
	return &MultiHandler{handlers: out}
}
