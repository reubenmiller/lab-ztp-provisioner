package logging_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/logging"
)

func TestMultiHandler_FansOut(t *testing.T) {
	var a, b bytes.Buffer
	h := logging.NewMulti(
		slog.NewTextHandler(&a, &slog.HandlerOptions{Level: slog.LevelDebug}),
		slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)
	logger := slog.New(h)
	logger.Info("hello", "k", "v")

	for name, buf := range map[string]*bytes.Buffer{"a": &a, "b": &b} {
		if !strings.Contains(buf.String(), "hello") {
			t.Errorf("sink %s missing record: %q", name, buf.String())
		}
		if !strings.Contains(buf.String(), "k=v") {
			t.Errorf("sink %s missing attr: %q", name, buf.String())
		}
	}
}

func TestMultiHandler_LevelGating(t *testing.T) {
	// One sink admits Debug, the other only Warn+. A Debug record must reach
	// the first but not the second.
	var debugBuf, warnBuf bytes.Buffer
	h := logging.NewMulti(
		slog.NewTextHandler(&debugBuf, &slog.HandlerOptions{Level: slog.LevelDebug}),
		slog.NewTextHandler(&warnBuf, &slog.HandlerOptions{Level: slog.LevelWarn}),
	)
	logger := slog.New(h)
	logger.Debug("only-debug")

	if !strings.Contains(debugBuf.String(), "only-debug") {
		t.Error("debug sink should have received the record")
	}
	if warnBuf.Len() != 0 {
		t.Errorf("warn sink should be empty, got %q", warnBuf.String())
	}
}

func TestMultiHandler_SingleChildShortCircuits(t *testing.T) {
	// With a single non-nil handler, NewMulti returns it directly to avoid
	// the per-record fan-out cost.
	var buf bytes.Buffer
	inner := slog.NewTextHandler(&buf, nil)
	got := logging.NewMulti(inner, nil)
	if got != inner {
		t.Errorf("expected single-handler short-circuit, got %T", got)
	}
}

// TestMultiHandler_WithAttrs verifies attribute propagation is preserved
// across all child handlers — important for downstream filters that rely
// on attached service/component attrs.
func TestMultiHandler_WithAttrs(t *testing.T) {
	var a, b bytes.Buffer
	h := logging.NewMulti(
		slog.NewTextHandler(&a, nil),
		slog.NewTextHandler(&b, nil),
	)
	logger := slog.New(h).With("svc", "ztp-agent")
	logger.Info("hi")

	for name, buf := range map[string]*bytes.Buffer{"a": &a, "b": &b} {
		if !strings.Contains(buf.String(), "svc=ztp-agent") {
			t.Errorf("sink %s missing With attr: %q", name, buf.String())
		}
	}
}
