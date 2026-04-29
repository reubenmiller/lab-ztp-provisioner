// Package appliers dispatches a ProvisioningBundle's modules to handlers.
//
// Two handler sources are supported and both are first-class:
//
//  1. Built-in Go handlers (compiled into ztp-agent) for fast, dependency-free
//     defaults. Useful when the device-image author wants a single static binary.
//
//  2. Drop-in POSIX shell scripts under a configurable directory (default
//     /etc/ztp/appliers.d/<module-type>.sh). The module's payload is fed on
//     stdin as JSON; non-zero exit indicates failure.
//
// Drop-in scripts WIN over built-ins, so operators can override behaviour
// without recompiling. Unknown module types are skipped (logged as "skipped"
// in the per-module result), never fatal — this keeps newer servers and older
// agents compatible.
package appliers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Handler applies a single module's payload to the device.
type Handler interface {
	Type() string
	Apply(ctx context.Context, payload map[string]any) (output string, err error)
}

// Dispatcher matches modules to handlers.
type Dispatcher struct {
	// ScriptsDir is the directory scanned for drop-in POSIX appliers.
	// Defaults to /etc/ztp/appliers.d. Set to "" to disable script appliers.
	ScriptsDir string
	// BuiltIn is consulted only when no drop-in script for the module type
	// exists, so operators can override built-ins by dropping a same-named
	// script into ScriptsDir.
	BuiltIn map[string]Handler
	// Timeout per applier invocation. Defaults to 60s.
	Timeout time.Duration
	// Verbose, when true, logs the combined output of every applier script even
	// when it succeeds (normally only failures are logged). Corresponds to the
	// -v / ZTP_APPLIER_DEBUG=1 flag.
	Verbose bool
	// ShellTrace, when true, runs scripts under `sh -x` so every command and
	// its arguments appear in the output. Implies Verbose.
	// Corresponds to ZTP_APPLIER_DEBUG=trace.
	ShellTrace bool
	// LogFile, when non-empty, appends the combined output of every applier
	// invocation (type header + output) to this file. Useful for post-mortem
	// debugging. Corresponds to ZTP_APPLIER_LOG=<path>.
	LogFile string
	// Logger receives structured log lines (info/warn per module result).
	Logger *slog.Logger
}

// New returns a Dispatcher with sensible defaults.
func New(builtin map[string]Handler) *Dispatcher {
	return &Dispatcher{
		ScriptsDir: "/etc/ztp/appliers.d",
		BuiltIn:    builtin,
		Timeout:    60 * time.Second,
		Logger:     slog.Default(),
	}
}

// Apply runs every module in bundle through the appropriate handler and
// returns per-module results. The bundle as a whole succeeds even when some
// modules fail; the agent decides what to do with partial success.
func (d *Dispatcher) Apply(ctx context.Context, bundle *protocol.ProvisioningBundle) []protocol.ModuleResult {
	results := make([]protocol.ModuleResult, 0, len(bundle.Modules))
	for _, m := range bundle.Modules {
		results = append(results, d.applyOne(ctx, m))
	}
	return results
}

func (d *Dispatcher) applyOne(ctx context.Context, m protocol.Module) protocol.ModuleResult {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}

	res := protocol.ModuleResult{Type: m.Type}
	logger.Info("applying module", "type", m.Type)
	if d.ScriptsDir != "" {
		script := filepath.Join(d.ScriptsDir, sanitizeType(m.Type)+".sh")
		if info, err := os.Stat(script); err == nil && !info.IsDir() {
			out, err := runScript(cctx, script, m.Payload, m.RawPayload, d.ShellTrace)
			res.Output = strings.TrimSpace(out)
			if err != nil {
				res.Error = err.Error()
				logger.Warn("applier failed", "type", m.Type, "script", script, "output", res.Output, "err", err)
			} else {
				res.OK = true
				if d.Verbose || d.ShellTrace {
					logger.Info("applier ok", "type", m.Type, "output", res.Output)
				} else {
					logger.Debug("applier ok", "type", m.Type, "output", res.Output)
				}
			}
			d.appendLog(m.Type, script, res.Output, res.Error)
			return res
		}
	}
	if h, ok := d.BuiltIn[m.Type]; ok {
		out, err := h.Apply(cctx, m.Payload)
		res.Output = out
		if err != nil {
			res.Error = err.Error()
			logger.Warn("applier (builtin) failed", "type", m.Type, "output", out, "err", err)
		} else {
			res.OK = true
			logger.Debug("applier (builtin) ok", "type", m.Type)
		}
		d.appendLog(m.Type, "(builtin)", res.Output, res.Error)
		return res
	}
	res.Skipped = true
	res.Error = "no applier registered for module type"
	return res
}

// appendLog writes a log entry for one applier run to d.LogFile when set.
func (d *Dispatcher) appendLog(moduleType, source, output, errStr string) {
	if d.LogFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(d.LogFile), 0o750); err != nil {
		d.Logger.Warn("could not create applier log directory", "path", d.LogFile, "err", err)
		return
	}
	f, err := os.OpenFile(d.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		d.Logger.Warn("could not open applier log", "path", d.LogFile, "err", err)
		return
	}
	defer f.Close()
	status := "ok"
	if errStr != "" {
		status = "FAILED"
	}
	fmt.Fprintf(f, "\n=== applier %s [%s] status=%s ===\n", moduleType, source, status)
	if output != "" {
		fmt.Fprintln(f, output)
	}
	if errStr != "" {
		fmt.Fprintf(f, "error: %s\n", errStr)
	}
}

// sanitizeType strips path separators so module types cannot be used to write
// or execute files outside the appliers directory.
func sanitizeType(t string) string {
	t = strings.TrimSpace(t)
	t = strings.ReplaceAll(t, "/", "_")
	t = strings.ReplaceAll(t, "\\", "_")
	t = strings.ReplaceAll(t, "..", "_")
	return t
}

func runScript(ctx context.Context, path string, payload map[string]any, raw []byte, shellTrace bool) (string, error) {
	var stdin []byte
	if raw != nil {
		// Module supplies its own opaque payload bytes (INI, etc.) — feed
		// them verbatim to the script.
		stdin = raw
	} else {
		body, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		stdin = body
	}
	var cmd *exec.Cmd
	if shellTrace {
		// sh -x traces every command to stderr; CombinedOutput merges it with stdout.
		cmd = exec.CommandContext(ctx, "sh", "-x", path)
	} else {
		cmd = exec.CommandContext(ctx, path)
	}
	cmd.Stdin = strings.NewReader(string(stdin))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("applier %s: %w", filepath.Base(path), err)
	}
	return string(out), nil
}

// MissingAllRequired returns an error if any of the listed keys is absent or
// empty in payload. Helpers like this are useful for built-in handlers.
func MissingAllRequired(payload map[string]any, keys ...string) error {
	missing := make([]string, 0)
	for _, k := range keys {
		v, ok := payload[k]
		if !ok || v == nil {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return errors.New("missing required fields: " + strings.Join(missing, ","))
	}
	return nil
}
