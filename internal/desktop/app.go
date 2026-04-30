// Package desktop is the only package in this module that imports
// Wails. It exposes a thin App struct whose methods are bound by the
// Wails runtime as JS-callable functions on the embedded webview.
//
// Everything substantial — engine, store, profile loading, HTTP API —
// lives in internal/server/runtime and is fully reusable by both the
// daemon binary (cmd/ztp-server) and the desktop binary (cmd/ztp-app).
// This package is the seam where the desktop's webview talks to that
// runtime; keep it small, keep it boring.
package desktop

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/options"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/runtime"
)

// App is bound to the Wails runtime via wails.Options.Bind. Each
// public method becomes a JS-callable function under
// window.go.desktop.App.* in the SPA. Returning struct values
// gets them JSON-marshalled by Wails on the boundary.
//
// ctx is the Wails runtime context, set on first OnStartup so
// Wails-runtime helpers (EventsEmit etc.) can be called from binding
// methods. Guarded by mu because Wails can technically restart the
// app and re-call OnStartup.
type App struct {
	handle *runtime.Handle

	mu  sync.RWMutex
	ctx context.Context
}

// New wires the App to the running engine handle. Called from
// cmd/ztp-app after runtime.Start has succeeded.
func New(h *runtime.Handle) *App {
	return &App{handle: h}
}

// SetContext stores the Wails runtime context. cmd/ztp-app calls
// this from wails.Options.OnStartup, which is when Wails first
// hands us a usable ctx. Without it, runtime.EventsEmit calls fail
// because the runtime can't find the application to dispatch to.
func (a *App) SetContext(ctx context.Context) {
	a.mu.Lock()
	a.ctx = ctx
	a.mu.Unlock()
}

// Context returns the stored Wails ctx, or nil if SetContext hasn't
// been called yet. Callers MUST nil-check; emitting events before
// startup completes is an error condition that should be silently
// dropped, not crash the app.
func (a *App) Context() context.Context {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ctx
}

// OnSecondInstanceLaunch prevent a second instance from launching
func (a *App) OnSecondInstanceLaunch(secondInstanceData options.SecondInstanceData) {
	secondInstanceArgs := secondInstanceData.Args

	ctx := a.Context()
	slog.Info("user opened second instance", "args", strings.Join(secondInstanceData.Args, ","), "workingDir", secondInstanceData.WorkingDirectory)
	wruntime.WindowUnminimise(ctx)
	wruntime.Show(ctx)
	go wruntime.EventsEmit(ctx, "launchArgs", secondInstanceArgs)
}

// RuntimeInfo is what the SPA reads at boot in desktop mode. It
// mirrors api.RuntimeConfig but adds the in-memory admin token —
// which never crosses the HTTP boundary; only this binding hands
// it to the trusted in-window SPA.
type RuntimeInfo struct {
	Mode         string   `json:"mode"`
	Token        string   `json:"token"`
	BaseURL      string   `json:"baseURL"`
	SigningKey   string   `json:"signingKey"`
	Capabilities []string `json:"capabilities"`
}

// SaveFile pops a native save dialog with the suggested filename and
// writes content to the chosen path. Returns the absolute path on
// success, "" if the operator cancelled. Wails' embedded webview does
// not honour <a download> links nor Content-Disposition: attachment, so
// any operator-initiated download has to round-trip through a binding
// to land bytes on the filesystem.
func (a *App) SaveFile(suggestedName, content string) (string, error) {
	ctx := a.Context()
	if ctx == nil {
		return "", errors.New("desktop runtime not ready")
	}
	path, err := wruntime.SaveFileDialog(ctx, wruntime.SaveDialogOptions{
		DefaultFilename: suggestedName,
		Title:           "Save file",
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// GetRuntimeInfo returns the SPA's bootstrap context. The token
// authenticates subsequent /v1/admin/* requests; baseURL is mostly
// informational (the SPA continues to fetch with relative paths
// since AssetsHandler proxies them through). Capabilities is the
// forward-compatible feature list, populated by build-tagged
// helpers — "ble.central.native" appears when the binary was built
// with -tags ble.
func (a *App) GetRuntimeInfo() RuntimeInfo {
	caps := bleCapabilities()
	if caps == nil {
		caps = []string{}
	}
	return RuntimeInfo{
		Mode:         "desktop",
		Token:        a.handle.AdminToken,
		BaseURL:      a.handle.BaseURL,
		SigningKey:   a.handle.SigningKeyB64,
		Capabilities: caps,
	}
}
