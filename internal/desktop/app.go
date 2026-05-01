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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"filippo.io/age"
	"github.com/wailsapp/wails/v2/pkg/options"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/runtime"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/sopsage"
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

	runtimeInfo RuntimeInfo

	mu  sync.RWMutex
	ctx context.Context
}

// New wires the App to the running engine handle. Called from
// cmd/ztp-app after runtime.Start has succeeded.
func New(h *runtime.Handle, info RuntimeInfo) *App {
	return &App{handle: h, runtimeInfo: info}
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
	Mode              string   `json:"mode"`
	Token             string   `json:"token"`
	BaseURL           string   `json:"baseURL"`
	SigningKey        string   `json:"signingKey"`
	DefaultSealRegex  string   `json:"defaultSealRegex,omitempty"`
	ConfigDir         string   `json:"configDir,omitempty"`
	ConfigPath        string   `json:"configPath,omitempty"`
	AdminTokenFile    string   `json:"adminTokenFile,omitempty"`
	SigningKeyFile    string   `json:"signingKeyFile,omitempty"`
	AgeKeyFile        string   `json:"ageKeyFile,omitempty"`
	ProfilesDir       string   `json:"profilesDir,omitempty"`
	FirstRun          bool     `json:"firstRun,omitempty"`
	BootstrappedFiles []string `json:"bootstrappedFiles,omitempty"`
	Capabilities      []string `json:"capabilities"`
}

const defaultSealRegex = `^(password|bootstrap_token|static_token|.*secret.*)$`

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

// OpenConfigDirectory opens the app config root in the host file manager.
func (a *App) OpenConfigDirectory() error {
	if a.runtimeInfo.ConfigDir == "" {
		return errors.New("desktop config directory is not set")
	}
	return openPathInFileManager(a.runtimeInfo.ConfigDir)
}

// ListProfileFiles returns .yaml/.yml files under profiles_dir.
func (a *App) ListProfileFiles() ([]string, error) {
	if a.runtimeInfo.ProfilesDir == "" {
		return nil, errors.New("profiles directory is not configured")
	}
	entries, err := os.ReadDir(a.runtimeInfo.ProfilesDir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (a *App) ReadProfileFile(name string) (string, error) {
	path, err := a.profilePath(name)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (a *App) WriteProfileFile(name, content string) error {
	path, err := a.profilePath(name)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func (a *App) DeleteProfileFile(name string) error {
	path, err := a.profilePath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (a *App) RevealSealedProfile(content string) (string, error) {
	if !sopsage.IsEncrypted([]byte(content)) {
		return "", errors.New("content does not appear to be SOPS encrypted")
	}
	if a.handle == nil || a.handle.AgeIdentity == nil {
		return "", errors.New("server age identity is not available")
	}
	plain, err := sopsage.Decrypt([]byte(content), []age.Identity{a.handle.AgeIdentity})
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (a *App) SealProfile(content, encryptedRegex string) (string, error) {
	recipients, err := a.sealRecipients()
	if err != nil {
		return "", err
	}
	plain := []byte(content)
	rules := sopsage.EncryptionRules{}
	if strings.TrimSpace(encryptedRegex) != "" {
		rules.EncryptedRegex = strings.TrimSpace(encryptedRegex)
	} else {
		clean, derived, err := sopsage.PrepareTaggedSeal(plain)
		if err != nil {
			return "", err
		}
		plain = clean
		rules = derived
		if rules.EncryptedRegex == "" {
			return "", fmt.Errorf("no %s tags found and no regex provided", sopsage.SealTag)
		}
	}
	out, err := sopsage.Encrypt(plain, recipients, rules)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// SealProfileForSave enforces encrypted-at-rest writes for profile files.
// If content already contains a SOPS block it's returned unchanged. For
// plaintext input, !encrypt tags are honoured when present; otherwise the
// app's default seal regex is applied.
func (a *App) SealProfileForSave(content string) (string, error) {
	if sopsage.IsEncrypted([]byte(content)) {
		return content, nil
	}

	recipients, err := a.sealRecipients()
	if err != nil {
		return "", err
	}

	plain := []byte(content)
	clean, derived, err := sopsage.PrepareTaggedSeal(plain)
	if err != nil {
		return "", err
	}

	rules := derived
	if strings.TrimSpace(rules.EncryptedRegex) == "" {
		rgx := strings.TrimSpace(a.runtimeInfo.DefaultSealRegex)
		if rgx == "" {
			rgx = defaultSealRegex
		}
		rules = sopsage.EncryptionRules{EncryptedRegex: rgx}
	} else {
		plain = clean
	}

	out, err := sopsage.Encrypt(plain, recipients, rules)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (a *App) profilePath(name string) (string, error) {
	if a.runtimeInfo.ProfilesDir == "" {
		return "", errors.New("profiles directory is not configured")
	}
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == ".." {
		return "", errors.New("invalid profile filename")
	}
	if base != name {
		return "", errors.New("profile filename must not contain path separators")
	}
	if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
		return "", errors.New("profile filename must end with .yaml or .yml")
	}
	return filepath.Join(a.runtimeInfo.ProfilesDir, base), nil
}

func (a *App) sealRecipients() ([]age.Recipient, error) {
	if a.handle == nil || a.handle.AgeIdentity == nil {
		return nil, errors.New("server age identity is not available")
	}
	out := make([]age.Recipient, 0, 1+len(a.handle.Config.AgeRecipients))
	seen := map[string]struct{}{}
	add := func(r age.Recipient) {
		s, ok := r.(fmt.Stringer)
		if !ok {
			return
		}
		k := s.String()
		if _, exists := seen[k]; exists {
			return
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	add(a.handle.AgeIdentity.Recipient())
	for _, s := range a.handle.Config.AgeRecipients {
		r, err := age.ParseX25519Recipient(strings.TrimSpace(s))
		if err != nil {
			return nil, err
		}
		add(r)
	}
	if len(out) == 0 {
		return nil, errors.New("no age recipients configured")
	}
	return out, nil
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
	out := a.runtimeInfo
	out.Mode = "desktop"
	out.Token = a.handle.AdminToken
	out.BaseURL = a.handle.BaseURL
	out.SigningKey = a.handle.SigningKeyB64
	if strings.TrimSpace(out.DefaultSealRegex) == "" {
		out.DefaultSealRegex = defaultSealRegex
	}
	out.Capabilities = caps
	return out
}
