package api

import (
	"encoding/json"
	"net/http"
)

// RuntimeConfig is what GET /v1/runtime-config returns. The SPA reads
// this at boot to decide whether to show the login modal (browser
// mode) or fetch the admin token from a desktop-shell binding
// (desktop mode), and to swap concrete adapters such as BLE.
//
// Capabilities is a forward-compatible string list, e.g.
// "ble.central.native" — the SPA feature-detects rather than version-
// checks so a new desktop-shell binding can be advertised without a
// SPA rebuild.
type RuntimeConfig struct {
	Mode         string   `json:"mode"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// handleRuntimeConfig is intentionally unauthenticated. Mode and
// capabilities are not secrets — the SPA must read them before it
// has any token. The admin token never flows through this endpoint;
// in desktop mode it's handed to the SPA via a Wails Go-binding.
func (s *Server) handleRuntimeConfig(w http.ResponseWriter, _ *http.Request) {
	mode := s.RuntimeMode
	if mode == "" {
		mode = "browser"
	}
	caps := s.RuntimeCapabilities
	if caps == nil {
		caps = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(RuntimeConfig{Mode: mode, Capabilities: caps})
}
