package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// handleServerInfo returns the small set of public details a device or the
// admin UI needs to bootstrap an agent: the server's Ed25519 signing public
// key (base64), the wire protocol version, and the URL of the embedded
// shell agent script. The endpoint is intentionally unauthenticated — none
// of the data is secret, and exposing it removes the operator step of
// "manually copy the pubkey out of the server logs".
func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	pub := s.Engine.PublicKey()
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	keyID := s.Engine.SigningKeyID()
	agentScriptURL := ""
	if len(s.AgentScript) > 0 {
		agentScriptURL = absoluteURL(r, "/v1/agent.sh")
	}
	// Cache for a minute — pubkey rotation is rare and operators reload the
	// onboarding page often.
	w.Header().Set("Cache-Control", "public, max-age=60")

	// text/plain: line-oriented key=value, consumed by the shell agent via
	// kv_get so it needs no JSON parser to discover the server pubkey.
	if wantsTextPlain(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writeKV := func(k, v string) {
			v = strings.ReplaceAll(v, "\n", `\n`)
			v = strings.ReplaceAll(v, "\r", `\r`)
			_, _ = w.Write([]byte(k + "=" + v + "\n"))
		}
		writeKV("protocol_version", protocol.Version)
		writeKV("public_key", pubB64)
		writeKV("key_id", keyID)
		if agentScriptURL != "" {
			writeKV("agent_script_url", agentScriptURL)
		}
		return
	}

	resp := struct {
		ProtocolVersion string `json:"protocol_version"`
		PublicKey       string `json:"public_key"` // base64 Ed25519
		KeyID           string `json:"key_id"`     // matches signed envelopes
		AgentScriptURL  string `json:"agent_script_url,omitempty"`
	}{
		ProtocolVersion: protocol.Version,
		PublicKey:       pubB64,
		KeyID:           keyID,
		AgentScriptURL:  agentScriptURL,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleAgentScript serves the POSIX shell agent script the server was
// configured with. Hosting the canonical version on the server lets a
// brand-new device bootstrap with:
//
//	curl -fsSL https://ztp.example.com/v1/agent.sh | \
//	    ZTP_SERVER=https://ztp.example.com \
//	    ZTP_SERVER_PUBKEY=... \
//	    sh
//
// The server's signing public key is required and is exposed by
// /v1/server-info; admins typically copy the full one-liner from the
// onboarding wizard which inlines the current pubkey.
func (s *Server) handleAgentScript(w http.ResponseWriter, _ *http.Request) {
	if len(s.AgentScript) == 0 {
		http.Error(w, "agent script not configured on this server", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write(s.AgentScript)
}

// absoluteURL builds an absolute https?://host/path URL from an incoming
// request, honouring X-Forwarded-Proto / X-Forwarded-Host so that links
// rendered in /v1/server-info remain correct behind a reverse proxy.
func absoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		scheme = v
	}
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		host = v
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + path
}
