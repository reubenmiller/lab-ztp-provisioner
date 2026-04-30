// Package api wires the Engine and Store into HTTP handlers.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Server is the HTTP-facing surface. It exposes a small public endpoint for
// device enrollment and an admin namespace guarded by a static bearer token.
type Server struct {
	Engine     *server.Engine
	Store      store.Store
	AdminToken string // operators authenticate to /v1/admin/* with this
	Logger     *slog.Logger
	Hub        *Hub // optional: pushes pending events to operators over WS

	// Resolver and ProfileLoader power the profiles admin endpoints. When nil,
	// /v1/admin/profiles routes are not registered.
	Resolver      ProfileResolver
	ProfileLoader ProfileLoader

	// AgentScript is the optional POSIX shell agent script, served at
	// GET /v1/agent.sh. When non-empty, /v1/server-info advertises the URL
	// so devices can bootstrap with a single `curl … | sh` pipe.
	AgentScript []byte

	// EncryptionRecipients is the list of age recipient strings exposed
	// via GET /v1/admin/profiles/encryption-key. ztpctl secrets seal/set
	// uses this to encrypt files for everyone the server is allowed to
	// decrypt for. The first entry is conventionally the server's own
	// public key; additional entries come from age_recipients in config.
	EncryptionRecipients []string

	// SPA, when non-nil, is registered as the catch-all handler for
	// non-API GET requests. The runtime sets it to the embedded
	// SvelteKit admin app (or an external dir when web.dir is set);
	// leaving it nil keeps the server JSON-only for deployments that
	// front the SPA elsewhere (e.g. Caddy).
	SPA http.Handler

	// RuntimeMode and RuntimeCapabilities populate GET /v1/runtime-config
	// so the SPA can switch its UX (e.g. skip the login modal in
	// desktop mode, prefer a native BLE adapter when advertised).
	// Empty Mode is treated as "browser" by the handler.
	RuntimeMode         string
	RuntimeCapabilities []string
}

// Routes returns an http.Handler with all routes registered.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/enroll/status", s.handleEnrollStatus)
	mux.HandleFunc("GET /v1/server-info", s.handleServerInfo)
	mux.HandleFunc("GET /v1/runtime-config", s.handleRuntimeConfig)
	mux.HandleFunc("GET /v1/agent.sh", s.handleAgentScript)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Admin
	admin := http.NewServeMux()
	admin.HandleFunc("GET /v1/admin/pending", s.handleListPending)
	admin.HandleFunc("POST /v1/admin/pending/{id}/approve", s.handleApprovePending)
	admin.HandleFunc("POST /v1/admin/pending/{id}/reject", s.handleRejectPending)
	admin.HandleFunc("GET /v1/admin/devices", s.handleListDevices)
	admin.HandleFunc("PATCH /v1/admin/devices/{id}", s.handlePatchDevice)
	admin.HandleFunc("DELETE /v1/admin/devices/{id}", s.handleDeleteDevice)
	admin.HandleFunc("GET /v1/admin/allowlist", s.handleListAllowlist)
	admin.HandleFunc("POST /v1/admin/allowlist", s.handleAddAllowlist)
	admin.HandleFunc("DELETE /v1/admin/allowlist/{id}", s.handleRemoveAllowlist)
	admin.HandleFunc("POST /v1/admin/tokens", s.handleIssueToken)
	admin.HandleFunc("GET /v1/admin/tokens", s.handleListTokens)
	admin.HandleFunc("DELETE /v1/admin/tokens/{id}", s.handleRevokeToken)
	admin.HandleFunc("GET /v1/admin/audit", s.handleAuditTail)

	if s.Resolver != nil {
		s.registerProfileRoutes(admin)
	}
	if s.Hub != nil {
		admin.HandleFunc("GET /v1/admin/pending/stream", s.Hub.ServeWS)
	}

	mux.Handle("/v1/admin/", s.requireAdmin(admin))

	// SPA fallback. Registered last so all explicit /v1/* and /healthz
	// patterns above take precedence (Go ServeMux uses longest-prefix
	// matching). The handler itself rejects /v1/* paths defensively.
	if s.SPA != nil {
		mux.Handle("/", s.SPA)
	}

	return logRequests(s.Logger, mux)
}

func (s *Server) requireAdmin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prefer Authorization header; fall back to ?token= for SSE streams
		// (EventSource cannot set custom headers from a browser).
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if s.AdminToken == "" || token != s.AdminToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func logRequests(l *slog.Logger, h http.Handler) http.Handler {
	if l == nil {
		l = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		l.Debug("http", "method", r.Method, "path", r.URL.Path, "elapsed", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- Enrollment ----------------------------------------------------------

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var env protocol.SignedEnvelope
	if err := decodeJSON(r, &env); err != nil {
		http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := s.Engine.Enroll(ctx, &env)
	if err != nil {
		s.Logger.Error("enroll failed", "err", err)
		msg := "internal error"
		if s.RuntimeMode == "desktop" {
			msg = err.Error()
		}
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	if resp.Status == protocol.StatusPending {
		status = http.StatusAccepted // 202 conveys "still waiting"
	}
	if resp.Status == protocol.StatusRejected {
		status = http.StatusForbidden
	}
	if wantsTextPlain(r) {
		writeEnrollText(w, status, resp)
		return
	}
	writeJSON(w, status, resp)
}

// handleEnrollStatus is a public polling endpoint for BLE relays. Rather than
// re-submitting the full signed envelope (which would fail with "nonce replay"),
// the relay calls this to check whether the pending request has been approved.
func (s *Server) handleEnrollStatus(w http.ResponseWriter, r *http.Request) {
	pubkey := r.URL.Query().Get("pubkey")
	if pubkey == "" {
		http.Error(w, "pubkey query parameter required", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if p, err := s.Store.FindPendingByPublicKey(ctx, pubkey); err == nil {
		writeJSON(w, http.StatusOK, protocol.EnrollResponse{
			ProtocolVersion: protocol.Version,
			Status:          protocol.StatusPending,
			Reason:          p.Reason,
			RetryAfter:      10,
		})
		return
	}
	if _, err := s.Store.FindDeviceByPublicKey(ctx, pubkey); err == nil {
		writeJSON(w, http.StatusOK, protocol.EnrollResponse{
			ProtocolVersion: protocol.Version,
			Status:          protocol.StatusAccepted,
		})
		return
	}
	// Neither pending nor enrolled — may have been rejected or the entry expired.
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		ProtocolVersion: protocol.Version,
		Status:          protocol.StatusRejected,
		Reason:          "pending request not found; it may have been rejected or expired",
	})
}

// wantsTextPlain returns true when the client's Accept header lists
// "text/plain" before "application/json" (or only "text/plain"). The check is
// intentionally simple — exhaustive RFC 7231 negotiation isn't worth it for
// two known-good types.
func wantsTextPlain(r *http.Request) bool {
	a := r.Header.Get("Accept")
	if a == "" {
		return false
	}
	a = strings.ToLower(a)
	tp := strings.Index(a, "text/plain")
	if tp < 0 {
		return false
	}
	js := strings.Index(a, "application/json")
	return js < 0 || tp < js
}

// writeEnrollText renders an EnrollResponse as line-oriented "key=value" text,
// the format expected by the pure-shell agent. The signed text manifest is
// included when the response was accepted, so the agent never has to parse
// JSON.
func writeEnrollText(w http.ResponseWriter, status int, resp *protocol.EnrollResponse) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)

	writeKV := func(k, v string) {
		// Strip CR/LF from values so each record stays on one line.
		v = strings.ReplaceAll(v, "\n", `\n`)
		v = strings.ReplaceAll(v, "\r", `\r`)
		_, _ = w.Write([]byte(k + "=" + v + "\n"))
	}
	writeKV("protocol_version", resp.ProtocolVersion)
	writeKV("status", string(resp.Status))
	if resp.Reason != "" {
		writeKV("reason", resp.Reason)
	}
	if resp.RetryAfter > 0 {
		writeKV("retry_after", itoa(resp.RetryAfter))
	}
	if resp.Bundle != nil {
		writeKV("bundle.alg", resp.Bundle.Algorithm)
		writeKV("bundle.key_id", resp.Bundle.KeyID)
		writeKV("bundle.payload", resp.Bundle.Payload)
		writeKV("bundle.signature", resp.Bundle.Signature)
	}
	if resp.TextManifest != nil {
		writeKV("manifest.alg", resp.TextManifest.Algorithm)
		writeKV("manifest.key_id", resp.TextManifest.KeyID)
		writeKV("manifest.payload", resp.TextManifest.Payload)
		writeKV("manifest.signature", resp.TextManifest.Signature)
	}
	if resp.EncryptedBundle != nil {
		writeKV("encrypted.alg", resp.EncryptedBundle.Algorithm)
		writeKV("encrypted.server_key", resp.EncryptedBundle.ServerKey)
		writeKV("encrypted.nonce", resp.EncryptedBundle.Nonce)
		writeKV("encrypted.ciphertext", resp.EncryptedBundle.Ciphertext)
	}
}

func itoa(n int) string {
	// Avoid pulling in strconv just for this; n is always small and non-negative.
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// --- Admin: pending ------------------------------------------------------

func (s *Server) handleListPending(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListPending(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// approvePendingRequest is the optional body of POST
// /v1/admin/pending/{id}/approve. Operators can pin the provisioning profile
// the device should receive when its (subsequent) enrollment is signed —
// without this, the engine falls back to selector matching / default. The
// chosen name is persisted on Device.ProfileName so it survives re-enrollment.
type approvePendingRequest struct {
	Profile string `json:"profile,omitempty"`
}

func (s *Server) handleApprovePending(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.Store.GetPending(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// Body is optional. An empty/missing body keeps the legacy "approve and
	// let the resolver pick a profile" behaviour; a JSON body lets the
	// operator pin a specific profile at approval time.
	var req approvePendingRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	// Move to a known device record. Next enrollment will pass known_keypair.
	dev := &store.Device{
		ID:          p.DeviceID,
		PublicKey:   p.PublicKey,
		Facts:       p.Facts,
		ProfileName: req.Profile,
	}
	if err := s.Store.UpsertDevice(r.Context(), dev); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.Store.DeletePending(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	details := ""
	if req.Profile != "" {
		details = "profile=" + req.Profile
	}
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "approve", DeviceID: p.DeviceID, Details: details,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRejectPending(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := s.Store.GetPending(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if err := s.Store.DeletePending(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "reject", DeviceID: p.DeviceID,
	})
	w.WriteHeader(http.StatusNoContent)
}

// --- Admin: devices ------------------------------------------------------

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListDevices(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.Store.GetDevice(r.Context(), id); err != nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	if err := s.Store.DeleteDevice(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "device.delete", DeviceID: id,
	})
	w.WriteHeader(http.StatusNoContent)
}

// patchDeviceRequest carries the operator-editable bits of a device. Only
// the fields actually present in the JSON body are mutated; unset fields
// leave the existing values intact. To clear a field, pass an empty value
// (e.g. {"profile": ""} unsets the override).
type patchDeviceRequest struct {
	// Profile sets Device.Overrides["_profile"] which the engine consults
	// during enrollment as the highest-priority profile selector.
	Profile *string `json:"profile,omitempty"`
}

func (s *Server) handlePatchDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	dev, err := s.Store.GetDevice(r.Context(), id)
	if err != nil || dev == nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	var req patchDeviceRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Profile != nil {
		if dev.Overrides == nil {
			dev.Overrides = map[string]any{}
		}
		if *req.Profile == "" {
			delete(dev.Overrides, "_profile")
		} else {
			dev.Overrides["_profile"] = *req.Profile
		}
	}
	if err := s.Store.UpsertDevice(r.Context(), dev); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "device.patch", DeviceID: id,
	})
	writeJSON(w, http.StatusOK, dev)
}

// --- Admin: allowlist ----------------------------------------------------

func (s *Server) handleListAllowlist(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListAllowlist(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	var e store.AllowlistEntry
	if err := decodeJSON(r, &e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if e.DeviceID == "" {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}
	if err := s.Store.AddAllowlist(r.Context(), e); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleRemoveAllowlist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.RemoveAllowlist(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Admin: tokens -------------------------------------------------------

// IssueTokenRequest is the body of POST /v1/admin/tokens.
type IssueTokenRequest struct {
	DeviceID   string `json:"device_id,omitempty"`
	MaxUses    int    `json:"max_uses,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Profile    string `json:"profile,omitempty"`
}

// IssueTokenResponse returns the freshly minted token. The plaintext value is
// shown ONCE — operators must record it before the response leaves the wire.
type IssueTokenResponse struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

func (s *Server) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	var req IssueTokenRequest
	_ = decodeJSON(r, &req) // body is optional

	id, secret, hash, err := newTokenSecret()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t := store.BootstrapToken{
		ID:        id,
		Hash:      hash,
		DeviceID:  req.DeviceID,
		MaxUses:   req.MaxUses,
		Profile:   req.Profile,
		CreatedAt: time.Now().UTC(),
	}
	if req.TTLSeconds > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(req.TTLSeconds) * time.Second)
	}
	if err := s.Store.AddToken(r.Context(), t); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, IssueTokenResponse{ID: id, Secret: secret})
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListTokens(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Redact hashes from output to keep them out of operator dashboards.
	type redacted struct {
		ID        string    `json:"id"`
		DeviceID  string    `json:"device_id,omitempty"`
		Profile   string    `json:"profile,omitempty"`
		ExpiresAt time.Time `json:"expires_at,omitempty"`
		Uses      int       `json:"uses"`
		MaxUses   int       `json:"max_uses,omitempty"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := make([]redacted, 0, len(list))
	for _, t := range list {
		out = append(out, redacted{
			ID: t.ID, DeviceID: t.DeviceID, Profile: t.Profile, ExpiresAt: t.ExpiresAt,
			Uses: t.Uses, MaxUses: t.MaxUses, CreatedAt: t.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.RevokeToken(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Admin: audit --------------------------------------------------------

func (s *Server) handleAuditTail(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListAudit(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}
