// Provisioning-profile admin endpoints.
//
// Profiles come from two sources:
//
//   - File-backed (loaded from --profiles-dir, optionally SOPS-encrypted).
//     Read-only via this API; operators edit the YAML in git and SIGHUP
//     the server (or hit /reload) to pick up changes.
//   - DB-backed (created via this API). Editable.
//
// GET responses are passed through profiles.Redact() so secret values like
// wifi passwords and c8y bootstrap tokens never leave the server in plain
// text. To rotate a secret on a DB profile use POST /secrets which accepts a
// patch document and merges it into the stored body before persisting.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/profiles"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

// ProfileResolver is the subset of profiles.Resolver the API needs. Defined
// as an interface so tests can stub it.
type ProfileResolver interface {
	List(ctx context.Context) ([]profiles.Profile, error)
	Get(ctx context.Context, name string) (*profiles.Profile, error)
}

// ProfileLoader is the subset of profiles.FileLoader needed to trigger a
// reload from disk. Optional: when nil, /reload returns 501.
type ProfileLoader interface {
	Load(ctx context.Context) (int, error)
}

// registerProfileRoutes is wired by Routes() when s.Resolver != nil.
func (s *Server) registerProfileRoutes(admin *http.ServeMux) {
	admin.HandleFunc("GET /v1/admin/profiles", s.handleListProfiles)
	admin.HandleFunc("GET /v1/admin/profiles/{name}", s.handleGetProfile)
	admin.HandleFunc("GET /v1/admin/profiles/{name}/export", s.handleExportProfile)
	admin.HandleFunc("POST /v1/admin/profiles", s.handleCreateProfile)
	admin.HandleFunc("PUT /v1/admin/profiles/{name}", s.handleUpdateProfile)
	admin.HandleFunc("DELETE /v1/admin/profiles/{name}", s.handleDeleteProfile)
	admin.HandleFunc("POST /v1/admin/profiles/reload", s.handleReloadProfiles)
	admin.HandleFunc("GET /v1/admin/profiles/encryption-key", s.handleEncryptionKey)
}

// encryptionKeyResponse is the public-key payload ztpctl uses to seal
// secrets so the server can decrypt them. We expose every recipient the
// server has been told about (its own pubkey plus any age_recipients
// from config) so a CLI seal automatically produces a file decryptable
// by every operator who's already configured.
type encryptionKeyResponse struct {
	Alg        string   `json:"alg"`
	Recipients []string `json:"recipients"`
}

func (s *Server) handleEncryptionKey(w http.ResponseWriter, _ *http.Request) {
	if len(s.EncryptionRecipients) == 0 {
		http.Error(w, "server has no age key configured", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, encryptionKeyResponse{
		Alg:        "age-x25519",
		Recipients: append([]string(nil), s.EncryptionRecipients...),
	})
}

// profileSummary is the listing-friendly projection: name + metadata, no
// payload bodies. Keeps list responses small and prevents accidental
// disclosure of even-redacted secret structure.
type profileSummary struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Source      profiles.Source   `json:"source"`
	Labels      map[string]string `json:"labels,omitempty"`
	Priority    int               `json:"priority,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	UpdatedBy   string            `json:"updated_by,omitempty"`
}

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	all, err := s.Resolver.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]profileSummary, 0, len(all))
	for _, p := range all {
		out = append(out, profileSummary{
			Name: p.Name, Description: p.Description, Source: p.Source,
			Labels: p.Labels, Priority: p.Priority,
			UpdatedAt: p.UpdatedAt, UpdatedBy: p.UpdatedBy,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, err := s.Resolver.Get(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if p == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Redact sensitive fields before returning.
	red := profiles.Redact(p)
	writeJSON(w, http.StatusOK, red)
}

// handleExportProfile returns the profile as a YAML document suitable for
// dropping into profiles_dir as a file-backed profile. Sensitive fields
// (wifi password, c8y static_token, hook script body, file contents) are
// replaced with `<redacted>` placeholders — the operator must edit the
// downloaded file to plug in real secrets, or pre-encrypt it with SOPS.
// This is intentional: an export endpoint that reveals plaintext secrets
// would be a tempting credential-exfiltration channel.
func (s *Server) handleExportProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, err := s.Resolver.Get(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if p == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	red := profiles.Redact(p)
	// Strip server-side metadata that doesn't belong in a file-on-disk
	// representation: source/updated_at/updated_by are derived at load time.
	if rp, ok := red.(*profiles.Profile); ok {
		rp.Source = ""
		rp.UpdatedAt = time.Time{}
		rp.UpdatedBy = ""
	}
	// Marshal directly with yaml.v3 so the output uses the same keys the
	// file loader expects (yaml struct tags); a JSON round-trip would emit
	// CamelCase keys for fields that only carry yaml tags and the result
	// would not round-trip through profiles_dir.
	buf, err := yaml.Marshal(red)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+".yaml\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("# ztp profile exported from " + name + "\n# Sensitive fields are redacted; replace `<redacted>` placeholders before deploying.\n"))
	_, _ = w.Write(buf)
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "profile.export", Details: name,
	})
}

// profileCreateRequest is the create/update payload. The Name in the URL
// (PUT) wins over any name in the body.
type profileCreateRequest struct {
	Name        string             `json:"name,omitempty"`
	Description string             `json:"description,omitempty"`
	Labels      map[string]string  `json:"labels,omitempty"`
	Priority    int                `json:"priority,omitempty"`
	Selector    *profiles.Selector `json:"selector,omitempty"`
	Payload     json.RawMessage    `json:"payload,omitempty"`
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var req profileCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := profiles.ValidateName(req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.upsertDBProfile(r.Context(), req.Name, req, "create"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := profiles.ValidateName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Refuse to overwrite a file-backed profile.
	if existing, _ := s.Resolver.Get(r.Context(), name); existing != nil && existing.Source == profiles.SourceFile {
		http.Error(w, "profile is file-backed; edit the YAML and reload", http.StatusForbidden)
		return
	}
	var req profileCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.upsertDBProfile(r.Context(), name, req, "update"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// Refuse to delete a file-backed profile.
	if existing, _ := s.Resolver.Get(r.Context(), name); existing != nil && existing.Source == profiles.SourceFile {
		http.Error(w, "profile is file-backed; delete the YAML and reload", http.StatusForbidden)
		return
	}
	if err := s.Store.DeleteProfile(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "profile.delete", Details: name,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReloadProfiles(w http.ResponseWriter, r *http.Request) {
	if s.ProfileLoader == nil {
		http.Error(w, "no file profile loader configured", http.StatusNotImplemented)
		return
	}
	n, err := s.ProfileLoader.Load(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "profile.reload",
	})
	writeJSON(w, http.StatusOK, map[string]int{"loaded": n})
}

func (s *Server) upsertDBProfile(ctx context.Context, name string, req profileCreateRequest, action string) error {
	// Build the profile struct from the request, then re-marshal as the
	// canonical body JSON the store keeps. This lets the resolver decode it
	// later through the same path file-backed profiles take.
	p := profiles.Profile{
		Name:        name,
		Description: req.Description,
		Labels:      req.Labels,
		Priority:    req.Priority,
		Source:      profiles.SourceDB,
		UpdatedAt:   time.Now().UTC(),
		UpdatedBy:   "operator",
	}
	if req.Selector != nil {
		p.Selector = req.Selector
	}
	// The Payload field is delivered as raw JSON so callers can hand-write
	// any subset of providers without needing the server to know all the
	// possible shapes. Validate by round-tripping through profiles.Profile.
	if len(req.Payload) > 0 {
		var dec struct {
			Payload json.RawMessage `json:"payload"`
		}
		dec.Payload = req.Payload
		raw, _ := json.Marshal(dec)
		var probe profiles.Profile
		if err := json.Unmarshal(raw, &probe); err != nil {
			return err
		}
		p.Payload = probe.Payload
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	rec := store.ProfileRecord{
		Name:        p.Name,
		Description: p.Description,
		BodyJSON:    body,
		UpdatedAt:   p.UpdatedAt,
		UpdatedBy:   p.UpdatedBy,
	}
	if err := s.Store.UpsertProfile(ctx, rec); err != nil {
		return err
	}
	_ = s.Store.AppendAudit(ctx, store.AuditEntry{
		Actor: "operator", Action: "profile." + action, Details: name,
	})
	return nil
}
