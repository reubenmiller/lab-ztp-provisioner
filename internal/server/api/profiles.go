// Provisioning-profile admin endpoints.
//
// All profiles are file-backed (loaded from --profiles-dir, optionally
// SOPS-encrypted). Read-only via this API; operators edit the YAML files
// directly (via the Config/Secrets API or git) and SIGHUP the server (or
// hit /reload) to pick up changes.
//
// GET responses are passed through profiles.Redact() so secret values like
// wifi passwords and c8y bootstrap tokens never leave the server in plain
// text.
package api

import (
	"context"
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
