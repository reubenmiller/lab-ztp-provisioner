// Config-file management endpoints. These expose the profiles_dir filesystem
// to the admin UI so both the desktop app and the browser-based ztp-server
// UI can list, read, write, seal, and reveal profile YAML files.
//
// All endpoints require the admin bearer token (they sit under /v1/admin/).
// File access is restricted to the configured profiles_dir; path-traversal
// attempts are rejected with 400.
//
// Endpoints:
//
//	GET  /v1/admin/config/files          — list .yaml/.yml filenames
//	GET  /v1/admin/config/files/{name}   — read raw file content
//	PUT  /v1/admin/config/files/{name}   — write file (creates if absent)
//	POST /v1/admin/config/seal           — seal YAML content, return ciphertext
//	POST /v1/admin/config/reveal         — decrypt SOPS-age content, return plaintext
package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/sopsage"
)

const defaultConfigSealRegex = `^(password|bootstrap_token|static_token|.*secret.*)$`

func (s *Server) registerConfigFileRoutes(admin *http.ServeMux) {
	admin.HandleFunc("GET /v1/admin/config/files", s.handleListConfigFiles)
	admin.HandleFunc("GET /v1/admin/config/files/{name}", s.handleGetConfigFile)
	admin.HandleFunc("PUT /v1/admin/config/files/{name}", s.handlePutConfigFile)
	admin.HandleFunc("POST /v1/admin/config/seal", s.handleSealConfig)
	admin.HandleFunc("POST /v1/admin/config/reveal", s.handleRevealConfig)
}

// configFilePath resolves name to an absolute path inside ProfilesDir.
// Returns an error for any path that escapes the directory or has an
// unsupported extension so callers never need to validate separately.
func (s *Server) configFilePath(name string) (string, error) {
	base := filepath.Base(strings.TrimSpace(name))
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("invalid profile filename")
	}
	if base != name {
		return "", fmt.Errorf("profile filename must not contain path separators")
	}
	if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
		return "", fmt.Errorf("profile filename must end with .yaml or .yml")
	}
	return filepath.Join(s.ProfilesDir, base), nil
}

func (s *Server) handleListConfigFiles(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.ProfilesDir)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []string{})
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, names)
}

func (s *Server) handleGetConfigFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	path, err := s.configFilePath(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handlePutConfigFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	path, err := s.configFilePath(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MiB max
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Auto-seal on write: honour !encrypt/!seal tags; fall back to default
	// regex when neither is present and content is not already encrypted.
	content, err := s.autoSeal(body)
	if err != nil {
		http.Error(w, "seal failed: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = s.Store.AppendAudit(r.Context(), store.AuditEntry{
		Actor: "operator", Action: "config.write", Details: name,
	})
	// Trigger an in-process reload so the new file is picked up immediately.
	if s.ProfileLoader != nil {
		_, _ = s.ProfileLoader.Load(r.Context())
	}
	w.WriteHeader(http.StatusNoContent)
}

// autoSeal applies SOPS-age encryption to plaintext YAML. Already-encrypted
// content is returned unchanged. Tag-based rules (!encrypt / !seal) take
// precedence; the default regex is the fallback.
func (s *Server) autoSeal(content []byte) ([]byte, error) {
	if sopsage.IsEncrypted(content) {
		return content, nil
	}
	recipients, err := s.sealRecipients()
	if err != nil {
		// No key configured — return content as-is (no encryption applied).
		return content, nil
	}

	plain := content
	clean, derived, err := sopsage.PrepareTaggedSeal(plain)
	if err != nil {
		return nil, err
	}
	rules := derived
	if strings.TrimSpace(rules.EncryptedRegex) == "" {
		rules = sopsage.EncryptionRules{EncryptedRegex: defaultConfigSealRegex}
	} else {
		plain = clean
	}
	return sopsage.Encrypt(plain, recipients, rules)
}

func (s *Server) handleSealConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if sopsage.IsEncrypted(body) {
		// Already sealed — nothing to do.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return
	}
	recipients, err := s.sealRecipients()
	if err != nil {
		http.Error(w, "no age key configured: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	plain := body
	clean, derived, err := sopsage.PrepareTaggedSeal(plain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rules := derived
	if strings.TrimSpace(rules.EncryptedRegex) == "" {
		rules = sopsage.EncryptionRules{EncryptedRegex: defaultConfigSealRegex}
	} else {
		plain = clean
	}
	sealed, err := sopsage.Encrypt(plain, recipients, rules)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sealed)
}

func (s *Server) handleRevealConfig(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !sopsage.IsEncrypted(body) {
		http.Error(w, "content does not appear to be SOPS encrypted", http.StatusBadRequest)
		return
	}
	if s.AgeIdentity == nil {
		http.Error(w, "server age identity is not available", http.StatusServiceUnavailable)
		return
	}
	plain, err := sopsage.Decrypt(body, []age.Identity{s.AgeIdentity})
	if err != nil {
		http.Error(w, "decrypt failed: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(plain)
}

func (s *Server) sealRecipients() ([]age.Recipient, error) {
	if s.AgeIdentity == nil {
		return nil, fmt.Errorf("server age identity is not configured")
	}
	seen := map[string]struct{}{}
	var out []age.Recipient
	add := func(r age.Recipient) {
		k := fmt.Sprintf("%v", r)
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	add(s.AgeIdentity.Recipient())
	for _, rec := range s.EncryptionRecipients {
		r, err := age.ParseX25519Recipient(strings.TrimSpace(rec))
		if err != nil {
			continue
		}
		add(r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no age recipients available")
	}
	return out, nil
}
