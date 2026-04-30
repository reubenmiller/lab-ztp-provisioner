package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/zalando/go-keyring"
)

const c8yKeyringService = "io.thin-edge.ztp-app"

type c8ySecret struct {
	URL      string    `json:"url,omitempty"`
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
	Updated  time.Time `json:"updated_at,omitempty"`
}

type c8yCredentialMeta struct {
	ID       string    `json:"id"`
	URL      string    `json:"url,omitempty"`
	Username string    `json:"username,omitempty"`
	Updated  time.Time `json:"updated_at,omitempty"`
}

type c8yCredentialIndex struct {
	Entries []c8yCredentialMeta `json:"entries,omitempty"`
}

// C8YCredential is the non-secret representation returned to the SPA.
// Secret material is never returned over the Wails boundary.
type C8YCredential struct {
	ID        string `json:"id"`
	URL       string `json:"url,omitempty"`
	Username  string `json:"username,omitempty"`
	HasSecret bool   `json:"hasSecret"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func (a *App) ListC8YCredentials() ([]C8YCredential, error) {
	idx, err := a.readC8YCredentialIndex()
	if err != nil {
		return nil, err
	}
	out := make([]C8YCredential, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		_, err := keyring.Get(c8yKeyringService, c8yCredentialKey(e.ID))
		hasSecret := err == nil
		if errors.Is(err, keyring.ErrNotFound) {
			hasSecret = false
		} else if err != nil {
			return nil, fmt.Errorf("keyring get %q: %w", e.ID, err)
		}
		c := C8YCredential{ID: e.ID, URL: e.URL, Username: e.Username, HasSecret: hasSecret}
		if !e.Updated.IsZero() {
			c.UpdatedAt = e.Updated.UTC().Format(time.RFC3339)
		}
		out = append(out, c)
	}
	return out, nil
}

// SetC8YCredential stores/updates one credential entry.
// The secret is persisted in the OS keyring; only non-secret metadata lands on disk.
func (a *App) SetC8YCredential(id, url, username, password string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("credential id is required")
	}
	url = strings.TrimSpace(url)
	if url == "" {
		return errors.New("credential url is required")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}
	secret := c8ySecret{URL: url, Username: strings.TrimSpace(username), Password: password, Updated: time.Now().UTC()}
	raw, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	if err := keyring.Set(c8yKeyringService, c8yCredentialKey(id), string(raw)); err != nil {
		return fmt.Errorf("keyring set %q: %w", id, err)
	}
	idx, err := a.readC8YCredentialIndex()
	if err != nil {
		return err
	}
	updated := false
	for i := range idx.Entries {
		if idx.Entries[i].ID == id {
			idx.Entries[i].URL = secret.URL
			idx.Entries[i].Username = secret.Username
			idx.Entries[i].Updated = secret.Updated
			updated = true
			break
		}
	}
	if !updated {
		idx.Entries = append(idx.Entries, c8yCredentialMeta{ID: id, URL: secret.URL, Username: secret.Username, Updated: secret.Updated})
	}
	sort.Slice(idx.Entries, func(i, j int) bool {
		return idx.Entries[i].ID < idx.Entries[j].ID
	})
	return a.writeC8YCredentialIndex(idx)
}

func (a *App) DeleteC8YCredential(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("credential id is required")
	}
	if err := keyring.Delete(c8yKeyringService, c8yCredentialKey(id)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keyring delete %q: %w", id, err)
	}
	idx, err := a.readC8YCredentialIndex()
	if err != nil {
		return err
	}
	next := idx.Entries[:0]
	for _, e := range idx.Entries {
		if e.ID != id {
			next = append(next, e)
		}
	}
	idx.Entries = next
	return a.writeC8YCredentialIndex(idx)
}

// BuildC8YCredentialLookup returns a runtime credential_ref lookup backed by
// the desktop credential index and OS keyring.
func BuildC8YCredentialLookup(configDir string) payload.CredentialLookup {
	configDir = strings.TrimSpace(configDir)
	if configDir == "" {
		return nil
	}
	return func(ref string) (payload.CredentialMaterial, bool) {
		meta, secret, ok := readDesktopCredential(configDir, ref)
		if !ok {
			return payload.CredentialMaterial{}, false
		}
		return payload.CredentialMaterial{
			URL:      firstNonEmpty(secret.URL, meta.URL),
			Username: firstNonEmpty(secret.Username, meta.Username),
			Password: secret.Password,
		}, true
	}
}

func c8yCredentialKey(id string) string {
	return "c8y:" + id
}

func (a *App) c8yCredentialIndexPath() (string, error) {
	if strings.TrimSpace(a.runtimeInfo.ConfigDir) == "" {
		return "", errors.New("desktop config directory is not set")
	}
	return c8yCredentialIndexPath(a.runtimeInfo.ConfigDir), nil
}

func c8yCredentialIndexPath(configDir string) string {
	return filepath.Join(configDir, "c8y-credentials.json")
}

func (a *App) readC8YCredentialIndex() (c8yCredentialIndex, error) {
	path, err := a.c8yCredentialIndexPath()
	if err != nil {
		return c8yCredentialIndex{}, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c8yCredentialIndex{}, nil
	}
	if err != nil {
		return c8yCredentialIndex{}, err
	}
	var idx c8yCredentialIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return c8yCredentialIndex{}, fmt.Errorf("decode credential index: %w", err)
	}
	return idx, nil
}

func (a *App) writeC8YCredentialIndex(idx c8yCredentialIndex) error {
	path, err := a.c8yCredentialIndexPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func readDesktopCredential(configDir, id string) (c8yCredentialMeta, c8ySecret, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return c8yCredentialMeta{}, c8ySecret{}, false
	}
	b, err := os.ReadFile(c8yCredentialIndexPath(configDir))
	if err != nil {
		return c8yCredentialMeta{}, c8ySecret{}, false
	}
	var idx c8yCredentialIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return c8yCredentialMeta{}, c8ySecret{}, false
	}
	var meta c8yCredentialMeta
	found := false
	for _, entry := range idx.Entries {
		if entry.ID == id {
			meta = entry
			found = true
			break
		}
	}
	if !found {
		return c8yCredentialMeta{}, c8ySecret{}, false
	}
	raw, err := keyring.Get(c8yKeyringService, c8yCredentialKey(id))
	if err != nil {
		return c8yCredentialMeta{}, c8ySecret{}, false
	}
	var secret c8ySecret
	if err := json.Unmarshal([]byte(raw), &secret); err != nil {
		return c8yCredentialMeta{}, c8ySecret{}, false
	}
	return meta, secret, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
