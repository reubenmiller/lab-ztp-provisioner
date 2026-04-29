package payload

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// SSH installs authorized_keys for a target user.
type SSH struct {
	User         string   `yaml:"user,omitempty" json:"user,omitempty"`                     // unix user; default "root"
	Keys         []string `yaml:"keys,omitempty" json:"keys,omitempty"`                     // OpenSSH public-key lines
	GitHubUsers  []string `yaml:"github_users,omitempty" json:"github_users,omitempty"`     // usernames to fetch from https://github.com/<user>.keys
	GitHubAPIURL string   `yaml:"github_api_url,omitempty" json:"github_api_url,omitempty"` // override base URL (default "https://github.com"); useful for GHE

	mu    sync.Mutex
	cache map[string]githubKeysCacheEntry
}

type githubKeysCacheEntry struct {
	keys      []string
	fetchedAt time.Time
}

// githubKeysCacheTTL bounds how often we re-hit github.com for the same user.
const githubKeysCacheTTL = 5 * time.Minute

func (*SSH) Name() string { return "ssh" }

func (s *SSH) Build(ctx context.Context, device *store.Device) ([]protocol.Module, error) {
	user := s.User
	if user == "" {
		user = "root"
	}
	keys := s.Keys
	ghUsers := s.GitHubUsers
	if device != nil && device.Overrides != nil {
		if v, ok := device.Overrides["ssh_keys"]; ok {
			if list, ok := v.([]string); ok {
				keys = list
			}
		}
		if v, ok := device.Overrides["ssh_github_users"]; ok {
			if list, ok := v.([]string); ok {
				ghUsers = list
			}
		}
	}

	for _, ghUser := range ghUsers {
		ghUser = strings.TrimSpace(ghUser)
		if ghUser == "" {
			continue
		}
		fetched, err := s.fetchGitHubKeys(ctx, ghUser)
		if err != nil {
			slog.Warn("ssh: fetch github keys", "user", ghUser, "err", err)
			continue
		}
		keys = append(keys, fetched...)
	}

	keys = dedupeKeys(keys)
	if len(keys) == 0 {
		return nil, nil
	}

	return []protocol.Module{{
		Type:       "ssh.authorized_keys.v2",
		RawPayload: encodeSSHINI(user, keys),
	}}, nil
}

// encodeSSHINI renders the ssh.authorized_keys.v2 payload. Repeated `key=`
// lines preserve insertion order — the parser emits one record per line, so
// they don't collide.
func encodeSSHINI(user string, keys []string) []byte {
	var sb strings.Builder
	sb.WriteString("[ssh]\n")
	fmt.Fprintf(&sb, "user=%s\n", user)
	for _, k := range keys {
		if k == "" {
			continue
		}
		fmt.Fprintf(&sb, "key=%s\n", k)
	}
	return []byte(sb.String())
}

// fetchGitHubKeys retrieves the public SSH keys for a GitHub user from
// https://github.com/<user>.keys (or the configured GitHubAPIURL base).
// Results are cached per-SSH-instance for githubKeysCacheTTL to avoid
// hammering GitHub during bursts of provisioning.
func (s *SSH) fetchGitHubKeys(ctx context.Context, user string) ([]string, error) {
	s.mu.Lock()
	if s.cache == nil {
		s.cache = make(map[string]githubKeysCacheEntry)
	}
	if e, ok := s.cache[user]; ok && time.Since(e.fetchedAt) < githubKeysCacheTTL {
		s.mu.Unlock()
		return e.keys, nil
	}
	s.mu.Unlock()

	base := strings.TrimRight(s.GitHubAPIURL, "/")
	if base == "" {
		base = "https://github.com"
	}
	url := fmt.Sprintf("%s/%s.keys", base, user)

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tedge-ztp-server")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}

	s.mu.Lock()
	s.cache[user] = githubKeysCacheEntry{keys: keys, fetchedAt: time.Now()}
	s.mu.Unlock()
	return keys, nil
}

// dedupeKeys removes duplicate authorized_keys entries while preserving order.
// Keys are compared by the (type, base64) pair so a re-comment doesn't cause
// a duplicate to slip through.
func dedupeKeys(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, k := range in {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		fields := strings.Fields(k)
		var fp string
		if len(fields) >= 2 {
			fp = fields[0] + " " + fields[1]
		} else {
			fp = k
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		out = append(out, k)
	}
	return out
}
