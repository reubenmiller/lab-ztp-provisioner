package profiles

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// FileLoader reads profile YAML files from a directory. SOPS-encrypted files
// are detected and decrypted in-process via the sopsage package; environment
// -variable interpolation runs after decryption so ${VAR} works inside
// encrypted values too.
type FileLoader struct {
	Dir    string
	Logger *slog.Logger

	// AgeIdentity is the server's age private key, used to decrypt SOPS-age
	// sealed profile files. Nil disables decryption support — encrypted
	// files will fail to load with a clear error rather than crashing.
	AgeIdentity age.Identity

	// GetEnv is the environment lookup callback used during interpolation.
	// Tests inject their own; production code should use OSEnv().
	GetEnv func(string) (string, bool)

	mu       sync.RWMutex
	profiles map[string]Profile
}

// NewFileLoader returns a loader bound to dir. Pass an empty dir to disable
// file-backed profiles entirely (Load is a no-op).
func NewFileLoader(dir string, logger *slog.Logger) *FileLoader {
	if logger == nil {
		logger = slog.Default()
	}
	return &FileLoader{
		Dir:      dir,
		Logger:   logger,
		GetEnv:   OSEnv(),
		profiles: map[string]Profile{},
	}
}

// Load (re-)reads every *.yaml / *.yml file in Dir. On success the new map
// atomically replaces the previous one. Per-file errors are logged but do
// not abort the load — operators can fix one broken file without taking
// the whole server down. Returns the count of successfully loaded profiles
// and the first hard error (if any).
func (l *FileLoader) Load(ctx context.Context) (int, error) {
	if l.Dir == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(l.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			l.Logger.Warn("profiles dir does not exist", "dir", l.Dir)
			return 0, nil
		}
		return 0, fmt.Errorf("read profiles dir: %w", err)
	}
	loaded := make(map[string]Profile, len(entries))
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(l.Dir, name)
		p, err := l.loadOne(ctx, path)
		if err != nil {
			l.Logger.Error("profile load failed", "path", path, "err", err)
			continue
		}
		if existing, ok := loaded[p.Name]; ok {
			l.Logger.Warn("duplicate profile name; later file wins",
				"name", p.Name, "first", existing.UpdatedBy, "second", path)
		}
		loaded[p.Name] = p
	}
	l.mu.Lock()
	l.profiles = loaded
	l.mu.Unlock()
	return len(loaded), nil
}

// loadOne reads, optionally decrypts, interpolates, and parses one file.
// Returns a fully-populated Profile with Source=SourceFile.
func (l *FileLoader) loadOne(ctx context.Context, path string) (Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	stat, _ := os.Stat(path)
	mtime := time.Time{}
	if stat != nil {
		mtime = stat.ModTime().UTC()
	}

	if IsSOPS(raw) {
		dec, err := DecryptSOPS(ctx, raw, l.AgeIdentity)
		if err != nil {
			return Profile{}, fmt.Errorf("decrypt sops: %w", err)
		}
		raw = dec
	}

	// Decode as a generic tree first so we can run interpolation, then
	// re-marshal and decode into the typed Profile. yaml.v3 can't both
	// decode-into-struct and run a callback on string leaves, so the
	// round-trip is the simplest correct option.
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return Profile{}, fmt.Errorf("parse yaml: %w", err)
	}
	getEnv := l.GetEnv
	if getEnv == nil {
		getEnv = OSEnv()
	}
	if _, err := InterpolateTree(tree, getEnv); err != nil {
		return Profile{}, fmt.Errorf("env interpolation: %w", err)
	}
	out, err := yaml.Marshal(tree)
	if err != nil {
		return Profile{}, fmt.Errorf("re-marshal: %w", err)
	}
	var p Profile
	if err := yaml.Unmarshal(out, &p); err != nil {
		return Profile{}, fmt.Errorf("decode profile: %w", err)
	}
	if p.Name == "" {
		// Fall back to the file stem so operators can omit the redundant
		// `name:` field.
		p.Name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if err := ValidateName(p.Name); err != nil {
		return Profile{}, err
	}
	p.Source = SourceFile
	p.UpdatedAt = mtime
	p.UpdatedBy = "file:" + filepath.Base(path)
	return p, nil
}

// Snapshot returns a copy of the currently-loaded profiles, sorted by
// (priority desc, name asc) — the order Resolver.Resolve uses for selector
// evaluation.
func (l *FileLoader) Snapshot() []Profile {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Profile, 0, len(l.profiles))
	for _, p := range l.profiles {
		out = append(out, p)
	}
	sortByPriority(out)
	return out
}

// Get returns the named file profile, or nil if missing.
func (l *FileLoader) Get(name string) *Profile {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if p, ok := l.profiles[name]; ok {
		cp := p
		return &cp
	}
	return nil
}

func sortByPriority(ps []Profile) {
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Priority != ps[j].Priority {
			return ps[i].Priority > ps[j].Priority
		}
		return ps[i].Name < ps[j].Name
	})
}
