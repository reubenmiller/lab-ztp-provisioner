package profiles

import (
	"context"
	"testing"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

type memStore struct{ m map[string]Profile }

func (s *memStore) ListProfiles(_ context.Context) ([]Profile, error) {
	out := make([]Profile, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, p)
	}
	return out, nil
}
func (s *memStore) GetProfile(_ context.Context, name string) (*Profile, error) {
	if p, ok := s.m[name]; ok {
		return &p, nil
	}
	return nil, nil
}

func newRes(profiles map[string]Profile, def string) *Resolver {
	return NewResolver(nil, &memStore{m: profiles}, def, nil)
}

func TestResolver_Override_BeatsEverything(t *testing.T) {
	r := newRes(map[string]Profile{
		"a": {Name: "a"},
		"b": {Name: "b"},
	}, "a")
	got, err := r.Resolve(context.Background(), ResolveHints{Override: "b", PersistedProfile: "a", Profile: "a"}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "b" {
		t.Errorf("override should win, got %s", got.Name)
	}
}

func TestResolver_Persisted_BeatsHint(t *testing.T) {
	r := newRes(map[string]Profile{"a": {Name: "a"}, "b": {Name: "b"}}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{PersistedProfile: "a", Profile: "b"}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "a" {
		t.Errorf("persisted should win, got %s", got.Name)
	}
}

func TestResolver_Hint_WhenNoOverrideOrPersisted(t *testing.T) {
	r := newRes(map[string]Profile{"a": {Name: "a"}, "b": {Name: "b"}}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{Profile: "b"}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "b" {
		t.Errorf("hint should win, got %s", got.Name)
	}
}

func TestResolver_SelectorMatch(t *testing.T) {
	r := newRes(map[string]Profile{
		"rpi": {Name: "rpi", Priority: 10, Selector: &Selector{MatchModel: "^rpi"}},
		"x86": {Name: "x86", Priority: 10, Selector: &Selector{MatchModel: "^intel"}},
	}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{}, protocol.DeviceFacts{Model: "rpi-4"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "rpi" {
		t.Errorf("expected rpi, got %s", got.Name)
	}
}

func TestResolver_DefaultFallback(t *testing.T) {
	r := newRes(map[string]Profile{"default": {Name: "default"}}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "default" {
		t.Errorf("got %s", got.Name)
	}
}

func TestResolver_ConfiguredDefault(t *testing.T) {
	r := newRes(map[string]Profile{"site-a": {Name: "site-a"}}, "site-a")
	got, err := r.Resolve(context.Background(), ResolveHints{}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "site-a" {
		t.Errorf("got %s", got.Name)
	}
}

func TestResolver_NoMatch_ErrNoProfile(t *testing.T) {
	r := newRes(map[string]Profile{"a": {Name: "a", Selector: &Selector{MatchModel: "^never$"}}}, "")
	_, err := r.Resolve(context.Background(), ResolveHints{}, protocol.DeviceFacts{Model: "x"})
	if err != ErrNoProfile {
		t.Errorf("got %v, want ErrNoProfile", err)
	}
}

func TestResolver_MissingHintFallsThrough(t *testing.T) {
	// Explicit hint refers to a profile that doesn't exist; resolver should
	// log and fall through to default rather than fail hard.
	r := newRes(map[string]Profile{"default": {Name: "default"}}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{Profile: "ghost"}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "default" {
		t.Errorf("expected default fallthrough, got %s", got.Name)
	}
}

func TestResolver_RequestedHint_BeatsDefault(t *testing.T) {
	// Device-supplied hint wins over the configured default when no other
	// step matched.
	r := newRes(map[string]Profile{
		"site-a": {Name: "site-a"},
		"lab":    {Name: "lab"},
	}, "site-a")
	got, err := r.Resolve(context.Background(), ResolveHints{Requested: "lab"}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "lab" {
		t.Errorf("requested should beat default, got %s", got.Name)
	}
}

func TestResolver_SelectorBeatsRequested(t *testing.T) {
	// Selector match (operator-controlled) outranks the device's advisory
	// hint. This is the security-relevant case: a misconfigured device
	// must not be able to opt out of a fleet-wide policy.
	r := newRes(map[string]Profile{
		"rpi": {Name: "rpi", Priority: 10, Selector: &Selector{MatchModel: "^rpi"}},
		"lab": {Name: "lab"},
	}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{Requested: "lab"}, protocol.DeviceFacts{Model: "rpi-4"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "rpi" {
		t.Errorf("selector should beat requested, got %s", got.Name)
	}
}

func TestResolver_VerifierBeatsRequested(t *testing.T) {
	// Verifier-bound profile (allowlist / token) outranks the device's hint.
	r := newRes(map[string]Profile{
		"locked": {Name: "locked"},
		"open":   {Name: "open"},
	}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{Profile: "locked", Requested: "open"}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "locked" {
		t.Errorf("verifier should beat requested, got %s", got.Name)
	}
}

func TestResolver_RequestedMissing_FallsThrough(t *testing.T) {
	// Unknown requested profile must not brick the device; it falls through
	// to the configured default.
	r := newRes(map[string]Profile{"default": {Name: "default"}}, "")
	got, err := r.Resolve(context.Background(), ResolveHints{Requested: "ghost"}, protocol.DeviceFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "default" {
		t.Errorf("expected default fallthrough, got %s", got.Name)
	}
}

func TestResolver_BuildRegistry(t *testing.T) {
	r := NewResolver(nil, nil, "", nil)
	reg := r.BuildRegistry(&Profile{Payload: &payload.Set{
		WiFi: &payload.WiFi{Networks: []payload.WiFiConfig{{SSID: "n"}}},
	}})
	if len(reg) != 1 {
		t.Errorf("expected 1 provider, got %d", len(reg))
	}
	// nil profile -> empty registry, not panic
	reg = r.BuildRegistry(nil)
	if reg == nil || len(reg) != 0 {
		t.Errorf("expected empty registry, got %v", reg)
	}
}
