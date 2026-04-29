package profiles

import (
	"strings"
	"testing"
)

func TestInterpolateString_Basic(t *testing.T) {
	env := map[string]string{"FOO": "bar", "EMPTY": ""}
	get := func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"${FOO}", "bar", false},
		{"prefix-${FOO}-suffix", "prefix-bar-suffix", false},
		{"${MISSING:-fallback}", "fallback", false},
		{"${EMPTY:-fallback}", "", false}, // empty is set, default not used
		{"${FOO} and ${MISSING:-x}", "bar and x", false},
		{"no vars here", "no vars here", false},
		{"$${FOO}", "${FOO}", false}, // literal
		{"${MISSING}", "", true},
	}
	for _, c := range cases {
		got, err := InterpolateString(c.in, get)
		if (err != nil) != c.wantErr {
			t.Errorf("InterpolateString(%q): err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("InterpolateString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestInterpolateTree(t *testing.T) {
	env := map[string]string{"PASS": "s3cret"}
	get := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	tree := map[string]any{
		"wifi": map[string]any{
			"password": "${PASS}",
			"networks": []any{
				map[string]any{"ssid": "n1", "password": "${PASS}"},
			},
		},
		"plain": "untouched",
	}
	out, err := InterpolateTree(tree, get)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	m := out.(map[string]any)
	w := m["wifi"].(map[string]any)
	if w["password"] != "s3cret" {
		t.Errorf("password not interpolated: %v", w["password"])
	}
	nets := w["networks"].([]any)
	if nets[0].(map[string]any)["password"] != "s3cret" {
		t.Errorf("nested password not interpolated: %v", nets[0])
	}
}

func TestValidateName(t *testing.T) {
	good := []string{"default", "lab-1", "site_a", "a", "abc123"}
	bad := []string{"", "Default", "-bad", "a..b", strings.Repeat("a", 64)}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) unexpected error: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := ValidateName(n); err == nil {
			t.Errorf("ValidateName(%q) expected error", n)
		}
	}
}
