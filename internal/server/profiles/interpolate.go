package profiles

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// envPattern matches ${VAR} or ${VAR:-default}. We deliberately do NOT
// support $VAR (no braces) because that's ambiguous around punctuation and
// because operators routinely write strings that contain dollar signs (shell
// snippets, regex patterns). Forcing the brace form keeps the substitution
// opt-in.
var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// InterpolateString replaces ${VAR} / ${VAR:-default} occurrences in s with
// values from getEnv. Missing variables with no default produce an error so
// misconfiguration fails loudly at startup rather than silently emitting an
// empty wifi password.
//
// To embed a literal "${" without interpolation, write "$${" — the doubled
// dollar collapses to a single dollar after substitution.
func InterpolateString(s string, getEnv func(string) (string, bool)) (string, error) {
	if !strings.Contains(s, "${") {
		return s, nil
	}
	// Two-pass: first protect literal $${ markers, then interpolate.
	const sentinel = "\x00ZTP_DOLLAR\x00"
	s = strings.ReplaceAll(s, "$${", sentinel+"{")

	var firstErr error
	out := envPattern.ReplaceAllStringFunc(s, func(match string) string {
		groups := envPattern.FindStringSubmatch(match)
		name := groups[1]
		hasDefault := strings.Contains(match, ":-")
		def := groups[2]
		if v, ok := getEnv(name); ok {
			return v
		}
		if hasDefault {
			return def
		}
		if firstErr == nil {
			firstErr = fmt.Errorf("environment variable %q is not set and no default provided", name)
		}
		return match
	})
	if firstErr != nil {
		return "", firstErr
	}
	return strings.ReplaceAll(out, sentinel, "$"), nil
}

// InterpolateTree walks an arbitrary YAML-decoded tree (map[string]any /
// []any / string / scalar) and rewrites every string leaf via
// InterpolateString. Returns the first interpolation error encountered.
//
// Maps are mutated in place; the function returns the (possibly replaced)
// root so callers can interpolate primitive top-level values too.
func InterpolateTree(v any, getEnv func(string) (string, bool)) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		return InterpolateString(x, getEnv)
	case map[string]any:
		for k, vv := range x {
			nv, err := InterpolateTree(vv, getEnv)
			if err != nil {
				return nil, fmt.Errorf("at key %q: %w", k, err)
			}
			x[k] = nv
		}
		return x, nil
	case []any:
		for i, vv := range x {
			nv, err := InterpolateTree(vv, getEnv)
			if err != nil {
				return nil, fmt.Errorf("at index %d: %w", i, err)
			}
			x[i] = nv
		}
		return x, nil
	default:
		return v, nil
	}
}

// OSEnv returns a getEnv callback that reads from os.Getenv. Use it as the
// default in production; tests pass their own.
func OSEnv() func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := os.LookupEnv(name)
		return v, ok
	}
}
