package sopsage

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// normalizeYAML re-marshals YAML through yaml.v3 so two semantically
// identical documents compare equal even when the source text differs in
// quoting, indentation, or key ordering. Tests use this to focus on the
// structural correctness of decrypt output rather than chasing
// formatting trivia.
func normalizeYAML(t *testing.T, in []byte) string {
	t.Helper()
	var v any
	if err := yaml.Unmarshal(in, &v); err != nil {
		t.Fatalf("normalize unmarshal: %v\ninput:\n%s", err, in)
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("normalize marshal: %v", err)
	}
	return string(out)
}
