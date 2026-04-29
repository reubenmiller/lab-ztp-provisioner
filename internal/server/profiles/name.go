package profiles

import (
	"fmt"
	"regexp"
	"strings"
)

// nameRE constrains profile names to a subset that is safe in URLs, file
// paths, and shell snippets without escaping.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidateName returns nil iff name conforms to the profile-name grammar.
// Returned errors are user-facing (rendered in API responses + UI).
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("profile name is required")
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("profile name %q is invalid: must match [a-z0-9][a-z0-9_-]{0,62}", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("profile name %q is invalid", name)
	}
	return nil
}

// DefaultName is the canonical name of the fallback profile. The resolver
// uses this when no explicit assignment matches and config.DefaultProfile
// is unset.
const DefaultName = "default"
