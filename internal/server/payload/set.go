package payload

// Set bundles all built-in PayloadProvider configurations into a single
// YAML-loadable struct. It used to live in internal/server/config as
// PayloadConfig; it now lives next to the providers themselves so that the
// profiles package can embed it without pulling in the full server config
// (which would form an import cycle).
//
// Each field is a pointer so an unset provider stays nil and is skipped by
// BuildRegistry. The YAML tags preserve the original schema so existing
// configs continue to parse.
type Set struct {
	WiFi       *WiFi       `yaml:"wifi,omitempty" json:"wifi,omitempty" ztp:"contains_secrets"`
	SSH        *SSH        `yaml:"ssh,omitempty" json:"ssh,omitempty"`
	Cumulocity *Cumulocity `yaml:"cumulocity,omitempty" json:"cumulocity,omitempty" ztp:"contains_secrets"`
	Files      *Files      `yaml:"files,omitempty" json:"files,omitempty"`
	Hook       *Hook       `yaml:"hook,omitempty" json:"hook,omitempty" ztp:"sensitive"`
	Passwd     *Passwd     `yaml:"passwd,omitempty" json:"passwd,omitempty" ztp:"contains_secrets"`
}

// BuildRegistry returns a Registry containing the providers that are non-nil
// in this Set, in the canonical order: wifi, ssh, c8y, files, hook. Provider
// stack order is observable to the device (modules are applied in registry
// order), so we keep it deterministic across reloads.
func (s *Set) BuildRegistry() Registry {
	if s == nil {
		return nil
	}
	r := make(Registry, 0, 6)
	if s.WiFi != nil {
		r = append(r, s.WiFi)
	}
	if s.SSH != nil {
		r = append(r, s.SSH)
	}
	if s.Cumulocity != nil {
		r = append(r, s.Cumulocity)
	}
	if s.Files != nil {
		r = append(r, s.Files)
	}
	if s.Hook != nil {
		r = append(r, s.Hook)
	}
	if s.Passwd != nil {
		r = append(r, s.Passwd)
	}
	return r
}
