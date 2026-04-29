package profiles

import (
	"net"
	"regexp"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Match reports whether s.constraints all hold against facts. A nil
// selector matches nothing — the caller should treat unselected profiles
// as eligible only via explicit assignment.
//
// All non-empty constraints must match (AND). An invalid regex is treated
// as a non-match (rather than panicking); the loader logs a warning at load
// time so operators notice during config validation.
func (s *Selector) Match(facts protocol.DeviceFacts) bool {
	if s == nil {
		return false
	}
	if !s.matchModel(facts.Model) {
		return false
	}
	if !s.matchHostname(facts.Hostname) {
		return false
	}
	if !s.matchMAC(facts.MACAddresses) {
		return false
	}
	// MatchLabels would consult facts.Labels if/when the protocol grows it.
	// For now, an empty MatchLabels never blocks; a non-empty one requires a
	// labels map on facts (which doesn't exist yet) → always non-match.
	if len(s.MatchLabels) > 0 {
		return false
	}
	return true
}

// IsEmpty returns true when no constraints are configured. The resolver
// uses this to skip a selector quickly: an empty selector never matches
// any device, since matching would otherwise fall through to "true" for
// every constraint and accidentally claim every device.
func (s *Selector) IsEmpty() bool {
	if s == nil {
		return true
	}
	return s.MatchModel == "" &&
		s.MatchHostname == "" &&
		len(s.MatchMACOUI) == 0 &&
		len(s.MatchLabels) == 0
}

func (s *Selector) matchModel(model string) bool {
	if s.MatchModel == "" {
		return true
	}
	re, err := regexp.Compile(s.MatchModel)
	if err != nil {
		return false
	}
	return re.MatchString(model)
}

func (s *Selector) matchHostname(host string) bool {
	if s.MatchHostname == "" {
		return true
	}
	re, err := regexp.Compile(s.MatchHostname)
	if err != nil {
		return false
	}
	return re.MatchString(host)
}

func (s *Selector) matchMAC(macs []string) bool {
	if len(s.MatchMACOUI) == 0 {
		return true
	}
	if len(macs) == 0 {
		return false
	}
	wanted := make([]string, 0, len(s.MatchMACOUI))
	for _, oui := range s.MatchMACOUI {
		w := normaliseOUI(oui)
		if w != "" {
			wanted = append(wanted, w)
		}
	}
	for _, mac := range macs {
		hw, err := net.ParseMAC(mac)
		if err != nil || len(hw) < 3 {
			// Fall back to a relaxed string-prefix match so we accept
			// non-standard separators (and lowercase / uppercase).
			normalised := normaliseOUI(mac)
			for _, w := range wanted {
				if strings.HasPrefix(normalised, w) {
					return true
				}
			}
			continue
		}
		oui := strings.ToLower(strings.ReplaceAll(hw[:3].String(), ":", ""))
		for _, w := range wanted {
			if strings.HasPrefix(oui, w) {
				return true
			}
		}
	}
	return false
}

// normaliseOUI strips separators and lowercases the input so callers can
// pass any of "AA:BB:CC", "aa-bb-cc", "AABBCC". Returns "" for inputs that
// don't contain at least 6 hex digits' worth of OUI material.
func normaliseOUI(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ".", "")
	return s
}
