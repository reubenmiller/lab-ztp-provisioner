package profiles

import (
	"testing"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

func TestSelector_Match(t *testing.T) {
	cases := []struct {
		name string
		sel  *Selector
		f    protocol.DeviceFacts
		want bool
	}{
		{"nil selector never matches", nil, protocol.DeviceFacts{}, false},
		{"empty selector never matches via Match", &Selector{}, protocol.DeviceFacts{Model: "x"}, true},
		{"model regex match", &Selector{MatchModel: "^rpi-"}, protocol.DeviceFacts{Model: "rpi-4"}, true},
		{"model regex miss", &Selector{MatchModel: "^rpi-"}, protocol.DeviceFacts{Model: "intel"}, false},
		{"hostname regex", &Selector{MatchHostname: "^lab-\\d+$"}, protocol.DeviceFacts{Hostname: "lab-7"}, true},
		{"oui colon match", &Selector{MatchMACOUI: []string{"dc:a6:32"}}, protocol.DeviceFacts{MACAddresses: []string{"DC:A6:32:11:22:33"}}, true},
		{"oui no separator", &Selector{MatchMACOUI: []string{"dca632"}}, protocol.DeviceFacts{MACAddresses: []string{"dc:a6:32:aa:bb:cc"}}, true},
		{"oui mismatch", &Selector{MatchMACOUI: []string{"00:11:22"}}, protocol.DeviceFacts{MACAddresses: []string{"dc:a6:32:aa:bb:cc"}}, false},
		{"and-of-constraints all match", &Selector{MatchModel: "rpi", MatchHostname: "lab"}, protocol.DeviceFacts{Model: "rpi-4", Hostname: "lab-1"}, true},
		{"and-of-constraints one fails", &Selector{MatchModel: "rpi", MatchHostname: "lab"}, protocol.DeviceFacts{Model: "rpi-4", Hostname: "prod"}, false},
		{"labels constraint always non-match (facts has no labels)", &Selector{MatchLabels: map[string]string{"env": "prod"}}, protocol.DeviceFacts{}, false},
	}
	for _, c := range cases {
		got := c.sel.Match(c.f)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestSelector_IsEmpty(t *testing.T) {
	if !(*Selector)(nil).IsEmpty() {
		t.Error("nil selector should be empty")
	}
	if !(&Selector{}).IsEmpty() {
		t.Error("zero selector should be empty")
	}
	if (&Selector{MatchModel: "x"}).IsEmpty() {
		t.Error("selector with MatchModel should not be empty")
	}
}
