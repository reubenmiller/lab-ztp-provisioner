package payload

import (
	"context"
	"fmt"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// WiFiConfig is a single network the device should join. The applier on the
// device decides whether to render wpa_supplicant.conf or a NetworkManager
// keyfile based on what's installed.
type WiFiConfig struct {
	SSID     string `json:"ssid" yaml:"ssid"`
	Password string `json:"password,omitempty" yaml:"password,omitempty" ztp:"sensitive"`
	Hidden   bool   `json:"hidden,omitempty" yaml:"hidden,omitempty"`
	Priority int    `json:"priority,omitempty" yaml:"priority,omitempty"`
	KeyMgmt  string `json:"key_mgmt,omitempty" yaml:"key_mgmt,omitempty"` // e.g. "WPA-PSK", "NONE"
}

// WiFi is a Provider that emits a wifi.v2 (INI) module consumed by the
// wifi.v2.sh applier on the device. The historical wifi.v1 (JSON)
// type was removed; agents that still ship only wifi.v1.sh appliers
// will silently skip the unknown module type and need to be upgraded.
type WiFi struct {
	Networks []WiFiConfig `yaml:"networks,omitempty" json:"networks,omitempty"`
}

func (WiFi) Name() string { return "wifi" }

func (w *WiFi) Build(_ context.Context, device *store.Device) ([]protocol.Module, error) {
	networks := w.Networks
	if device != nil && device.Overrides != nil {
		if v, ok := device.Overrides["wifi"]; ok {
			if list, ok := v.([]WiFiConfig); ok {
				networks = list
			}
		}
	}
	if len(networks) == 0 {
		return nil, nil
	}
	return []protocol.Module{{
		Type:       "wifi.v2",
		RawPayload: encodeWiFiINI(networks),
	}}, nil
}

// encodeWiFiINI renders the wifi.v2 INI payload. One [network] section per
// configured network, in declaration order.
func encodeWiFiINI(networks []WiFiConfig) []byte {
	var sb strings.Builder
	for i, n := range networks {
		hidden := "false"
		if n.Hidden {
			hidden = "true"
		}
		iniSection(&sb, i > 0, "network",
			"ssid", n.SSID,
			"password", n.Password,
			"key_mgmt", n.KeyMgmt,
			"hidden", hidden,
			"priority", fmt.Sprintf("%d", n.Priority),
		)
	}
	return []byte(sb.String())
}
