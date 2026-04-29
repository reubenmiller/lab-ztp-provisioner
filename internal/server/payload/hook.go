package payload

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Hook emits a hook.v2 (INI) module that asks the device to run a
// shell snippet after the rest of the bundle has been applied.
// Disabled by default; only included when Script is non-empty. The
// historical hook.v1 (JSON) type was removed.
//
// The agent verifies the bundle signature before executing any hook, and
// the device-side applier should refuse to run unsigned bundles. Operators
// should treat this module as privileged and only enable it when truly
// needed.
type Hook struct {
	Script      string `yaml:"script,omitempty" json:"script,omitempty" ztp:"sensitive"`
	Interpreter string `yaml:"interpreter,omitempty" json:"interpreter,omitempty"` // default "/bin/sh"
}

func (Hook) Name() string { return "hook" }

func (h *Hook) Build(_ context.Context, _ *store.Device) ([]protocol.Module, error) {
	if h.Script == "" {
		return nil, nil
	}
	interp := h.Interpreter
	if interp == "" {
		interp = "/bin/sh"
	}
	var sb strings.Builder
	iniSection(&sb, false, "hook",
		"interpreter", interp,
		"script_b64", base64.StdEncoding.EncodeToString([]byte(h.Script)),
	)
	return []protocol.Module{{
		Type:       "hook.v2",
		RawPayload: []byte(sb.String()),
	}}, nil
}
