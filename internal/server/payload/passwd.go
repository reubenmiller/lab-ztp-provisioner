package payload

import (
	"context"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Passwd describes the configuration for passwd.v2 applier.
// Each user entry contains a name and password.
type Passwd struct {
	Users []PasswdUser `yaml:"users" json:"users"`
}

type PasswdUser struct {
	Name     string `yaml:"name" json:"name"`
	Password string `yaml:"password" json:"password" ztp:"sensitive"`
}

func (p *Passwd) Name() string { return "passwd" }

func (p *Passwd) Build(_ context.Context, _ *store.Device) ([]protocol.Module, error) {
	if p == nil || len(p.Users) == 0 {
		return nil, nil
	}
	return []protocol.Module{{
		Type:       "passwd.v2",
		RawPayload: encodePasswdINI(p.Users),
	}}, nil
}

// encodePasswdINI renders the passwd.v2 INI payload. One [user] section per
// entry, matching the format expected by the passwd.v2.sh applier.
func encodePasswdINI(users []PasswdUser) []byte {
	var sb strings.Builder
	for i, u := range users {
		iniSection(&sb, i > 0, "user",
			"name", u.Name,
			"password", u.Password,
		)
	}
	return []byte(sb.String())
}
