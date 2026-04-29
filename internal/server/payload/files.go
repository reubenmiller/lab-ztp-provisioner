package payload

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// FileSpec describes one file the device should write.
//
// Contents are flagged sensitive because operators sometimes drop secrets
// (TLS keys, API tokens, /etc/wpa_supplicant snippets) into the files
// provider when there's no dedicated handler for them. Redacting by default
// is the safer choice; nothing in the wire format depends on the contents
// being visible to the API caller.
type FileSpec struct {
	Path     string `json:"path" yaml:"path"`
	Mode     string `json:"mode,omitempty" yaml:"mode,omitempty"`                         // e.g. "0644"
	Owner    string `json:"owner,omitempty" yaml:"owner,omitempty"`                       // e.g. "root:root"
	Contents string `json:"contents,omitempty" yaml:"contents,omitempty" ztp:"sensitive"` // raw contents
	Base64   string `json:"base64,omitempty" yaml:"base64,omitempty" ztp:"sensitive"`     // for binary files
}

// Files emits a files.v2 (INI) module consumed by the files.v2.sh
// applier. The historical files.v1 (JSON) type was removed.
type Files struct {
	Files []FileSpec `yaml:"files,omitempty" json:"files,omitempty"`
}

func (Files) Name() string { return "files" }

func (f *Files) Build(_ context.Context, device *store.Device) ([]protocol.Module, error) {
	files := f.Files
	if device != nil && device.Overrides != nil {
		if v, ok := device.Overrides["files"]; ok {
			if list, ok := v.([]FileSpec); ok {
				files = list
			}
		}
	}
	if len(files) == 0 {
		return nil, nil
	}
	return []protocol.Module{{
		Type:       "files.v2",
		RawPayload: encodeFilesINI(files),
	}}, nil
}

// encodeFilesINI renders the files.v2 INI payload. Contents are always
// base64-encoded into `contents_b64=` to remove the JSON-era ambiguity
// between `contents` and `base64` and to handle binary/multi-line bytes.
func encodeFilesINI(files []FileSpec) []byte {
	var sb strings.Builder
	for i, fs := range files {
		var b64 string
		if fs.Base64 != "" {
			b64 = fs.Base64
		} else if fs.Contents != "" {
			b64 = base64.StdEncoding.EncodeToString([]byte(fs.Contents))
		}
		mode := fs.Mode
		if mode == "" {
			mode = "0644"
		}
		iniSection(&sb, i > 0, "file",
			"path", fs.Path,
			"mode", mode,
			"owner", fs.Owner,
			"contents_b64", b64,
		)
	}
	return []byte(sb.String())
}
