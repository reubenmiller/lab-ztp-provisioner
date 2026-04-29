package sopsage

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// macOnlyEncryptedInit is the 32-byte tag mixed into the SHA-512 hash
// when MACOnlyEncrypted is true. The bytes are the SHA-256 of the ASCII
// string "sops"; upstream picked it so the MAC differs unambiguously
// between modes even when they happen to cover the same leaves.
var macOnlyEncryptedInit = [32]byte{
	0x4f, 0xe6, 0xf2, 0xf7, 0x3a, 0x46, 0x77, 0xc8,
	0xa5, 0x6f, 0x16, 0xed, 0x59, 0x07, 0x10, 0xc5,
	0x91, 0xa3, 0x4f, 0xa2, 0x35, 0x99, 0x83, 0x14,
	0xb1, 0x44, 0xa6, 0xa6, 0x82, 0xea, 0xa8, 0xc8,
}

// IsEncrypted reports whether yamlBytes contains a top-level "sops:" key,
// which is sops's reliable marker for an encrypted document.
func IsEncrypted(yamlBytes []byte) bool {
	for i := 0; i <= len(yamlBytes)-len("sops:"); i++ {
		if (i == 0 || yamlBytes[i-1] == '\n') &&
			yamlBytes[i] == 's' && yamlBytes[i+1] == 'o' &&
			yamlBytes[i+2] == 'p' && yamlBytes[i+3] == 's' &&
			yamlBytes[i+4] == ':' {
			return true
		}
	}
	return false
}

// Decrypt opens a sops-encrypted YAML document and returns plaintext YAML.
// MAC verification is mandatory; tampered documents return ErrMACMismatch.
//
// The implementation walks a yaml.Node tree directly so document order is
// preserved for both the MAC computation (which must match upstream sops's
// in-order traversal) and the re-emitted output (no gratuitous key
// reordering on round-trips through `ztpctl secrets edit`).
func Decrypt(yamlBytes []byte, identities []age.Identity) ([]byte, error) {
	return decryptCore(yamlBytes, identities, false)
}

// DecryptIgnoreMAC is Decrypt without MAC verification, reserved for
// admin-recovery flows like `ztpctl secrets reveal --ignore-mac`. The
// server's profile loader never calls this.
func DecryptIgnoreMAC(yamlBytes []byte, identities []age.Identity) ([]byte, error) {
	return decryptCore(yamlBytes, identities, true)
}

func decryptCore(yamlBytes []byte, identities []age.Identity, ignoreMAC bool) ([]byte, error) {
	if !IsEncrypted(yamlBytes) {
		return nil, ErrNotEncrypted
	}

	var root yaml.Node
	if err := yaml.Unmarshal(yamlBytes, &root); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("expected a YAML document")
	}
	rootMap := root.Content[0]
	if rootMap.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected the root to be a YAML mapping")
	}

	meta, err := extractSOPSMeta(rootMap)
	if err != nil {
		return nil, err
	}

	dataKey, err := decryptDataKey(meta.AgeRecipients, identities)
	if err != nil {
		return nil, err
	}

	d := &nodeDecryptor{dataKey: dataKey}
	if err := d.walk(rootMap, nil); err != nil {
		return nil, fmt.Errorf("decrypt tree: %w", err)
	}

	if !ignoreMAC {
		if err := verifyMAC(meta, dataKey, d); err != nil {
			return nil, err
		}
	}

	out, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("re-marshal: %w", err)
	}
	return out, nil
}

// extractSOPSMeta locates "sops:" in the root mapping, removes it from the
// node tree (so subsequent walks ignore it), and returns the typed metadata.
func extractSOPSMeta(rootMap *yaml.Node) (Metadata, error) {
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value == "sops" {
			rawSops := rootMap.Content[i+1]
			rootMap.Content = append(rootMap.Content[:i], rootMap.Content[i+2:]...)
			var m Metadata
			if err := rawSops.Decode(&m); err != nil {
				return Metadata{}, fmt.Errorf("decode sops metadata: %w", err)
			}
			return m, nil
		}
	}
	return Metadata{}, ErrNotEncrypted
}

// nodeDecryptor walks a yaml.Node tree in document order, decrypting
// ENC[…] scalars in place and recording every leaf for MAC verification.
type nodeDecryptor struct {
	dataKey []byte

	// allLeaves and encryptedLeaves are MAC inputs in document order.
	// allLeaves covers every scalar (used when MACOnlyEncrypted=false);
	// encryptedLeaves covers only originally-encrypted scalars.
	allLeaves       []string
	encryptedLeaves []string
}

func (d *nodeDecryptor) walk(n *yaml.Node, path []string) error {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if err := d.walk(n.Content[i+1], append(append([]string{}, path...), k)); err != nil {
				return fmt.Errorf("at %q: %w", k, err)
			}
		}
	case yaml.SequenceNode:
		// Sequence indices are NOT added to AAD — matches upstream sops.
		for _, c := range n.Content {
			if err := d.walk(c, path); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		if looksLikeEncToken(n.Value) {
			plain, err := decryptLeaf(n.Value, d.dataKey, aadForPath(path))
			if err != nil {
				return err
			}
			s := stringifyForMAC(plain)
			d.allLeaves = append(d.allLeaves, s)
			d.encryptedLeaves = append(d.encryptedLeaves, s)
			rewriteScalar(n, plain)
		} else {
			// Non-encrypted scalars must still feed the MAC through the
			// same typed stringifier the encrypt path uses; otherwise an
			// unquoted bool (n.Value="true") would diverge from the
			// Title-case "True" upstream sops hashes.
			v, err := scalarValueFromNode(n)
			if err != nil {
				return err
			}
			d.allLeaves = append(d.allLeaves, stringifyForMAC(v))
		}
	case yaml.AliasNode:
		return fmt.Errorf("anchor/alias nodes are not supported")
	}
	return nil
}

// rewriteScalar mutates a node so it represents the decrypted plaintext
// with an appropriate YAML tag and quoting.
func rewriteScalar(n *yaml.Node, v any) {
	switch x := v.(type) {
	case string:
		n.Value = x
		n.Tag = ""
		if needsQuoting(x) {
			n.Style = yaml.DoubleQuotedStyle
		} else {
			n.Style = 0
		}
	case bool:
		if x {
			n.Value = "true"
		} else {
			n.Value = "false"
		}
		n.Tag = "!!bool"
		n.Style = 0
	case int:
		n.Value = strconv.FormatInt(int64(x), 10)
		n.Tag = "!!int"
		n.Style = 0
	case int64:
		n.Value = strconv.FormatInt(x, 10)
		n.Tag = "!!int"
		n.Style = 0
	case uint64:
		n.Value = strconv.FormatUint(x, 10)
		n.Tag = "!!int"
		n.Style = 0
	case float64:
		n.Value = strconv.FormatFloat(x, 'f', -1, 64)
		n.Tag = "!!float"
		n.Style = 0
	case []byte:
		n.Value = string(x)
		n.Tag = "!!binary"
		n.Style = 0
	}
}

// needsQuoting returns true if a plaintext string would otherwise be
// interpreted as a non-string scalar by a YAML parser, and so must be
// emitted quoted to round-trip safely.
func needsQuoting(s string) bool {
	switch s {
	case "", "true", "false", "True", "False", "TRUE", "FALSE",
		"null", "Null", "NULL", "~",
		"yes", "Yes", "YES", "no", "No", "NO",
		"on", "On", "ON", "off", "Off", "OFF":
		return true
	}
	if _, err := strconv.ParseInt(s, 10, 64); err == nil {
		return true
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	return false
}

// aadForPath builds the cipher additional-data string sops uses for a
// given YAML key path: each key followed by ":". Sequence indices are
// NOT included (matches upstream).
func aadForPath(path []string) string {
	n := 0
	for _, p := range path {
		n += len(p) + 1
	}
	out := make([]byte, 0, n)
	for _, p := range path {
		out = append(out, p...)
		out = append(out, ':')
	}
	return string(out)
}

// stringifyForMAC mirrors upstream sops's ToBytes for a plaintext leaf.
// Note the Title-case True/False for bools — that's Python compat from
// the original sops implementation and is part of the wire format.
func stringifyForMAC(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case []byte:
		return string(x)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// verifyMAC recomputes plain SHA-512 (not HMAC — upstream sops uses a
// raw hash) over the in-order leaf strings, then compares against the
// stored MAC after decrypting it with `lastmodified` as AAD.
func verifyMAC(meta Metadata, dataKey []byte, d *nodeDecryptor) error {
	if meta.MAC == "" {
		return fmt.Errorf("%w: file has no MAC", ErrMACMismatch)
	}
	h := sha512.New()
	if meta.MACOnlyEncrypted {
		h.Write(macOnlyEncryptedInit[:])
		for _, s := range d.encryptedLeaves {
			h.Write([]byte(s))
		}
	} else {
		for _, s := range d.allLeaves {
			h.Write([]byte(s))
		}
	}
	computed := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	plain, err := decryptLeaf(meta.MAC, dataKey, meta.LastModified)
	if err != nil {
		return fmt.Errorf("%w: decode mac: %v", ErrMACMismatch, err)
	}
	stored, ok := plain.(string)
	if !ok {
		return fmt.Errorf("%w: mac kind", ErrMACMismatch)
	}
	if !hmac.Equal([]byte(computed), []byte(strings.ToUpper(stored))) {
		return ErrMACMismatch
	}
	return nil
}

// formatLastModified formats t in the RFC3339-Z form sops uses when
// sealing a file. UTC is canonical; we never emit local offsets so MAC
// verification is reproducible across hosts.
func formatLastModified(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
