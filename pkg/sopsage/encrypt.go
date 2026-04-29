package sopsage

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// interpolationPlaceholderRe matches a scalar whose entire value is a single
// ${VAR} or ${VAR:-default} reference — the same shape that
// internal/server/profiles.InterpolateString resolves at load time. We refuse
// to encrypt such leaves even when the key matches the encryption rule:
// the placeholder string itself is not secret (the real value lives in the
// env var), and sealing it would just bloat the file with an ENC[…] blob
// that decrypts back to the same indirection.
var interpolationPlaceholderRe = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}$`)

// Encrypt produces a SOPS-format YAML document from the supplied plaintext.
// The data key is freshly generated, sealed once per recipient, and used to
// AES-256-GCM-encrypt every leaf the EncryptionRules selects. The MAC is
// the same plain SHA-512 over in-order leaf strings that Decrypt verifies.
//
// recipients must contain at least one age recipient — a file no one can
// decrypt is indistinguishable from data loss, and callers (notably
// `ztpctl secrets seal`) are expected to always include the operator's
// own recipient on top of the server's.
func Encrypt(plainYAML []byte, recipients []age.Recipient, rules EncryptionRules) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}
	if err := rules.validate(); err != nil {
		return nil, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(plainYAML, &root); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("expected a YAML document")
	}
	rootMap := root.Content[0]
	if rootMap.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected the root to be a YAML mapping")
	}
	// Refuse to re-encrypt an already-sealed file: the sops: block would
	// otherwise be encrypted as data, and the file would round-trip
	// nonsensically.
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value == "sops" {
			return nil, fmt.Errorf("input already contains a sops: block")
		}
	}

	dataKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, fmt.Errorf("read data key: %w", err)
	}

	enc := &nodeEncryptor{dataKey: dataKey, rules: rules}
	if err := enc.walk(rootMap, nil, false); err != nil {
		return nil, fmt.Errorf("encrypt tree: %w", err)
	}

	// MAC is computed over the same in-order leaf list Decrypt uses. We
	// already collected leaves during the walk, in plaintext form (the
	// MAC always covers plaintext, not ciphertext).
	mac := computeMAC(enc, rules)

	// Seal the MAC itself with `lastmodified` as AAD — that's how upstream
	// stores it and how Decrypt re-verifies.
	now := formatLastModified(time.Now())
	macToken, err := encryptLeaf(mac, dataKey, now)
	if err != nil {
		return nil, fmt.Errorf("seal mac: %w", err)
	}

	stanzas, err := encryptDataKey(dataKey, recipients)
	if err != nil {
		return nil, err
	}

	meta := Metadata{
		AgeRecipients:     stanzas,
		LastModified:      now,
		MAC:               macToken,
		EncryptedRegex:    rules.EncryptedRegex,
		UnencryptedRegex:  rules.UnencryptedRegex,
		EncryptedSuffix:   rules.EncryptedSuffix,
		UnencryptedSuffix: rules.UnencryptedSuffix,
		Version:           "3.7.3",
	}
	if err := appendSOPSMeta(rootMap, meta); err != nil {
		return nil, err
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return out, nil
}

// nodeEncryptor mirrors nodeDecryptor for the encrypt direction. It seals
// every leaf selected by EncryptionRules and gathers the in-order
// plaintext list used for the MAC.
type nodeEncryptor struct {
	dataKey []byte
	rules   EncryptionRules

	allLeaves       []string
	encryptedLeaves []string
}

// walk recurses into n. parentEncrypted carries the inherited "everything
// below me is encrypted" decision so a key matching the encrypt rule
// transitively seals every leaf in its subtree, indices and all (matches
// upstream sops behaviour).
func (e *nodeEncryptor) walk(n *yaml.Node, path []string, parentEncrypted bool) error {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i].Value
			childEncrypted := parentEncrypted
			if !childEncrypted {
				want, err := e.rules.shouldEncrypt(k, parentEncrypted)
				if err != nil {
					return err
				}
				childEncrypted = want
			}
			if err := e.walk(n.Content[i+1], append(append([]string{}, path...), k), childEncrypted); err != nil {
				return fmt.Errorf("at %q: %w", k, err)
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if err := e.walk(c, path, parentEncrypted); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		v, err := scalarValueFromNode(n)
		if err != nil {
			return err
		}
		s := stringifyForMAC(v)
		e.allLeaves = append(e.allLeaves, s)
		if parentEncrypted {
			// Skip pure ${VAR} / ${VAR:-default} placeholders: they carry
			// no secret material themselves, and the runtime interpolator
			// only fires on plaintext scalars. Recording the leaf in
			// allLeaves above keeps the MAC stable across seal/reveal.
			if str, ok := v.(string); ok && interpolationPlaceholderRe.MatchString(str) {
				return nil
			}
			token, err := encryptLeaf(v, e.dataKey, aadForPath(path))
			if err != nil {
				return err
			}
			e.encryptedLeaves = append(e.encryptedLeaves, s)
			n.Value = token
			n.Tag = "" // emit unquoted; ENC[…] is plain ASCII
			n.Style = 0
		}
	case yaml.AliasNode:
		return fmt.Errorf("anchor/alias nodes are not supported")
	}
	return nil
}

// scalarValueFromNode interprets a yaml.Node scalar according to its
// resolved tag. We avoid the "decode into any" round-trip yaml.v3 offers
// because that loses the Title-case bool distinction — we want the same
// Go-typed value the original document represented so encryptLeaf's type
// tag is faithful.
func scalarValueFromNode(n *yaml.Node) (any, error) {
	tag := n.Tag
	if tag == "" || tag == "!" {
		// Fall back to yaml.v3's resolver via Decode, which infers
		// !!bool / !!int / !!float / !!str just like the parser.
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	}
	switch tag {
	case "!!str":
		return n.Value, nil
	case "!!bool", "!!int", "!!float", "!!binary":
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	case "!!null":
		return "", nil // sealed nulls become empty strings; matches upstream behaviour
	}
	// Unknown custom tag: take the raw string. We never see this in
	// practice for sealed config files, but failing closed would block
	// edits of files with stray local tags.
	return n.Value, nil
}

// computeMAC produces the uppercase hex SHA-512 over the in-order leaf
// strings, optionally prefixed with the macOnlyEncryptedInit tag. Same
// algorithm as verifyMAC, factored separately because the encrypt path
// has direct access to the gathered leaves rather than via the walker.
func computeMAC(e *nodeEncryptor, rules EncryptionRules) string {
	_ = rules
	h := sha512.New()
	// We always emit MACOnlyEncrypted=false (i.e. we hash all leaves) to
	// match the upstream default. The metadata field is therefore left
	// at its zero value and verifyMAC takes the all-leaves branch.
	for _, s := range e.allLeaves {
		h.Write([]byte(s))
	}
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// appendSOPSMeta serializes meta and appends it under the "sops" key on
// rootMap. Round-tripping through yaml.Marshal+Unmarshal lets the struct
// tags drive emission so we don't hand-build a node tree.
func appendSOPSMeta(rootMap *yaml.Node, meta Metadata) error {
	b, err := yaml.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal sops meta: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parse sops meta: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return fmt.Errorf("unexpected sops metadata shape")
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "sops"}
	rootMap.Content = append(rootMap.Content, keyNode, doc.Content[0])
	return nil
}
