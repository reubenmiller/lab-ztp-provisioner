package sopsage

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// SealTag is the YAML tag operators apply to leaves they want encrypted
// during the first `ztpctl secrets seal` run. The leading "!" makes it a
// local tag in YAML's data model. We chose "!encrypt" over "!secret" for
// symmetry with the action (the file gets encrypted, not "made secret").
const SealTag = "!encrypt"

// PrepareTaggedSeal walks plainYAML, strips any SealTag annotations, and
// returns (1) the de-tagged YAML and (2) an EncryptionRules whose regex
// matches exactly the keys whose values were tagged. The result feeds
// directly into Encrypt:
//
//	clean, rules, _ := sopsage.PrepareTaggedSeal(input)
//	out, _ := sopsage.Encrypt(clean, recipients, rules)
//
// If no tags are present, the returned rules are zero-valued (no leaves
// will be encrypted) — callers should detect that and either fall back
// to a different selection mechanism or fail loudly.
//
// Restrictions: only mapping leaves can be tagged. Tagging a sequence or
// mapping node is rejected because the resulting regex-based re-seal
// (used by `secrets edit`) cannot reproduce subtree-scoped sealing
// faithfully — the operator should tag the individual scalar leaves
// inside instead.
func PrepareTaggedSeal(plainYAML []byte) ([]byte, EncryptionRules, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(plainYAML, &root); err != nil {
		return nil, EncryptionRules{}, fmt.Errorf("parse yaml: %w", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, EncryptionRules{}, fmt.Errorf("expected a YAML document")
	}
	keys := map[string]struct{}{}
	if err := stripTags(root.Content[0], "", keys); err != nil {
		return nil, EncryptionRules{}, err
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return nil, EncryptionRules{}, fmt.Errorf("marshal: %w", err)
	}
	return out, rulesFromKeys(keys), nil
}

// stripTags walks a yaml.Node tree mutating any !encrypt-tagged leaf back
// to a plain scalar and recording its parent key. parentKey is the name
// of the mapping entry the current node was reached through, or "" for
// the root.
func stripTags(n *yaml.Node, parentKey string, keys map[string]struct{}) error {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i].Value
			child := n.Content[i+1]
			if child.Tag == SealTag {
				if child.Kind != yaml.ScalarNode {
					return fmt.Errorf("%s tag on non-scalar value at key %q is not supported", SealTag, k)
				}
				keys[k] = struct{}{}
				child.Tag = ""
			}
			if err := stripTags(child, k, keys); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Tag == SealTag {
				return fmt.Errorf("%s tag inside a sequence (under %q) is not supported", SealTag, parentKey)
			}
			if err := stripTags(c, parentKey, keys); err != nil {
				return err
			}
		}
	}
	return nil
}

// rulesFromKeys turns a set of mapping-key names into an EncryptionRules
// whose EncryptedRegex matches exactly those names. We anchor with
// `^...$` so e.g. tagging "token" doesn't end up sealing "metadata.token"
// somewhere else. Each key is regex-quoted because operators sometimes
// use dotted keys (e.g. "url.suffix").
func rulesFromKeys(keys map[string]struct{}) EncryptionRules {
	if len(keys) == 0 {
		return EncryptionRules{}
	}
	parts := make([]string, 0, len(keys))
	for k := range keys {
		parts = append(parts, regexp.QuoteMeta(k))
	}
	expr := "^("
	for i, p := range parts {
		if i > 0 {
			expr += "|"
		}
		expr += p
	}
	expr += ")$"
	return EncryptionRules{EncryptedRegex: expr}
}
