package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// BuildTextManifest renders a ProvisioningBundle as a deterministic, line-based
// "key=value" text document suitable for trivial parsing by a pure-shell
// agent. The format is:
//
//	device_id=<id>
//	expires_at=<RFC3339>
//	issued_at=<RFC3339>
//	module=<type> <base64-of-canonical-json-payload>
//	module=<type> <base64-of-canonical-json-payload>
//	module-sealed=<type> <format> <ephemeral_pub_b64> <nonce_b64> <ciphertext_b64>
//	protocol_version=<v>
//
// Lines are sorted lexicographically and joined with "\n" (no trailing
// newline). The same input always yields the same bytes, making it suitable
// as a signature input.
//
// Module payload bytes are the canonicalised JSON of Module.Payload — that is
// what an applier receives on stdin in JSON-mode. A pure-shell agent does not
// have to parse that JSON at all (the applier itself can).
//
// Sealed modules (Module.Sealed != nil) are rendered as a single
// `module-sealed=` line with the SealedPayload fields space-separated. The
// shell agent performs ECDH against EphemeralPub with its X25519 private
// key, then ChaCha20-Poly1305-decrypts Ciphertext (which has the 16-byte tag
// appended) using Nonce. The decrypted bytes are dispatched to the applier
// just like a clear `module=` line.
func BuildTextManifest(b *ProvisioningBundle) ([]byte, error) {
	if b == nil {
		return nil, errors.New("nil bundle")
	}
	lines := []string{
		"device_id=" + escapeTextValue(b.DeviceID),
		"issued_at=" + b.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"protocol_version=" + escapeTextValue(b.ProtocolVersion),
	}
	if !b.ExpiresAt.IsZero() {
		lines = append(lines, "expires_at="+b.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
	}
	for _, m := range b.Modules {
		if m.Sealed != nil {
			// Sealed modules carry per-module ciphertext addressed to the
			// device's ephemeral X25519 key. The shell agent decodes the
			// fields and decrypts after ECDH.
			lines = append(lines, "module-sealed="+m.Type+" "+
				m.Sealed.Format+" "+
				m.Sealed.EphemeralPub+" "+
				m.Sealed.Nonce+" "+
				m.Sealed.Ciphertext)
			continue
		}
		var bodyBytes []byte
		if m.RawPayload != nil {
			// Module supplies its own payload bytes (e.g. INI). Use them
			// verbatim so they reach the applier byte-for-byte after the
			// agent base64-decodes the manifest line.
			bodyBytes = m.RawPayload
		} else {
			canon, err := Canonicalize(m.Payload)
			if err != nil {
				return nil, fmt.Errorf("canonicalize module %s: %w", m.Type, err)
			}
			bodyBytes = canon
		}
		lines = append(lines, "module="+m.Type+" "+base64.StdEncoding.EncodeToString(bodyBytes))
	}
	sort.Strings(lines)

	var buf bytes.Buffer
	for i, l := range lines {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(l)
	}
	return buf.Bytes(), nil
}

// SignTextManifest signs the bytes produced by BuildTextManifest with the
// server's Ed25519 key and returns a SignedEnvelope whose Payload field
// carries the base64-encoded text bytes (i.e. the SAME bytes the agent will
// verify and parse).
func SignTextManifest(bundle *ProvisioningBundle, priv ed25519.PrivateKey, keyID string) (*SignedEnvelope, error) {
	body, err := BuildTextManifest(bundle)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, body)
	return &SignedEnvelope{
		ProtocolVersion: Version,
		KeyID:           keyID,
		Algorithm:       "ed25519",
		Payload:         base64.StdEncoding.EncodeToString(body),
		Signature:       base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// escapeTextValue replaces newlines and carriage returns in a value so a
// single key=value line stays on a single line. Other characters are passed
// through verbatim — values are typed (IDs, RFC3339 timestamps, base64) and
// don't otherwise need escaping in this format.
func escapeTextValue(s string) string {
	if !strings.ContainsAny(s, "\n\r") {
		return s
	}
	r := strings.NewReplacer("\n", `\n`, "\r", `\r`)
	return r.Replace(s)
}
