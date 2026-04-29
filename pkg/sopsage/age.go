package sopsage

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// decryptDataKey walks the file's age stanzas and tries each supplied
// identity against each stanza, returning on the first success. The
// upstream sops CLI does the same; identity ordering is therefore the
// caller's contract for "which key to try first".
func decryptDataKey(stanzas []AgeStanza, identities []age.Identity) ([]byte, error) {
	if len(stanzas) == 0 {
		return nil, fmt.Errorf("file has no age recipient stanzas")
	}
	if len(identities) == 0 {
		return nil, ErrNoMatchingIdentity
	}
	var lastErr error
	for _, st := range stanzas {
		// armor.NewReader handles the BEGIN/END frame plus the
		// whitespace/newline tolerance that sops's pretty-printed YAML
		// introduces.
		r := armor.NewReader(strings.NewReader(st.Enc))
		// age.Decrypt itself iterates identities and short-circuits on
		// the first one that successfully unwraps, so we only need to
		// drive the outer recipient loop.
		dr, err := age.Decrypt(r, identities...)
		if err != nil {
			lastErr = fmt.Errorf("recipient %q: %w", st.Recipient, err)
			continue
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, dr); err != nil {
			lastErr = fmt.Errorf("recipient %q: read: %w", st.Recipient, err)
			continue
		}
		dk := buf.Bytes()
		if len(dk) != 32 {
			// sops always uses a 32-byte AES-256 key; anything else
			// means the file was tampered with or produced by a
			// version we don't understand.
			lastErr = fmt.Errorf("recipient %q: data key length %d", st.Recipient, len(dk))
			continue
		}
		return dk, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoMatchingIdentity, lastErr)
	}
	return nil, ErrNoMatchingIdentity
}

// encryptDataKey seals the freshly-generated data key to every recipient.
// We refuse zero recipients because a file with no decryptors is
// indistinguishable from data loss; callers must enforce "always include
// at least one identity-derived recipient" upstream.
func encryptDataKey(dataKey []byte, recipients []age.Recipient) ([]AgeStanza, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}
	out := make([]AgeStanza, 0, len(recipients))
	for _, rcp := range recipients {
		var armored bytes.Buffer
		aw := armor.NewWriter(&armored)
		w, err := age.Encrypt(aw, rcp)
		if err != nil {
			return nil, fmt.Errorf("age encrypt: %w", err)
		}
		if _, err := w.Write(dataKey); err != nil {
			return nil, fmt.Errorf("age write: %w", err)
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("age close: %w", err)
		}
		if err := aw.Close(); err != nil {
			return nil, fmt.Errorf("armor close: %w", err)
		}
		out = append(out, AgeStanza{
			Recipient: recipientString(rcp),
			Enc:       armored.String(),
		})
	}
	return out, nil
}

// recipientString returns the canonical "age1…" form of a recipient.
// age.Recipient itself doesn't expose the encoded form via the interface;
// the X25519Recipient.String method does, and any future recipient kind
// we add (e.g. plugin) will need the same treatment.
func recipientString(r age.Recipient) string {
	type stringer interface{ String() string }
	if s, ok := r.(stringer); ok {
		return s.String()
	}
	return ""
}
