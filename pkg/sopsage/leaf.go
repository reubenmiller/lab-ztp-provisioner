package sopsage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// sopsNonceSize is the IV length sops uses with AES-GCM. Note this is NOT
// the standard 12-byte nonce; sops historically picked 32 bytes and the
// Go stdlib supports it via cipher.NewGCMWithNonceSize.
const sopsNonceSize = 32

// encTokenRe matches a sops-encrypted leaf. The regex anchors the entire
// string to avoid silently accepting trailing junk; partial matches would
// hide bugs in upstream tooling that we'd rather surface.
var encTokenRe = regexp.MustCompile(
	`^ENC\[AES256_GCM,data:([^,]*),iv:([^,]*),tag:([^,]*),type:(str|int|float|bool|bytes)\]$`,
)

// looksLikeEncToken is a fast pre-filter before the full regex match.
// Walking large YAML trees benefits from short-circuiting plain string
// leaves without touching the regex engine.
func looksLikeEncToken(s string) bool {
	return len(s) > 5 && s[:4] == "ENC[" && s[len(s)-1] == ']'
}

// encryptedLeaf is the parsed form of an ENC[…] token, kept intentionally
// public-within-package so the tree walker can pass values around without
// reparsing.
type encryptedLeaf struct {
	data []byte
	iv   []byte
	tag  []byte
	kind string // "str" | "int" | "float" | "bool" | "bytes"
}

func parseEncToken(s string) (*encryptedLeaf, error) {
	m := encTokenRe.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("not an ENC[…] token")
	}
	data, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(m[2])
	if err != nil {
		return nil, fmt.Errorf("iv: %w", err)
	}
	if len(iv) != sopsNonceSize {
		return nil, fmt.Errorf("iv length: got %d want %d", len(iv), sopsNonceSize)
	}
	tag, err := base64.StdEncoding.DecodeString(m[3])
	if err != nil {
		return nil, fmt.Errorf("tag: %w", err)
	}
	return &encryptedLeaf{data: data, iv: iv, tag: tag, kind: m[4]}, nil
}

// decryptLeaf opens one ENC[…] token and converts the plaintext bytes back
// to the original Go scalar based on the embedded type tag.
func decryptLeaf(token string, dataKey []byte, aad string) (any, error) {
	leaf, err := parseEncToken(token)
	if err != nil {
		return nil, err
	}
	plain, err := openAESGCM(dataKey, leaf.iv, leaf.data, leaf.tag, aad)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}
	return scalarFromTyped(plain, leaf.kind)
}

// encryptLeaf seals one Go scalar value as an ENC[…] token. value may be
// any scalar a YAML decoder would produce (string/int/int64/float64/bool)
// or a []byte; other types are rejected rather than silently stringified
// because the type-tag round-trip relies on a fixed mapping.
func encryptLeaf(value any, dataKey []byte, aad string) (string, error) {
	plain, kind, err := typedFromScalar(value)
	if err != nil {
		return "", err
	}
	iv := make([]byte, sopsNonceSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("read iv: %w", err)
	}
	ct, tag, err := sealAESGCM(dataKey, iv, plain, aad)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ENC[AES256_GCM,data:%s,iv:%s,tag:%s,type:%s]",
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(tag),
		kind,
	), nil
}

// scalarFromTyped reverses sops's type-tag stringification. The empty
// string for a non-str kind is treated as an error rather than silently
// returning a zero value — sops never emits an empty int/bool blob, so
// seeing one means the file is malformed.
func scalarFromTyped(plain []byte, kind string) (any, error) {
	switch kind {
	case "str":
		return string(plain), nil
	case "int":
		n, err := strconv.ParseInt(string(plain), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("int decode: %w", err)
		}
		return n, nil
	case "float":
		f, err := strconv.ParseFloat(string(plain), 64)
		if err != nil {
			return nil, fmt.Errorf("float decode: %w", err)
		}
		return f, nil
	case "bool":
		switch string(plain) {
		case "true", "True", "TRUE":
			return true, nil
		case "false", "False", "FALSE":
			return false, nil
		}
		return nil, fmt.Errorf("bool decode: %q", string(plain))
	case "bytes":
		// sops "bytes" is the raw byte sequence the user supplied; we
		// represent it as a Go []byte. yaml.v3 will marshal that as
		// a !!binary base64 scalar which is correct for round-trip.
		return plain, nil
	}
	return nil, fmt.Errorf("unknown type %q", kind)
}

// typedFromScalar maps a Go value to (plaintext bytes, sops type tag).
// We accept the integer widths yaml.v3 produces (int, int64) and reject
// anything we can't reverse cleanly during decrypt — silent stringification
// would let bugs hide.
func typedFromScalar(v any) ([]byte, string, error) {
	switch x := v.(type) {
	case string:
		return []byte(x), "str", nil
	case bool:
		// Title-case to match upstream sops (which inherited it from the
		// original Python implementation). Critical for MAC compatibility:
		// the encrypted bytes ARE the case-sensitive form.
		if x {
			return []byte("True"), "bool", nil
		}
		return []byte("False"), "bool", nil
	case int:
		return []byte(strconv.FormatInt(int64(x), 10)), "int", nil
	case int64:
		return []byte(strconv.FormatInt(x, 10)), "int", nil
	case uint64:
		return []byte(strconv.FormatUint(x, 10)), "int", nil
	case float64:
		return []byte(strconv.FormatFloat(x, 'f', -1, 64)), "float", nil
	case []byte:
		return x, "bytes", nil
	}
	return nil, "", fmt.Errorf("unsupported scalar type %T", v)
}

// openAESGCM is the AES-256-GCM-with-32-byte-nonce decrypt primitive sops
// uses. Caller supplies the AAD string verbatim (see package doc for path
// derivation rules); we always pass it as bytes here.
func openAESGCM(key, iv, ciphertext, tag []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, sopsNonceSize)
	if err != nil {
		return nil, err
	}
	// Go's GCM API expects ciphertext||tag concatenated; sops stores them
	// separately so we glue them back together here.
	ct := make([]byte, 0, len(ciphertext)+len(tag))
	ct = append(ct, ciphertext...)
	ct = append(ct, tag...)
	return gcm.Open(nil, iv, ct, []byte(aad))
}

// sealAESGCM is the inverse of openAESGCM and returns ciphertext and tag
// separately so the caller can format them into the ENC[…] token without
// extra slicing.
func sealAESGCM(key, iv, plaintext []byte, aad string) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, sopsNonceSize)
	if err != nil {
		return nil, nil, err
	}
	out := gcm.Seal(nil, iv, plaintext, []byte(aad))
	tagSize := gcm.Overhead()
	ct := out[:len(out)-tagSize]
	tag := out[len(out)-tagSize:]
	return ct, tag, nil
}
