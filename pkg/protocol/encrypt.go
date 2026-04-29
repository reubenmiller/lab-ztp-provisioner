package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// AlgX25519ChaCha20 is the only encryption algorithm currently defined for
// EncryptedPayload.
const AlgX25519ChaCha20 = "x25519-chacha20poly1305"

// GenerateX25519 returns (privateKey, publicKey) for one-shot ECDH.
//
// The private key is 32 bytes (clamped per RFC 7748 by curve25519.X25519);
// the public key is the corresponding 32-byte value.
func GenerateX25519() (priv [32]byte, pub [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return
	}
	pubB, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	copy(pub[:], pubB)
	return
}

// SealForDevice encrypts plaintext for a device whose ephemeral X25519
// public key (sent in EnrollRequest.EphemeralX25519, base64) is devicePubB64.
// The returned EncryptedPayload includes the server's ephemeral X25519 public
// key and a fresh 12-byte ChaCha20-Poly1305 nonce.
//
// Confidentiality is end-to-end: a BLE relay or any other intermediary
// observing the ciphertext cannot read the bundle without the device's
// ephemeral private key.
func SealForDevice(devicePubB64 string, plaintext []byte) (*EncryptedPayload, error) {
	devPub, err := decodeX25519(devicePubB64)
	if err != nil {
		return nil, fmt.Errorf("device pub: %w", err)
	}
	priv, pub, err := GenerateX25519()
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(priv[:], devPub[:])
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return &EncryptedPayload{
		Algorithm:  AlgX25519ChaCha20,
		ServerKey:  base64.StdEncoding.EncodeToString(pub[:]),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// OpenForDevice decrypts an EncryptedPayload using the device's ephemeral
// X25519 private key. devicePriv must be the same key whose public form was
// included in the EnrollRequest.
func OpenForDevice(devicePriv [32]byte, p *EncryptedPayload) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil encrypted payload")
	}
	if p.Algorithm != AlgX25519ChaCha20 {
		return nil, fmt.Errorf("unsupported alg %q", p.Algorithm)
	}
	srvPub, err := decodeX25519(p.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("server key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(p.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(p.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}
	shared, err := curve25519.X25519(devicePriv[:], srvPub[:])
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("nonce length")
	}
	return aead.Open(nil, nonce, ct, nil)
}

// SealModuleForDevice encrypts a single module's payload bytes for a device
// using the same X25519 + ChaCha20-Poly1305 primitive as SealForDevice. It is
// the per-module counterpart used to keep secrets (e.g. a Cumulocity
// enrollment token) opaque to anything that touches the bundle outside the
// device — the ZTP server's logs, audit trail, persisted bundle, a BLE
// relay, the reverse proxy, and so on.
//
// format must be either "json" (decrypted bytes are canonical JSON destined
// for Module.Payload) or "raw" (decrypted bytes are opaque, e.g. an INI
// document destined for Module.RawPayload).
func SealModuleForDevice(devicePubB64 string, plaintext []byte, format string) (*SealedPayload, error) {
	if format != "json" && format != "raw" {
		return nil, fmt.Errorf("unsupported sealed payload format %q", format)
	}
	devPub, err := decodeX25519(devicePubB64)
	if err != nil {
		return nil, fmt.Errorf("device pub: %w", err)
	}
	priv, pub, err := GenerateX25519()
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(priv[:], devPub[:])
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return &SealedPayload{
		Algorithm:    AlgX25519ChaCha20,
		EphemeralPub: base64.StdEncoding.EncodeToString(pub[:]),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ct),
		Format:       format,
	}, nil
}

// OpenSealedModule decrypts a SealedPayload using the device's ephemeral
// X25519 private key and returns the plaintext bytes plus the format hint the
// caller should use to interpret them.
func OpenSealedModule(devicePriv [32]byte, p *SealedPayload) ([]byte, string, error) {
	if p == nil {
		return nil, "", errors.New("nil sealed payload")
	}
	if p.Algorithm != AlgX25519ChaCha20 {
		return nil, "", fmt.Errorf("unsupported alg %q", p.Algorithm)
	}
	srvPub, err := decodeX25519(p.EphemeralPub)
	if err != nil {
		return nil, "", fmt.Errorf("ephemeral pub: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(p.Nonce)
	if err != nil {
		return nil, "", fmt.Errorf("nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(p.Ciphertext)
	if err != nil {
		return nil, "", fmt.Errorf("ciphertext: %w", err)
	}
	shared, err := curve25519.X25519(devicePriv[:], srvPub[:])
	if err != nil {
		return nil, "", err
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		return nil, "", err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, "", errors.New("nonce length")
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, "", err
	}
	return pt, p.Format, nil
}

func decodeX25519(b64 string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}
