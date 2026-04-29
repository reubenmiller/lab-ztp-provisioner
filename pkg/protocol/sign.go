package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// ErrSignature is returned when signature verification fails.
var ErrSignature = errors.New("invalid signature")

// Sign canonicalises v, signs the bytes with priv, and returns a SignedEnvelope.
// keyID is an opaque label callers use to identify the signer (e.g. "device",
// "server-2026-04").
func Sign(v any, priv ed25519.PrivateKey, keyID string) (*SignedEnvelope, error) {
	canon, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	return &SignedEnvelope{
		ProtocolVersion: Version,
		KeyID:           keyID,
		Algorithm:       "ed25519",
		Payload:         base64.StdEncoding.EncodeToString(canon),
		Signature:       base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify checks the signature on env using pub and, on success, returns the
// canonical payload bytes for the caller to JSON-decode.
func Verify(env *SignedEnvelope, pub ed25519.PublicKey) ([]byte, error) {
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	if env.Algorithm != "ed25519" {
		return nil, fmt.Errorf("unsupported alg %q", env.Algorithm)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, ErrSignature
	}
	return payload, nil
}

// DecodePayloadUnverified base64-decodes the payload from env without
// checking the signature. Used for BLE TOFU mode when no server pubkey is
// configured. Callers should log a warning before calling this.
func DecodePayloadUnverified(env *SignedEnvelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return payload, nil
}

// NewNonce returns a base64-encoded 16-byte random nonce suitable for use in
// EnrollRequest.Nonce.
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// EncodePublicKey returns the base64 form used on the wire for an Ed25519
// public key.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePublicKey parses the wire form of an Ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
