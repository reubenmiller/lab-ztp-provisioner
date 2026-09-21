package protocol

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// ErrSignature is returned when signature verification fails.
var ErrSignature = errors.New("invalid signature")

// p256PointLen is the length of an uncompressed P-256 point: a 0x04 tag plus
// two 32-byte coordinates. This is what PSA's psa_export_public_key emits for
// a P-256 key, so a constrained device can put its exported bytes straight on
// the wire.
const p256PointLen = 65

// p256SigLen is the length of a raw (r || s) P-256 signature, each value
// left-padded to the 32-byte field size.
//
// Deliberately NOT ASN.1/DER: PSA's psa_sign_hash emits raw r||s, and asking a
// microcontroller to wrap that in DER — or to parse DER coming back — costs
// code for no benefit. The Go side converts instead.
const p256SigLen = 64

// Sign canonicalises v, signs the bytes with priv, and returns a SignedEnvelope.
// keyID is an opaque label callers use to identify the signer (e.g. "device",
// "server-2026-04").
//
// This is the Ed25519 entry point, kept for every caller and agent that has
// always used it. Use SignWithSuite to sign under a specific suite.
func Sign(v any, priv ed25519.PrivateKey, keyID string) (*SignedEnvelope, error) {
	return SignWithSuite(v, priv, keyID, SuiteEd25519X25519)
}

// SignWithSuite canonicalises v and signs it under the given suite. key must
// match the suite: an ed25519.PrivateKey for SuiteEd25519X25519, an
// *ecdsa.PrivateKey on P-256 for SuiteP256.
func SignWithSuite(v any, key crypto.Signer, keyID string, suite Suite) (*SignedEnvelope, error) {
	canon, err := Canonicalize(v)
	if err != nil {
		return nil, err
	}
	sig, err := signCanonical(canon, key, suite)
	if err != nil {
		return nil, err
	}
	return &SignedEnvelope{
		ProtocolVersion: Version,
		KeyID:           keyID,
		Algorithm:       suite.SignAlg(),
		Payload:         base64.StdEncoding.EncodeToString(canon),
		Signature:       base64.StdEncoding.EncodeToString(sig),
	}, nil
}

func signCanonical(canon []byte, key crypto.Signer, suite Suite) ([]byte, error) {
	switch suite {
	case SuiteP256:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("suite %s needs an *ecdsa.PrivateKey, got %T", suite, key)
		}
		if priv.Curve != elliptic.P256() {
			return nil, fmt.Errorf("suite %s needs a P-256 key", suite)
		}
		digest := sha256.Sum256(canon)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, err
		}
		return encodeP256Signature(r, s), nil
	default:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("suite %s needs an ed25519.PrivateKey, got %T", suite, key)
		}
		return ed25519.Sign(priv, canon), nil
	}
}

// Verify checks the signature on env using pub and, on success, returns the
// canonical payload bytes for the caller to JSON-decode.
//
// pub is an ed25519.PublicKey or an *ecdsa.PublicKey, matching env.Algorithm.
// The parameter is crypto.PublicKey (an alias for any) rather than a concrete
// type so that existing Ed25519 callers compile unchanged.
func Verify(env *SignedEnvelope, pub crypto.PublicKey) ([]byte, error) {
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	switch env.Algorithm {
	case AlgEd25519:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("alg %s needs an ed25519.PublicKey, got %T", env.Algorithm, pub)
		}
		if !ed25519.Verify(key, payload, sig) {
			return nil, ErrSignature
		}
	case AlgECDSAP256:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("alg %s needs an *ecdsa.PublicKey, got %T", env.Algorithm, pub)
		}
		r, s, err := decodeP256Signature(sig)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(payload)
		if !ecdsa.Verify(key, digest[:], r, s) {
			return nil, ErrSignature
		}
	default:
		return nil, fmt.Errorf("unsupported alg %q", env.Algorithm)
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

// EncodePublicKeyForSuite returns the base64 wire form of a public key under
// the given suite: a raw 32-byte Ed25519 key, or an uncompressed P-256 point.
func EncodePublicKeyForSuite(pub crypto.PublicKey, suite Suite) (string, error) {
	switch suite {
	case SuiteP256:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("suite %s needs an *ecdsa.PublicKey, got %T", suite, pub)
		}
		return base64.StdEncoding.EncodeToString(encodeP256Point(key)), nil
	default:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return "", fmt.Errorf("suite %s needs an ed25519.PublicKey, got %T", suite, pub)
		}
		return base64.StdEncoding.EncodeToString(key), nil
	}
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

// DecodePublicKeyForAlg parses the wire form of a public key, choosing the key
// type from an envelope's algorithm. The result is suitable to pass to Verify.
func DecodePublicKeyForAlg(s, alg string) (crypto.PublicKey, error) {
	switch alg {
	case AlgEd25519, "":
		return DecodePublicKey(s)
	case AlgECDSAP256:
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		return decodeP256Point(b)
	default:
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}
}

// encodeP256Point renders a public key as an uncompressed SEC 1 point.
func encodeP256Point(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, p256PointLen)
	out[0] = 4
	pub.X.FillBytes(out[1:33])
	pub.Y.FillBytes(out[33:65])
	return out
}

// decodeP256Point parses an uncompressed SEC 1 point and rejects anything not
// on the curve.
//
// Point validation goes through crypto/ecdh, whose NewPublicKey performs the
// on-curve check; elliptic.IsOnCurve and elliptic.Unmarshal are both
// deprecated. The parsed coordinates are then reused to build the
// ecdsa.PublicKey that ecdsa.Verify needs.
func decodeP256Point(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != p256PointLen || b[0] != 4 {
		return nil, fmt.Errorf("expected a %d-byte uncompressed P-256 point, got %d bytes",
			p256PointLen, len(b))
	}
	if _, err := ecdh.P256().NewPublicKey(b); err != nil {
		return nil, fmt.Errorf("invalid P-256 point: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(b[1:33]),
		Y:     new(big.Int).SetBytes(b[33:65]),
	}, nil
}

// encodeP256Signature renders (r, s) as the raw 64-byte form PSA emits.
func encodeP256Signature(r, s *big.Int) []byte {
	out := make([]byte, p256SigLen)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func decodeP256Signature(sig []byte) (r, s *big.Int, err error) {
	if len(sig) != p256SigLen {
		return nil, nil, fmt.Errorf("expected a %d-byte raw P-256 signature, got %d bytes",
			p256SigLen, len(sig))
	}
	return new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]), nil
}
