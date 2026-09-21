package protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// AlgX25519ChaCha20 is the original encryption algorithm for EncryptedPayload
// and SealedPayload, used by SuiteEd25519X25519.
const AlgX25519ChaCha20 = "x25519-chacha20poly1305"

// AlgP256ChaCha20 is the encryption algorithm used by SuiteP256: ECDH on
// NIST P-256, HKDF-SHA256 to derive the content key, then the same
// ChaCha20-Poly1305 AEAD as the default suite.
//
// Why this one derives a key and AlgX25519ChaCha20 does not: X25519's output
// is already a uniformly random 32-byte string, so using it directly as an
// AEAD key is defensible. A P-256 ECDH shared secret is an x-coordinate — a
// field element with structure and bias — and must not be used as a key
// directly. HKDF-SHA256 is the standard fix, it is one PSA call on the device
// (PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256))), and
// SHA-256 is already linked for the signatures.
const AlgP256ChaCha20 = "p256-hkdf-sha256-chacha20poly1305"

// p256HKDFInfo is the HKDF info string binding derived keys to this protocol
// and version. An empty salt is used so the device does not have to carry one.
// Changing this value breaks every deployed device; bump the algorithm
// identifier instead.
const p256HKDFInfo = "ztp/seal/v1"

// deriveP256Key performs ECDH against peerPub and runs the shared secret
// through HKDF-SHA256 to produce a ChaCha20-Poly1305 key.
func deriveP256Key(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, []byte(p256HKDFInfo)), key); err != nil {
		return nil, err
	}
	for i := range shared {
		shared[i] = 0
	}
	return key, nil
}

// decodeP256Ephemeral parses a base64 uncompressed P-256 point as a key
// agreement public key.
func decodeP256Ephemeral(b64 string) (*ecdh.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPublicKey(b)
}

// sealWithSuite is the shared body of the per-module and whole-bundle sealing
// paths: agree on a key with the device's ephemeral public key, then AEAD the
// plaintext under a fresh nonce. It returns the server's ephemeral public key,
// the nonce and the ciphertext, all base64.
func sealWithSuite(devicePubB64 string, plaintext []byte, suite Suite) (pub, nonce, ct string, err error) {
	var (
		aeadKey   []byte
		serverPub []byte
	)
	switch suite {
	case SuiteP256:
		devPub, err := decodeP256Ephemeral(devicePubB64)
		if err != nil {
			return "", "", "", fmt.Errorf("device pub: %w", err)
		}
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return "", "", "", err
		}
		if aeadKey, err = deriveP256Key(priv, devPub); err != nil {
			return "", "", "", err
		}
		serverPub = priv.PublicKey().Bytes()
	default:
		devPub, err := decodeX25519(devicePubB64)
		if err != nil {
			return "", "", "", fmt.Errorf("device pub: %w", err)
		}
		priv, pubArr, err := GenerateX25519()
		if err != nil {
			return "", "", "", err
		}
		if aeadKey, err = curve25519.X25519(priv[:], devPub[:]); err != nil {
			return "", "", "", err
		}
		serverPub = pubArr[:]
	}

	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return "", "", "", err
	}
	n := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		return "", "", "", err
	}
	return base64.StdEncoding.EncodeToString(serverPub),
		base64.StdEncoding.EncodeToString(n),
		base64.StdEncoding.EncodeToString(aead.Seal(nil, n, plaintext, nil)),
		nil
}

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
	return SealForDeviceSuite(devicePubB64, plaintext, SuiteEd25519X25519)
}

// SealForDeviceSuite is SealForDevice under an explicit suite. devicePubB64 is
// the device's ephemeral key-agreement public key for that suite —
// EnrollRequest.EphemeralX25519 or EnrollRequest.EphemeralP256.
func SealForDeviceSuite(devicePubB64 string, plaintext []byte, suite Suite) (*EncryptedPayload, error) {
	pub, nonce, ct, err := sealWithSuite(devicePubB64, plaintext, suite)
	if err != nil {
		return nil, err
	}
	return &EncryptedPayload{
		Algorithm:  suite.SealAlg(),
		ServerKey:  pub,
		Nonce:      nonce,
		Ciphertext: ct,
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
	return SealModuleForDeviceSuite(devicePubB64, plaintext, format, SuiteEd25519X25519)
}

// SealModuleForDeviceSuite is SealModuleForDevice under an explicit suite.
func SealModuleForDeviceSuite(devicePubB64 string, plaintext []byte, format string, suite Suite) (*SealedPayload, error) {
	if format != "json" && format != "raw" {
		return nil, fmt.Errorf("unsupported sealed payload format %q", format)
	}
	pub, nonce, ct, err := sealWithSuite(devicePubB64, plaintext, suite)
	if err != nil {
		return nil, err
	}
	return &SealedPayload{
		Algorithm:    suite.SealAlg(),
		EphemeralPub: pub,
		Nonce:        nonce,
		Ciphertext:   ct,
		Format:       format,
	}, nil
}

// OpenSealedModuleP256 decrypts a SuiteP256 SealedPayload using the device's
// ephemeral P-256 private key.
//
// The Go agent does not use this suite — it exists for constrained devices,
// and the Rust agent implements it independently (clients/rust/src/encrypt.rs)
// — but the server's own tests round-trip through it, and it is the executable
// reference for what a device implementation has to do.
func OpenSealedModuleP256(devicePriv *ecdh.PrivateKey, p *SealedPayload) ([]byte, string, error) {
	if p == nil {
		return nil, "", errors.New("nil sealed payload")
	}
	if p.Algorithm != AlgP256ChaCha20 {
		return nil, "", fmt.Errorf("unsupported alg %q", p.Algorithm)
	}
	pt, err := openP256(devicePriv, p.EphemeralPub, p.Nonce, p.Ciphertext)
	if err != nil {
		return nil, "", err
	}
	return pt, p.Format, nil
}

// OpenForDeviceP256 decrypts a SuiteP256 EncryptedPayload (whole-bundle
// encryption) using the device's ephemeral P-256 private key.
func OpenForDeviceP256(devicePriv *ecdh.PrivateKey, p *EncryptedPayload) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil encrypted payload")
	}
	if p.Algorithm != AlgP256ChaCha20 {
		return nil, fmt.Errorf("unsupported alg %q", p.Algorithm)
	}
	return openP256(devicePriv, p.ServerKey, p.Nonce, p.Ciphertext)
}

func openP256(devicePriv *ecdh.PrivateKey, peerPubB64, nonceB64, ctB64 string) ([]byte, error) {
	peerPub, err := decodeP256Ephemeral(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("ephemeral pub: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}
	key, err := deriveP256Key(devicePriv, peerPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("nonce length")
	}
	return aead.Open(nil, nonce, ct, nil)
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
