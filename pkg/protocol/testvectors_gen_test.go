// TestGenerateVectors regenerates the cross-language test vector files in
// testdata/vectors/ (repo root). It runs automatically as part of
// `go test ./pkg/protocol` and is also invoked by the Rust crate's build.rs
// so that `cargo test` works without a prior manual generation step.
//
// The output files are .gitignore'd — they contain deterministic synthetic
// keys that would otherwise be flagged by secret scanners.
package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func TestGenerateVectors(t *testing.T) {
	outDir := filepath.Join("..", "..", "testdata", "vectors")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	generateCanonicalVectors(t, outDir)
	generateSignVectors(t, outDir)
	generateSealVectors(t, outDir)
	generateEnrollRequestVector(t, outDir)
}

// ---- canonical ---------------------------------------------------------------

type canonicalCase struct {
	Input    json.RawMessage `json:"input"`
	Expected string          `json:"expected"` // base64(canonical_bytes)
}

func generateCanonicalVectors(t *testing.T, dir string) {
	t.Helper()

	type testCase struct {
		value any
	}
	cases := []testCase{
		{map[string]any{}},
		{map[string]any{"a": 1}},
		{map[string]any{"b": 1, "a": 2}},
		{map[string]any{"b": 1, "a": map[string]any{"y": 2, "x": 3}}},
		// Unicode: "é" (U+00E9, 2 bytes) sorts before "中" (U+4E2D, 3 bytes)
		{map[string]any{"\u00e9": 1, "\u4e2d": 2}},
		// Various value types
		{map[string]any{"z": nil, "a": true, "b": false}},
		// Numbers (integer only — we avoid floats which have repr difference risk)
		{map[string]any{"n": 42, "m": -7}},
		// Array preserves order
		{[]any{3, 1, 2}},
		// String
		{"hello world"},
		// Null
		{nil},
		// String escaping: control chars, backslash, quote
		{map[string]any{"s": "line1\nline2\ttabbed\\back\"quote"}},
	}

	var vectors []canonicalCase
	for _, c := range cases {
		inputJSON, err := json.Marshal(c.value)
		if err != nil {
			t.Fatalf("marshal input: %v", err)
		}
		canon, err := Canonicalize(c.value)
		if err != nil {
			t.Fatalf("canonicalize: %v", err)
		}
		vectors = append(vectors, canonicalCase{
			Input:    json.RawMessage(inputJSON),
			Expected: base64.StdEncoding.EncodeToString(canon),
		})
	}

	writeJSONFile(t, filepath.Join(dir, "canonical.json"), vectors)
}

// ---- sign --------------------------------------------------------------------

type signVector struct {
	// base64 of the 64-byte Ed25519 private key (Go format: seed || pubkey)
	PrivKeyB64 string          `json:"priv_key_b64"`
	PubKeyB64  string          `json:"pub_key_b64"`
	InputJSON  json.RawMessage `json:"input"`
	CanonB64   string          `json:"canonical_b64"` // base64 of the canonical bytes that are signed
	SigB64     string          `json:"signature_b64"` // base64 of ed25519 signature
}

func generateSignVectors(t *testing.T, dir string) {
	t.Helper()

	// Fixed seed for reproducibility: [1, 2, ..., 32]
	seed := fixedSeed(1, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Fixed ephemeral X25519 public key for the EnrollRequest
	ephPriv := fixedX25519Priv(10, 41)
	ephPubBytes, _ := curve25519.X25519(ephPriv[:], curve25519.Basepoint)

	inputs := []any{
		// Simple object
		map[string]any{"b": "val", "a": 42},
		// Full EnrollRequest (the real signing use-case)
		EnrollRequest{
			ProtocolVersion: Version,
			Nonce:           base64.StdEncoding.EncodeToString(fixedSeed(0, 16)),
			Timestamp:       time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			DeviceID:        "test-device-001",
			PublicKey:       base64.StdEncoding.EncodeToString(pub),
			EphemeralX25519: base64.StdEncoding.EncodeToString(ephPubBytes),
			EncryptBundle:   false,
			BootstrapToken:  "tok123",
			Facts: DeviceFacts{
				MachineID:    "deadbeef0123456789ab",
				MACAddresses: []string{"aa:bb:cc:dd:ee:ff"},
				Hostname:     "testhost.local",
				OS:           "linux",
				Arch:         "amd64",
				AgentVersion: "dev",
			},
			Capabilities: []string{"wifi.v2", "ssh.authorized_keys.v2", "c8y.v2", "files.v2", "hook.v2", "passwd.v2"},
		},
	}

	var vectors []signVector
	for _, inp := range inputs {
		inputJSON, err := json.Marshal(inp)
		if err != nil {
			t.Fatalf("marshal input: %v", err)
		}
		canon, err := Canonicalize(inp)
		if err != nil {
			t.Fatalf("canonicalize: %v", err)
		}
		sig := ed25519.Sign(priv, canon)

		// Verify round-trips before committing to the vector file
		if !ed25519.Verify(pub, canon, sig) {
			t.Fatal("sign/verify round-trip failed")
		}

		vectors = append(vectors, signVector{
			PrivKeyB64: base64.StdEncoding.EncodeToString(priv),
			PubKeyB64:  base64.StdEncoding.EncodeToString(pub),
			InputJSON:  json.RawMessage(inputJSON),
			CanonB64:   base64.StdEncoding.EncodeToString(canon),
			SigB64:     base64.StdEncoding.EncodeToString(sig),
		})
	}

	writeJSONFile(t, filepath.Join(dir, "sign.json"), vectors)
}

// ---- seal --------------------------------------------------------------------

type sealVector struct {
	// device's ephemeral X25519 private key (used to decrypt)
	DevicePrivB64 string `json:"device_priv_b64"`
	// device's ephemeral X25519 public key (sent in EnrollRequest.EphemeralX25519)
	DevicePubB64 string `json:"device_pub_b64"`
	// server's ephemeral X25519 public key (= EncryptedPayload.ServerKey or SealedPayload.EphemeralPub)
	ServerEphPubB64 string `json:"server_eph_pub_b64"`
	NoncB64         string `json:"nonce_b64"`      // base64 of 12-byte nonce
	PlaintextB64    string `json:"plaintext_b64"`  // base64 of plaintext
	CiphertextB64   string `json:"ciphertext_b64"` // base64 of ciphertext with AEAD tag appended
}

type sealVectors struct {
	// EncryptedPayload: whole-bundle encryption (EncryptedPayload.ServerKey = server eph pub)
	EncryptedPayload sealVector `json:"encrypted_payload"`
	// SealedPayload: per-module encryption (SealedPayload.EphemeralPub = server eph pub)
	SealedModule sealVector `json:"sealed_module"`
}

func generateSealVectors(t *testing.T, dir string) {
	t.Helper()

	// Fixed device X25519 private key: [1..32]
	devicePriv := fixedX25519Priv(1, 32)
	devicePubBytes, _ := curve25519.X25519(devicePriv[:], curve25519.Basepoint)

	// Fixed server ephemeral X25519 private key: [32..1]
	serverEphPriv := fixedX25519PrivDescending()
	serverEphPubBytes, _ := curve25519.X25519(serverEphPriv[:], curve25519.Basepoint)

	// Fixed 12-byte nonce
	nonce := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

	// Fixed plaintext
	plaintext := []byte(`{"ssid":"TestNetwork","password":"secret123"}`)

	// Compute shared secret from server side: ECDH(serverEphPriv, devicePub)
	shared, err := curve25519.X25519(serverEphPriv[:], devicePubBytes)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}
	aead, err := chacha20poly1305.New(shared)
	if err != nil {
		t.Fatalf("chacha20poly1305: %v", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)

	// Verify: device can decrypt using devicePriv + serverEphPub
	sharedDev, _ := curve25519.X25519(devicePriv[:], serverEphPubBytes)
	aeadDev, _ := chacha20poly1305.New(sharedDev)
	pt, err := aeadDev.Open(nil, nonce, ct, nil)
	if err != nil || string(pt) != string(plaintext) {
		t.Fatalf("seal round-trip failed: %v, got %q want %q", err, pt, plaintext)
	}

	v := sealVector{
		DevicePrivB64:   base64.StdEncoding.EncodeToString(devicePriv[:]),
		DevicePubB64:    base64.StdEncoding.EncodeToString(devicePubBytes),
		ServerEphPubB64: base64.StdEncoding.EncodeToString(serverEphPubBytes),
		NoncB64:         base64.StdEncoding.EncodeToString(nonce),
		PlaintextB64:    base64.StdEncoding.EncodeToString(plaintext),
		CiphertextB64:   base64.StdEncoding.EncodeToString(ct),
	}

	vectors := sealVectors{
		EncryptedPayload: v,
		SealedModule:     v, // same primitive, same vector
	}

	writeJSONFile(t, filepath.Join(dir, "seal.json"), vectors)
}

// ---- enroll request ----------------------------------------------------------

type enrollRequestVector struct {
	PrivKeyB64     string          `json:"priv_key_b64"` // base64 of 64-byte ed25519 private key
	PubKeyB64      string          `json:"pub_key_b64"`
	Request        json.RawMessage `json:"request"`         // serialized EnrollRequest
	CanonB64       string          `json:"canonical_b64"`   // base64 of canonical bytes (what is signed)
	SignedEnvelope json.RawMessage `json:"signed_envelope"` // full SignedEnvelope
}

func generateEnrollRequestVector(t *testing.T, dir string) {
	t.Helper()

	seed := fixedSeed(1, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	ephPriv := fixedX25519Priv(10, 41)
	ephPubBytes, _ := curve25519.X25519(ephPriv[:], curve25519.Basepoint)

	req := EnrollRequest{
		ProtocolVersion: Version,
		Nonce:           base64.StdEncoding.EncodeToString(fixedSeed(1, 16)),
		Timestamp:       time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
		DeviceID:        "test-device-001",
		PublicKey:       base64.StdEncoding.EncodeToString(pub),
		EphemeralX25519: base64.StdEncoding.EncodeToString(ephPubBytes),
		EncryptBundle:   false,
		BootstrapToken:  "bootstrap-tok-001",
		Facts: DeviceFacts{
			MachineID:    "deadbeef0123456789ab",
			MACAddresses: []string{"aa:bb:cc:dd:ee:ff"},
			Hostname:     "testhost.local",
			OS:           "linux",
			Arch:         "amd64",
			AgentVersion: "dev",
		},
		Capabilities: []string{"wifi.v2", "ssh.authorized_keys.v2", "c8y.v2", "files.v2", "hook.v2", "passwd.v2"},
	}

	env, err := Sign(req, priv, "device")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify
	if _, err := Verify(env, pub); err != nil {
		t.Fatalf("verify: %v", err)
	}

	canon, err := Canonicalize(req)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	reqJSON, _ := json.Marshal(req)
	envJSON, _ := json.Marshal(env)

	vec := enrollRequestVector{
		PrivKeyB64:     base64.StdEncoding.EncodeToString(priv),
		PubKeyB64:      base64.StdEncoding.EncodeToString(pub),
		Request:        json.RawMessage(reqJSON),
		CanonB64:       base64.StdEncoding.EncodeToString(canon),
		SignedEnvelope: json.RawMessage(envJSON),
	}

	writeJSONFile(t, filepath.Join(dir, "enroll_request.json"), vec)
}

// ---- helpers -----------------------------------------------------------------

// writeJSONFile marshals v as indented JSON and writes it to path.
func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("wrote %s (%d bytes)", path, len(b))
}

// fixedSeed returns a []byte where each element = start + i.
func fixedSeed(start, length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}

// fixedX25519Priv builds a [32]byte X25519 private key with bytes [start..start+31].
func fixedX25519Priv(start, _ int) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(start + i)
	}
	return k
}

// fixedX25519PrivDescending builds a [32]byte key with bytes [32, 31, ..., 1].
func fixedX25519PrivDescending() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(32 - i)
	}
	return k
}
