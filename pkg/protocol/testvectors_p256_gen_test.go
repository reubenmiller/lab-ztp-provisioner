// P-256 suite test vectors, written alongside the Ed25519/X25519 ones by
// TestGenerateP256Vectors. They exist so a constrained-device implementation
// (Zephyr/PSA, which has no Ed25519) can be pinned to the Go behaviour without
// running a server: canonical bytes, an ECDSA verification case, and a sealed
// module it must be able to open.
//
// Signature vectors carry the canonical bytes and a signature to VERIFY rather
// than to reproduce: ECDSA is randomised, so two correct implementations
// produce different signatures over the same input. The canonical bytes are
// the part that must match exactly, and they are what a device's own signing
// path is really being tested on.
package protocol

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

type p256SignVector struct {
	// PubKeyB64 is the base64 uncompressed point, exactly as a device puts
	// it in EnrollRequest.public_key.
	PubKeyB64 string          `json:"pub_key_b64"`
	InputJSON json.RawMessage `json:"input_json"`
	// CanonB64 is the RFC 8785 canonical encoding a device must reproduce
	// byte-for-byte before signing.
	CanonB64 string `json:"canon_b64"`
	// SigB64 is a valid raw r||s signature over CanonB64, for a device that
	// wants to exercise its verification path.
	SigB64 string `json:"sig_b64"`
	Alg    string `json:"alg"`
}

type p256SealVector struct {
	// DevicePrivB64 is the device's ephemeral P-256 private key (raw scalar),
	// DevicePubB64 the matching uncompressed point it would advertise as
	// ephemeral_p256.
	DevicePrivB64 string `json:"device_priv_b64"`
	DevicePubB64  string `json:"device_pub_b64"`
	// The sealed payload fields, as they appear in a module-sealed= manifest
	// line: ephemeral_pub, nonce, ciphertext.
	EphemeralPubB64 string `json:"ephemeral_pub_b64"`
	NonceB64        string `json:"nonce_b64"`
	CiphertextB64   string `json:"ciphertext_b64"`
	PlaintextB64    string `json:"plaintext_b64"`
	Format          string `json:"format"`
	Alg             string `json:"alg"`
	// HKDFInfo is the info string bound into the key derivation. A device
	// that uses a different one will fail the AEAD tag check, which is hard
	// to debug without seeing the expected value.
	HKDFInfo string `json:"hkdf_info"`
}

func TestGenerateP256Vectors(t *testing.T) {
	outDir := filepath.Join("..", "..", "testdata", "vectors")
	generateP256SignVectors(t, outDir)
	generateP256SealVectors(t, outDir)
}

// fixedP256Key derives a deterministic P-256 key from a fixed scalar so the
// vector file is stable across runs.
func fixedP256Key(t *testing.T, scalar int) *ecdsa.PrivateKey {
	t.Helper()
	d := new(big.Int).SetBytes(fixedSeed(scalar, 32))
	n := elliptic.P256().Params().N
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))

	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = d
	priv.PublicKey.Curve = elliptic.P256()
	//nolint:staticcheck // ScalarBaseMult is the only way to derive a public
	// key from a chosen scalar; crypto/ecdh cannot import a raw D.
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())
	return priv
}

func generateP256SignVectors(t *testing.T, dir string) {
	t.Helper()

	key := fixedP256Key(t, 1)
	pubB64, err := EncodePublicKeyForSuite(&key.PublicKey, SuiteP256)
	if err != nil {
		t.Fatal(err)
	}

	ephPriv := fixedP256Key(t, 10)
	ephPubB64, err := EncodePublicKeyForSuite(&ephPriv.PublicKey, SuiteP256)
	if err != nil {
		t.Fatal(err)
	}

	inputs := []any{
		map[string]any{"b": "val", "a": 42},
		// The shape a Zephyr device actually sends: no machine-id, no
		// os-release, a board name as the model, and the fields it can
		// cheaply produce.
		EnrollRequest{
			ProtocolVersion:  Version,
			Nonce:            base64.StdEncoding.EncodeToString(fixedSeed(0, 16)),
			Timestamp:        time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC),
			DeviceID:         "zephyr-aabbccddeeff",
			PublicKey:        pubB64,
			EphemeralP256:    ephPubB64,
			ResponseFormat:   "text",
			MaxResponseBytes: 4096,
			Facts: DeviceFacts{
				MACAddresses: []string{"aa:bb:cc:dd:ee:ff"},
				Model:        "esp32c6_devkitc",
				Hostname:     "tedge-modbus",
				OS:           "zephyr",
				AgentVersion: "dev",
			},
			Capabilities: []string{"wifi.v2", "c8y.v2"},
		},
	}

	var vectors []p256SignVector
	for _, inp := range inputs {
		inputJSON, err := json.Marshal(inp)
		if err != nil {
			t.Fatalf("marshal input: %v", err)
		}
		canon, err := Canonicalize(inp)
		if err != nil {
			t.Fatalf("canonicalize: %v", err)
		}
		env, err := SignWithSuite(inp, key, "device", SuiteP256)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if _, err := Verify(env, &key.PublicKey); err != nil {
			t.Fatalf("sign/verify round-trip failed: %v", err)
		}
		if env.Payload != base64.StdEncoding.EncodeToString(canon) {
			t.Fatal("envelope payload is not the canonical bytes")
		}
		vectors = append(vectors, p256SignVector{
			PubKeyB64: pubB64,
			InputJSON: json.RawMessage(inputJSON),
			CanonB64:  env.Payload,
			SigB64:    env.Signature,
			Alg:       env.Algorithm,
		})
	}
	writeJSONFile(t, filepath.Join(dir, "sign_p256.json"), vectors)
}

func generateP256SealVectors(t *testing.T, dir string) {
	t.Helper()

	devPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devPubB64 := base64.StdEncoding.EncodeToString(devPriv.PublicKey().Bytes())

	plaintext := []byte("[c8y]\n" +
		"url=example.cumulocity.com\n" +
		"tenant=t12345\n" +
		"external_id=zephyr-aabbccddeeff\n" +
		"one_time_password=vector-token\n")

	sealed, err := SealModuleForDeviceSuite(devPubB64, plaintext, "raw", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	got, format, err := OpenSealedModuleP256(devPriv, sealed)
	if err != nil {
		t.Fatalf("seal/open round-trip failed: %v", err)
	}
	if string(got) != string(plaintext) || format != "raw" {
		t.Fatal("seal/open round-trip returned different bytes")
	}

	writeJSONFile(t, filepath.Join(dir, "seal_p256.json"), p256SealVector{
		DevicePrivB64:   base64.StdEncoding.EncodeToString(devPriv.Bytes()),
		DevicePubB64:    devPubB64,
		EphemeralPubB64: sealed.EphemeralPub,
		NonceB64:        sealed.Nonce,
		CiphertextB64:   sealed.Ciphertext,
		PlaintextB64:    base64.StdEncoding.EncodeToString(plaintext),
		Format:          sealed.Format,
		Alg:             sealed.Algorithm,
		HKDFInfo:        p256HKDFInfo,
	})
}
