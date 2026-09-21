package protocol

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseSuite(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    Suite
		wantErr bool
	}{
		{"", DefaultSuite, false},
		{"ed25519-x25519", SuiteEd25519X25519, false},
		{"p256", SuiteP256, false},
		{"rsa", "", true},
	} {
		got, err := ParseSuite(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSuite(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSuite(%q): %v", tc.in, err)
		} else if got != tc.want {
			t.Errorf("ParseSuite(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSignVerify_P256RoundTrip(t *testing.T) {
	key := p256Key(t)
	payload := map[string]any{"b": 2, "a": 1}

	env, err := SignWithSuite(payload, key, "device", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	if env.Algorithm != AlgECDSAP256 {
		t.Fatalf("alg = %q, want %q", env.Algorithm, AlgECDSAP256)
	}

	// The signature must be raw r||s, not DER: that is what a PSA device
	// produces and what it can verify without an ASN.1 parser.
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != p256SigLen {
		t.Fatalf("signature is %d bytes, want the raw form of %d", len(sig), p256SigLen)
	}

	canon, err := Verify(env, &key.PublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if string(canon) != `{"a":1,"b":2}` {
		t.Fatalf("canonical payload = %s", canon)
	}
}

func TestVerify_P256TamperedPayload(t *testing.T) {
	key := p256Key(t)
	env, err := SignWithSuite(map[string]any{"a": 1}, key, "device", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"a":2}`))
	if _, err := Verify(env, &key.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v, want ErrSignature", err)
	}
}

// A device must not be able to have an Ed25519 envelope checked against a
// P-256 key or vice versa — the algorithm and the key type have to agree.
func TestVerify_AlgKeyTypeMismatch(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := p256Key(t)

	edEnv, err := Sign(map[string]any{"a": 1}, edPriv, "device")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(edEnv, &ecKey.PublicKey); err == nil {
		t.Error("ed25519 envelope verified against a P-256 key")
	}

	ecEnv, err := SignWithSuite(map[string]any{"a": 1}, ecKey, "device", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ecEnv, edPub); err == nil {
		t.Error("P-256 envelope verified against an ed25519 key")
	}
}

func TestVerify_UnknownAlgRejected(t *testing.T) {
	key := p256Key(t)
	env, err := SignWithSuite(map[string]any{"a": 1}, key, "device", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	env.Algorithm = "rsa-pkcs1"
	if _, err := Verify(env, &key.PublicKey); err == nil {
		t.Fatal("unknown alg was accepted")
	}
}

func TestDecodePublicKeyForAlg_P256(t *testing.T) {
	key := p256Key(t)
	b64, err := EncodePublicKeyForSuite(&key.PublicKey, SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != p256PointLen || raw[0] != 4 {
		t.Fatalf("public key is %d bytes starting %#x, want a %d-byte uncompressed point",
			len(raw), raw[0], p256PointLen)
	}
	got, err := DecodePublicKeyForAlg(b64, AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if !got.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("round-tripped public key differs")
	}
}

func TestDecodePublicKeyForAlg_RejectsOffCurvePoint(t *testing.T) {
	bogus := make([]byte, p256PointLen)
	bogus[0] = 4
	bogus[1] = 1 // x=1, y=0 is not on P-256
	_, err := DecodePublicKeyForAlg(base64.StdEncoding.EncodeToString(bogus), AlgECDSAP256)
	if err == nil {
		t.Fatal("an off-curve point was accepted")
	}
}

func TestSealModule_P256RoundTrip(t *testing.T) {
	devPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devPubB64 := base64.StdEncoding.EncodeToString(devPriv.PublicKey().Bytes())
	plaintext := []byte("[c8y]\nurl=example.cumulocity.com\none_time_password=s3cret\n")

	sealed, err := SealModuleForDeviceSuite(devPubB64, plaintext, "raw", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Algorithm != AlgP256ChaCha20 {
		t.Fatalf("alg = %q, want %q", sealed.Algorithm, AlgP256ChaCha20)
	}
	got, format, err := OpenSealedModuleP256(devPriv, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if format != "raw" {
		t.Errorf("format = %q, want raw", format)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext = %q, want %q", got, plaintext)
	}
}

func TestSealModule_P256TamperedCiphertextFails(t *testing.T) {
	devPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devPubB64 := base64.StdEncoding.EncodeToString(devPriv.PublicKey().Bytes())
	sealed, err := SealModuleForDeviceSuite(devPubB64, []byte("secret"), "raw", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xff
	sealed.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	if _, _, err := OpenSealedModuleP256(devPriv, sealed); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

// A P-256 sealed payload must not be openable by the X25519 path, and the
// algorithm tag is what keeps the two apart.
func TestOpenSealedModule_RejectsForeignAlg(t *testing.T) {
	devPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devPubB64 := base64.StdEncoding.EncodeToString(devPriv.PublicKey().Bytes())
	sealed, err := SealModuleForDeviceSuite(devPubB64, []byte("secret"), "raw", SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenSealedModule([32]byte{}, sealed); err == nil {
		t.Fatal("P-256 payload accepted by the X25519 opener")
	}
}

func TestEnrollRequest_EphemeralKeySelection(t *testing.T) {
	req := &EnrollRequest{EphemeralX25519: "x", EphemeralP256: "p"}
	if k, ok := req.EphemeralKey(SuiteEd25519X25519); !ok || k != "x" {
		t.Errorf("ed25519 suite selected %q (ok=%v)", k, ok)
	}
	if k, ok := req.EphemeralKey(SuiteP256); !ok || k != "p" {
		t.Errorf("p256 suite selected %q (ok=%v)", k, ok)
	}

	// A device that sent only the X25519 key must read as "absent" under the
	// P-256 suite, so the engine rejects rather than sealing to the wrong key.
	only := &EnrollRequest{EphemeralX25519: "x"}
	if _, ok := only.EphemeralKey(SuiteP256); ok {
		t.Error("p256 suite accepted an x25519-only request")
	}
}

// The default suite must keep producing byte-identical envelopes, since every
// deployed agent verifies them.
func TestSign_DefaultSuiteUnchanged(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Sign(map[string]any{"a": 1}, priv, "device")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignWithSuite(map[string]any{"a": 1}, priv, "device", SuiteEd25519X25519)
	if err != nil {
		t.Fatal(err)
	}
	if a.Algorithm != AlgEd25519 || a.Algorithm != b.Algorithm ||
		a.Payload != b.Payload || a.Signature != b.Signature {
		t.Fatalf("default suite diverged from Sign: %+v vs %+v", a, b)
	}
}
