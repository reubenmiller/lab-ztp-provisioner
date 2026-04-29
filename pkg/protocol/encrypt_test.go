package protocol

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncryptRoundTrip(t *testing.T) {
	devPriv, devPub, err := GenerateX25519()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	devPubB64 := base64.StdEncoding.EncodeToString(devPub[:])

	plaintext := []byte(`{"hello":"world"}`)
	enc, err := SealForDevice(devPubB64, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if enc.Algorithm != AlgX25519ChaCha20 {
		t.Fatalf("alg: %s", enc.Algorithm)
	}
	got, err := OpenForDevice(devPriv, enc)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("mismatch: %s", got)
	}

	// Tamper with ciphertext: must fail.
	enc.Ciphertext = enc.Ciphertext[:len(enc.Ciphertext)-2] + "AA"
	if _, err := OpenForDevice(devPriv, enc); err == nil {
		t.Fatal("expected open to fail after tamper")
	}
}
