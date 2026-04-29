// Package identity manages the device's long-lived Ed25519 identity key.
//
// The default implementation persists the private key to disk. A TPM-backed
// implementation can be added later by satisfying Provider.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

// Provider abstracts the source of a device's signing key.
type Provider interface {
	PrivateKey() ed25519.PrivateKey
	PublicKey() ed25519.PublicKey
}

type fileProvider struct {
	priv ed25519.PrivateKey
}

func (f *fileProvider) PrivateKey() ed25519.PrivateKey { return f.priv }
func (f *fileProvider) PublicKey() ed25519.PublicKey   { return f.priv.Public().(ed25519.PublicKey) }

// LoadOrCreateFile reads an Ed25519 private key from path, generating and
// persisting a new one if the file does not exist. The file is created with
// permissions 0600.
func LoadOrCreateFile(path string) (Provider, error) {
	if path == "" {
		return nil, errors.New("identity path is required")
	}
	b, err := os.ReadFile(path)
	if err == nil {
		raw, derr := base64.StdEncoding.DecodeString(string(b))
		if derr != nil {
			return nil, derr
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("identity key has wrong size")
		}
		return &fileProvider{priv: ed25519.PrivateKey(raw)}, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	out := []byte(base64.StdEncoding.EncodeToString(priv))
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, err
	}
	return &fileProvider{priv: priv}, nil
}
