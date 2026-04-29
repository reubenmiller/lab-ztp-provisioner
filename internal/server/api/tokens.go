package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/google/uuid"
)

// newTokenSecret returns (id, plaintext secret, sha256 hex hash). The
// plaintext is shown to the operator once; only the hash is stored.
func newTokenSecret() (id, secret, hash string, err error) {
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(secret))
	hash = hex.EncodeToString(sum[:])
	id = uuid.NewString()
	return
}
