package trust

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// BootstrapToken trusts requests carrying a known, unexpired, not-yet-exhausted
// bootstrap token. The token's plaintext is sent in EnrollRequest.BootstrapToken;
// only its SHA-256 hash is stored.
type BootstrapToken struct {
	Store store.Store
}

func (b *BootstrapToken) Name() string { return "bootstrap_token" }

// HashToken is exposed so the admin CLI can store hashes consistently.
func HashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (b *BootstrapToken) Verify(ctx context.Context, req *protocol.EnrollRequest) (Result, error) {
	if req.BootstrapToken == "" {
		return Result{Decision: Pending}, nil
	}
	hash := HashToken(req.BootstrapToken)
	tok, err := b.Store.GetTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{Decision: Reject, Reason: "unknown bootstrap token"}, nil
		}
		return Result{Decision: Pending}, err
	}
	if !tok.ExpiresAt.IsZero() && time.Now().After(tok.ExpiresAt) {
		return Result{Decision: Reject, Reason: "bootstrap token expired"}, nil
	}
	if tok.MaxUses > 0 && tok.Uses >= tok.MaxUses {
		return Result{Decision: Reject, Reason: "bootstrap token exhausted"}, nil
	}
	if tok.DeviceID != "" && tok.DeviceID != req.DeviceID {
		return Result{Decision: Reject, Reason: "bootstrap token bound to a different device"}, nil
	}
	if err := b.Store.IncrementTokenUse(ctx, tok.ID); err != nil {
		return Result{Decision: Pending}, err
	}
	return Result{Decision: Trust, Reason: "valid bootstrap token", Profile: tok.Profile}, nil
}
