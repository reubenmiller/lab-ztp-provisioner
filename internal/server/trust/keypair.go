package trust

import (
	"context"
	"errors"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// KnownKeypair trusts requests whose public key matches a key already
// recorded for the device (i.e. the device has been seen and approved before).
//
// First-contact requests are returned as Pending with no reason — the chain
// then either rejects or queues for manual approval. After an operator
// approves a pending request, the device's pubkey is stored in the device
// record, and subsequent requests pass through this verifier directly.
type KnownKeypair struct {
	Store store.Store
}

func (k *KnownKeypair) Name() string { return "known_keypair" }

func (k *KnownKeypair) Verify(ctx context.Context, req *protocol.EnrollRequest) (Result, error) {
	d, err := k.Store.GetDevice(ctx, req.DeviceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return Result{Decision: Pending}, nil
		}
		return Result{Decision: Pending}, err
	}
	if d.PublicKey == "" || d.PublicKey != req.PublicKey {
		// Device exists but the key changed — that's suspicious. Reject so an
		// operator notices and either re-approves or investigates.
		return Result{Decision: Reject, Reason: "public key does not match recorded key for device"}, nil
	}
	return Result{Decision: Trust, Reason: "known device key"}, nil
}
