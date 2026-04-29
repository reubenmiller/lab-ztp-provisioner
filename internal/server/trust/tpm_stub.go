package trust

import (
	"context"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// TPMAttestation is a stub Verifier. Real implementations would validate a
// TPM quote / EK certificate chain against a trusted manufacturer CA. Plug
// your implementation in by satisfying the Verifier interface and adding the
// instance to the Chain via configuration.
//
// Out of the box this verifier is a no-op (always Pending) so it can sit in
// the chain without affecting other verifiers.
type TPMAttestation struct{}

func (TPMAttestation) Name() string { return "tpm_attestation_stub" }

func (TPMAttestation) Verify(_ context.Context, _ *protocol.EnrollRequest) (Result, error) {
	return Result{Decision: Pending, Reason: "TPM attestation not configured"}, nil
}
