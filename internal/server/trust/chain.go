// Package trust contains the composable verifier chain that decides whether
// an incoming EnrollRequest should be auto-trusted, queued for manual
// approval, or rejected.
//
// Each Verifier returns one of three Decisions; the Engine walks the chain in
// order and uses the first non-Pending result. If every verifier returns
// Pending the request is queued for an operator to approve in the web UI.
//
// New verifiers (TPM attestation, mTLS, etc.) implement Verifier and are
// added to the chain via configuration — the engine itself stays unchanged.
package trust

import (
	"context"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Decision aliases store.Decision so verifier authors only need this package.
type Decision = store.Decision

const (
	Trust   = store.DecisionTrust
	Pending = store.DecisionPending
	Reject  = store.DecisionReject
)

// Result is what a Verifier produces.
type Result struct {
	Decision Decision
	Reason   string // free-form, surfaced in audit logs and (where safe) to clients
	Verifier string // populated by Chain
	Profile  string // optional profile hint (allowlist entry / token / etc.)
}

// Verifier inspects an EnrollRequest and decides what to do with it.
//
// Implementations MUST:
//   - return (Result{Decision: Pending}, nil) when they don't have an opinion
//     (so the next verifier in the chain gets a turn);
//   - never return Trust unless the verifier is fully satisfied the request
//     is authentic (signature, freshness, identity binding);
//   - never block on slow I/O without honouring ctx.
type Verifier interface {
	Name() string
	Verify(ctx context.Context, req *protocol.EnrollRequest) (Result, error)
}

// Chain is an ordered list of verifiers. The first non-Pending result wins.
type Chain []Verifier

// Run walks the chain. If every verifier returns Pending, the final Result has
// Decision == Pending so the engine can queue the request for manual approval.
func (c Chain) Run(ctx context.Context, req *protocol.EnrollRequest) (Result, error) {
	last := Result{Decision: Pending, Reason: "no verifier matched"}
	for _, v := range c {
		r, err := v.Verify(ctx, req)
		if err != nil {
			return Result{Verifier: v.Name(), Decision: Reject, Reason: err.Error()}, err
		}
		r.Verifier = v.Name()
		switch r.Decision {
		case Trust, Reject:
			return r, nil
		case Pending:
			last = r
			continue
		}
	}
	return last, nil
}
