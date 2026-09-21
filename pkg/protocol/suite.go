package protocol

import "fmt"

// A Suite names a coherent set of algorithms for one device population.
//
// The wire format carries algorithm identifiers per message (SignedEnvelope.alg,
// SealedPayload.alg), so a server can serve several suites at once and a device
// only ever has to implement the one its fleet was provisioned with. The suite
// is what an operator selects — per profile, so a fleet of constrained devices
// can be served differently from a fleet of Linux boxes without a global flag
// day.
//
// Why a second suite exists: Mbed TLS — and therefore the PSA crypto stack that
// every Zephyr microcontroller build uses — does not implement Ed25519. A
// microcontroller that already carries P-256, SHA-256 and an AEAD for its own
// device-management TLS can reuse them at no extra flash cost, whereas Ed25519
// would mean a second signature stack and Curve25519 a second curve. On boards
// where the provisioning image already fills its flash partition, that
// difference decides whether the device can be provisioned at all.
type Suite string

const (
	// SuiteEd25519X25519 is the original suite and remains the default: every
	// existing agent (Go, Rust, POSIX shell) speaks it and nothing about those
	// code paths changes.
	SuiteEd25519X25519 Suite = "ed25519-x25519"

	// SuiteP256 is the constrained-device suite: one curve (NIST P-256) for
	// both signatures and key agreement, SHA-256 throughout, and the same
	// ChaCha20-Poly1305 AEAD as the default suite.
	SuiteP256 Suite = "p256"

	// DefaultSuite is used when neither the profile nor the server config
	// selects one.
	DefaultSuite = SuiteEd25519X25519
)

// Algorithm identifiers as they appear in SignedEnvelope.alg.
const (
	AlgEd25519   = "ed25519"
	AlgECDSAP256 = "ecdsa-p256-sha256"
)

// SignAlg returns the identifier this suite puts in SignedEnvelope.alg.
func (s Suite) SignAlg() string {
	if s == SuiteP256 {
		return AlgECDSAP256
	}
	return AlgEd25519
}

// SealAlg returns the identifier this suite puts in SealedPayload.alg and
// EncryptedPayload.alg.
func (s Suite) SealAlg() string {
	if s == SuiteP256 {
		return AlgP256ChaCha20
	}
	return AlgX25519ChaCha20
}

// EphemeralField names the EnrollRequest field a device of this suite uses to
// publish its ephemeral key-agreement public key. Used in error messages so an
// operator who has mismatched a profile against a device sees which field was
// expected.
func (s Suite) EphemeralField() string {
	if s == SuiteP256 {
		return "ephemeral_p256"
	}
	return "ephemeral_x25519"
}

// ParseSuite validates an operator-supplied suite name. The empty string
// selects DefaultSuite so that an omitted `crypto:` block means "unchanged".
func ParseSuite(s string) (Suite, error) {
	switch Suite(s) {
	case "":
		return DefaultSuite, nil
	case SuiteEd25519X25519:
		return SuiteEd25519X25519, nil
	case SuiteP256:
		return SuiteP256, nil
	default:
		return "", fmt.Errorf("unknown crypto suite %q (want %q or %q)",
			s, SuiteEd25519X25519, SuiteP256)
	}
}

// SuiteForSignAlg maps an inbound envelope's algorithm back to its suite. The
// server uses it to answer a device in the same suite it spoke, without the
// device having to name one.
func SuiteForSignAlg(alg string) (Suite, error) {
	switch alg {
	case AlgEd25519:
		return SuiteEd25519X25519, nil
	case AlgECDSAP256:
		return SuiteP256, nil
	default:
		return "", fmt.Errorf("unsupported alg %q", alg)
	}
}
