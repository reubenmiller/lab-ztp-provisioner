// Package protocol defines the wire format shared between the ZTP server and
// device agents. The format is transport-agnostic and works equally well over
// HTTPS, mDNS-discovered LAN, or BLE GATT relays.
//
// All payloads are JSON. Signatures are detached Ed25519 over a canonicalised
// (RFC 8785 / JCS) representation of the payload object so the Go and shell
// agents produce identical signing inputs.
package protocol

import "time"

// Version is the current wire protocol version. The server and agent both
// emit this value and reject mismatched majors.
const Version = "1"

// EnrollRequest is sent by a device to claim an identity and request a
// provisioning bundle. It is signed by the device's long-lived identity key
// (Ed25519). The PublicKey field carries the verifier needed by the server,
// allowing trust-on-first-use flows.
type EnrollRequest struct {
	ProtocolVersion string    `json:"protocol_version"`
	Nonce           string    `json:"nonce"`     // base64(random 16 bytes)
	Timestamp       time.Time `json:"timestamp"` // RFC3339, UTC
	DeviceID        string    `json:"device_id"`
	PublicKey       string    `json:"public_key"`                 // base64 Ed25519 pub
	EphemeralX25519 string    `json:"ephemeral_x25519,omitempty"` // base64; for end-to-end encryption (whole bundle and/or sensitive modules)
	// EncryptBundle requests that the entire SignedEnvelope be wrapped in an
	// EncryptedPayload addressed to EphemeralX25519. Useful when the
	// transport itself is untrusted (e.g. a BLE relay). Independent of
	// per-module sealing, which the server applies whenever it has a
	// sensitive payload AND EphemeralX25519 is present.
	EncryptBundle  bool              `json:"encrypt_bundle,omitempty"`
	BootstrapToken string            `json:"bootstrap_token,omitempty"`
	Facts          DeviceFacts       `json:"facts"`
	Capabilities   []string          `json:"capabilities,omitempty"` // module types the device supports
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// DeviceFacts is the operator-visible identity surface of a device. It is what
// shows up in the "pending approval" list of the web UI.
type DeviceFacts struct {
	MachineID    string   `json:"machine_id,omitempty"`
	MACAddresses []string `json:"mac_addresses,omitempty"`
	Serial       string   `json:"serial,omitempty"`
	Model        string   `json:"model,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	OS           string   `json:"os,omitempty"`
	Arch         string   `json:"arch,omitempty"`
	// OSPrettyName is the human-readable OS name from /etc/os-release
	// (PRETTY_NAME field), e.g. "Debian GNU/Linux 12 (bookworm)".
	OSPrettyName string `json:"os_pretty_name,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

// SignedEnvelope wraps a JSON document with a detached signature.
// Payload is the canonicalised JSON bytes (base64 encoded) so verifiers do not
// have to re-canonicalise. KeyID identifies which key signed it (e.g. "device"
// or a server key fingerprint).
type SignedEnvelope struct {
	ProtocolVersion string `json:"protocol_version"`
	KeyID           string `json:"key_id"`
	Algorithm       string `json:"alg"`       // "ed25519"
	Payload         string `json:"payload"`   // base64(canonical JSON)
	Signature       string `json:"signature"` // base64(sig)
}

// EnrollStatus is the high-level result returned to a device.
type EnrollStatus string

const (
	StatusAccepted EnrollStatus = "accepted"
	StatusPending  EnrollStatus = "pending"
	StatusRejected EnrollStatus = "rejected"
)

// EnrollResponse is the server's reply. When Status == StatusAccepted the
// Bundle field contains a signed (and optionally encrypted) ProvisioningBundle.
type EnrollResponse struct {
	ProtocolVersion string          `json:"protocol_version"`
	Status          EnrollStatus    `json:"status"`
	Reason          string          `json:"reason,omitempty"`
	RetryAfter      int             `json:"retry_after,omitempty"` // seconds; for "pending"
	Bundle          *SignedEnvelope `json:"bundle,omitempty"`
	// EncryptedBundle, if present, is an X25519+ChaCha20-Poly1305 ciphertext
	// over the SignedEnvelope JSON. Used when transport is untrusted (BLE relay).
	EncryptedBundle *EncryptedPayload `json:"encrypted_bundle,omitempty"`
	// TextManifest, if present, is an alternative bundle representation as
	// signed line-based "key=value" text. It is omitted from JSON responses
	// (it would just duplicate Bundle) and rendered only when the client
	// asks for `Accept: text/plain`.
	TextManifest *SignedEnvelope `json:"-"`
	// ServerTime is the server's UTC clock at the time of the response.
	// Devices whose clocks are not yet synced (e.g. before NTP via a
	// newly-provisioned network) can compute a correction offset from this
	// field and retry with an adjusted timestamp.
	ServerTime *time.Time `json:"server_time,omitempty"`
}

// EncryptedPayload carries an end-to-end-encrypted payload addressed to the
// device's ephemeral X25519 key from EnrollRequest.EphemeralX25519.
type EncryptedPayload struct {
	Algorithm  string `json:"alg"`        // "x25519-chacha20poly1305"
	ServerKey  string `json:"server_key"` // base64 X25519 pub
	Nonce      string `json:"nonce"`      // base64 12 bytes
	Ciphertext string `json:"ciphertext"` // base64
}

// ProvisioningBundle is the configuration delivered to a device. Modules are
// processed independently; unknown module types must be skipped, not fail the
// whole provisioning.
type ProvisioningBundle struct {
	ProtocolVersion string    `json:"protocol_version"`
	DeviceID        string    `json:"device_id"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at,omitempty"`
	Modules         []Module  `json:"modules"`
}

// Module is one piece of configuration. Type uniquely identifies a handler
// (e.g. "wifi.v2", "ssh.authorized_keys.v2"). Payload is opaque JSON whose
// schema is defined by the handler.
//
// RawPayload, if non-nil, is used verbatim as the module's payload bytes
// (still base64-encoded into the manifest line). It exists to support
// non-JSON payload formats — e.g. wifi.v2 ships an INI document so the
// applier needs no JSON parser. When RawPayload is set, Payload is ignored
// and need not be valid JSON-shaped data.
//
// Sealed, if non-nil, replaces Payload/RawPayload with an end-to-end-encrypted
// ciphertext addressed to the device's ephemeral X25519 key. The server
// populates this for modules that carry secrets the server itself should not
// retain in plaintext logs/audit/SQLite (e.g. a Cumulocity enrollment token).
// The agent decrypts before dispatching to the applier; everything downstream
// of the dispatcher behaves as if the module had been delivered in the clear.
//
// Sensitive is a server-side hint, not part of the wire format. Providers set
// it on modules that contain secrets so the engine knows to seal them before
// signing the bundle. It is intentionally json-omitted because once the engine
// has sealed the payload there is nothing for the wire-format reader to do
// with this flag.
type Module struct {
	Type       string         `json:"type"`
	Payload    map[string]any `json:"payload,omitempty"`
	Sealed     *SealedPayload `json:"sealed,omitempty"`
	RawPayload []byte         `json:"raw_payload,omitempty"`
	Sensitive  bool           `json:"-"`
}

// SealedPayload is a per-module ciphertext addressed to the device's ephemeral
// X25519 key (EnrollRequest.EphemeralX25519). It uses the same primitive as
// EncryptedPayload (X25519 + ChaCha20-Poly1305) but lives inside a Module so a
// single bundle can mix sealed and clear modules. Format describes how the
// agent should treat the decrypted bytes: "json" → unmarshal into the
// module's Payload map; "raw" → hand directly to the applier as RawPayload.
type SealedPayload struct {
	Algorithm    string `json:"alg"`           // "x25519-chacha20poly1305"
	EphemeralPub string `json:"ephemeral_pub"` // base64 X25519 pub the agent uses for ECDH
	Nonce        string `json:"nonce"`         // base64 12 bytes
	Ciphertext   string `json:"ciphertext"`    // base64
	Format       string `json:"format"`        // "json" | "raw"
}

// Acknowledgement is sent by the device after applying (or failing to apply)
// a bundle, to close the loop with the server.
type Acknowledgement struct {
	ProtocolVersion string         `json:"protocol_version"`
	DeviceID        string         `json:"device_id"`
	BundleIssuedAt  time.Time      `json:"bundle_issued_at"`
	Results         []ModuleResult `json:"results"`
}

// ModuleResult is the per-module outcome of applying a bundle.
type ModuleResult struct {
	Type    string `json:"type"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"` // true when no applier handled the type
	Error   string `json:"error,omitempty"`
	Output  string `json:"output,omitempty"`
}
