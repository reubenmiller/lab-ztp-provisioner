// Package discovery defines the shared wire types and topic helpers used by
// Zenoh-based (and future) discovery transports.
//
// The ZTP discovery flow:
//
//  1. An unprovisioned agent opens its preferred discovery transport and
//     publishes a BeaconPayload to the RequestTopic for its device ID.
//
//  2. The ZTP server subscribes to RequestWildcard, surfaces each beacon in
//     the admin UI as a "Pending" device, and waits for an operator decision.
//
//  3. When an operator approves a device the server publishes an
//     ApprovalPayload carrying the server's HTTPS URL to ApproveTopic.
//
//  4. The agent receives the approval, switches to the standard HTTPS
//     enrollment flow (POST /v1/enroll) using the supplied URL, and the
//     existing trust chain (known_keypair verifier) issues the bundle.
//
// No provisioning secrets travel over the discovery topics.  The initial
// BeaconPayload is unencrypted — treat the Zenoh router as untrusted.
// Sensitive module payloads are sealed by the enrollment engine to the
// device's ephemeral X25519 key before they ever leave the server.
package discovery

import (
	"fmt"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

const topicPrefix = "ztp/discovery"

// RequestWildcard is the Zenoh key expression the server subscribes to in
// order to detect all unprovisioned devices.
const RequestWildcard = topicPrefix + "/request/*"

// RequestTopic returns the Zenoh key expression on which the agent with the
// given id publishes its discovery beacon.
func RequestTopic(deviceID string) string {
	return fmt.Sprintf("%s/request/%s", topicPrefix, deviceID)
}

// ApproveTopic returns the Zenoh key expression on which the server publishes
// the approval notification for the device with the given id.
func ApproveTopic(deviceID string) string {
	return fmt.Sprintf("%s/approve/%s", topicPrefix, deviceID)
}

// BeaconPayload is the JSON-encoded message an unprovisioned agent publishes
// to announce itself.  It carries enough metadata for an operator to identify
// the device and decide whether to approve it.
//
// The payload purposefully contains no secrets — treat it as public.
type BeaconPayload struct {
	DeviceID   string               `json:"device_id"`
	PublicKey  string               `json:"public_key"` // base64 Ed25519 public key
	Facts      protocol.DeviceFacts `json:"facts"`
	Transports []string             `json:"transports,omitempty"` // preferred transports, e.g. ["lan","ble"]
	Metadata   map[string]string    `json:"metadata,omitempty"`
	IssuedAt   time.Time            `json:"issued_at"`
}

// ApprovalPayload is the JSON-encoded message the server publishes after an
// operator approves a pending device.  It carries the server HTTPS URL the
// agent should use for the subsequent standard enrollment call.
type ApprovalPayload struct {
	DeviceID  string    `json:"device_id"`
	ServerURL string    `json:"server_url"`
	IssuedAt  time.Time `json:"issued_at"`
}
