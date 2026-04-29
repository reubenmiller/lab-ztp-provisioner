package server

import (
	"encoding/base64"
	"encoding/json"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// decodePayload extracts the EnrollRequest from a SignedEnvelope WITHOUT
// verifying the signature. Callers must verify before trusting the result;
// this exists so the engine can read the device's claimed public key in order
// to feed it back into Verify.
func decodePayload(env *protocol.SignedEnvelope) (*protocol.EnrollRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, err
	}
	var req protocol.EnrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func unmarshalCanonical(b []byte, v any) error {
	return json.Unmarshal(b, v)
}
