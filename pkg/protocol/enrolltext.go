package protocol

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// The text rendering of an EnrollResponse: one `key=value` record per line,
// for devices without a JSON parser (the POSIX shell agent over HTTP via
// `Accept: text/plain`, and constrained BLE devices via
// EnrollRequest.ResponseFormat = "text").
//
//	protocol_version=1
//	status=accepted
//	reason=...            (optional)
//	retry_after=<secs>    (optional)
//	server_time=<RFC3339> (optional)
//	bundle.alg=... / bundle.key_id=... / bundle.payload=... / bundle.signature=...
//	manifest.alg=... / manifest.key_id=... / manifest.payload=... / manifest.signature=...
//	encrypted.alg=... / encrypted.server_key=... / encrypted.nonce=... / encrypted.ciphertext=...
//
// Readers must ignore keys they do not know, so records can be added.
//
// When the device asked for an encrypted bundle, only the encrypted.* records
// are present, and for a text-format request the decrypted plaintext is the
// manifest.* records of MarshalEnvelopeText — the same lines the device would
// otherwise have read in the clear, so it needs one parser for both cases.

// MarshalEnrollText renders resp in the text format. It is what the HTTP
// transport writes, and what the server measures against
// EnrollRequest.MaxResponseBytes for a text-format request.
func MarshalEnrollText(resp *EnrollResponse) []byte {
	var buf bytes.Buffer
	writeKV(&buf, "protocol_version", resp.ProtocolVersion)
	writeKV(&buf, "status", string(resp.Status))
	if resp.Reason != "" {
		writeKV(&buf, "reason", resp.Reason)
	}
	if resp.RetryAfter > 0 {
		writeKV(&buf, "retry_after", strconv.Itoa(resp.RetryAfter))
	}
	if resp.ServerTime != nil {
		writeKV(&buf, "server_time", resp.ServerTime.UTC().Format("2006-01-02T15:04:05Z"))
	}
	if resp.Bundle != nil {
		buf.Write(MarshalEnvelopeText("bundle", resp.Bundle))
	}
	if resp.TextManifest != nil {
		buf.Write(MarshalEnvelopeText("manifest", resp.TextManifest))
	}
	if resp.EncryptedBundle != nil {
		writeKV(&buf, "encrypted.alg", resp.EncryptedBundle.Algorithm)
		writeKV(&buf, "encrypted.server_key", resp.EncryptedBundle.ServerKey)
		writeKV(&buf, "encrypted.nonce", resp.EncryptedBundle.Nonce)
		writeKV(&buf, "encrypted.ciphertext", resp.EncryptedBundle.Ciphertext)
	}
	return buf.Bytes()
}

// MarshalEnvelopeText renders a SignedEnvelope as `<prefix>.alg=…`,
// `<prefix>.key_id=…`, `<prefix>.payload=…` and `<prefix>.signature=…` lines.
func MarshalEnvelopeText(prefix string, env *SignedEnvelope) []byte {
	var buf bytes.Buffer
	writeKV(&buf, prefix+".alg", env.Algorithm)
	writeKV(&buf, prefix+".key_id", env.KeyID)
	writeKV(&buf, prefix+".payload", env.Payload)
	writeKV(&buf, prefix+".signature", env.Signature)
	return buf.Bytes()
}

// ParseEnrollStatus extracts status, reason and retry_after from an enroll
// response body in either rendering. A relay forwards the body to the device
// verbatim, but needs these three fields to hold a pending device while an
// operator decides — and the device, not the relay, chose the rendering.
//
// status is "" when the body is neither form.
func ParseEnrollStatus(body []byte) (status, reason string, retryAfter int) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var parsed struct {
			Status     string `json:"status"`
			Reason     string `json:"reason"`
			RetryAfter int    `json:"retry_after"`
		}
		_ = json.Unmarshal(trimmed, &parsed)
		return parsed.Status, parsed.Reason, parsed.RetryAfter
	}
	for line := range strings.SplitSeq(string(trimmed), "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "=")
		if !ok {
			continue
		}
		switch k {
		case "status":
			status = v
		case "reason":
			reason = unescapeTextValue(v)
		case "retry_after":
			retryAfter, _ = strconv.Atoi(v)
		}
	}
	return status, reason, retryAfter
}

// writeKV writes one record, escaping CR/LF so each stays on one line.
func writeKV(buf *bytes.Buffer, k, v string) {
	buf.WriteString(k)
	buf.WriteByte('=')
	buf.WriteString(escapeTextValue(v))
	buf.WriteByte('\n')
}

func unescapeTextValue(v string) string {
	return strings.NewReplacer(`\n`, "\n", `\r`, "\r").Replace(v)
}
