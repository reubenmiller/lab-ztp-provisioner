//go:build ble

package desktop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/transport/ble"
)

// bleProgressEvent is the Wails event name the SPA listens for to
// drive the on-screen status state machine. Constant kept here (and
// referenced from web/src/lib/ble/wails.ts) so a rename is a one-grep
// change across both sides.
const bleProgressEvent = "ble:progress"

// blePendingEvent fires once when the server returns "pending" for the
// in-flight BLE enrollment, before the binding starts polling for the
// approval verdict. The SPA uses it to render the inline approve / reject
// card for a relay that is still holding the BLE session open.
const blePendingEvent = "ble:pending"

// BlePending is the payload of blePendingEvent. devicePublicKey is the
// key to look up the matching record in /v1/admin/pending.
type BlePending struct {
	DeviceID        string `json:"deviceId,omitempty"`
	DevicePublicKey string `json:"devicePublicKey,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// blePendingPollInterval is how often we re-check /v1/enroll/status while
// holding the BLE connection open during operator approval. It matches
// the server's RetryAfter advisory; the polling loop honours whatever
// the server says if it differs.
const blePendingPollInterval = 2 * time.Second

// blePendingMaxWait caps how long we keep a BLE session alive waiting for
// the operator to approve. Five minutes is comfortably more than any
// realistic approval workflow (operator clicks Approve from the inline
// card or the Pending tab) and well within BlueZ / CoreBluetooth's idle
// connection tolerance.
const blePendingMaxWait = 5 * time.Minute

// BleProgress mirrors ble.ProgressFn's (phase, detail) over the wire.
// Emitted as a single struct event so the SPA gets typed JSON with
// no string parsing.
type BleProgress struct {
	Phase  string `json:"phase"`
	Detail string `json:"detail,omitempty"`
}

// BleSupported reports that this binary was compiled with -tags ble
// and a native BLE central is available. The SPA reads this via the
// capabilities list (see GetRuntimeInfo) rather than calling it
// directly, but the explicit boolean is here for completeness.
func (a *App) BleSupported() bool { return true }

// BleEnrollResult is the outcome of a single BLE onboarding attempt.
// Fields mirror the EnrollResponse the server returns on the wire so
// the SPA can render a consistent message regardless of which
// transport got there. BundleDelivered=true means the device already
// has its provisioning bundle and the enrollment is complete from the
// device's perspective; if false (pending or rejected), no bundle was
// written back and the device is still waiting / will time out.
type BleEnrollResult struct {
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
	DeviceID        string `json:"deviceId,omitempty"`
	DevicePublicKey string `json:"devicePublicKey,omitempty"`
	BundleDelivered bool   `json:"bundleDelivered"`
	EnvelopeBytes   int    `json:"envelopeBytes"`
	BundleBytes     int    `json:"bundleBytes,omitempty"`
}

// BleEnroll runs a single onboarding attempt against the first ZTP
// peripheral the OS surfaces. Steps:
//
//  1. Scan up to scanTimeoutMs (default 20s) for ServiceUUID.
//  2. Connect, do the trigger-and-receive exchange (see ble.Enroll).
//  3. POST the envelope to the in-process server's /v1/enroll.
//  4. If status=accepted: write the bundle back to the device,
//     disconnect, return.
//  5. If status=pending: HOLD the BLE connection open and poll
//     /v1/enroll/status until the operator approves (or rejects /
//     timeout). Once accepted, re-POST the same envelope (the nonce
//     is forgotten while the request was queued for approval) to
//     retrieve the bundle, then write it back without scanning or
//     reconnecting. This avoids the ~30s of CoreBluetooth /
//     CBPeripheral cool-down that a disconnect-and-reconnect cycle
//     would otherwise impose on every approval.
//
// The function can block for up to scanTimeout + blePendingMaxWait,
// which is dominated by the approval window. Wails marshals errors
// as rejected JS promises; the SPA shows progress events throughout.
func (a *App) BleEnroll(scanTimeoutMs int) (BleEnrollResult, error) {
	if a.handle == nil {
		return BleEnrollResult{}, errors.New("desktop runtime not initialised")
	}
	scanTimeout := time.Duration(scanTimeoutMs) * time.Millisecond
	if scanTimeout <= 0 {
		scanTimeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout+blePendingMaxWait+90*time.Second)
	defer cancel()

	enrollURL := a.handle.BaseURL + "/v1/enroll"
	statusURL := a.handle.BaseURL + "/v1/enroll/status"
	// Let per-request contexts govern deadline/cancellation. Using the same
	// 30s client timeout as the server masks accepted-path engine failures
	// (for example a downstream issuer timing out) with a local
	// "Client.Timeout exceeded" before the server can send its 500 response.
	httpClient := &http.Client{}

	// progress fires a Wails event on every ble.Enroll milestone. The
	// SPA's onMount subscribes via wruntime.EventsOn (in-webview JS)
	// and updates the UI state accordingly. ctx may be nil if the
	// Wails app hasn't fully started — drop events silently in that
	// case rather than crashing.
	progress := func(phase, detail string) {
		appCtx := a.Context()
		if appCtx == nil {
			return
		}
		wruntime.EventsEmit(appCtx, bleProgressEvent, BleProgress{Phase: phase, Detail: detail})
	}

	res := BleEnrollResult{}
	flow, err := ble.Enroll(ctx, scanTimeout, progress, func(envelope []byte) ([]byte, error) {
		res.EnvelopeBytes = len(envelope)
		// Surface device-id / public-key from the envelope payload —
		// best-effort UI sugar, parse failures don't abort.
		id, pubkey := extractDeviceFields(envelope)
		if id != "" || pubkey != "" {
			res.DeviceID = id
			res.DevicePublicKey = pubkey
		}
		bundle, status, reason, err := submitEnroll(ctx, httpClient, enrollURL, envelope)
		if err != nil {
			return nil, err
		}
		res.Status = status
		res.Reason = reason
		switch status {
		case "accepted":
			res.BundleBytes = len(bundle)
			return bundle, nil
		case "rejected":
			// Don't write back — return empty so the BLE session
			// closes cleanly and the SPA renders the rejection.
			return nil, nil
		case "pending":
			// Hold the connection; poll until the approval verdict.
			progress("pending", reason)
			if appCtx := a.Context(); appCtx != nil {
				wruntime.EventsEmit(appCtx, blePendingEvent, BlePending{
					DeviceID:        id,
					DevicePublicKey: pubkey,
					Reason:          reason,
				})
			}
			if pubkey == "" {
				return nil, fmt.Errorf("pending response missing device public key — cannot poll status")
			}
			finalBundle, finalStatus, finalReason, err := waitForApproval(ctx, httpClient, statusURL, enrollURL, pubkey, envelope, progress)
			if err != nil {
				return nil, err
			}
			res.Status = finalStatus
			res.Reason = finalReason
			if finalStatus != "accepted" {
				return nil, nil
			}
			res.BundleBytes = len(finalBundle)
			return finalBundle, nil
		default:
			return nil, fmt.Errorf("unexpected enroll status %q", status)
		}
	})
	if err != nil {
		return res, err
	}
	res.BundleDelivered = len(flow.BundleBytes) > 0
	return res, nil
}

// waitForApproval polls /v1/enroll/status while the operator decides.
// On approval, it re-POSTs the original envelope to /v1/enroll once
// to fetch the signed bundle. On rejection or context cancellation,
// it returns the latest status and an empty bundle so the caller can
// surface the verdict and let ble.Enroll close the link cleanly.
//
// Polling rather than a wake-channel: the operator may approve from
// the inline BLE card OR from the Pending tab OR from another
// browser session entirely; the server is the authoritative state
// holder, so /v1/enroll/status is the simplest way to observe it
// without coupling the BLE binding to the admin API internals.
func waitForApproval(ctx context.Context, c *http.Client, statusURL, enrollURL, pubkey string, envelope []byte, progress ble.ProgressFn) ([]byte, string, string, error) {
	deadline := time.Now().Add(blePendingMaxWait)
	interval := blePendingPollInterval
	statusQuery := statusURL + "?pubkey=" + url.QueryEscape(pubkey)
	for {
		if time.Now().After(deadline) {
			return nil, "pending", "approval timeout — operator did not respond within " + blePendingMaxWait.String(), nil
		}
		select {
		case <-ctx.Done():
			return nil, "pending", "cancelled", ctx.Err()
		case <-time.After(interval):
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusQuery, nil)
		if err != nil {
			return nil, "", "", fmt.Errorf("build status request: %w", err)
		}
		resp, err := c.Do(req)
		if err != nil {
			// Transient HTTP failures (e.g. engine restart mid-poll)
			// shouldn't kill the BLE session — log via progress and
			// keep polling until the deadline.
			progress("pending", "status poll failed: "+err.Error())
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var parsed struct {
			Status     string `json:"status"`
			Reason     string `json:"reason"`
			RetryAfter int    `json:"retry_after"`
		}
		_ = json.Unmarshal(body, &parsed)
		if parsed.RetryAfter > 0 {
			interval = time.Duration(parsed.RetryAfter) * time.Second
		}
		switch parsed.Status {
		case "accepted":
			// Re-POST the original envelope; the nonce was forgotten
			// when the request was queued for approval, so this goes
			// through and returns the signed bundle.
			progress("submitting", "approval received — fetching bundle")
			bundle, status2, reason2, err := submitEnroll(ctx, c, enrollURL, envelope)
			if err != nil {
				return nil, "", "", fmt.Errorf("re-submit after approval: %w", err)
			}
			if status2 != "accepted" {
				return nil, status2, reason2, nil
			}
			return bundle, status2, reason2, nil
		case "rejected":
			return nil, "rejected", parsed.Reason, nil
		case "pending":
			// continue polling
		default:
			progress("pending", "unexpected status from server: "+parsed.Status)
		}
	}
}

// submitEnroll POSTs the envelope to the local enroll endpoint and
// returns the response bytes plus the parsed status/reason. The
// envelope is authoritative-bytes; we don't re-encode it.
func submitEnroll(ctx context.Context, c *http.Client, url string, envelope []byte) ([]byte, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(envelope))
	if err != nil {
		return nil, "", "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", "", fmt.Errorf("post /v1/enroll: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", "", fmt.Errorf("read body: %w", err)
	}
	// 200=accepted, 202=pending, 403=rejected — the body still parses
	// either way (it's an EnrollResponse JSON). Hand body back as the
	// "bundle" only when we'll actually write it; for pending/rejected
	// the caller short-circuits.
	var parsed struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &parsed)
	if parsed.Status == "" {
		// Server didn't speak the protocol — surface as a hard error.
		return nil, "", "", fmt.Errorf("/v1/enroll: %s: %s", resp.Status, string(body))
	}
	return body, parsed.Status, parsed.Reason, nil
}

// extractDeviceFields peeks at the envelope's signed payload to pull
// out device_id and public_key for display. Parse failures are not
// fatal — the caller treats both fields as best-effort.
func extractDeviceFields(envelope []byte) (id, pubkey string) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(envelope, &env); err != nil || env.Payload == "" {
		return "", ""
	}
	// The payload is base64'd canonical JSON. We only need a best-
	// effort decode — leave the heavy validation to the engine.
	dec, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		// Try URL-safe encoding which the agent may use.
		dec, err = base64.RawURLEncoding.DecodeString(env.Payload)
		if err != nil {
			return "", ""
		}
	}
	var inner struct {
		DeviceID  string `json:"device_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(dec, &inner); err != nil {
		return "", ""
	}
	return inner.DeviceID, inner.PublicKey
}
