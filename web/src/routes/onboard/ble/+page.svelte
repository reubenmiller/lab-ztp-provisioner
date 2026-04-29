<script lang="ts">
  // Web Bluetooth bridge: an operator running the admin UI on a Chrome/Edge
  // browser can scan for nearby devices advertising the ZTP service UUID,
  // connect to one, pull its signed EnrollRequest envelope over GATT, and
  // forward it to the server's /v1/enroll endpoint. The signed response is
  // then chunked back over the same characteristics so the device can verify
  // and apply the manifest.
  //
  // This works without any native code or BLE hardware on the server — the
  // operator's browser is the relay. Because the envelope is signed by the
  // device's own keypair end-to-end, the browser never sees plaintext secrets
  // and cannot forge enrollments.
  //
  // Limitations: Web Bluetooth is Chromium-only. Safari and Firefox do not
  // expose it. iOS does not at all. The page checks for support at load and
  // shows guidance otherwise.

  import { onMount } from 'svelte';
  import { api, type ServerInfo, type PendingRequest, type ProfileSummary } from '$lib/api';
  import { detect, hasCapability, type RuntimeInfo } from '$lib/runtime';

  let info = $state<ServerInfo | null>(null);
  let infoErr = $state<string | null>(null);
  let profiles = $state<ProfileSummary[]>([]);
  let selectedProfile = $state<string>('');
  // nativeBle is true when the desktop binary advertises the native
  // BLE central binding. We prefer it over Web Bluetooth because it
  // works on Safari / Firefox / no-Chromium hosts and bypasses the
  // browser's permission UX (operator just clicks "Scan & relay" and
  // the OS BLE stack does its thing). When false the Web Bluetooth
  // fallback is used unchanged.
  let nativeBle = $state(false);

  onMount(async () => {
    try {
      const rt = await detect();
      nativeBle = hasCapability(rt, 'ble.central.native');
    } catch { /* fall back to web bluetooth */ }
    try {
      info = await api.serverInfo();
    } catch (e: any) {
      infoErr = e.message;
    }
    try {
      profiles = await api.profiles();
    } catch {
      profiles = [];
    }
  });

  const pubkey = $derived(info?.public_key ?? '<paste server pubkey here>');
  const deviceCmd = $derived(
    `ztp-agent-ble \\\n  -transport ble \\\n  -server-pubkey "${pubkey}" \\\n  -device-id "$(cat /etc/machine-id)" \\\n  -identity /var/lib/ztp/identity.key \\\n  -appliers /etc/ztp/appliers.d`
  );

  function copy(s: string) {
    navigator.clipboard?.writeText(s);
  }

  // Service / characteristic UUIDs MUST match internal/transport/ble/doc.go.
  const SERVICE_UUID = '6e400001-b5a3-f393-e0a9-e50e24dcca9e';
  const REQUEST_UUID = '6e400002-b5a3-f393-e0a9-e50e24dcca9e';
  const RESPONSE_UUID = '6e400003-b5a3-f393-e0a9-e50e24dcca9e';
  const STATUS_UUID = '6e400004-b5a3-f393-e0a9-e50e24dcca9e';
  // The relay writes the current wall-clock time (RFC3339 UTC) to
  // TIME_SYNC_UUID before kicking off enrollment. The device uses this to
  // correct its local clock offset so the EnrollRequest timestamp passes the
  // server's skew check on devices that haven't run NTP yet (very common on
  // first boot — clocks default to 1970-01-01).
  const TIME_SYNC_UUID = '6e400005-b5a3-f393-e0a9-e50e24dcca9e';

  type Step =
    | { kind: 'idle' }
    | { kind: 'scanning' }
    | { kind: 'connected'; deviceName: string }
    | { kind: 'reading' }
    | { kind: 'relaying' }
    | { kind: 'pending'; reason: string }
    | { kind: 'writing' }
    | { kind: 'delivering'; detail: string }
    | { kind: 'done'; deviceId: string }
    | { kind: 'error'; message: string };

  let step = $state<Step>({ kind: 'idle' });
  let log = $state<string[]>([]);
  let pendingRecord = $state<PendingRequest | null>(null);
  let approving = $state(false);
  // deliveringBundle is true between approve and the bundle landing on the
  // device. Under the hood the relay still has to scan + reconnect because
  // the previous BLE session was torn down at the pending verdict, but the
  // operator already approved a known device — surfacing "scanning" again
  // reads like fresh discovery and confuses people. While this flag is on,
  // every progress phase is folded into one "Delivering bundle" step with
  // a sub-detail line.
  let deliveringBundle = $state(false);
  const webBluetooth = typeof navigator !== 'undefined' && 'bluetooth' in navigator;
  // supported is derived: native BLE wins when advertised, otherwise
  // fall back to Web Bluetooth. Both being unavailable shows the
  // unsupported-browser guidance card.
  const supported = $derived(nativeBle || webBluetooth);
  const isIOS = typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent);

  // wakeRelay lets the inline Approve/Reject buttons short-circuit the poll
  // delay without navigating away (which would close the BLE connection).
  let wakeRelay: { resolve: () => void; reject: (reason: any) => void } | null = null;

  function logLine(s: string) {
    log = [...log, `${new Date().toLocaleTimeString()}  ${s}`];
  }

  async function fetchPendingRecord(pubkey: string): Promise<PendingRequest | null> {
    try {
      const all = await api.pending();
      return all.find(p => p.public_key === pubkey) ?? null;
    } catch { return null; }
  }

  async function approveInline() {
    if (!pendingRecord || approving) return;
    approving = true;
    try {
      await api.approve(pendingRecord.id, selectedProfile || undefined);
      logLine(`approved ${pendingRecord.device_id}`);
      pendingRecord = null;
      if (wakeRelay) {
        // Web Bluetooth flow: the relay's polling loop is parked on
        // wakeRelay; resolve it so the existing GATT connection
        // re-submits the envelope without scanning again.
        wakeRelay.resolve();
      } else if (nativeBle) {
        // Native flow: BleEnroll is still running on the Go side and
        // already polling /v1/enroll/status while holding the BLE
        // session open. The api.approve call above flips the server
        // state to accepted, the binding's poll picks it up within
        // a couple of seconds, re-POSTs the envelope to fetch the
        // bundle, and writes it over the existing GATT connection.
        // No reconnect / no scan / no cool-down. Just transition the
        // visible status so the page reflects what's about to happen.
        deliveringBundle = true;
        step = { kind: 'delivering', detail: 'fetching bundle…' };
      }
    } catch (e: any) {
      logLine(`error approving: ${e.message}`);
    } finally {
      approving = false;
    }
  }

  async function rejectInline() {
    if (!pendingRecord || approving) return;
    approving = true;
    try {
      await api.reject(pendingRecord.id);
      logLine(`rejected ${pendingRecord.device_id}`);
      pendingRecord = null;
      if (wakeRelay) {
        wakeRelay.reject(new Error('enrollment rejected by operator'));
      }
      // Native flow: BleEnroll's polling loop will see the rejection
      // verdict on its next /v1/enroll/status hit and return, which
      // surfaces as the 'rejected' branch in nativeRelay below. The
      // SPA doesn't need to drive the step transition itself.
    } catch (e: any) {
      logLine(`error rejecting: ${e.message}`);
    } finally {
      approving = false;
    }
  }

  // ----- BLE framing helpers -----
  // Each fragment is [u16 BE length][payload]. A fragment with length 0 marks
  // end-of-message. Matches the Go implementation exactly.
  const FRAG = 180;

  function frame(payload: Uint8Array): Uint8Array[] {
    const out: Uint8Array[] = [];
    for (let i = 0; i < payload.length; i += FRAG) {
      const chunk = payload.subarray(i, Math.min(i + FRAG, payload.length));
      const buf = new Uint8Array(2 + chunk.length);
      new DataView(buf.buffer).setUint16(0, chunk.length, false);
      buf.set(chunk, 2);
      out.push(buf);
    }
    out.push(new Uint8Array([0, 0])); // EOM
    return out;
  }

  // wailsEventsOn is Wails' in-webview event subscription helper.
  // window.runtime is injected by Wails at JS context startup; the
  // signature here matches the v2 runtime API we need.
  type WailsEventCallback = (data: unknown) => void;
  type WailsRuntime = {
    EventsOn?: (event: string, cb: WailsEventCallback) => () => void;
  };
  function wailsEventsOn(event: string, cb: WailsEventCallback): (() => void) | null {
    const rt = (window as unknown as { runtime?: WailsRuntime }).runtime;
    if (!rt?.EventsOn) return null;
    return rt.EventsOn(event, cb);
  }

  // applyBleProgress maps the Go-side phase strings (see
  // internal/transport/ble/central.go Phase* constants) into the
  // existing Step state machine plus a log line. New phases land
  // in the default branch as a logLine without breaking the UI.
  //
  // When deliveringBundle is true (post-approval auto-restart),
  // every phase is folded into the 'delivering' step with a
  // descriptive sub-detail, so the operator sees one continuous
  // "Delivering bundle… reconnecting / sending / writing" instead
  // of the underlying scan-connect-trigger-relay-write sequence.
  function applyBleProgress(p: { phase: string; detail?: string }) {
    const detail = p.detail ?? '';
    if (deliveringBundle) {
      switch (p.phase) {
        case 'scanning':
          step = { kind: 'delivering', detail: 'reconnecting to device…' };
          logLine('reconnecting to device…');
          return;
        case 'connected':
          step = { kind: 'delivering', detail: `reconnected to ${detail || 'device'}` };
          logLine(`reconnected to ${detail || 'device'}`);
          return;
        case 'time-sync':
          logLine(`sent time sync: ${detail}`);
          return;
        case 'trigger':
          step = { kind: 'delivering', detail: 'requesting fresh envelope…' };
          logLine('requesting fresh envelope from device…');
          return;
        case 'envelope-read':
          logLine(`envelope received (${detail})`);
          return;
        case 'submitting':
          step = { kind: 'delivering', detail: 'forwarding to server…' };
          logLine('forwarding envelope to /v1/enroll…');
          return;
        case 'writing-bundle':
          step = { kind: 'delivering', detail: `writing bundle (${detail})` };
          logLine(`writing bundle to device (${detail})`);
          return;
        case 'done':
          logLine('flow complete');
          return;
        default:
          logLine(`ble: ${p.phase}${detail ? ' — ' + detail : ''}`);
          return;
      }
    }
    switch (p.phase) {
      case 'scanning':
        step = { kind: 'scanning' };
        logLine('scanning for ZTP peripheral…');
        return;
      case 'connected':
        step = { kind: 'connected', deviceName: detail || '(unknown)' };
        logLine(`connected to ${detail || 'device'}`);
        return;
      case 'time-sync':
        logLine(`sent time sync: ${detail}`);
        return;
      case 'trigger':
        step = { kind: 'reading' };
        logLine('triggered device, waiting for envelope…');
        return;
      case 'envelope-read':
        logLine(`envelope received (${detail})`);
        return;
      case 'submitting':
        step = { kind: 'relaying' };
        logLine('forwarding envelope to /v1/enroll…');
        return;
      case 'writing-bundle':
        step = { kind: 'writing' };
        logLine(`writing bundle to device (${detail})`);
        return;
      case 'done':
        // Final step is set by the binding's return value (which
        // also carries the deviceId); just log here.
        logLine('flow complete');
        return;
      default:
        logLine(`ble: ${p.phase}${detail ? ' — ' + detail : ''}`);
    }
  }

  // nativeRelay invokes the desktop binary's BleEnroll Wails binding.
  // Progress is streamed via the "ble:progress" event fired by the
  // binding; the final {status, deviceId, …} return value drives the
  // terminal Step (done/pending/rejected/error).
  type BleResult = {
    status: string;
    reason?: string;
    deviceId?: string;
    devicePublicKey?: string;
    bundleDelivered: boolean;
    envelopeBytes: number;
    bundleBytes?: number;
  };

  async function nativeRelay() {
    const w = window as unknown as { go?: { desktop?: { App?: { BleEnroll?: (timeoutMs: number) => Promise<BleResult> } } } };
    const fn = w.go?.desktop?.App?.BleEnroll;
    if (!fn) {
      step = { kind: 'error', message: 'native BLE binding not available' };
      return;
    }
    const off = wailsEventsOn('ble:progress', (data) => {
      applyBleProgress(data as { phase: string; detail?: string });
    });
    // The native binding now holds the BLE session open during the
    // "pending" verdict and polls /v1/enroll/status until approval —
    // it fires ble:pending once with the structured device record so
    // the SPA can render the inline approve/reject card without
    // BleEnroll having returned yet. After approval the binding
    // re-POSTs the envelope, fetches the bundle, and writes it over
    // the same GATT connection. So we only see the BleEnroll promise
    // resolve at the terminal verdict.
    const offPending = wailsEventsOn('ble:pending', (data) => {
      const p = data as { deviceId?: string; devicePublicKey?: string; reason?: string };
      step = { kind: 'pending', reason: p.reason ?? 'awaiting manual approval' };
      logLine(`Server: pending — ${p.reason ?? 'awaiting approval'}. Approve below or in the Pending tab.`);
      if (p.devicePublicKey) {
        fetchPendingRecord(p.devicePublicKey).then((rec) => { pendingRecord = rec; });
      }
    });
    try {
      if (!deliveringBundle) {
        step = { kind: 'scanning' };
      }
      const r = await fn(20000);
      logLine(`Native BLE returned: status=${r.status} envelopeBytes=${r.envelopeBytes} bundleDelivered=${r.bundleDelivered}`);
      if (r.status === 'accepted' && r.bundleDelivered) {
        step = { kind: 'done', deviceId: r.deviceId ?? '(unknown)' };
        return;
      }
      if (r.status === 'pending') {
        // BleEnroll only returns "pending" when its internal approval
        // wait timed out (default 5min) without an operator verdict.
        // Surface as an error with a clear next step.
        step = { kind: 'error', message: r.reason ?? 'approval window timed out' };
        logLine('Approval window timed out — click Scan & relay to start over.');
        return;
      }
      if (r.status === 'rejected') {
        step = { kind: 'error', message: `rejected: ${r.reason ?? '(no reason)'}` };
        return;
      }
      step = { kind: 'error', message: `unexpected status: ${r.status}` };
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      logLine(`error: ${msg}`);
      step = { kind: 'error', message: msg };
    } finally {
      // Unsubscribe so a second click of Scan & relay doesn't double-
      // fire UI updates from a stale listener still wired to the
      // previous attempt. The recursive autoRetry call above unsubscribes
      // before recursing so this finally is a no-op in that path.
      off?.();
      offPending?.();
      deliveringBundle = false;
    }
  }

  async function relay() {
    if (nativeBle) return nativeRelay();
    if (!webBluetooth) return;
    try {
      step = { kind: 'scanning' };
      logLine('Requesting device with ZTP service…');
      // requestDevice MUST be called from a user gesture (the click handler
      // satisfies that). We pass acceptAllDevices: false + a service filter
      // so the chooser only lists ZTP-advertising peripherals.
      const dev = await navigator.bluetooth.requestDevice({
        filters: [{ services: [SERVICE_UUID] }],
      });
      logLine(`Selected: ${dev.name ?? '(unnamed)'} ${dev.id}`);
      step = { kind: 'connected', deviceName: dev.name ?? dev.id };

      const server = await dev.gatt!.connect();
      logLine('GATT connected');
      const svc = await server.getPrimaryService(SERVICE_UUID);
      const reqCh = await svc.getCharacteristic(REQUEST_UUID);
      const respCh = await svc.getCharacteristic(RESPONSE_UUID);
      const statCh = await svc.getCharacteristic(STATUS_UUID);

      // Sync the device's clock BEFORE it builds its EnrollRequest. Many
      // first-boot devices have no NTP yet and would otherwise stamp the
      // request with 1970-01-01, blowing past the server's clock_skew window.
      // We write our current wall-clock time as RFC3339 UTC; the device adds
      // the offset to time.Now() when constructing the timestamp. The
      // characteristic is optional on older device builds — silently skip if
      // it's not present.
      try {
        const timeSyncCh = await svc.getCharacteristic(TIME_SYNC_UUID);
        const nowIso = new Date().toISOString();
        await timeSyncCh.writeValueWithoutResponse(new TextEncoder().encode(nowIso));
        logLine(`Sent time sync: ${nowIso}`);
      } catch (e: any) {
        logLine(`time sync skipped (device may predate this feature): ${e.message ?? e}`);
      }

      // Subscribe to status + response notifications BEFORE poking the device
      // so we don't miss the early bytes.
      const responseBytes: number[] = [];
      const eom = new Promise<void>((resolve, reject) => {
        respCh.addEventListener('characteristicvaluechanged', (ev) => {
          const v = (ev.target as BluetoothRemoteGATTCharacteristic).value!;
          if (v.byteLength < 2) return;
          const n = v.getUint16(0, false);
          if (n === 0) {
            resolve();
            return;
          }
          for (let i = 0; i < n; i++) responseBytes.push(v.getUint8(2 + i));
        });
        setTimeout(() => reject(new Error('timeout waiting for device response')), 60000);
      });
      await respCh.startNotifications();
      await statCh.startNotifications();
      statCh.addEventListener('characteristicvaluechanged', (ev) => {
        const v = (ev.target as BluetoothRemoteGATTCharacteristic).value!;
        const code = v.getUint8(0);
        const label = ['idle', 'relaying', 'done', 'error'][code] ?? `unknown(${code})`;
        logLine(`device status → ${label}`);
      });

      // Kick the device into building its enrollment envelope by writing an
      // empty EOM. The peripheral handler ignores the request bytes and
      // returns its signed envelope as the response.
      step = { kind: 'reading' };
      logLine('Writing EOM, waiting for envelope…');
      await reqCh.writeValueWithoutResponse(new Uint8Array([0, 0]));
      await eom;
      logLine(`Got envelope (${responseBytes.length} bytes)`);

      // Forward to the server. The envelope is a JSON-encoded SignedEnvelope;
      // /v1/enroll accepts it directly.
      step = { kind: 'relaying' };
      const envelope = new Uint8Array(responseBytes);
      const postEnvelope = async () =>
        fetch('/v1/enroll', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: envelope,
        });

      let res = await postEnvelope();
      if (!res.ok) {
        throw new Error(`server: ${res.status} ${await res.text()}`);
      }
      let respBody = new Uint8Array(await res.arrayBuffer());
      logLine(`Server responded (${respBody.length} bytes)`);

      // Extract pubkey (and device-id) from the envelope up-front for status
      // polling. This is best-effort UI sugar — errors here don't abort relay.
      let devicePubkey = '';
      let deviceId = '(unknown)';
      try {
        const envJson = JSON.parse(new TextDecoder().decode(envelope));
        const payloadJson = JSON.parse(atob(envJson.payload));
        devicePubkey = payloadJson.public_key ?? '';
        deviceId = payloadJson.device_id ?? deviceId;
      } catch { /* best-effort */ }

      // If the server returns "pending" (device needs manual approval), poll the
      // lightweight /v1/enroll/status endpoint rather than re-posting the signed
      // envelope.  Re-posting would fail with "nonce replay" because the nonce
      // was already consumed by the first POST.  The server forgets the nonce
      // when queuing a pending request, so once the operator approves we can
      // re-submit the envelope once to receive the provisioning bundle.
      type EnrollResp = { status?: string; reason?: string; retry_after?: number };
      let parsed: EnrollResp = {};
      try { parsed = JSON.parse(new TextDecoder().decode(respBody)); } catch { /* non-JSON, pass through */ }

      if (parsed.status === 'pending') {
        step = { kind: 'pending', reason: parsed.reason ?? 'awaiting manual approval' };
        logLine(`Server: pending — ${parsed.reason ?? 'awaiting approval'}. Approve below or in the Pending tab.`);
        pendingRecord = await fetchPendingRecord(devicePubkey);

        let retryMs = (parsed.retry_after ?? 10) * 1000;
        while (true) {
          // Wait for either the poll interval or an inline Approve/Reject click.
          await new Promise<void>((resolve, reject) => {
            wakeRelay = { resolve, reject };
            setTimeout(resolve, retryMs);
          });
          wakeRelay = null;
          logLine('Polling enrollment status…');
          const statusRes = await fetch(`/v1/enroll/status?pubkey=${encodeURIComponent(devicePubkey)}`);
          if (!statusRes.ok) throw new Error(`status poll failed: ${statusRes.status} ${await statusRes.text()}`);
          const statusJson = await statusRes.json() as EnrollResp;
          retryMs = (statusJson.retry_after ?? 10) * 1000;
          if (statusJson.status === 'accepted') break;
          if (statusJson.status === 'rejected') throw new Error(`enrollment rejected: ${statusJson.reason ?? ''}`);
          if (statusJson.status !== 'pending') throw new Error(`unexpected status from server: ${statusJson.status}`);
          step = { kind: 'pending', reason: statusJson.reason ?? parsed.reason ?? 'awaiting manual approval' };
          pendingRecord = await fetchPendingRecord(devicePubkey);
        }

        // Re-submit the original enrollment envelope now that the device is
        // approved. The nonce was forgotten by the server, so this goes through
        // normally and returns the signed provisioning bundle.
        logLine('Approved — re-submitting enrollment for provisioning bundle…');
        pendingRecord = null;
        step = { kind: 'relaying' };
        res = await postEnvelope();
        if (!res.ok) throw new Error(`server: ${res.status} ${await res.text()}`);
        respBody = new Uint8Array(await res.arrayBuffer());
        logLine(`Server responded (${respBody.length} bytes)`);
      }

      // Stream the signed response back to the device so it can verify and
      // apply the manifest. Use writeValueWithResponse: each fragment is up
      // to 182 bytes, which exceeds the negotiated ATT MTU on most links.
      // Without-response writes >MTU are silently truncated by CoreBluetooth
      // (and unreliable on BlueZ), so the peripheral sees a fragment whose
      // length header overstates the bytes that arrived and the JSON body
      // is corrupted. With-response triggers ATT Long Write, which the
      // peripheral stack reassembles before the WriteEvent callback fires.
      // Mirrors the native central in internal/transport/ble/central.go.
      step = { kind: 'writing' };
      for (const frag of frame(respBody)) {
        await reqCh.writeValueWithResponse(frag);
      }
      logLine('Response delivered to device');
      step = { kind: 'done', deviceId };
    } catch (e: any) {
      logLine(`error: ${e.message ?? e}`);
      step = { kind: 'error', message: e.message ?? String(e) };
    }
  }
</script>

<h2>BLE relay</h2>
<p class="lede">
  Bridge an offline device's enrollment over Bluetooth using this browser as the relay. The device must be running <code>ztp-agent-ble</code> (compiled with <code>-tags ble</code>) and advertising the ZTP service UUID.
</p>

{#if !supported}
  <div class="warn">
    <strong>Web Bluetooth is not available in this browser.</strong>
    {#if isIOS}
    <br />
    Apple blocks Web Bluetooth in Safari and all iOS browsers. To use the BLE relay on iPhone or iPad:
    <ol style="margin: 0.5rem 0 0 1.25rem; padding: 0;">
      <li>Install the <a href="https://apps.apple.com/gb/app/webble/id1193531073" target="_blank" rel="noopener"><strong>WebBLE</strong></a> app from the App Store (paid). It is a browser that implements the Web Bluetooth API via CoreBluetooth.</li>
      <li>Open <strong>this URL</strong> inside the WebBLE app. The relay will then work normally.</li>
      <li>If the server uses a self-signed certificate (e.g. <code>ztp.local</code> with mkcert), you must first install the mkcert root CA on your iPhone: email yourself the CA cert, open it on the device, then go to Settings → General → VPN &amp; Device Management → install the profile, and enable it under Settings → General → About → Certificate Trust Settings.</li>
    </ol>
    {:else}
    <br />
    Open this page in Chrome, Edge, or another Chromium-based browser on macOS, Linux, Windows, or Android.
    Safari and Firefox do not expose Web Bluetooth.
    {/if}
    <p style="margin: 0.75rem 0 0;">Or run the <code>ztp-app</code> desktop binary, which uses your machine's native Bluetooth stack and works regardless of browser. Alternatively, <a href="/onboard">return to the onboarding wizard</a> and choose a network option — if the device can join a LAN it can reach the ZTP server directly via mDNS with no BLE relay needed.</p>
  </div>
{:else}
  <section class="card">
    <h3>1. Start the agent on the device</h3>
    <p>
      Run the BLE-enabled agent binary on the device. <code>ztp-agent-ble</code> is
      pre-built in <code>bin/</code>, or build it with <code>just agent-ble</code>.
    </p>
    {#if infoErr}
      <p class="warn-inline">Could not fetch server pubkey: {infoErr}. Replace the placeholder below manually.</p>
    {/if}
    <div class="cmd-block">
      <pre>{deviceCmd}</pre>
      <button class="copy" onclick={() => copy(deviceCmd.replace(/\\\n\s+/g, ' '))}>Copy</button>
    </div>
    <p class="muted hint">
      <code>ztp-agent-ble</code> must run on the <strong>Linux device</strong> (BlueZ required).
      <code>-transport ble</code> skips the 3 s network probe and advertises BLE immediately;
      use <code>-transport auto</code> (the default) if the device might also have network access.
      Cross-compile from macOS: <code>just cross-agent-ble arm64</code> (Raspberry Pi) or <code>just cross-agent-ble</code> (amd64).
    </p>
  </section>

  <section class="card">
    <h3>2. {nativeBle ? 'Relay using native Bluetooth' : 'Relay from this browser'}</h3>
    <p>
      {#if nativeBle}
        The desktop app will scan via the host OS Bluetooth stack and connect to the first device advertising the ZTP service UUID <code>6e400001-…ca9e</code>. macOS may prompt for Bluetooth permission the first time.
      {:else}
        Click the button below to open the browser's BLE chooser. Only devices advertising the ZTP service UUID <code>6e400001-…ca9e</code> will appear.
      {/if}
    </p>
    <button class="primary" onclick={relay} disabled={step.kind !== 'idle' && step.kind !== 'done' && step.kind !== 'error'}>
      {#if step.kind === 'idle' || step.kind === 'done' || step.kind === 'error'}
        Scan & relay
      {:else if step.kind === 'pending'}
        Waiting for approval…
      {:else if step.kind === 'delivering'}
        Delivering bundle…
      {:else}
        Working… ({step.kind})
      {/if}
    </button>
  </section>

  <section class="card">
    <h3>3. Status</h3>
    {#if step.kind === 'idle'}
      <p class="muted">Idle. Click <em>Scan &amp; relay</em> to begin.</p>
    {:else if step.kind === 'pending'}
      <p class="pending">⏳ Pending — {step.reason}</p>
      {#if pendingRecord}
        <div class="pending-card">
          <dl>
            <dt>Device ID</dt><dd><code>{pendingRecord.device_id}</code></dd>
            <dt>Fingerprint</dt><dd><code>{pendingRecord.fingerprint}</code></dd>
            {#if pendingRecord.facts?.model}<dt>Model</dt><dd>{pendingRecord.facts.model}</dd>{/if}
            {#if (pendingRecord.facts?.mac_addresses ?? []).length}<dt>MAC</dt><dd>{pendingRecord.facts.mac_addresses!.join(', ')}</dd>{/if}
            {#if pendingRecord.facts?.serial}<dt>Serial</dt><dd>{pendingRecord.facts.serial}</dd>{/if}
            {#if pendingRecord.facts?.hostname}<dt>Hostname</dt><dd>{pendingRecord.facts.hostname}</dd>{/if}
          </dl>
          <div class="profile-pick">
            <label for="ble-profile">Profile</label>
            <select id="ble-profile" bind:value={selectedProfile} disabled={approving} title="Profile to assign on approval (optional — leave as auto to use selectors / default)">
              <option value="">auto (selectors / default)</option>
              {#each profiles as prof (prof.name)}
                <option value={prof.name}>{prof.name}</option>
              {/each}
            </select>
          </div>
          <div class="pending-actions">
            <button class="ok" onclick={approveInline} disabled={approving}>
              {approving ? 'Approving…' : '✓ Approve'}
            </button>
            <button class="bad" onclick={rejectInline} disabled={approving}>Reject</button>
          </div>
        </div>
      {:else}
        <p class="muted">
          Loading device details… or open the <a href="/pending">Pending</a> tab to approve.
        </p>
      {/if}
    {:else if step.kind === 'done'}
      <p class="ok">
        ✓ Relay complete for <code>{step.deviceId}</code>. The device should now
        verify and apply its manifest. Watch <a href="/devices">Devices</a> or
        <a href="/audit">Audit</a> for the new entry.
      </p>
    {:else if step.kind === 'error'}
      <p class="err">✗ {step.message}</p>
    {:else if step.kind === 'delivering'}
      <p class="delivering">📦 Delivering bundle… <span class="muted">{step.detail}</span></p>
    {:else}
      <p>{step.kind}…</p>
    {/if}

    {#if log.length}
      <details open>
        <summary>Trace ({log.length} lines)</summary>
        <pre>{log.join('\n')}</pre>
      </details>
    {/if}
  </section>
{/if}

<section class="card">
  <h3>How this works</h3>
  <ol>
    <li>The device runs <code>ztp-agent-ble</code> (built with <code>go build -tags ble</code>) and advertises the ZTP service over BLE.</li>
    <li>Your browser scans for that service, connects, and writes a single end-of-message marker.</li>
    <li>The device builds its signed <code>EnrollRequest</code> envelope and notifies it back to the browser.</li>
    <li>The browser POSTs the envelope (unmodified) to <code>/v1/enroll</code>. If the server responds with <em>pending</em> (manual approval required), an approval card appears inline — click <em>Approve</em> without navigating away, which would close the BLE connection. The relay polls every 10 s as a fallback if you approve from the <a href="/pending">Pending</a> tab instead.</li>
    <li>Once the server returns an accepted bundle, it is chunked back to the device over BLE; the device verifies and applies its manifest.</li>
  </ol>
  <p class="muted">
    The browser is a transparent pipe — it never sees plaintext secrets, and a
    rogue browser cannot forge enrollment because the device's signature would
    fail server-side verification.
  </p>
</section>

<style>
  h2 { margin-top: 0; }
  .lede { color: #8b949e; max-width: 60ch; }
  .lede code, p code, li code { background: #161b22; padding: 0.05rem 0.3rem; border-radius: 3px; }

  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
  }
  .card h3 { margin-top: 0; }
  .muted { color: #8b949e; }
  .ok { color: #3fb950; }
  .err { color: #f85149; }
  .pending { color: #d29922; }
  .delivering { color: #58a6ff; }
  .warn {
    background: #2d1f00;
    border: 1px solid #d29922;
    border-left-width: 3px;
    border-radius: 4px;
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
    color: #d29922;
  }
  .hint { font-size: 0.85rem; margin-top: 0.5rem; }
  .warn-inline { color: #d29922; font-size: 0.85rem; margin-bottom: 0.5rem; }

  .cmd-block {
    position: relative;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.75rem 3.5rem 0.75rem 1rem;
    margin: 0.5rem 0;
  }
  .cmd-block pre {
    margin: 0;
    font-size: 0.85rem;
    white-space: pre-wrap;
    word-break: break-all;
    color: #e6edf3;
  }
  .cmd-block .copy {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    padding: 0.2rem 0.5rem;
    font-size: 0.75rem;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #8b949e;
    cursor: pointer;
  }
  .cmd-block .copy:hover { background: #30363d; color: #e6edf3; }

  .primary {
    background: #238636;
    color: white;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.5rem 1rem;
    font: inherit;
    cursor: pointer;
  }
  .primary:disabled { opacity: 0.6; cursor: progress; }

  details { margin-top: 0.75rem; }
  details summary { cursor: pointer; color: #8b949e; }
  details pre {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.75rem;
    margin: 0.5rem 0 0;
    overflow-x: auto;
    font-size: 0.85rem;
    max-height: 240px;
  }

  .pending-card {
    background: #1c1a00;
    border: 1px solid #d29922;
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin-top: 0.75rem;
  }
  .pending-card dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 1rem;
    margin: 0 0 0.75rem;
    font-size: 0.9rem;
  }
  .pending-card dt { color: #8b949e; }
  .pending-card dd { margin: 0; }
  .profile-pick {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: 0.5rem 0 0.75rem;
    font-size: 0.9rem;
  }
  .profile-pick label { color: #8b949e; }
  .profile-pick select {
    background: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.25rem 0.5rem;
    font: inherit;
  }
  .pending-actions { display: flex; gap: 0.5rem; }
  .pending-actions button {
    padding: 0.35rem 1rem;
    border-radius: 4px;
    border: 1px solid #30363d;
    cursor: pointer;
    font: inherit;
  }
  .pending-actions button.ok  { background: #238636; color: white; }
  .pending-actions button.bad { background: #da3633; color: white; }
  .pending-actions button:disabled { opacity: 0.6; cursor: progress; }
  ol { padding-left: 1.25rem; }
  ol li { margin: 0.4rem 0; }
  a { color: #58a6ff; }
</style>
