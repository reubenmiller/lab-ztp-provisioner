<!-- Headless BLE relay controller.
     Always mounted in the app layout. Has no rendered template.
     Registers bleRelay.start / bleRelay.stop and manages the relay
     loop so the sidebar toggle works from any page without navigating
     to the /onboard/ble route. -->
<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { detect, hasCapability } from '$lib/runtime';
  import { bleRelay } from '$lib/ble-relay.svelte';

  // ── Runtime ───────────────────────────────────────────────────────────
  let nativeBle = false;
  const webBluetooth = typeof navigator !== 'undefined' && 'bluetooth' in navigator;

  // ── BLE UUIDs — must match internal/transport/ble/doc.go ─────────────
  const SERVICE_UUID   = '6e400001-b5a3-f393-e0a9-e50e24dcca9e';
  const REQUEST_UUID   = '6e400002-b5a3-f393-e0a9-e50e24dcca9e';
  const RESPONSE_UUID  = '6e400003-b5a3-f393-e0a9-e50e24dcca9e';
  const STATUS_UUID    = '6e400004-b5a3-f393-e0a9-e50e24dcca9e';
  const TIME_SYNC_UUID = '6e400005-b5a3-f393-e0a9-e50e24dcca9e';
  const FRAG = 180;
  const RESTART_DELAY_MS = 2500;

  // ── Noise filter ──────────────────────────────────────────────────────
  // "saw N BLE advertisement(s)" = scan window expired with no ZTP device found.
  // "On Windows centrals…" = long OS-specific advisory from the Go BLE stack.
  // Neither is an actionable error; suppress them from the shared activity log.
  const NOISE_RE = /\d+ BLE advertisement|On Windows centrals|the OS may only see/;

  function logEvent(msg: string) {
    if (NOISE_RE.test(msg)) return;
    bleRelay.activity = [
      { time: new Date().toLocaleTimeString(), msg },
      ...bleRelay.activity,
    ].slice(0, 10);
  }

  function setStatus(s: string) { bleRelay.status = s; }

  // ── BLE framing ───────────────────────────────────────────────────────
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

  // ── Wails event helper ────────────────────────────────────────────────
  type WailsEventCallback = (data: unknown) => void;
  type WailsRuntime = { EventsOn?: (event: string, cb: WailsEventCallback) => () => void };
  function wailsEventsOn(event: string, cb: WailsEventCallback): (() => void) | null {
    const rt = (window as unknown as { runtime?: WailsRuntime }).runtime;
    if (!rt?.EventsOn) return null;
    return rt.EventsOn(event, cb);
  }

  // ── Native BLE relay ──────────────────────────────────────────────────
  type BleResult = {
    status: string; reason?: string; deviceId?: string;
    bundleDelivered: boolean; envelopeBytes: number;
  };

  let deliveringBundle = false;

  function applyBleProgress(p: { phase: string; detail?: string }) {
    const d = p.detail ?? '';
    if (deliveringBundle) {
      switch (p.phase) {
        case 'scanning':       setStatus('BLE: reconnecting…');             return;
        case 'connected':      setStatus(`BLE: reconnected to ${d || 'device'}`); return;
        case 'writing-bundle': setStatus('BLE: writing bundle…');           return;
        default: return;
      }
    }
    switch (p.phase) {
      case 'scanning':       setStatus('BLE: scanning…');                   return;
      case 'connected':      setStatus(`BLE: connected — ${d || '(unknown)'}`); return;
      case 'trigger':        setStatus('BLE: reading envelope…');           return;
      case 'submitting':     setStatus('BLE: forwarding to server…');       return;
      case 'writing-bundle': setStatus('BLE: writing bundle…');             return;
    }
  }

  async function nativeRelay() {
    const w = window as unknown as {
      go?: { desktop?: { App?: { BleEnroll?: (ms: number) => Promise<BleResult> } } }
    };
    const fn = w.go?.desktop?.App?.BleEnroll;
    if (!fn) return;

    const off = wailsEventsOn('ble:progress', (data) => {
      applyBleProgress(data as { phase: string; detail?: string });
    });
    try {
      if (!deliveringBundle) setStatus('BLE: scanning…');
      const r = await fn(20000);
      if (r.status === 'accepted' && r.bundleDelivered) {
        logEvent(`Enrolled: ${r.deviceId ?? '(unknown)'}`);
        setStatus(''); return;
      }
      if (r.status === 'rejected') {
        logEvent(`Rejected: ${r.reason ?? '(no reason)'}`);
        setStatus(''); return;
      }
      // 'pending' timeout or unexpected — silent retry
      setStatus('');
    } catch (e: any) {
      const msg = e?.message ?? String(e);
      if (!NOISE_RE.test(msg)) logEvent(`BLE error: ${msg}`);
      setStatus('');
    } finally {
      off?.();
      deliveringBundle = false;
    }
  }

  // ── Web Bluetooth relay ───────────────────────────────────────────────
  async function relay() {
    if (nativeBle) return nativeRelay();
    if (!webBluetooth) return;
    try {
      setStatus('BLE: scanning…');
      const dev = await navigator.bluetooth.requestDevice({
        filters: [{ services: [SERVICE_UUID] }],
      });
      logEvent(`Connected: ${dev.name ?? dev.id}`);
      setStatus(`BLE: connected — ${dev.name ?? dev.id}`);

      const server = await dev.gatt!.connect();
      const svc    = await server.getPrimaryService(SERVICE_UUID);
      const reqCh  = await svc.getCharacteristic(REQUEST_UUID);
      const respCh = await svc.getCharacteristic(RESPONSE_UUID);
      const statCh = await svc.getCharacteristic(STATUS_UUID);

      // Optional clock sync (silently skip on older firmware)
      try {
        const tc = await svc.getCharacteristic(TIME_SYNC_UUID);
        await tc.writeValueWithoutResponse(new TextEncoder().encode(new Date().toISOString()));
      } catch {}

      const responseBytes: number[] = [];
      const eom = new Promise<void>((resolve, reject) => {
        respCh.addEventListener('characteristicvaluechanged', (ev) => {
          const v = (ev.target as BluetoothRemoteGATTCharacteristic).value!;
          if (v.byteLength < 2) return;
          const n = v.getUint16(0, false);
          if (n === 0) { resolve(); return; }
          for (let i = 0; i < n; i++) responseBytes.push(v.getUint8(2 + i));
        });
        setTimeout(() => reject(new Error('timeout waiting for device response')), 60000);
      });
      await respCh.startNotifications();
      await statCh.startNotifications();

      setStatus('BLE: reading envelope…');
      await reqCh.writeValueWithoutResponse(new Uint8Array([0, 0]));
      await eom;

      setStatus('BLE: forwarding to server…');
      const envelope = new Uint8Array(responseBytes);
      const postEnvelope = async () => fetch('/v1/enroll', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: envelope,
      });

      let res = await postEnvelope();
      if (!res.ok) throw new Error(`server: ${res.status} ${await res.text()}`);
      let respBody = new Uint8Array(await res.arrayBuffer());

      let devicePubkey = '', deviceId = '(unknown)';
      try {
        const env = JSON.parse(new TextDecoder().decode(envelope));
        const pl  = JSON.parse(atob(env.payload));
        devicePubkey = pl.public_key ?? '';
        deviceId     = pl.device_id  ?? deviceId;
      } catch {}

      type EnrollResp = { status?: string; reason?: string; retry_after?: number };
      // The body is JSON, or key=value lines when the device asked for
      // response_format "text" (see pkg/protocol/enrolltext.go). The device
      // chose the rendering, so read status from either.
      const parseEnrollResp = (body: Uint8Array): EnrollResp => {
        const text = new TextDecoder().decode(body);
        try { return JSON.parse(text); } catch {}
        const kv: Record<string, string> = {};
        for (const line of text.split('\n')) {
          const i = line.indexOf('=');
          if (i > 0) kv[line.slice(0, i)] = line.slice(i + 1).replace(/\r$/, '');
        }
        const retry = Number(kv.retry_after);
        return {
          status: kv.status,
          reason: kv.reason?.replace(/\\n/g, '\n').replace(/\\r/g, '\r'),
          retry_after: Number.isFinite(retry) && retry > 0 ? retry : undefined,
        };
      };
      const parsed = parseEnrollResp(respBody);

      if (parsed.status === 'pending') {
        setStatus('BLE: awaiting approval…');
        logEvent(`Pending approval${deviceId !== '(unknown)' ? ` — ${deviceId}` : ''}`);
        let retryMs = (parsed.retry_after ?? 10) * 1000;
        while (true) {
          // Poll until the operator approves from the Fleet page.
          await new Promise<void>(r => setTimeout(r, retryMs));
          const sr = await fetch(`/v1/enroll/status?pubkey=${encodeURIComponent(devicePubkey)}`);
          if (!sr.ok) throw new Error(`status poll: ${sr.status}`);
          const sj = await sr.json() as EnrollResp;
          retryMs = (sj.retry_after ?? 10) * 1000;
          if (sj.status === 'accepted') break;
          if (sj.status === 'rejected') throw new Error(`enrollment rejected: ${sj.reason ?? ''}`);
          if (sj.status !== 'pending') throw new Error(`unexpected status: ${sj.status}`);
          setStatus('BLE: awaiting approval…');
        }
        setStatus('BLE: delivering bundle…');
        res = await postEnvelope();
        if (!res.ok) throw new Error(`server: ${res.status} ${await res.text()}`);
        respBody = new Uint8Array(await res.arrayBuffer());
      }

      setStatus('BLE: writing bundle…');
      for (const frag of frame(respBody)) {
        await reqCh.writeValueWithResponse(frag);
      }
      logEvent(`Enrolled: ${deviceId}`);
      setStatus('');
    } catch (e: any) {
      const msg = e.message ?? String(e);
      if (!NOISE_RE.test(msg)) logEvent(`BLE error: ${msg}`);
      setStatus('');
    }
  }

  // ── Loop management ───────────────────────────────────────────────────
  async function startLoop() {
    if (bleRelay.relaying) return;
    bleRelay.relaying = true;
    setStatus('');
    while (bleRelay.relaying) {
      await relay();
      if (!bleRelay.relaying) break;
      await new Promise<void>(r => setTimeout(r, RESTART_DELAY_MS));
      if (!bleRelay.relaying) break;
    }
    bleRelay.relaying = false;
    setStatus('');
  }

  function stopLoop() {
    bleRelay.relaying = false;
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────
  onMount(async () => {
    try {
      const rt = await detect();
      nativeBle = hasCapability(rt, 'ble.central.native');
    } catch {}
    bleRelay.start = startLoop;
    bleRelay.stop  = stopLoop;
    if (bleRelay.enabled && !bleRelay.relaying) startLoop();
  });

  onDestroy(() => {
    bleRelay.relaying = false;
    bleRelay.start = null;
    bleRelay.stop  = null;
  });
</script>
