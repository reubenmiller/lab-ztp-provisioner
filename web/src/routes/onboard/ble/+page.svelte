<script lang="ts">
  // BLE relay status page.
  // All relay logic lives in BleRelayController (mounted in the layout) which
  // writes to shared bleRelay state. This page just reads that state and
  // provides the toggle + activity view as a reference.
  import { bleRelay } from '$lib/ble-relay.svelte';

  const webBluetooth = typeof navigator !== 'undefined' && 'bluetooth' in navigator;
  const isIOS = typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent);
  // Consider BLE supported if the controller is actively relaying (native desktop)
  // or Web Bluetooth is available in this browser.
  const supported = $derived(webBluetooth || bleRelay.relaying);

  function toggle() {
    if (bleRelay.enabled) {
      bleRelay.enabled = false;
      localStorage.setItem('ztp-ble-relay-enabled', 'false');
      bleRelay.stop?.();
    } else {
      bleRelay.enabled = true;
      localStorage.setItem('ztp-ble-relay-enabled', 'true');
      bleRelay.start?.();
    }
  }
</script>

<h2>BLE relay</h2>
<p class="lede">
  Bridge a device's enrollment over Bluetooth. The relay runs continuously in the background —
  toggle it from the sidebar or here. Approved devices appear on the
  <a href="/pending">Fleet</a> page.
</p>

{#if !supported}
  <div class="warn">
    <strong>Web Bluetooth is not available in this browser.</strong>
    {#if isIOS}
    <br />
    Apple blocks Web Bluetooth in Safari and all iOS browsers. To use the BLE relay on iPhone or iPad:
    <ol style="margin: 0.5rem 0 0 1.25rem; padding: 0;">
      <li>Install the <a href="https://apps.apple.com/gb/app/webble/id1193531073" target="_blank" rel="noopener"><strong>WebBLE</strong></a> app from the App Store (paid).</li>
      <li>Open <strong>this URL</strong> inside the WebBLE app.</li>
      <li>If the server uses a self-signed certificate install the mkcert root CA: email the cert to yourself, open on the device, Settings → General → VPN &amp; Device Management → install, then Settings → General → About → Certificate Trust Settings → enable it.</li>
    </ol>
    {:else}
    <br />
    Open this page in Chrome, Edge, or another Chromium-based browser on macOS, Linux, Windows, or Android.
    Safari and Firefox do not expose Web Bluetooth.
    {/if}
    <p style="margin: 0.75rem 0 0;">The <code>ztp-app</code> desktop binary uses the host OS Bluetooth stack and works regardless of browser.</p>
  </div>
{:else}
  <section class="card">
    <h3>Relay</h3>
    <p class="hint">
      {bleRelay.relaying
        ? 'Scanning continuously for ZTP devices. Approve pending devices on the Fleet page.'
        : 'Toggle on to start scanning for ZTP devices advertising over Bluetooth.'}
    </p>
    <label class="toggle-wrap">
      <div class="toggle-track" class:on={bleRelay.enabled}>
        <div class="toggle-thumb"></div>
      </div>
      <input type="checkbox" checked={bleRelay.enabled} onchange={toggle} style="display:none" />
      <span class="toggle-label">
        {#if bleRelay.relaying}
          {bleRelay.status || 'Running…'}
        {:else}
          Relay off
        {/if}
      </span>
    </label>
  </section>

  <section class="card">
    <h3>Recent activity</h3>
    {#if bleRelay.activity.length}
      <ul class="activity">
        {#each bleRelay.activity as a (a.time + a.msg)}
          <li><span class="act-time">{a.time}</span>{a.msg}</li>
        {/each}
      </ul>
    {:else}
      <p class="muted">No activity yet. Turn the relay on to start scanning.</p>
    {/if}
  </section>
{/if}

<details class="card how-details">
  <summary><strong>How this works</strong></summary>
  <ol>
    <li>The device runs <code>ztp-agent-ble</code> (built with <code>go build -tags ble</code>) and advertises the ZTP service over BLE.</li>
    <li>The relay (browser or desktop app) scans, connects, and reads the device's signed <code>EnrollRequest</code> envelope over GATT.</li>
    <li>The relay POSTs the envelope to <code>/v1/enroll</code>. If manual approval is needed, approve the device on the <a href="/pending">Fleet</a> page — the relay polls for the result automatically.</li>
    <li>Once accepted, the provisioning bundle is written back to the device over BLE; the device verifies and applies it.</li>
  </ol>
  <p class="muted">
    The relay is a transparent pipe — it never sees plaintext secrets.
    A rogue relay cannot forge enrollments because the device's Ed25519 signature
    is verified server-side.
  </p>
</details>

<style>
  h2 { margin-top: 0; }
  .lede { color: var(--text-muted); max-width: 64ch; margin-bottom: 1.25rem; }
  .lede a, p a, li a { color: var(--accent); }
  .hint { color: var(--text-muted); font-size: 0.875rem; margin: 0 0 0.75rem; }

  .card {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
  }
  .card h3 { margin-top: 0; }
  .muted { color: var(--text-muted); }

  .warn {
    background: rgba(227, 179, 65, 0.08);
    border: 1px solid var(--warning);
    border-left-width: 3px;
    border-radius: 4px;
    padding: 0.75rem 1rem;
    margin-bottom: 1rem;
    color: var(--warning);
  }

  /* Toggle switch */
  .toggle-wrap {
    display: inline-flex;
    align-items: center;
    gap: 0.65rem;
    cursor: pointer;
    user-select: none;
  }
  .toggle-track {
    width: 40px;
    height: 22px;
    border-radius: 11px;
    background: var(--hover);
    border: 1px solid var(--border);
    position: relative;
    transition: background 0.2s, border-color 0.2s;
    flex-shrink: 0;
  }
  .toggle-track.on { background: var(--success); border-color: var(--success); }
  .toggle-thumb {
    position: absolute;
    top: 2px; left: 2px;
    width: 16px; height: 16px;
    border-radius: 50%;
    background: var(--text-dim);
    transition: transform 0.2s, background 0.2s;
  }
  .toggle-track.on .toggle-thumb { transform: translateX(18px); background: #fff; }
  .toggle-label { font-size: 0.9rem; color: var(--text-muted); }
  .toggle-track.on ~ .toggle-label { color: var(--text); }

  /* Activity */
  .activity {
    list-style: none; padding: 0; margin: 0;
    font-size: 0.85rem;
  }
  .activity li {
    display: flex; gap: 0.75rem;
    padding: 0.25rem 0;
    border-bottom: 1px solid var(--hover);
    color: var(--text-muted);
  }
  .activity li:last-child { border-bottom: none; }
  .act-time { color: var(--text-dim); font-variant-numeric: tabular-nums; flex-shrink: 0; }

  /* How-this-works */
  .how-details { cursor: default; }
  .how-details > summary {
    cursor: pointer; list-style: none;
    display: flex; align-items: center; gap: 0.4rem;
    color: var(--text-muted); margin: -0.25rem 0 0;
  }
  .how-details > summary::before {
    content: '\25B6'; font-size: 0.6rem; transition: transform 0.15s; flex-shrink: 0;
  }
  .how-details[open] > summary::before { transform: rotate(90deg); }
  ol { padding-left: 1.25rem; }
  ol li { margin: 0.4rem 0; color: var(--text-muted); font-size: 0.9rem; }
  code { background: var(--code-bg); padding: 0.05rem 0.3rem; border-radius: 3px; }
</style>
