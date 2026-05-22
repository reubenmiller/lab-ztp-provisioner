<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type PendingRequest, type Device, type ProfileSummary } from '$lib/api';
  import { confirmDialog } from '$lib/confirm.svelte';
  import { bleRelay } from '$lib/ble-relay.svelte';

  // ── Pending ───────────────────────────────────────────────────────────────
  let pending = $state<PendingRequest[]>([]);
  let selectedProfile = $state<Record<string, string>>({});

  // ── Enrolled ──────────────────────────────────────────────────────────────
  let devices = $state<Device[]>([]);
  let deleting = $state<string | null>(null);
  let menuOpen = $state<string | null>(null);

  // Allowlist modal
  let allowModal = $state<Device | null>(null);
  let alDeviceId = $state('');
  let alMac = $state('');
  let alSerial = $state('');
  let alNote = $state('');
  let alProfile = $state('');
  let alSubmitting = $state(false);
  let alSuccess = $state(false);
  let alErr = $state<string | null>(null);

  // ── Shared ────────────────────────────────────────────────────────────────
  let profiles = $state<ProfileSummary[]>([]);
  let err = $state<string | null>(null);

  async function loadAll() {
    try {
      [pending, devices, profiles] = await Promise.all([
        api.pending(),
        api.devices(),
        api.profiles(),
      ]);
      err = null;
    } catch (e: any) {
      err = e.message;
    }
  }

  // ── Pending actions ───────────────────────────────────────────────────────
  async function approve(id: string) {
    await api.approve(id, selectedProfile[id] || undefined);
    delete selectedProfile[id];
    await loadAll();
    window.dispatchEvent(new CustomEvent('ztp:pending-changed', { detail: { count: pending.length } }));
  }

  async function reject(id: string) {
    await api.reject(id);
    delete selectedProfile[id];
    await loadAll();
    window.dispatchEvent(new CustomEvent('ztp:pending-changed', { detail: { count: pending.length } }));
  }

  // ── Device actions ────────────────────────────────────────────────────────
  async function remove(id: string) {
    const ok = await confirmDialog({
      title: 'Delete device',
      message: `Delete device "${id}" from the enrollment record?\n\nThe device will be treated as unknown on its next enrollment attempt.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    deleting = id;
    try {
      await api.deleteDevice(id);
      await loadAll();
    } catch (e: any) {
      err = e.message;
    } finally {
      deleting = null;
    }
  }

  function openAllowModal(d: Device) {
    menuOpen = null;
    alDeviceId = d.id;
    alMac = d.facts?.mac_addresses?.[0] ?? '';
    alSerial = d.facts?.serial ?? '';
    alNote = '';
    alProfile = d.profile_name ?? '';
    alErr = null;
    alSuccess = false;
    allowModal = d;
  }

  async function submitAllow(e: Event) {
    e.preventDefault();
    alSubmitting = true;
    alErr = null;
    alSuccess = false;
    try {
      await api.addAllow({
        device_id: alDeviceId,
        ...(alMac ? { mac: alMac } : {}),
        ...(alSerial ? { serial: alSerial } : {}),
        ...(alNote ? { note: alNote } : {}),
        ...(alProfile ? { profile: alProfile } : {}),
      });
      alSuccess = true;
      setTimeout(() => { allowModal = null; }, 800);
    } catch (ex: any) {
      alErr = ex.message;
    } finally {
      alSubmitting = false;
    }
  }

  function closeMenuOnOutsideClick(e: MouseEvent) {
    if (!(e.target as HTMLElement).closest('.menu-wrap')) menuOpen = null;
  }

  onMount(() => {
    loadAll();
    window.addEventListener('ztp:pending', loadAll);
    window.addEventListener('ztp:enrolled', loadAll);
  });
  onDestroy(() => {
    window.removeEventListener('ztp:pending', loadAll);
    window.removeEventListener('ztp:enrolled', loadAll);
  });
</script>

<svelte:window onclick={closeMenuOnOutsideClick} />

{#if err}<p class="err">{err}</p>{/if}

<!-- ── Pending approvals ───────────────────────────────────────────────── -->
<section class="card">
  <h3>Pending approvals <small>{pending.length}</small></h3>
  {#if pending.length === 0}
    <p class="empty">No devices waiting for approval.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Device ID</th><th>Fingerprint</th><th>OS</th><th>Model</th><th>MAC</th><th>Reason</th><th>First seen</th><th>Profile</th><th></th>
        </tr>
      </thead>
      <tbody>
        {#each pending as p (p.id)}
          <tr class="pending-row">
            <td><code>{p.device_id}</code></td>
            <td><code class="fp">{p.fingerprint}</code></td>
            <td>
              {#if p.facts?.os_pretty_name}
                {p.facts.os_pretty_name}
              {:else if p.facts?.os}
                {p.facts.os}{p.facts?.arch ? ` / ${p.facts.arch}` : ''}
              {:else}
                —
              {/if}
            </td>
            <td>{p.facts?.model ?? '—'}</td>
            <td>{(p.facts?.mac_addresses ?? []).join(', ') || '—'}</td>
            <td>{p.reason}</td>
            <td>{new Date(p.first_seen).toLocaleString()}</td>
            <td>
              <select bind:value={selectedProfile[p.id]} title="Profile to assign on approval (optional — leave as auto to use selectors / default)">
                <option value="">auto</option>
                {#each profiles as prof (prof.name)}
                  <option value={prof.name}>{prof.name}</option>
                {/each}
              </select>
            </td>
            <td class="action-btns">
              <button class="btn-ok" onclick={() => approve(p.id)}>Approve</button>
              <button class="btn-bad" onclick={() => reject(p.id)}>Reject</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<!-- ── Enrolled devices ────────────────────────────────────────────────── -->
<section class="card">
  <h3>Enrolled devices <small>{devices.length}</small></h3>
  {#if devices.length === 0}
    <p class="empty">No enrolled devices yet.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Device ID</th><th>OS</th><th>Model</th><th>Hostname</th><th>MAC address(es)</th><th>Enrolled</th><th>Last seen</th><th></th>
        </tr>
      </thead>
      <tbody>
        {#each devices as d (d.id)}
          <tr>
            <td><code>{d.id}</code></td>
            <td class="os-cell">
              {#if d.facts?.os_pretty_name}
                <span class="os-name">{d.facts.os_pretty_name}</span>
              {:else if d.facts?.os}
                <span class="os-name">{d.facts.os}{d.facts?.arch ? ` / ${d.facts.arch}` : ''}</span>
              {:else}
                —
              {/if}
            </td>
            <td>{d.facts?.model ?? '—'}</td>
            <td>{d.facts?.hostname ?? '—'}</td>
            <td class="mac-cell">
              {#if d.facts?.mac_addresses?.length}
                {#each d.facts.mac_addresses as mac}
                  <code class="mac">{mac}</code>
                {/each}
              {:else}
                —
              {/if}
            </td>
            <td>{new Date(d.enrolled_at).toLocaleString()}</td>
            <td>{new Date(d.last_seen).toLocaleString()}</td>
            <td class="actions-cell">
              <div class="menu-wrap">
                <button class="menu-btn" title="Actions" onclick={(e) => { e.stopPropagation(); menuOpen = menuOpen === d.id ? null : d.id; }}>•••</button>
                {#if menuOpen === d.id}
                  <div class="menu-dropdown">
                    <button onclick={() => openAllowModal(d)}>Add to allowlist</button>
                    <button class="bad" disabled={deleting === d.id} onclick={() => { menuOpen = null; remove(d.id); }}>
                      {deleting === d.id ? '…' : 'Delete'}
                    </button>
                  </div>
                {/if}
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<!-- ── BLE debug log ──────────────────────────────────────────────── -->
{#if bleRelay.activity.length}
  <details class="ble-log">
    <summary>BLE relay log ({bleRelay.activity.length})</summary>
    <ul class="ble-activity">
      {#each bleRelay.activity as a (a.time + a.msg)}
        <li><span class="ble-act-time">{a.time}</span>{a.msg}</li>
      {/each}
    </ul>
  </details>
{/if}

{#if allowModal}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="modal-backdrop" onclick={(e) => { if ((e.target as HTMLElement).classList.contains('modal-backdrop')) allowModal = null; }}>
    <div class="modal">
      <h3>Add to allowlist</h3>
      <p class="modal-sub">Pre-filled from <code>{allowModal.id}</code>. Adjust as needed before saving.</p>
      {#if alErr}<p class="err">{alErr}</p>{/if}
      {#if alSuccess}<p class="ok">Added to allowlist.</p>{/if}
      <form onsubmit={submitAllow}>
        <div class="field">
          <label for="m-device">Device ID <span class="req">(required)</span></label>
          <input id="m-device" bind:value={alDeviceId} required />
          <small>Identifier the agent will report on enrollment.</small>
        </div>
        <div class="row">
          <div class="field">
            <label for="m-mac">MAC address <span class="opt">(optional)</span></label>
            <input id="m-mac" bind:value={alMac} placeholder="aa:bb:cc:dd:ee:ff" />
          </div>
          <div class="field">
            <label for="m-serial">Serial number <span class="opt">(optional)</span></label>
            <input id="m-serial" bind:value={alSerial} placeholder="e.g. SN-12345678" />
          </div>
        </div>
        <div class="field">
          <label for="m-note">Note <span class="opt">(optional)</span></label>
          <input id="m-note" bind:value={alNote} placeholder="e.g. lab device for QA team" />
        </div>
        <div class="field">
          <label for="m-profile">Profile <span class="opt">(optional)</span></label>
          <select id="m-profile" bind:value={alProfile}>
            <option value="">— use default resolution —</option>
            {#each profiles as p (p.name)}
              <option value={p.name}>{p.name}{p.description ? ` — ${p.description}` : ''}</option>
            {/each}
          </select>
        </div>
        <div class="modal-footer">
          <button type="button" onclick={() => allowModal = null}>Cancel</button>
          <button type="submit" disabled={alSubmitting || alSuccess}>
            {alSubmitting ? '…' : alSuccess ? 'Added!' : 'Add to allowlist'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<style>
  /* ── Cards ──────────────────────────────────────────────────────── */
  .card {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
    background: var(--surface-2);
  }
  h3 { margin: 0 0 0.75rem; font-size: 1rem; }
  h3 small { color: var(--text-muted); font-weight: normal; margin-left: 0.5rem; }

  .err { color: var(--danger); }
  .ok { color: var(--success); }
  .empty { color: var(--text-muted); font-style: italic; }

  table { width: 100%; border-collapse: collapse; margin-bottom: 0.5rem; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--text-muted); font-weight: normal; }
  code { background: var(--code-bg); padding: 0.1rem 0.3rem; border-radius: 3px; }
  .fp { font-size: 0.8rem; }

  /* Pending row highlight */
  .pending-row td { background: var(--accent-dim); }

  /* Pending action buttons */
  .action-btns .btn-ok, .action-btns .btn-bad {
    margin-right: 0.25rem; padding: 0.25rem 0.75rem;
    border-radius: 4px; border: none; cursor: pointer;
    transition: opacity 0.15s;
  }
  .action-btns .btn-ok:active, .action-btns .btn-bad:active { opacity: 0.75; }
  .btn-ok  { background: var(--success); color: #fff; }
  .btn-bad { background: var(--danger);  color: #fff; }

  /* Profile select */
  select {
    background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 0.2rem 0.4rem;
  }

  /* Enrolled table */
  .mac { display: block; margin-bottom: 0.15rem; background: none; padding: 0; }
  .mac:last-child { margin-bottom: 0; }
  .os-name { font-size: 0.9rem; }

  /* Kebab menu */
  .actions-cell { position: relative; width: 2.5rem; white-space: nowrap; }
  .menu-wrap { position: relative; display: inline-block; }
  .menu-btn {
    background: none; border: 1px solid transparent; border-radius: 4px;
    color: var(--text-muted); cursor: pointer; padding: 0.15rem 0.4rem; font-size: 1rem;
    letter-spacing: 0.05em;
  }
  .menu-btn:hover { border-color: var(--border); color: var(--text); background: var(--hover); }
  .menu-dropdown {
    position: absolute; right: 0; top: calc(100% + 4px); z-index: 100;
    background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
    min-width: 10rem; padding: 0.25rem 0; box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  }
  .menu-dropdown button {
    display: block; width: 100%; text-align: left;
    background: none; border: none; color: var(--text);
    padding: 0.4rem 0.75rem; cursor: pointer; font-size: 0.875rem;
  }
  .menu-dropdown button:hover { background: var(--hover); }
  .menu-dropdown button.bad { color: var(--danger); }
  .menu-dropdown button.bad:hover { background: var(--hover); }
  .menu-dropdown button:disabled { opacity: 0.5; cursor: default; }

  /* Allowlist modal */
  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(0,0,0,0.6);
    display: flex; align-items: center; justify-content: center; z-index: 200;
  }
  .modal {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 1.25rem 1.5rem; width: 480px; max-width: 95vw; max-height: 90vh; overflow-y: auto;
  }
  .modal h3 { margin: 0 0 0.25rem; color: var(--text); }
  .modal-sub { margin: 0 0 1rem; color: var(--text-muted); font-size: 0.85rem; }
  .field { display: flex; flex-direction: column; margin-bottom: 0.75rem; }
  .field label { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.25rem; }
  .field .opt { color: var(--text-dim); font-weight: normal; }
  .field .req { color: var(--warning); font-weight: normal; }
  .field small { color: var(--text-dim); font-size: 0.75rem; margin-top: 0.25rem; }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .row .field { flex: 1 1 12rem; }
  input {
    background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 0.35rem 0.5rem; width: 100%; box-sizing: border-box;
  }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  .modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1rem; }
  .modal-footer button {
    padding: 0.3rem 0.9rem; border-radius: 4px; border: 1px solid var(--border);
    cursor: pointer; background: var(--hover); color: var(--text); font-size: 0.875rem;
  }
  .modal-footer button[type="submit"] { background: var(--success); border-color: var(--success); color: white; }
  .modal-footer button[type="submit"]:disabled { opacity: 0.6; cursor: default; }

  /* BLE debug log */
  .ble-log {
    margin-top: 2rem;
    border-top: 1px solid var(--border);
    padding-top: 0.5rem;
  }
  .ble-log > summary {
    cursor: pointer;
    list-style: none;
    color: var(--text-dim);
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    user-select: none;
    display: flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.25rem 0;
  }
  .ble-log > summary::before {
    content: '\25B6';
    font-size: 0.5rem;
    transition: transform 0.15s;
  }
  .ble-log[open] > summary::before { transform: rotate(90deg); }
  .ble-log > summary:hover { color: var(--text-muted); }
  .ble-activity {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0 0;
    font-size: 0.82rem;
  }
  .ble-activity li {
    display: flex;
    gap: 0.75rem;
    padding: 0.2rem 0;
    border-bottom: 1px solid var(--hover);
    color: var(--text-muted);
  }
  .ble-activity li:last-child { border-bottom: none; }
  .ble-act-time {
    color: var(--text-dim);
    font-variant-numeric: tabular-nums;
    flex-shrink: 0;
  }
</style>
