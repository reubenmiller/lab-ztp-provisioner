<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type Device, type ProfileSummary } from '$lib/api';
  import { confirmDialog } from '$lib/confirm.svelte';

  let items = $state<Device[]>([]);
  let profiles = $state<ProfileSummary[]>([]);
  let err = $state<string | null>(null);
  let deleting = $state<string | null>(null);
  let menuOpen = $state<string | null>(null);

  // Allowlist modal state
  let allowModal = $state<Device | null>(null);
  let alDeviceId = $state('');
  let alMac = $state('');
  let alSerial = $state('');
  let alNote = $state('');
  let alProfile = $state('');
  let alSubmitting = $state(false);
  let alSuccess = $state(false);
  let alErr = $state<string | null>(null);

  async function load() {
    try {
      [items, profiles] = await Promise.all([api.devices(), api.profiles()]);
      err = null;
    } catch (e: any) { err = e.message; }
  }

  async function remove(id: string) {
    const ok = await confirmDialog({
      title: 'Delete device',
      message: `Delete device "${id}" from the enrollment record?\n\nThe device will be treated as unknown on its next enrollment attempt.`,
      confirmLabel: 'Delete',
      danger: true
    });
    if (!ok) return;
    deleting = id;
    try {
      await api.deleteDevice(id);
      await load();
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
        ...(alProfile ? { profile: alProfile } : {})
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
    if (!(e.target as HTMLElement).closest('.menu-wrap')) {
      menuOpen = null;
    }
  }

  function onEnrolledEvent() { load(); }

  onMount(() => {
    load();
    window.addEventListener('ztp:enrolled', onEnrolledEvent);
  });
  onDestroy(() => {
    window.removeEventListener('ztp:enrolled', onEnrolledEvent);
  });
</script>

<svelte:window onclick={closeMenuOnOutsideClick} />

<h2>Enrolled devices <small>{items.length}</small></h2>
{#if err}<p class="err">{err}</p>{/if}

<table>
  <thead><tr><th>Device ID</th><th>OS</th><th>Model</th><th>Hostname</th><th>MAC address(es)</th><th>Enrolled</th><th>Last seen</th><th></th></tr></thead>
  <tbody>
    {#each items as d (d.id)}
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
  h2 small { color: #8b949e; font-weight: normal; margin-left: 0.5rem; }
  .err { color: #f85149; }
  .ok { color: #3fb950; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; vertical-align: top; }
  th { color: #8b949e; font-weight: normal; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
  .mac-cell { }
  .mac { display: block; margin-bottom: 0.15rem; background: none; padding: 0; }
  .mac:last-child { margin-bottom: 0; }
  .os-name { font-size: 0.9rem; }

  /* Actions / kebab menu */
  .actions-cell { position: relative; width: 2.5rem; white-space: nowrap; }
  .menu-wrap { position: relative; display: inline-block; }
  .menu-btn {
    background: none; border: 1px solid transparent; border-radius: 4px;
    color: #8b949e; cursor: pointer; padding: 0.15rem 0.4rem; font-size: 1rem;
    letter-spacing: 0.05em;
  }
  .menu-btn:hover { border-color: #30363d; color: #e6edf3; background: #21262d; }
  .menu-dropdown {
    position: absolute; right: 0; top: calc(100% + 4px); z-index: 100;
    background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    min-width: 10rem; padding: 0.25rem 0; box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  }
  .menu-dropdown button {
    display: block; width: 100%; text-align: left;
    background: none; border: none; color: #e6edf3;
    padding: 0.4rem 0.75rem; cursor: pointer; font-size: 0.875rem;
  }
  .menu-dropdown button:hover { background: #21262d; }
  .menu-dropdown button.bad { color: #f85149; }
  .menu-dropdown button.bad:hover { background: #21262d; }
  .menu-dropdown button:disabled { opacity: 0.5; cursor: default; }

  /* Allowlist modal */
  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(0,0,0,0.6);
    display: flex; align-items: center; justify-content: center; z-index: 200;
  }
  .modal {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 1.25rem 1.5rem; width: 480px; max-width: 95vw; max-height: 90vh; overflow-y: auto;
  }
  .modal h3 { margin: 0 0 0.25rem; color: #e6edf3; }
  .modal-sub { margin: 0 0 1rem; color: #8b949e; font-size: 0.85rem; }
  .field { display: flex; flex-direction: column; margin-bottom: 0.75rem; }
  .field label { font-size: 0.85rem; color: #c9d1d9; margin-bottom: 0.25rem; }
  .field .opt { color: #8b949e; font-weight: normal; }
  .field .req { color: #f0883e; font-weight: normal; }
  .field small { color: #8b949e; font-size: 0.75rem; margin-top: 0.25rem; }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .row .field { flex: 1 1 12rem; }
  input, select {
    background: #0d1117; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 4px; padding: 0.35rem 0.5rem; width: 100%; box-sizing: border-box;
  }
  input:focus, select:focus { outline: none; border-color: #58a6ff; }
  .modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1rem; }
  .modal-footer button {
    padding: 0.3rem 0.9rem; border-radius: 4px; border: 1px solid #30363d;
    cursor: pointer; background: #21262d; color: #e6edf3; font-size: 0.875rem;
  }
  .modal-footer button[type="submit"] { background: #238636; border-color: #2ea043; color: white; }
  .modal-footer button[type="submit"]:disabled { opacity: 0.6; cursor: default; }
  .modal-footer button.bad { background: #da3633; color: white; }
</style>
