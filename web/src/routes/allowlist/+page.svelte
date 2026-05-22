<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type AllowlistEntry, type ProfileSummary } from '$lib/api';

  let items = $state<AllowlistEntry[]>([]);
  let profiles = $state<ProfileSummary[]>([]);
  let err = $state<string | null>(null);

  // Modal state
  let showModal = $state(false);
  let device_id = $state('');
  let mac = $state('');
  let serial = $state('');
  let note = $state('');
  let profile = $state('');
  let submitting = $state(false);

  async function refresh() {
    try {
      items = await api.allowlist();
      profiles = await api.profiles();
      err = null;
    } catch (e: any) { err = e.message; }
  }

  function openModal() {
    device_id = mac = serial = note = profile = '';
    err = null;
    showModal = true;
  }

  function closeModal() {
    showModal = false;
  }

  async function add(e: Event) {
    e.preventDefault();
    if (!device_id) return;
    submitting = true;
    try {
      await api.addAllow({ device_id, mac, serial, note, profile });
      showModal = false;
      await refresh();
    } catch (ex: any) { err = ex.message; }
    finally { submitting = false; }
  }

  async function remove(id: string) {
    await api.removeAllow(id);
    await refresh();
  }

  onMount(refresh);
</script>

<div class="page-header">
  <h2>Allowlist <small>{items.length}</small></h2>
  <button class="primary" onclick={openModal}>+ Add device</button>
</div>

{#if err && !showModal}<p class="err">{err}</p>{/if}

<table>
  <thead><tr><th>Device ID</th><th>MAC</th><th>Serial</th><th>Note</th><th>Profile</th><th>Created</th><th></th></tr></thead>
  <tbody>
    {#each items as e (e.device_id)}
      <tr>
        <td><code>{e.device_id}</code></td>
        <td>{e.mac ?? ''}</td>
        <td>{e.serial ?? ''}</td>
        <td>{e.note ?? ''}</td>
        <td>{e.profile ?? ''}</td>
        <td>{new Date(e.created_at).toLocaleString()}</td>
        <td><button class="bad" onclick={() => remove(e.device_id)}>Remove</button></td>
      </tr>
    {/each}
  </tbody>
</table>

{#if showModal}
  <div class="modal-backdrop" role="presentation" onclick={closeModal}>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"
         onclick={(e) => e.stopPropagation()}>
      <div class="modal-header">
        <h3 id="modal-title">Add allowlist entry</h3>
        <button class="close-btn" onclick={closeModal} aria-label="Close">×</button>
      </div>
      <form onsubmit={add}>
        <div class="field">
          <label for="al-device">Device ID <span class="req">(required)</span></label>
          <input id="al-device" bind:value={device_id} placeholder="e.g. lab-device-05" required />
          <small>Identifier the agent will report on enrollment (hostname, machine-id, etc.).</small>
        </div>
        <div class="row">
          <div class="field">
            <label for="al-mac">MAC address <span class="opt">(optional)</span></label>
            <input id="al-mac" bind:value={mac} placeholder="aa:bb:cc:dd:ee:ff" />
          </div>
          <div class="field">
            <label for="al-serial">Serial number <span class="opt">(optional)</span></label>
            <input id="al-serial" bind:value={serial} placeholder="e.g. SN-12345678" />
          </div>
        </div>
        <div class="field">
          <label for="al-note">Note <span class="opt">(optional)</span></label>
          <input id="al-note" bind:value={note} placeholder="e.g. lab device for QA team" />
        </div>
        <div class="field">
          <label for="al-profile">Profile <span class="opt">(optional)</span></label>
          <select id="al-profile" bind:value={profile}>
            <option value="">— use default resolution —</option>
            {#each profiles as p (p.name)}
              <option value={p.name}>{p.name}{p.description ? ` — ${p.description}` : ''}</option>
            {/each}
          </select>
          <small>If set, devices matched by this entry are auto-assigned to this profile.</small>
        </div>
        {#if err}<p class="err form-err">{err}</p>{/if}
        <div class="modal-footer">
          <button type="button" onclick={closeModal}>Cancel</button>
          <button type="submit" class="primary" disabled={submitting}>
            {submitting ? 'Adding…' : 'Add entry'}
          </button>
        </div>
      </form>
    </div>
  </div>
{/if}

<style>
  h2 small { color: #8b949e; font-weight: normal; margin-left: 0.5rem; }
  .err { color: #f85149; }
  .page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }
  .page-header h2 { margin: 0; }
  .primary {
    padding: 0.35rem 0.85rem;
    background: var(--accent);
    color: #1a1a1a;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 600;
  }
  .primary:hover { filter: brightness(1.1); }
  .primary:active { filter: brightness(0.9); }
  .primary:disabled { opacity: 0.6; cursor: default; }

  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; font-weight: normal; }
  button.bad { padding: 0.2rem 0.55rem; background: #da3633; color: white; border: none; border-radius: 4px; cursor: pointer; }
  button.bad:hover { background: #f85149; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }

  /* Modal */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }
  .modal {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    width: 100%;
    max-width: 520px;
    padding: 1.25rem 1.5rem 1rem;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
  }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 1rem;
  }
  .modal-header h3 { margin: 0; font-size: 1rem; }
  .close-btn {
    background: none;
    border: none;
    color: #8b949e;
    font-size: 1.4rem;
    cursor: pointer;
    line-height: 1;
    padding: 0 0.25rem;
  }
  .close-btn:hover { color: #e6edf3; }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .row .field { flex: 1 1 10rem; }
  .field { display: flex; flex-direction: column; margin-bottom: 0.75rem; }
  .field label { font-size: 0.85rem; color: #c9d1d9; margin-bottom: 0.25rem; }
  .field .opt { color: #8b949e; font-weight: normal; }
  .field .req { color: #f0883e; font-weight: normal; }
  .field small { color: #8b949e; font-size: 0.75rem; margin-top: 0.25rem; line-height: 1.3; }
  input, select {
    background: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.35rem 0.5rem;
    width: 100%;
    box-sizing: border-box;
    font-size: 0.875rem;
  }
  input:focus, select:focus { outline: none; border-color: #58a6ff; }
  .form-err { margin: 0.25rem 0 0.5rem; font-size: 0.85rem; }
  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 0.75rem;
    padding-top: 0.75rem;
    border-top: 1px solid #30363d;
  }
  .modal-footer button {
    padding: 0.4rem 0.9rem;
    border-radius: 5px;
    border: 1px solid #30363d;
    cursor: pointer;
    background: #21262d;
    color: #e6edf3;
    font-size: 0.875rem;
  }
  .modal-footer button:hover { background: #30363d; }
</style>
