<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type AllowlistEntry, type ProfileSummary } from '$lib/api';
  import HelpPanel from '$lib/components/HelpPanel.svelte';

  let items = $state<AllowlistEntry[]>([]);
  let profiles = $state<ProfileSummary[]>([]);
  let err = $state<string | null>(null);
  let device_id = $state(''), mac = $state(''), serial = $state(''), note = $state(''), profile = $state('');

  async function refresh() {
    try {
      items = await api.allowlist();
      profiles = await api.profiles();
      err = null;
    } catch (e: any) { err = e.message; }
  }
  async function add(e: Event) {
    e.preventDefault();
    if (!device_id) return;
    await api.addAllow({ device_id, mac, serial, note, profile });
    device_id = mac = serial = note = profile = '';
    await refresh();
  }
  async function remove(id: string) {
    await api.removeAllow(id);
    await refresh();
  }
  onMount(refresh);
</script>

<h2>Allowlist <small>{items.length}</small></h2>

<HelpPanel title="When should I use the allowlist?">
  The allowlist auto-approves a first-time enrollment when the device's facts
  match an entry. Use it when you know identifiers <em>before</em> the device boots.
  <ul>
    <li><strong>device id (required)</strong> — what the agent will report (e.g. <code>$(hostname)</code> or <code>$(cat /etc/machine-id)</code>).</li>
    <li><strong>MAC / serial</strong> — at least one is recommended; otherwise the entry matches by device-id alone.</li>
    <li>The match is consumed on first successful enrollment (audit logged); subsequent enrollments by the same pubkey skip the allowlist.</li>
    <li>For ad-hoc deploys without identifiers, prefer <a href="/tokens">bootstrap tokens</a> or manual <a href="/pending">approval</a>.</li>
  </ul>
</HelpPanel>

{#if err}<p class="err">{err}</p>{/if}

<form onsubmit={add}>
  <fieldset>
    <legend>Add an allowlist entry</legend>

    <div class="field">
      <label for="al-device">Device ID <span class="req">(required)</span></label>
      <input id="al-device" bind:value={device_id} placeholder="e.g. lab-device-05" required />
      <small>Identifier the agent will report on enrollment (hostname, machine-id, etc.).</small>
    </div>

    <div class="row">
      <div class="field">
        <label for="al-mac">MAC address <span class="opt">(optional)</span></label>
        <input id="al-mac" bind:value={mac} placeholder="aa:bb:cc:dd:ee:ff" />
        <small>Recommended for stronger matching against device facts.</small>
      </div>

      <div class="field">
        <label for="al-serial">Serial number <span class="opt">(optional)</span></label>
        <input id="al-serial" bind:value={serial} placeholder="e.g. SN-12345678" />
        <small>Hardware serial reported by the agent, if available.</small>
      </div>
    </div>

    <div class="field">
      <label for="al-note">Note <span class="opt">(optional)</span></label>
      <input id="al-note" bind:value={note} placeholder="e.g. lab device for QA team" />
      <small>Free-form description shown in audit logs and the table below.</small>
    </div>

    <div class="field">
      <label for="al-profile">Profile <span class="opt">(optional)</span></label>
      <select id="al-profile" bind:value={profile}>
        <option value="">— use default resolution —</option>
        {#each profiles as p (p.name)}
          <option value={p.name}>{p.name}{p.description ? ` — ${p.description}` : ''}</option>
        {/each}
      </select>
      <small>If set, devices matched by this entry are auto-assigned to this profile on enrollment.</small>
    </div>

    <button type="submit">Add entry</button>
  </fieldset>
</form>

<table>
  <thead><tr><th>Device ID</th><th>MAC</th><th>Serial</th><th>Note</th><th>Profile</th><th>Created</th><th></th></tr></thead>
  <tbody>
    {#each items as e (e.device_id)}
      <tr>
        <td><code>{e.device_id}</code></td>
        <td>{e.mac ?? ''}</td>
        <td>{e.serial ?? ''}</td>
        <td>{e.note ?? ''}</td>
        <td>{e.profile ? `${e.profile}` : ''}</td>
        <td>{new Date(e.created_at).toLocaleString()}</td>
        <td><button class="bad" onclick={() => remove(e.device_id)}>Remove</button></td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  h2 small { color: #8b949e; font-weight: normal; margin-left: 0.5rem; }
  .err { color: #f85149; }
  form { margin-bottom: 1.25rem; }
  fieldset {
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.75rem 1rem 1rem;
    background: #0d1117;
  }
  legend { color: #8b949e; padding: 0 0.4rem; font-size: 0.9rem; }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .row .field { flex: 1 1 12rem; }
  .field { display: flex; flex-direction: column; margin-bottom: 0.75rem; }
  .field label { font-size: 0.85rem; color: #c9d1d9; margin-bottom: 0.25rem; }
  .field .opt { color: #8b949e; font-weight: normal; }
  .field .req { color: #f0883e; font-weight: normal; }
  .field small { color: #8b949e; font-size: 0.75rem; margin-top: 0.25rem; line-height: 1.3; }
  input { background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: 4px; padding: 0.35rem 0.5rem; width: 100%; box-sizing: border-box; }
  input:focus { outline: none; border-color: #58a6ff; }
  select { background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: 4px; padding: 0.35rem 0.5rem; width: 100%; box-sizing: border-box; }
  select:focus { outline: none; border-color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; font-weight: normal; }
  button { padding: 0.25rem 0.75rem; border-radius: 4px; border: 1px solid #30363d; cursor: pointer; background: #21262d; color: #e6edf3; }
  button.bad { background: #da3633; color: white; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
</style>
