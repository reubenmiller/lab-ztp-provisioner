<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type ProfileSummary } from '$lib/api';
  import HelpPanel from '$lib/components/HelpPanel.svelte';
  import { confirmDialog } from '$lib/confirm.svelte';
  import { wailsSaveFile } from '$lib/runtime';

  let items = $state<ProfileSummary[]>([]);
  let err = $state<string | null>(null);
  let reloadMsg = $state<string | null>(null);
  let newName = $state('');
  let newDesc = $state('');

  async function refresh() {
    try { items = await api.profiles(); err = null; } catch (e: any) { err = e.message; }
  }

  async function reload() {
    reloadMsg = null;
    try {
      const r = await api.reloadProfiles();
      reloadMsg = `Reloaded ${r.loaded} file profile(s).`;
      await refresh();
    } catch (e: any) {
      err = e.message;
    }
  }

  async function create(e: Event) {
    e.preventDefault();
    if (!newName) return;
    try {
      await api.createProfile({ name: newName, description: newDesc });
      newName = ''; newDesc = '';
      await refresh();
    } catch (ex: any) { err = ex.message; }
  }

  async function exportProfile(name: string) {
    const url = api.exportProfileURL(name);
    const save = wailsSaveFile();
    if (save) {
      try {
        const res = await fetch(url);
        if (!res.ok) {
          err = `Export failed: ${res.status} ${res.statusText}`;
          return;
        }
        const text = await res.text();
        await save(`${name}.yaml`, text);
      } catch (e: any) {
        err = `Export failed: ${e.message ?? e}`;
      }
      return;
    }
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.yaml`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  async function del(name: string) {
    const ok = await confirmDialog({
      title: 'Delete profile',
      message: `Delete profile "${name}"? Devices using it will fall back to the default profile on next enrollment.`,
      confirmLabel: 'Delete',
      danger: true
    });
    if (!ok) return;
    try { await api.deleteProfile(name); await refresh(); } catch (e: any) { err = e.message; }
  }

  onMount(refresh);
</script>

<h2>Profiles <small>{items.length}</small></h2>

<HelpPanel title="What is a profile?">
  A <strong>profile</strong> is the bundle of payload-provider configuration
  (wifi networks, c8y issuer, ssh keys, files, hooks) that the server hands
  to a device at enrollment. Each device is matched to exactly one.
  <ul>
    <li><strong>file</strong> profiles live in <code>profiles_dir</code> on disk and are managed in git. They are <em>read-only</em> here; edit the YAML and reload (<code>kill -HUP</code> the server, or click <em>Reload from disk</em>).</li>
    <li><strong>db</strong> profiles are created and edited from this UI.</li>
    <li>Resolution precedence: device override → sticky <code>profile_name</code> → verifier hint (allowlist / token) → selector match → <code>default_profile</code> → literal <code>default</code>.</li>
    <li>Sensitive fields (wifi passwords, c8y static tokens, hook script bodies, file contents) are redacted in API responses and shown as <code>&lt;redacted&gt;</code>.</li>
  </ul>
</HelpPanel>

{#if err}<p class="err">{err}</p>{/if}
{#if reloadMsg}<p class="ok">{reloadMsg}</p>{/if}

<div class="actions">
  <button onclick={reload} title="Re-read profiles_dir from disk">Reload from disk</button>
</div>

<form onsubmit={create}>
  <fieldset>
    <legend>Create a DB-backed profile</legend>
    <div class="row">
      <div class="field">
        <label for="prof-name">Name <span class="req">(required)</span></label>
        <input id="prof-name" bind:value={newName} placeholder="e.g. lab-a" required pattern="[a-z0-9][a-z0-9_-]*" />
        <small>Lowercase letters, digits, dash and underscore. The empty profile is created and you edit its payload on the next page.</small>
      </div>
      <div class="field">
        <label for="prof-desc">Description <span class="opt">(optional)</span></label>
        <input id="prof-desc" bind:value={newDesc} placeholder="e.g. Lab devices, US-East" />
      </div>
    </div>
    <button type="submit">Create</button>
  </fieldset>
</form>

<table>
  <thead><tr><th>Name</th><th>Source</th><th>Description</th><th>Priority</th><th>Updated</th><th></th></tr></thead>
  <tbody>
    {#each items as p (p.name)}
      <tr>
        <td><a href={`/profiles/${encodeURIComponent(p.name)}`}><code>{p.name}</code></a></td>
        <td><span class="src src-{p.source}">{p.source}</span></td>
        <td>{p.description ?? ''}</td>
        <td>{p.priority ?? 0}</td>
        <td>{p.updated_at ? new Date(p.updated_at).toLocaleString() : ''}</td>
        <td class="row-actions">
          <button class="export" onclick={() => exportProfile(p.name)} title="Download as YAML (secrets redacted)">Export</button>
          {#if p.source === 'db'}
            <button class="bad" onclick={() => del(p.name)}>Delete</button>
          {:else}
            <span class="muted" title="Edit the YAML in profiles_dir and reload">read-only</span>
          {/if}
        </td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  h2 small { color: #8b949e; font-weight: normal; margin-left: 0.5rem; }
  .err { color: #f85149; }
  .ok { color: #3fb950; }
  .actions { margin-bottom: 1rem; }
  form { margin-bottom: 1.25rem; }
  fieldset { border: 1px solid #30363d; border-radius: 6px; padding: 0.75rem 1rem 1rem; background: #0d1117; }
  legend { color: #8b949e; padding: 0 0.4rem; font-size: 0.9rem; }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; }
  .row .field { flex: 1 1 14rem; }
  .field { display: flex; flex-direction: column; margin-bottom: 0.75rem; }
  .field label { font-size: 0.85rem; color: #c9d1d9; margin-bottom: 0.25rem; }
  .field .opt { color: #8b949e; }
  .field .req { color: #f0883e; }
  .field small { color: #8b949e; font-size: 0.75rem; margin-top: 0.25rem; }
  input { background: #0d1117; color: #e6edf3; border: 1px solid #30363d; border-radius: 4px; padding: 0.35rem 0.5rem; width: 100%; box-sizing: border-box; }
  input:focus { outline: none; border-color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; font-weight: normal; }
  button { padding: 0.25rem 0.75rem; border-radius: 4px; border: 1px solid #30363d; cursor: pointer; background: #21262d; color: #e6edf3; }
  button.bad { background: #da3633; color: white; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .src { padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.75rem; }
  .src-file { background: #1f6feb33; color: #58a6ff; }
  .src-db { background: #3fb95033; color: #3fb950; }
  .muted { color: #8b949e; font-size: 0.85rem; }
  .row-actions { display: flex; gap: 0.4rem; align-items: center; }
  .export {
    background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px;
    padding: 0.25rem 0.6rem; text-decoration: none; font-size: 0.85rem;
  }
  .export:hover { background: #30363d; text-decoration: none; }
</style>
