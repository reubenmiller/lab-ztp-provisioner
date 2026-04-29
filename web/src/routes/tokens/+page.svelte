<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type BootstrapToken, type ProfileSummary } from '$lib/api';
  import HelpPanel from '$lib/components/HelpPanel.svelte';

  let items = $state<BootstrapToken[]>([]);
  let profiles = $state<ProfileSummary[]>([]);
  let err = $state<string | null>(null);
  let lastSecret = $state<string | null>(null);
  let device_id = $state(''), max_uses = $state(1), ttl_hours = $state(24), profile = $state('');

  async function refresh() {
    try {
      items = await api.tokens();
      profiles = await api.profiles();
      err = null;
    } catch (e: any) { err = e.message; }
  }
  async function create(e: Event) {
    e.preventDefault();
    const r = await api.createToken({
      device_id: device_id || undefined,
      profile: profile || undefined,
      max_uses,
      ttl_seconds: ttl_hours > 0 ? ttl_hours * 3600 : undefined
    });
    lastSecret = r.secret;
    await refresh();
  }
  async function revoke(id: string) {
    await api.revokeToken(id);
    await refresh();
  }
  onMount(refresh);
</script>

<h2>Bootstrap tokens <small>{items.length}</small></h2>

<HelpPanel title="When should I use a bootstrap token?">
  A bootstrap token is a short-lived shared secret an agent presents on first
  contact, allowing the server to auto-approve without prior knowledge of the
  device's identity.
  <ul>
    <li>Leave <strong>device id</strong> blank for a generic token (any agent that knows the secret can claim it).</li>
    <li>Set <strong>device id</strong> to bind the token to a specific identity — useful for imaging pipelines.</li>
    <li><strong>max uses</strong> = <code>1</code> for one-shot tokens (recommended); higher for batch deployments.</li>
    <li><strong>TTL</strong> in hours. Set <code>0</code> to keep until manually revoked. Short TTLs (≤ 24h) are the safe default.</li>
    <li>The secret is shown <em>once</em> on creation. If you lose it, revoke and regenerate.</li>
  </ul>
</HelpPanel>

{#if err}<p class="err">{err}</p>{/if}

<form onsubmit={create}>
  <fieldset>
    <legend>Generate a new bootstrap token</legend>

    <div class="field">
      <label for="tok-device">Bind to device ID <span class="opt">(optional)</span></label>
      <input id="tok-device" bind:value={device_id} placeholder="e.g. lab-device-05" />
      <small>Leave blank for a generic token any agent can claim.</small>
    </div>

    <div class="row">
      <div class="field">
        <label for="tok-uses">Max uses</label>
        <input id="tok-uses" type="number" bind:value={max_uses} min="1" />
        <small>Number of agents that can claim this token. <code>1</code> = one-shot (recommended).</small>
      </div>

      <div class="field">
        <label for="tok-ttl">TTL <span class="opt">(hours)</span></label>
        <input id="tok-ttl" type="number" bind:value={ttl_hours} min="0" />
        <small>How long the token remains valid. <code>0</code> = never expires (revoke manually).</small>
      </div>
    </div>

    <div class="field">
      <label for="tok-profile">Profile <span class="opt">(optional)</span></label>
      <select id="tok-profile" bind:value={profile}>
        <option value="">— use default resolution —</option>
        {#each profiles as p (p.name)}
          <option value={p.name}>{p.name}{p.description ? ` — ${p.description}` : ''}</option>
        {/each}
      </select>
      <small>If set, devices that claim this token are auto-assigned to this profile.</small>
    </div>

    <button type="submit">Generate token</button>
  </fieldset>
</form>

{#if lastSecret}
  <p class="secret">
    <strong>Token (copy now — it will not be shown again):</strong>
    <code>{lastSecret}</code>
    <button onclick={() => navigator.clipboard.writeText(lastSecret!)}>Copy</button>
  </p>
{/if}

<table>
  <thead><tr><th>ID</th><th>Bound device</th><th>Profile</th><th>Uses</th><th>Expires</th><th>Created</th><th></th></tr></thead>
  <tbody>
    {#each items as t (t.id)}
      <tr>
        <td><code>{t.id}</code></td>
        <td>{t.device_id ?? '—'}</td>
        <td>{t.profile ?? ''}</td>
        <td>{t.uses}{t.max_uses > 0 ? `/${t.max_uses}` : ''}</td>
        <td>{t.expires_at ? new Date(t.expires_at).toLocaleString() : '—'}</td>
        <td>{new Date(t.created_at).toLocaleString()}</td>
        <td><button class="bad" onclick={() => revoke(t.id)}>Revoke</button></td>
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
  .secret { background: #1f2a37; padding: 0.5rem 1rem; border-radius: 4px; border-left: 3px solid #d29922; }
</style>
