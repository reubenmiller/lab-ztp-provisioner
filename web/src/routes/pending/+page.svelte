<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type PendingRequest, type ProfileSummary } from '$lib/api';
  import HelpPanel from '$lib/components/HelpPanel.svelte';

  let items = $state<PendingRequest[]>([]);
  let profiles = $state<ProfileSummary[]>([]);
  let selected = $state<Record<string, string>>({});
  let err = $state<string | null>(null);
  let stream: EventSource | undefined;

  async function load() {
    try {
      items = await api.pending();
      err = null;
    } catch (e: any) {
      err = e.message;
    }
  }

  async function loadProfiles() {
    try {
      profiles = await api.profiles();
    } catch {
      profiles = [];
    }
  }

  async function approve(id: string) {
    await api.approve(id, selected[id] || undefined);
    delete selected[id];
    await load();
  }
  async function reject(id: string) {
    await api.reject(id);
    delete selected[id];
    await load();
  }

  onMount(() => {
    load();
    loadProfiles();
    stream = api.pendingStream(() => load());
  });
  onDestroy(() => stream?.close());
</script>

<h2>Pending approvals <small>{items.length}</small></h2>

<HelpPanel title="What is the Pending queue?">
  Devices that contacted the server but couldn't auto-enroll land here. The most
  common reasons are <em>no allowlist match</em> and <em>no bootstrap token presented</em>.
  <ul>
    <li>Verify the <strong>fingerprint</strong> matches the device you expect (read it on the device's console or label).</li>
    <li><strong>Approve</strong> issues a signed bundle with the device's manifest; the device applies it and becomes a known peer.</li>
    <li><strong>Reject</strong> records the decision in the audit log and removes the entry. Re-enrollment requires a fresh request.</li>
    <li>Not sure which onboarding method to use? Open the <a href="/onboard">wizard</a>.</li>
  </ul>
</HelpPanel>

{#if err}<p class="err">{err}</p>{/if}

{#if items.length === 0}
  <p class="empty">No devices waiting for approval.</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>Device ID</th><th>Fingerprint</th><th>OS</th><th>Model</th><th>MAC</th><th>Reason</th><th>First seen</th><th>Profile</th><th></th>
      </tr>
    </thead>
    <tbody>
      {#each items as p (p.id)}
        <tr>
          <td><code>{p.device_id}</code></td>
          <td><code>{p.fingerprint}</code></td>
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
            <select bind:value={selected[p.id]} title="Profile to assign on approval (optional — leave as auto to use selectors / default)">
              <option value="">auto</option>
              {#each profiles as prof (prof.name)}
                <option value={prof.name}>{prof.name}</option>
              {/each}
            </select>
          </td>
          <td>
            <button class="ok" onclick={() => approve(p.id)}>Approve</button>
            <button class="bad" onclick={() => reject(p.id)}>Reject</button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}

<style>
  h2 small { color: #8b949e; font-weight: normal; margin-left: 0.5rem; }
  .err { color: #f85149; }
  .empty { color: #8b949e; font-style: italic; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; font-weight: normal; }
  button { margin-right: 0.25rem; padding: 0.25rem 0.75rem; border-radius: 4px; border: 1px solid #30363d; cursor: pointer; }
  button.ok { background: #238636; color: white; }
  button.bad { background: #da3633; color: white; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
  select {
    background: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.2rem 0.4rem;
  }
</style>
