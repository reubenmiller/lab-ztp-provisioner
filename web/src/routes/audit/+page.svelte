<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type AuditEntry } from '$lib/api';

  let items = $state<AuditEntry[]>([]);
  let err = $state<string | null>(null);

  async function refresh() {
    try { items = await api.audit(200); err = null; } catch (e: any) { err = e.message; }
  }
  onMount(refresh);
</script>

<h2>Audit log <small>{items.length}</small> <button onclick={refresh}>Refresh</button></h2>
{#if err}<p class="err">{err}</p>{/if}

<table>
  <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Device</th><th>Details</th></tr></thead>
  <tbody>
    {#each items as e}
      <tr>
        <td>{new Date(e.at).toLocaleString()}</td>
        <td>{e.actor}</td>
        <td><code>{e.action}</code></td>
        <td>{e.device_id ?? ''}</td>
        <td>{e.details ?? ''}</td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  h2 small { color: #8b949e; font-weight: normal; margin-left: 0.5rem; }
  h2 button { float: right; padding: 0.25rem 0.75rem; border-radius: 4px; border: 1px solid #30363d; cursor: pointer; background: #21262d; color: #e6edf3; }
  .err { color: #f85149; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; vertical-align: top; }
  th { color: #8b949e; font-weight: normal; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
</style>
