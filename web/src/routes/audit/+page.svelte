<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type AuditEntry } from '$lib/api';

  let items = $state<AuditEntry[]>([]);
  let err = $state<string | null>(null);
  let filter = $state('');

  function relativeTime(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const s = Math.floor(diff / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h / 24);
    return `${d}d ago`;
  }

  const filtered = $derived(
    filter.trim()
      ? items.filter(e => {
          const q = filter.trim().toLowerCase();
          return (
            e.actor.toLowerCase().includes(q) ||
            e.action.toLowerCase().includes(q) ||
            (e.device_id ?? '').toLowerCase().includes(q) ||
            (e.details ?? '').toLowerCase().includes(q)
          );
        })
      : items
  );

  async function refresh() {
    try { items = await api.audit(200); err = null; } catch (e: any) { err = e.message; }
  }
  onMount(refresh);
</script>

<h2>Audit log <small>{filter ? `${filtered.length} / ${items.length}` : items.length}</small> <button onclick={refresh}>Refresh</button></h2>
{#if err}<p class="err">{err}</p>{/if}

<div class="toolbar">
  <input class="filter-input" bind:value={filter} placeholder="Filter by actor, action, device, or details…" />
</div>

<table>
  <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Device</th><th>Details</th></tr></thead>
  <tbody>
    {#each filtered as e}
      <tr>
        <td class="nowrap" title={new Date(e.at).toLocaleString()}>{relativeTime(e.at)}</td>
        <td class="nowrap">{e.actor}</td>
        <td class="nowrap"><code>{e.action}</code></td>
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
  .toolbar { margin-bottom: 0.75rem; }
  .filter-input {
    width: 100%;
    max-width: 480px;
    padding: 0.35rem 0.6rem;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #e6edf3;
    font-size: 0.875rem;
    box-sizing: border-box;
  }
  .filter-input:focus { outline: none; border-color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; vertical-align: top; }
  th { color: #8b949e; font-weight: normal; }
  .nowrap { white-space: nowrap; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
</style>
