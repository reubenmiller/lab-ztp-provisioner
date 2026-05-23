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

<div class="table-wrap">
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
</div>
<div class="card-list">
  {#each filtered as e}
    <div class="a-card">
      <div class="a-card-head">
        <span class="a-actor">{e.actor}</span>
        <span class="a-time" title={new Date(e.at).toLocaleString()}>{relativeTime(e.at)}</span>
      </div>
      <div class="a-card-body">
        <code class="a-action">{e.action}</code>
        {#if e.device_id}<div class="a-row"><span class="a-label">Device</span><span>{e.device_id}</span></div>{/if}
        {#if e.details}<div class="a-row"><span class="a-label">Details</span><span class="a-details">{e.details}</span></div>{/if}
      </div>
    </div>
  {/each}
</div>

<style>
  h2 small { color: var(--text-muted); font-weight: normal; margin-left: 0.5rem; }
  h2 button { float: right; padding: 0.25rem 0.75rem; border-radius: 4px; border: 1px solid var(--border); cursor: pointer; background: var(--surface); color: var(--text); }
  .err { color: var(--danger); }
  .toolbar { margin-bottom: 0.75rem; }
  .filter-input {
    width: 100%;
    max-width: 480px;
    padding: 0.35rem 0.6rem;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    font-size: 0.875rem;
    box-sizing: border-box;
  }
  .filter-input:focus { outline: none; border-color: var(--accent); }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { color: var(--text-muted); font-weight: normal; }
  .nowrap { white-space: nowrap; }
  code { background: var(--code-bg); padding: 0.1rem 0.3rem; border-radius: 3px; }

  /* Card list (mobile) */
  .card-list { display: none; }
  @media (max-width: 900px) {
    .table-wrap { display: none; }
    .card-list  { display: flex; flex-direction: column; gap: 0.5rem; }
  }
  .a-card {
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    background: var(--surface);
  }
  .a-card-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 0.55rem 0.8rem;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    gap: 0.5rem;
  }
  .a-actor { font-weight: 600; font-size: 0.925rem; }
  .a-time { font-size: 0.8rem; color: var(--text-muted); white-space: nowrap; }
  .a-card-body {
    padding: 0.5rem 0.8rem;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    font-size: 0.875rem;
  }
  .a-action { align-self: flex-start; }
  .a-row { display: flex; gap: 0.5rem; align-items: baseline; flex-wrap: wrap; }
  .a-label {
    font-size: 0.6rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    color: var(--text-dim);
    white-space: nowrap;
  }
  .a-details { color: var(--text-muted); }
</style>
