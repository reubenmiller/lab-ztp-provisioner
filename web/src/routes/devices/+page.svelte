<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type Device } from '$lib/api';
  import { confirmDialog } from '$lib/confirm.svelte';

  let items = $state<Device[]>([]);
  let err = $state<string | null>(null);
  let deleting = $state<string | null>(null);

  async function load() {
    try { items = await api.devices(); err = null; } catch (e: any) { err = e.message; }
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

  onMount(load);
</script>

<h2>Enrolled devices <small>{items.length}</small></h2>
{#if err}<p class="err">{err}</p>{/if}

<table>
  <thead><tr><th>Device ID</th><th>Model</th><th>Hostname</th><th>Enrolled</th><th>Last seen</th><th></th></tr></thead>
  <tbody>
    {#each items as d (d.id)}
      <tr>
        <td><code>{d.id}</code></td>
        <td>{d.facts?.model ?? '—'}</td>
        <td>{d.facts?.hostname ?? '—'}</td>
        <td>{new Date(d.enrolled_at).toLocaleString()}</td>
        <td>{new Date(d.last_seen).toLocaleString()}</td>
        <td>
          <button class="bad" disabled={deleting === d.id} onclick={() => remove(d.id)}>
            {deleting === d.id ? '…' : 'Delete'}
          </button>
        </td>
      </tr>
    {/each}
  </tbody>
</table>

<style>
  h2 small { color: #8b949e; font-weight: normal; margin-left: 0.5rem; }
  .err { color: #f85149; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5rem; text-align: left; border-bottom: 1px solid #30363d; }
  th { color: #8b949e; font-weight: normal; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
  button.bad { background: #da3633; color: white; border: 1px solid #30363d; border-radius: 4px; padding: 0.2rem 0.6rem; cursor: pointer; }
  button.bad:disabled { opacity: 0.5; cursor: default; }
</style>
