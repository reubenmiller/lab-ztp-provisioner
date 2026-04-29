<script lang="ts">
  import { getActive, decide } from '$lib/confirm.svelte';

  function onKey(e: KeyboardEvent) {
    if (!getActive()) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      decide(false);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      decide(true);
    }
  }

  const active = $derived(getActive());
</script>

<svelte:window onkeydown={onKey} />

{#if active}
  <div
    class="overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="confirm-title"
    onclick={(e) => { if (e.target === e.currentTarget) decide(false); }}
  >
    <div class="box">
      {#if active.title}<h3 id="confirm-title">{active.title}</h3>{/if}
      <p>{active.message}</p>
      <div class="actions">
        <button class="cancel" onclick={() => decide(false)} type="button">
          {active.cancelLabel ?? 'Cancel'}
        </button>
        <button
          class="confirm"
          class:danger={active.danger}
          onclick={() => decide(true)}
          type="button"
          autofocus
        >
          {active.confirmLabel ?? 'Confirm'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(1, 4, 9, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }
  .box {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    max-width: 28rem;
    width: 90vw;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.4);
  }
  h3 { margin: 0 0 0.5rem; font-size: 1.05rem; }
  p { margin: 0 0 1rem; color: #c9d1d9; white-space: pre-wrap; }
  .actions { display: flex; justify-content: flex-end; gap: 0.5rem; }
  button {
    padding: 0.4rem 1rem;
    border-radius: 4px;
    border: 1px solid #30363d;
    background: #21262d;
    color: #e6edf3;
    cursor: pointer;
    font: inherit;
  }
  button.cancel:hover { background: #30363d; }
  button.confirm { background: #1f6feb; color: #fff; border-color: transparent; }
  button.confirm:hover { background: #388bfd; }
  button.confirm.danger { background: #da3633; }
  button.confirm.danger:hover { background: #f85149; }
</style>
