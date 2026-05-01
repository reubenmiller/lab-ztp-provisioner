<script lang="ts">
  import { goto } from '$app/navigation';
  import { getToasts, removeToast } from '$lib/toasts.svelte';

  const toasts = $derived(getToasts());

  function kindIcon(kind: string): string {
    switch (kind) {
      case 'enrolled': return '✓';
      case 'pending':  return '⏳';
      case 'error':    return '✕';
      default:         return 'ℹ';
    }
  }

  function handleClick(id: number, href?: string) {
    removeToast(id);
    if (href) goto(href);
  }
</script>

<div class="toast-stack" aria-live="polite" aria-atomic="false">
  {#each toasts as t (t.id)}
    <div
      class="toast toast-{t.kind}"
      role="status"
      onclick={() => handleClick(t.id, t.href)}
      onkeydown={(e) => e.key === 'Enter' && handleClick(t.id, t.href)}
      tabindex="0"
      title={t.href ? 'Click to navigate' : undefined}
    >
      <div class="toast-header">
        <span class="toast-icon" aria-hidden="true">{kindIcon(t.kind)}</span>
        <strong class="toast-title">{t.title}</strong>
        <button
          class="toast-close"
          onclick={(e) => { e.stopPropagation(); removeToast(t.id); }}
          aria-label="Dismiss notification"
          type="button"
        >×</button>
      </div>
      {#if t.body}
        <p class="toast-body">{t.body}</p>
      {/if}
    </div>
  {/each}
</div>

<style>
  .toast-stack {
    position: fixed;
    bottom: 1.25rem;
    right: 1.25rem;
    display: flex;
    flex-direction: column-reverse;
    gap: 0.5rem;
    z-index: 2000;
    max-width: 22rem;
    pointer-events: none;
  }

  .toast {
    pointer-events: all;
    background: #161b22;
    border: 1px solid #30363d;
    border-left-width: 3px;
    border-radius: 6px;
    padding: 0.65rem 0.75rem;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    cursor: default;
    animation: slide-in 0.18s ease;
  }
  .toast[title] { cursor: pointer; }
  .toast:hover { border-color: #58a6ff; }

  .toast-enrolled { border-left-color: #238636; }
  .toast-pending  { border-left-color: #d29922; }
  .toast-error    { border-left-color: #f85149; }
  .toast-info     { border-left-color: #1f6feb; }

  .toast-header {
    display: flex;
    align-items: center;
    gap: 0.45rem;
  }
  .toast-icon {
    font-size: 0.85rem;
    flex-shrink: 0;
  }
  .toast-enrolled .toast-icon { color: #3fb950; }
  .toast-pending  .toast-icon { color: #d29922; }
  .toast-error    .toast-icon { color: #f85149; }
  .toast-info     .toast-icon { color: #58a6ff; }

  .toast-title {
    flex: 1;
    font-size: 0.85rem;
    color: #e6edf3;
  }
  .toast-close {
    background: none;
    border: none;
    color: #6e7681;
    cursor: pointer;
    padding: 0 0.1rem;
    font-size: 1.1rem;
    line-height: 1;
    flex-shrink: 0;
  }
  .toast-close:hover { color: #e6edf3; }

  .toast-body {
    margin: 0.3rem 0 0 1.3rem;
    font-size: 0.78rem;
    color: #8b949e;
  }

  @keyframes slide-in {
    from { opacity: 0; transform: translateX(1rem); }
    to   { opacity: 1; transform: translateX(0); }
  }
</style>
