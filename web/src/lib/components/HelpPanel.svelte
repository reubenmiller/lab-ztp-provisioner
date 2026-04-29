<script lang="ts">
  // Collapsible "What is this page for?" panel reused across admin views.
  // Keeps inline guidance close to the action, so operators new to ZTP can
  // discover the right workflow without leaving the page.
  let { title = 'What is this?', open = $bindable(false), children } = $props<{
    title?: string;
    open?: boolean;
    children: any;
  }>();
</script>

<div class="help" class:open>
  <button class="toggle" onclick={() => (open = !open)} aria-expanded={open}>
    <span class="icon">{open ? '▾' : '▸'}</span>
    <span>{title}</span>
  </button>
  {#if open}
    <div class="body">{@render children()}</div>
  {/if}
</div>

<style>
  .help {
    border: 1px solid #30363d;
    border-radius: 6px;
    background: #161b22;
    margin-bottom: 1rem;
  }
  .toggle {
    width: 100%;
    text-align: left;
    background: transparent;
    border: 0;
    color: #58a6ff;
    padding: 0.5rem 0.75rem;
    cursor: pointer;
    font: inherit;
  }
  .icon { display: inline-block; width: 1rem; color: #8b949e; }
  .body {
    padding: 0 1rem 0.75rem 1.75rem;
    color: #c9d1d9;
    line-height: 1.5;
  }
  .body :global(code) {
    background: #0d1117;
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
  }
  .body :global(a) { color: #58a6ff; }
  .body :global(ul) { margin: 0.5rem 0; padding-left: 1.25rem; }
  .body :global(li) { margin: 0.25rem 0; }
</style>
