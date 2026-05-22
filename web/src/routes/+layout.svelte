<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { page } from '$app/stores';
  import { getToken, setToken, api, type PendingRequest, type Device } from '$lib/api';
  import { detect, type RuntimeInfo, type DesktopRuntimeInfo } from '$lib/runtime';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toasts from '$lib/components/Toasts.svelte';
  import BleRelayController from '$lib/components/BleRelayController.svelte';
  import { addToast } from '$lib/toasts.svelte';
  import { bleRelay } from '$lib/ble-relay.svelte';

  let { children } = $props();

  type NavItem = { href: string; label: string; icon: string; exact?: boolean };
  type NavGroup = { label: string | null; items: NavItem[] };

  const navGroups: NavGroup[] = [
    {
      label: null,
      items: [
        { href: '/pending', label: 'Fleet', icon: 'monitor' },
      ],
    },
    {
      label: 'Config',
      items: [
        { href: '/allowlist', label: 'Allowlist',        icon: 'shield-check' },
        { href: '/config',    label: 'Config / Secrets', icon: 'settings'     },
      ],
    },
    {
      label: null,
      items: [
        { href: '/audit', label: 'Audit', icon: 'clipboard-list' },
      ],
    },
  ];

  // Inline SVG path data — all Heroicons / Feather, stroke-only, viewBox 0 0 24 24.
  // All values are static compile-time constants; {@html icon()} is safe here.
  const ICON_PATHS: Record<string, string> = {
    inbox: `<path stroke-linecap="round" stroke-linejoin="round" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>`,
    monitor: `<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4" stroke-linecap="round"/>`,
    'shield-check': `<path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>`,
    key: `<path stroke-linecap="round" stroke-linejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>`,
    settings: `<path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>`,
    'user-plus': `<path stroke-linecap="round" stroke-linejoin="round" d="M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z"/>`,
    bluetooth: `<polyline points="6.5 6.5 17.5 17.5 12 23 12 1 17.5 6.5 6.5 17.5"/>`,
    'clipboard-list': `<path stroke-linecap="round" stroke-linejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/>`,
    lock: `<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4" stroke-linecap="round"/>`,
    'chevron-left': `<polyline points="15 18 9 12 15 6"/>`,
    'chevron-right': `<polyline points="9 18 15 12 9 6"/>`,
      online: `<circle cx="12" cy="12" r="7" fill="#00bb00" stroke="none" />`,
      offline: `<circle cx="12" cy="12" r="7" fill="#9ca3af" stroke="none" />`,
  };

  function icon(name: string): string {
    return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] ?? ''}</svg>`;
  }

  let pendingCount = $state(0);
  let sidebarExpanded = $state(true);
  let needsLogin     = $state(false);
  let tokenInput     = $state('');
  let tokenError     = $state('');
  let runtimeInfo    = $state<RuntimeInfo | null>(null);
  let sseStream: EventSource | null = null;

  const desktopRuntimeInfo = $derived(
    runtimeInfo?.mode === 'desktop' ? (runtimeInfo as DesktopRuntimeInfo) : null
  );

  function handlePendingChanged(e: Event) {
    pendingCount = (e as CustomEvent<{ count: number }>).detail.count;
  }

  function handleAuthRequired() {
    if (runtimeInfo?.mode === 'desktop') {
      console.warn('Auth required in desktop mode — engine may have restarted');
      return;
    }
    needsLogin = true;
  }

  onMount(() => {
    const saved = localStorage.getItem('ztp-sidebar-expanded');
    if (saved !== null) sidebarExpanded = saved !== 'false';

    detect().then((info) => {
      runtimeInfo = info;
      if (info.mode === 'desktop') {
        const desktop = info as { token?: string };
        if (desktop.token) setToken(desktop.token);
        needsLogin = false;
      } else if (!getToken()) {
        needsLogin = true;
      }
      // Start SSE only after we know the token. In browser mode a saved
      // token is already in localStorage; in desktop mode setToken() above
      // just populated it. Either way getToken() is now valid.
      if (getToken()) {
        startSSE();
        api.pending().then(ps => { pendingCount = ps.length; }).catch(() => {});
      }
    }).catch((err) => {
      console.warn('runtime detect failed', err);
      if (!getToken()) needsLogin = true;
      // If we already have a token (browser mode with saved token) still start SSE.
      if (getToken()) startSSE();
    });
    window.addEventListener('ztp:auth-required', handleAuthRequired);
    window.addEventListener('ztp:pending-changed', handlePendingChanged);

    return () => {
      window.removeEventListener('ztp:auth-required', handleAuthRequired);
      window.removeEventListener('ztp:pending-changed', handlePendingChanged);
      sseStream?.close();
    };
  });

  function toggleSidebar() {
    sidebarExpanded = !sidebarExpanded;
    localStorage.setItem('ztp-sidebar-expanded', String(sidebarExpanded));
  }

  function saveToken(e: SubmitEvent) {
    e.preventDefault();
    const t = tokenInput.trim();
    if (!t) { tokenError = 'Token must not be empty.'; return; }
    setToken(t);
    tokenInput = '';
    tokenError = '';
    needsLogin = false;
    startSSE();
  }

  function changeToken() { needsLogin = true; }

  function isActive(href: string, exact?: boolean): boolean {
    if (exact) return $page.url.pathname === href;
    return $page.url.pathname.startsWith(href);
  }

  function startSSE() {
    sseStream?.close();
    sseStream = api.pendingStream(
      (p: PendingRequest) => {
        pendingCount++;
        window.dispatchEvent(new CustomEvent('ztp:pending', { detail: p }));
        addToast({
          kind: 'pending',
          title: 'Device needs approval',
          body: p.device_id || p.fingerprint,
          href: '/pending',
          duration: 8000
        });
      },
      (d: Device) => {
        if (pendingCount > 0) pendingCount--;
        window.dispatchEvent(new CustomEvent('ztp:enrolled', { detail: d }));
        addToast({
          kind: 'enrolled',
          title: 'Device enrolled',
          body: d.id,
          href: '/pending',
          duration: 6000
        });
      }
    );
  }
</script>

{#if needsLogin}
  <div class="login-overlay">
    <form class="login-box" onsubmit={saveToken}>
      <h2>ZTP Admin — sign in</h2>
      <p>Enter your admin token to continue. The token is stored only in your browser's local storage.</p>
      <label for="token-input">Admin token</label>
      <input
        id="token-input"
        type="password"
        autocomplete="off"
        bind:value={tokenInput}
        placeholder="Paste your ZTP_ADMIN_TOKEN here"
      />
      {#if tokenError}<p class="err">{tokenError}</p>{/if}
      <button type="submit">Save &amp; continue</button>
    </form>
  </div>
{:else}
  <div class="app-shell">
    <!-- ─── Left sidebar ─────────────────────────────────────────────── -->
    <aside class="sidebar" class:collapsed={!sidebarExpanded} aria-label="Main navigation">

      <!-- Brand / logo row -->
      <div class="brand">
        <span class="brand-mark">ZTP</span>
        <span class="brand-name">Admin</span>
      </div>

      <!-- Nav groups -->
      <nav class="sidebar-nav">
        {#each navGroups as group, gi (gi)}
          {#if group.label}
            <span class="group-label">{group.label}</span>
          {:else if gi > 0}
            <hr class="group-sep" aria-hidden="true" />
          {/if}
          {#each group.items as item (item.href)}
            <a
              href={item.href}
              class:active={isActive(item.href, item.exact)}
              title={!sidebarExpanded ? item.label : undefined}
            >
              {@html icon(item.icon)}
              <span class="nav-label">{item.label}</span>
              {#if item.href === '/pending' && pendingCount > 0}
                <span class="pending-badge" title="{pendingCount} device(s) awaiting approval">{pendingCount}</span>
              {/if}
            </a>
          {/each}
        {/each}
      </nav>

      <!-- Footer: BLE toggle + mDNS + token + collapse -->
      <div class="sidebar-footer">
        <button
          class="sidebar-btn ble-toggle-btn"
          class:ble-on={bleRelay.enabled}
          type="button"
          onclick={() => {
            if (bleRelay.enabled) {
              bleRelay.enabled = false;
              localStorage.setItem('ztp-ble-relay-enabled', 'false');
              bleRelay.stop?.();
            } else {
              bleRelay.enabled = true;
              localStorage.setItem('ztp-ble-relay-enabled', 'true');
              bleRelay.start?.();
            }
          }}
          title={bleRelay.enabled ? 'BLE relay on - click to turn off' : 'BLE relay off - click to turn on'}
        >
          {@html icon('bluetooth')}
          <span class="nav-label">BLE</span>
          <span class="ble-pill" class:on={bleRelay.enabled}></span>
        </button>
        {#if runtimeInfo}
          <button
            class="sidebar-btn"
            class:mdns-on={runtimeInfo.mdns}
            type="button"
            aria-pressed={runtimeInfo.mdns}
            title={runtimeInfo.mdns ? 'mDNS active — _ztp._tcp is advertised on the LAN' : 'mDNS inactive — devices cannot auto-discover this server'}
            tabindex="-1"
            style="pointer-events: none; user-select: none; cursor: default;"
            disabled
          >
            {@html icon(runtimeInfo.mdns ? 'online' : 'offline')}
            <span class="nav-label mdns-label">mDNS {runtimeInfo.mdns ? 'active' : 'inactive'}</span>
          </button>
        {/if}
        {#if runtimeInfo?.mode !== 'desktop'}
          <button
            class="sidebar-btn"
            onclick={changeToken}
            title={!sidebarExpanded ? 'Change admin token' : undefined}
          >
            {@html icon('lock')}
            <span class="nav-label">Change token</span>
          </button>
        {/if}
        <button
          class="sidebar-btn toggle-btn"
          onclick={toggleSidebar}
          title={sidebarExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
        >
          {@html icon(sidebarExpanded ? 'chevron-left' : 'chevron-right')}
          <span class="nav-label">Collapse</span>
        </button>
      </div>
    </aside>

    <!-- ─── Page body ──────────────────────────────────────────────── -->
    <div class="page-body">
      <main>{@render children()}</main>
    </div>
  </div>
{/if}

<ConfirmDialog />
<Toasts />
<BleRelayController />

<style>
  /* ── Cumulocity-branded CSS custom properties ───────────────────── */
  :global(:root) {
    --bg:          #212121;
    --surface:     #2a2a2a;
    --surface-2:   #1e1e1e;
    --hover:       #333333;
    --border:      #3d3d3d;
    --accent:      #ffbe00;
    --accent-dim:  rgba(255, 190, 0, 0.12);
    --accent-dim2: rgba(255, 190, 0, 0.2);
    --text:        #f0f0f0;
    --text-muted:  #999999;
    --text-dim:    #777777;
    --success:     #3fb950;
    --danger:      #f85149;
    --warning:     #e3b341;
    --code-bg:     #1a1a1a;
  }

  /* ── Reset / globals ─────────────────────────────────────────────── */
  :global(html, body) {
    margin: 0;
    height: 100%;
    overflow: hidden;
  }
  :global(body) {
    font-family: system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
  }

  /* ── App shell: sidebar + page body side by side ─────────────────── */
  .app-shell {
    display: flex;
    height: 100vh;
    overflow: hidden;
  }

  /* ── Sidebar ────────────────────────────────────────────────────── */
  .sidebar {
    flex-shrink: 0;
    width: 210px;
    background: var(--surface);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    white-space: nowrap;
    transition: width 0.2s ease;
    will-change: width;
  }
  .sidebar.collapsed { width: 52px; }

  /* Brand row */
  .brand {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.9rem 0.85rem 0.8rem;
    border-bottom: 1px solid var(--border);
    min-height: 52px;
    box-sizing: border-box;
  }
  .brand-mark {
    flex-shrink: 0;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    background: var(--accent);
    color: #000;
    border-radius: 4px;
    padding: 0.2rem 0.38rem;
  }
  .brand-name {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--text);
  }

  /* Nav area */
  .sidebar-nav {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: 0.5rem 0.35rem;
    display: flex;
    flex-direction: column;
    gap: 1px;
    scrollbar-width: thin;
    scrollbar-color: var(--border) transparent;
  }
  .group-label {
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: var(--text-dim);
    padding: 0.7rem 0.55rem 0.2rem;
    display: block;
  }
  .group-sep {
    border: none;
    border-top: 1px solid var(--hover);
    margin: 0.4rem 0.15rem;
  }
  .sidebar-nav a {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.45rem 0.55rem;
    border-radius: 5px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 0.875rem;
    transition: background 0.1s, color 0.1s;
  }
  .sidebar-nav a:hover             { background: var(--hover); color: var(--text); }
  .sidebar-nav a.active            { background: var(--accent-dim); color: var(--accent); }
  .sidebar-nav a.active:hover      { background: var(--accent-dim2); }

  /* Pending badge on nav item */
  .pending-badge {
    margin-left: auto;
    flex-shrink: 0;
    background: var(--accent);
    color: #000;
    font-size: 0.68rem;
    font-weight: 700;
    line-height: 1;
    padding: 0.15rem 0.4rem;
    border-radius: 10px;
    min-width: 1.2em;
    text-align: center;
  }

  /* Footer */
  .sidebar-footer {
    border-top: 1px solid var(--border);
    padding: 0.35rem;
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .sidebar-btn {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.45rem 0.55rem;
    border-radius: 5px;
    background: none;
    border: none;
    color: var(--text-muted);
    cursor: pointer;
    font: inherit;
    font-size: 0.875rem;
    width: 100%;
    text-align: left;
    white-space: nowrap;
    transition: background 0.1s, color 0.1s;
  }
  .sidebar-btn:hover { background: var(--hover); color: var(--text); }

  /* BLE toggle */
  .ble-toggle-btn { gap: 0.6rem; }
  .ble-pill {
    display: inline-block;
    width: 30px;
    height: 16px;
    border-radius: 8px;
    background: var(--hover);
    border: 1px solid var(--border);
    position: relative;
    margin-left: auto;
    flex-shrink: 0;
    transition: background 0.2s, border-color 0.2s;
  }
  .ble-pill::after {
    content: '';
    position: absolute;
    top: 2px;
    left: 2px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--text-dim);
    transition: transform 0.2s, background 0.2s;
  }
  .ble-pill.on {
    background: var(--success);
    border-color: var(--success);
  }
  .ble-pill.on::after {
    transform: translateX(14px);
    background: #fff;
  }
  .ble-toggle-btn.ble-on { color: var(--success); }
  .ble-toggle-btn.ble-on:hover { color: var(--success); background: rgba(63,185,80,0.1); }
  .sidebar.collapsed .ble-pill { display: none; }

  /* mDNS status */
  .mdns-label { display: block; line-height: 1.2; }
  .mdns-indicator { color: var(--text-dim); }
  .mdns-on { color: var(--text-muted); }

  /* Hide labels when collapsed */
  .sidebar.collapsed .nav-label    { display: none; }
  .sidebar.collapsed .group-label  { display: none; }
  .sidebar.collapsed .brand-name   { display: none; }
  .sidebar.collapsed .mdns-label   { display: none; }
  .sidebar.collapsed .pending-badge { display: none; }

  /* ── Page body ──────────────────────────────────────────────────── */
  .page-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }
  main { padding: 1.5rem; flex: 1; }

  /* ── Login overlay ──────────────────────────────────────────────── */
  .login-overlay {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--bg);
  }
  .login-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 2rem;
    width: 100%;
    max-width: 420px;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .login-box h2    { margin: 0 0 0.5rem; font-size: 1.25rem; }
  .login-box p     { margin: 0; color: var(--text-muted); font-size: 0.9rem; }
  .login-box label { font-size: 0.9rem; color: var(--text-muted); }
  .login-box input {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--bg);
    color: var(--text);
    font-size: 1rem;
    font-family: monospace;
  }
  .login-box input:focus { outline: 2px solid var(--accent); border-color: transparent; }
  .login-box button {
    padding: 0.6rem 1.25rem;
    background: var(--accent);
    color: #000;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    align-self: flex-end;
  }
  .login-box button:hover { background: #ffd040; }
  .err { color: var(--danger); margin: 0; font-size: 0.85rem; }
</style>