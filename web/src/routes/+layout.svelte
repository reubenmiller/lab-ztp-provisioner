<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { page } from '$app/stores';
  import { getToken, setToken, api, type PendingRequest, type Device } from '$lib/api';
  import { detect, type RuntimeInfo, type DesktopRuntimeInfo, wailsOpenConfigDirectory } from '$lib/runtime';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import Toasts from '$lib/components/Toasts.svelte';
  import { addToast } from '$lib/toasts.svelte';

  let { children } = $props();

  type NavItem = { href: string; label: string; icon: string; exact?: boolean };
  type NavGroup = { label: string | null; items: NavItem[] };

  const navGroups: NavGroup[] = [
    {
      label: 'Fleet',
      items: [
        { href: '/pending',  label: 'Pending', icon: 'inbox'   },
        { href: '/devices',  label: 'Devices', icon: 'monitor' },
      ],
    },
    {
      label: 'Config',
      items: [
        { href: '/allowlist', label: 'Allowlist',       icon: 'shield-check' },
        { href: '/tokens',    label: 'Tokens',          icon: 'key'          },
        { href: '/config',    label: 'Config / Secrets', icon: 'settings'    },
      ],
    },
    {
      label: 'Onboarding',
      items: [
        { href: '/onboard',     label: 'Onboard',   icon: 'user-plus', exact: true },
        { href: '/onboard/ble', label: 'BLE Relay', icon: 'bluetooth' },
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
  };

  function icon(name: string): string {
    return `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] ?? ''}</svg>`;
  }

  let sidebarExpanded = $state(true);
  let needsLogin     = $state(false);
  let tokenInput     = $state('');
  let tokenError     = $state('');
  let runtimeInfo    = $state<RuntimeInfo | null>(null);
  let sseStream: EventSource | null = null;

  const desktopRuntimeInfo = $derived(
    runtimeInfo?.mode === 'desktop' ? (runtimeInfo as DesktopRuntimeInfo) : null
  );

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
      if (getToken()) startSSE();
    }).catch((err) => {
      console.warn('runtime detect failed', err);
      if (!getToken()) needsLogin = true;
      // If we already have a token (browser mode with saved token) still start SSE.
      if (getToken()) startSSE();
    });
    window.addEventListener('ztp:auth-required', handleAuthRequired);

    return () => {
      window.removeEventListener('ztp:auth-required', handleAuthRequired);
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

  async function openConfigDir() {
    const fn = wailsOpenConfigDirectory();
    if (!fn) return;
    try { await fn(); } catch (err) { console.warn('open config directory failed', err); }
  }

  function isActive(href: string, exact?: boolean): boolean {
    if (exact) return $page.url.pathname === href;
    return $page.url.pathname.startsWith(href);
  }

  function startSSE() {
    sseStream?.close();
    sseStream = api.pendingStream(
      (p: PendingRequest) => {
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
        window.dispatchEvent(new CustomEvent('ztp:enrolled', { detail: d }));
        addToast({
          kind: 'enrolled',
          title: 'Device enrolled',
          body: d.id,
          href: '/devices',
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
            </a>
          {/each}
        {/each}
      </nav>

      <!-- Footer: mDNS indicator + token action + collapse toggle -->
      <div class="sidebar-footer">
        {#if runtimeInfo}
          <div
            class="mdns-indicator"
            class:mdns-on={runtimeInfo.mdns}
            title={runtimeInfo.mdns ? 'mDNS active — _ztp._tcp is being advertised on the LAN' : 'mDNS inactive — devices cannot auto-discover this server'}
          >
            <span class="mdns-led" aria-hidden="true"></span>
            <span class="nav-label mdns-label">mDNS {runtimeInfo.mdns ? 'active' : 'inactive'}</span>
          </div>
        {/if}
        <button
          class="sidebar-btn"
          onclick={changeToken}
          title={!sidebarExpanded ? 'Change admin token' : undefined}
        >
          {@html icon('lock')}
          <span class="nav-label">Change token</span>
        </button>
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
      {#if desktopRuntimeInfo?.configDir}
        <section class="desktop-config-notice">
          <p>
            Config: <code>{desktopRuntimeInfo.configDir}</code>
            <button class="open-config-btn" onclick={openConfigDir}>Open</button>
          </p>
          {#if desktopRuntimeInfo.configPath}
            <p>Config file: <code>{desktopRuntimeInfo.configPath}</code></p>
          {/if}
          {#if desktopRuntimeInfo.firstRun}
            <p class="banner-title">First run — generated files are ready.</p>
            {#if desktopRuntimeInfo.adminTokenFile}<p>Token: <code>{desktopRuntimeInfo.adminTokenFile}</code></p>{/if}
            {#if desktopRuntimeInfo.signingKeyFile}<p>Signing key: <code>{desktopRuntimeInfo.signingKeyFile}</code></p>{/if}
            {#if desktopRuntimeInfo.ageKeyFile}<p>Age key: <code>{desktopRuntimeInfo.ageKeyFile}</code></p>{/if}
            {#if desktopRuntimeInfo.profilesDir}<p>Profiles: <code>{desktopRuntimeInfo.profilesDir}</code></p>{/if}
          {/if}
        </section>
      {/if}
      <main>{@render children()}</main>
    </div>
  </div>
{/if}

<ConfirmDialog />
<Toasts />

<style>
  /* ── Reset / globals ─────────────────────────────────────────────── */
  :global(html, body) {
    margin: 0;
    height: 100%;
    overflow: hidden;
  }
  :global(body) {
    font-family: system-ui, -apple-system, sans-serif;
    background: #0d1117;
    color: #e6edf3;
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
    background: #161b22;
    border-right: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    overflow: hidden;           /* clips label text when narrow */
    white-space: nowrap;        /* prevents label text wrapping */
    transition: width 0.2s ease;
    /* Hardware-accelerated so it doesn't jank during page repaints */
    will-change: width;
  }
  .sidebar.collapsed { width: 52px; }

  /* Brand row */
  .brand {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.9rem 0.85rem 0.8rem;
    border-bottom: 1px solid #30363d;
    min-height: 52px;
    box-sizing: border-box;
  }
  .brand-mark {
    flex-shrink: 0;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    background: #1f6feb;
    color: #fff;
    border-radius: 4px;
    padding: 0.2rem 0.38rem;
  }
  .brand-name {
    font-size: 0.9rem;
    font-weight: 600;
    color: #e6edf3;
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
    scrollbar-color: #30363d transparent;
  }
  .group-label {
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: #6e7681;
    padding: 0.7rem 0.55rem 0.2rem;
    display: block;
  }
  .group-sep {
    border: none;
    border-top: 1px solid #21262d;
    margin: 0.4rem 0.15rem;
  }
  .sidebar-nav a {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.45rem 0.55rem;
    border-radius: 5px;
    color: #8b949e;
    text-decoration: none;
    font-size: 0.875rem;
    transition: background 0.1s, color 0.1s;
  }
  .sidebar-nav a:hover             { background: #21262d; color: #e6edf3; }
  .sidebar-nav a.active            { background: rgba(31,111,235,0.15); color: #58a6ff; }
  .sidebar-nav a.active:hover      { background: rgba(31,111,235,0.22); }

  /* Footer */
  .sidebar-footer {
    border-top: 1px solid #30363d;
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
    color: #8b949e;
    cursor: pointer;
    font: inherit;
    font-size: 0.875rem;
    width: 100%;
    text-align: left;
    white-space: nowrap;
    transition: background 0.1s, color 0.1s;
  }
  .sidebar-btn:hover { background: #21262d; color: #e6edf3; }

  /* mDNS status indicator */
  .mdns-indicator {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.45rem 0.55rem;
    font-size: 0.875rem;
    color: #6e7681;
    white-space: nowrap;
  }
  .mdns-indicator.mdns-on { color: #8b949e; }
  .mdns-led {
    flex-shrink: 0;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #3d4450;
    box-shadow: none;
    transition: background 0.3s, box-shadow 0.3s;
  }
  .mdns-on .mdns-led {
    background: #2ea043;
    box-shadow: 0 0 5px #2ea043aa;
  }
  .mdns-label { font-size: 0.875rem; }

  /* Hide labels when sidebar is collapsed */
  .sidebar.collapsed .nav-label    { display: none; }
  .sidebar.collapsed .group-label  { display: none; }
  .sidebar.collapsed .brand-name   { display: none; }

  /* ── Page body ──────────────────────────────────────────────────── */
  .page-body {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }
  main { padding: 1.5rem; flex: 1; }

  /* Desktop config notice */
  .desktop-config-notice {
    border-bottom: 1px solid #30363d;
    background: #0f151d;
    padding: 0.5rem 1.25rem;
  }
  .desktop-config-notice p {
    margin: 0.15rem 0;
    color: #b7c0c8;
    font-size: 0.82rem;
    line-height: 1.35;
  }
  .desktop-config-notice .banner-title {
    margin-top: 0.4rem;
    color: #e6edf3;
    font-weight: 600;
  }
  .desktop-config-notice code {
    color: #d2d9e0;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }
  .open-config-btn {
    margin-left: 0.4rem;
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
    border-radius: 4px;
    padding: 0.1rem 0.4rem;
    font-size: 0.72rem;
    cursor: pointer;
  }
  .open-config-btn:hover { background: #30363d; }

  /* ── Login overlay ──────────────────────────────────────────────── */
  .login-overlay {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0d1117;
  }
  .login-box {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 2rem;
    width: 100%;
    max-width: 420px;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .login-box h2    { margin: 0 0 0.5rem; font-size: 1.25rem; }
  .login-box p     { margin: 0; color: #8b949e; font-size: 0.9rem; }
  .login-box label { font-size: 0.9rem; color: #8b949e; }
  .login-box input {
    padding: 0.5rem 0.75rem;
    border: 1px solid #30363d;
    border-radius: 6px;
    background: #0d1117;
    color: #e6edf3;
    font-size: 1rem;
    font-family: monospace;
  }
  .login-box input:focus { outline: 2px solid #1f6feb; border-color: transparent; }
  .login-box button {
    padding: 0.6rem 1.25rem;
    background: #1f6feb;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    cursor: pointer;
    align-self: flex-end;
  }
  .login-box button:hover { background: #388bfd; }
  .err { color: #f85149; margin: 0; font-size: 0.85rem; }
</style>
