<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { getToken, setToken } from '$lib/api';
  import { detect, type RuntimeInfo, type DesktopRuntimeInfo, wailsOpenConfigDirectory } from '$lib/runtime';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';

  let { children } = $props();
  const tabs = [
    { href: '/onboard', label: 'Onboard', primary: true, exact: true },
    { href: '/onboard/ble', label: 'BLE Relay' },
    { href: '/pending', label: 'Pending' },
    { href: '/devices', label: 'Devices' },
    { href: '/allowlist', label: 'Allowlist' },
    { href: '/tokens', label: 'Tokens' },
    { href: '/profiles', label: 'Profiles' },
    { href: '/config', label: 'Config/Secrets' },
    { href: '/audit', label: 'Audit' }
  ];

  let needsLogin = $state(false);
  let tokenInput = $state('');
  let tokenError = $state('');
  let runtimeInfo = $state<RuntimeInfo | null>(null);

  const desktopRuntimeInfo = $derived(
    runtimeInfo?.mode === 'desktop' ? (runtimeInfo as DesktopRuntimeInfo) : null
  );

  function handleAuthRequired() {
    // In desktop mode the token comes from the Wails binding and a
    // 401 means the binding broke or the engine restarted — log and
    // keep the UI usable rather than show a login modal that has no
    // useful answer.
    if (runtimeInfo?.mode === 'desktop') {
      console.warn('Auth required in desktop mode — engine may have restarted');
      return;
    }
    needsLogin = true;
  }

  onMount(() => {
    detect().then((info) => {
      runtimeInfo = info;
      if (info.mode === 'desktop') {
        // Token came from the Wails binding (see $lib/runtime.detect);
        // store it for $lib/api which still reads localStorage. The
        // value is in-memory anyway — no plaintext lands on disk in
        // a meaningful way under Wails' user-data root.
        const desktop = info as { token?: string };
        if (desktop.token) setToken(desktop.token);
        needsLogin = false;
      } else if (!getToken()) {
        needsLogin = true;
      }
    }).catch((err) => {
      // Detection failure — fall back to the historical browser flow.
      console.warn('runtime detect failed', err);
      if (!getToken()) needsLogin = true;
    });
    window.addEventListener('ztp:auth-required', handleAuthRequired);
    return () => window.removeEventListener('ztp:auth-required', handleAuthRequired);
  });

  function saveToken(e: SubmitEvent) {
    e.preventDefault();
    const t = tokenInput.trim();
    if (!t) { tokenError = 'Token must not be empty.'; return; }
    setToken(t);
    tokenInput = '';
    tokenError = '';
    needsLogin = false;
  }

  function changeToken() {
    needsLogin = true;
  }

  async function openConfigDir() {
    const fn = wailsOpenConfigDirectory();
    if (!fn) return;
    try {
      await fn();
    } catch (err) {
      console.warn('open config directory failed', err);
    }
  }
</script>

{#if needsLogin}
  <!-- Login overlay — blocks the entire UI until a valid token is stored -->
  <div class="login-overlay">
    <form class="login-box" onsubmit={saveToken}>
      <h2>ZTP Admin — sign in</h2>
      <p>Enter your admin token to continue. The token is stored only in your browser's local storage.</p>
      <label for="token-input">Admin token</label>
      <!-- type="password" hides the value; autocomplete="off" avoids password manager noise -->
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
  <header>
    <h1>ZTP Admin</h1>
    <nav>
      {#each tabs as t (t.href)}
        <a href={t.href} class:active={t.exact ? $page.url.pathname === t.href : $page.url.pathname.startsWith(t.href)} class:primary={t.primary}>{t.label}</a>
      {/each}
      <button class="token-btn" onclick={changeToken} title="Change admin token">&#128274;</button>
    </nav>
  </header>

  {#if desktopRuntimeInfo?.configDir}
    <section class="desktop-config-notice">
      <p>
        Desktop config directory: <code>{desktopRuntimeInfo.configDir}</code>
        <button class="open-config-btn" onclick={openConfigDir}>Open</button>
      </p>
      {#if desktopRuntimeInfo.configPath}
        <p>
          Config file: <code>{desktopRuntimeInfo.configPath}</code>
        </p>
      {/if}
      {#if desktopRuntimeInfo.firstRun}
        <p class="banner-title">First run complete: generated files are ready.</p>
        {#if desktopRuntimeInfo.adminTokenFile}<p>Admin token file: <code>{desktopRuntimeInfo.adminTokenFile}</code></p>{/if}
        {#if desktopRuntimeInfo.signingKeyFile}<p>Signing key file: <code>{desktopRuntimeInfo.signingKeyFile}</code></p>{/if}
        {#if desktopRuntimeInfo.ageKeyFile}<p>Age key file: <code>{desktopRuntimeInfo.ageKeyFile}</code></p>{/if}
        {#if desktopRuntimeInfo.profilesDir}<p>Profiles directory: <code>{desktopRuntimeInfo.profilesDir}</code></p>{/if}
      {/if}
    </section>
  {/if}

  <main>{@render children()}</main>
{/if}

<ConfirmDialog />

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, sans-serif;
    background: #0d1117;
    color: #e6edf3;
  }
  header {
    padding: 1rem 1.5rem;
    border-bottom: 1px solid #30363d;
    background: #161b22;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  h1 { margin: 0; font-size: 1.2rem; flex: 1 0 auto; }
  nav { display: flex; gap: 1rem; align-items: center; }
  nav a {
    color: #8b949e;
    text-decoration: none;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
  }
  nav a.active { color: #fff; background: #30363d; }
  nav a.primary { color: #58a6ff; }
  nav a.primary.active { color: #fff; background: #1f6feb; }
  .token-btn {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 1rem;
    color: #8b949e;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
  }
  .token-btn:hover { background: #30363d; color: #e6edf3; }
  .desktop-config-notice {
    border-bottom: 1px solid #30363d;
    background: #0f151d;
    padding: 0.65rem 1.5rem;
  }
  .desktop-config-notice p {
    margin: 0.2rem 0;
    color: #b7c0c8;
    font-size: 0.85rem;
    line-height: 1.3;
  }
  .desktop-config-notice .banner-title {
    margin-top: 0.55rem;
    color: #e6edf3;
    font-weight: 600;
  }
  .desktop-config-notice code {
    color: #d2d9e0;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
  }
  .open-config-btn {
    margin-left: 0.45rem;
    background: #21262d;
    border: 1px solid #30363d;
    color: #c9d1d9;
    border-radius: 5px;
    padding: 0.15rem 0.45rem;
    font-size: 0.75rem;
    cursor: pointer;
  }
  .open-config-btn:hover { background: #30363d; }
  main { padding: 1.5rem; }

  /* login overlay */
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
  .login-box h2 { margin: 0 0 0.5rem; font-size: 1.25rem; }
  .login-box p { margin: 0; color: #8b949e; font-size: 0.9rem; }
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
