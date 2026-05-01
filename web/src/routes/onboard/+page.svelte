<script lang="ts">
  // Onboarding wizard: walks an operator through three short questions and
  // recommends the most appropriate enrollment method. Each result links to
  // the page where they actually do the work (Pending / Allowlist / Tokens /
  // BLE scanner) and shows a copy-pasteable agent invocation tailored to
  // the choice.

  import { onMount } from 'svelte';
  import { api, type ServerInfo, type ProfileSummary } from '$lib/api';

  type Network = 'lan' | 'cloud' | 'offline';
  type Knowledge = 'nothing' | 'identity' | 'secret';
  type Trust = 'manual' | 'automatic';
  type Style = 'binary' | 'shell';

  let network = $state<Network | null>(null);
  let knowledge = $state<Knowledge | null>(null);
  let trust = $state<Trust | null>(null);
  let style = $state<Style>('shell');
  let insecure = $state(false);
  let info = $state<ServerInfo | null>(null);
  let infoErr = $state<string | null>(null);
  let profiles = $state<ProfileSummary[]>([]);
  let profile = $state<string>('');

  // Server URL the device should reach — persisted to localStorage so it
  // survives page reloads and is shared across wizard runs.
  type ServerPreset = 'origin' | 'localhost' | 'compose' | 'custom';
  const SERVER_PRESET_KEY = 'ztp-server-preset';
  const CUSTOM_SERVER_KEY = 'ztp-custom-server';

  let serverPreset = $state<ServerPreset>('origin');
  let customServer = $state('https://ztp.example.com');

  const originURL = $derived(
    typeof window !== 'undefined' ? window.location.origin.replace(/:5\d{3}$/, ':8080') : 'https://ztp.example.com',
  );
  const serverURL = $derived(
    serverPreset === 'origin'
      ? originURL
      : serverPreset === 'localhost'
        ? 'http://localhost:8080'
        : serverPreset === 'compose'
          ? 'http://server:8080'
          : customServer,
  );

  // Persist server URL choice immediately when it changes.
  $effect(() => {
    if (typeof localStorage === 'undefined') return;
    localStorage.setItem(SERVER_PRESET_KEY, serverPreset);
    localStorage.setItem(CUSTOM_SERVER_KEY, customServer);
  });

  onMount(async () => {
    // Restore persisted server URL choice.
    const savedPreset = localStorage.getItem(SERVER_PRESET_KEY) as ServerPreset | null;
    if (savedPreset) serverPreset = savedPreset;
    const savedCustom = localStorage.getItem(CUSTOM_SERVER_KEY);
    if (savedCustom) customServer = savedCustom;

    try {
      info = await api.serverInfo();
    } catch (e: any) {
      infoErr = e.message;
    }
    try {
      profiles = await api.profiles();
    } catch {
      profiles = [];
    }
  });

  // Step is derived from how many questions have been answered.
  const step = $derived(network == null ? 1 : knowledge == null ? 2 : trust == null ? 3 : 4);

  const pubkey = $derived(info?.public_key ?? '<paste server pubkey here>');
  const scriptURL = $derived(`${serverURL}/v1/agent.sh`);

  // Back navigation — undo the most recently answered question.
  function back() {
    if (trust != null) { trust = null; }
    else if (knowledge != null) { knowledge = null; }
    else if (network != null) { network = null; }
  }

  function reset() {
    network = null;
    knowledge = null;
    trust = null;
  }

  // ---- command builders ---------------------------------------------------
  function shellCmd(extraEnv: string[] = []): string {
    const env = [
      `ZTP_SERVER=${serverURL}`,
      `ZTP_SERVER_PUBKEY=${pubkey}`,
      ...(insecure ? ['ZTP_INSECURE=1'] : []),
      ...(profile ? [`ZTP_PROFILE=${profile}`] : []),
      ...extraEnv,
    ].join(' \\\n      ');
    const curlFlags = insecure ? '-fsSLk' : '-fsSL';
    return `curl ${curlFlags} ${scriptURL} \\\n  | env ${env} \\\n      sh`;
  }
  function binaryCmd(extraFlags: string[] = []): string {
    const flags = [
      `-server ${serverURL}`,
      `-server-pubkey "${pubkey}"`,
      ...(insecure ? ['--insecure'] : []),
      ...(profile ? [`--profile ${profile}`] : []),
      ...extraFlags,
      '-device-id "$(cat /etc/machine-id)"',
      '-identity /var/lib/ztp/identity.key',
      '-appliers /etc/ztp/appliers.d',
    ].join(' \\\n  ');
    return `ztp-agent ${flags}`;
  }
  function bleCmd(): string {
    const flags = [
      `-server ${serverURL}`,
      `-server-pubkey "${pubkey}"`,
      ...(profile ? [`--profile ${profile}`] : []),
      '-device-id "$(cat /etc/machine-id)"',
      '-identity /var/lib/ztp/identity.key',
      '-appliers /etc/ztp/appliers.d',
    ].join(' \\\n  ');
    return `ztp-agent-ble ${flags}`;
  }

  // ---- recommendation engine ----------------------------------------------
  type Recommendation = {
    method: 'allowlist' | 'token' | 'manual' | 'ble';
    title: string;
    rationale: string;
    steps: { label: string; href?: string; cmd?: string; cmdNote?: string }[];
    allowStyleToggle: boolean;
  };

  const recommendation = $derived<Recommendation | null>((() => {
    if (step !== 4) return null;
    if (network === 'offline') {
      return {
        method: 'ble',
        title: 'BLE relay (no network on the device)',
        rationale:
          'The device cannot reach the server, so an operator-held phone or laptop bridges one signed enrollment envelope over Bluetooth.',
        allowStyleToggle: false,
        steps: [
          {
            label: 'On the device, run the BLE-enabled agent binary (BLE support is compiled in, not a runtime flag).',
            cmd: bleCmd(),
            cmdNote: 'Cross-compile for the Linux device: `just cross-agent-ble arch=arm64` (arm64) or `just cross-agent-ble` (amd64). BLE peripheral mode requires Linux (BlueZ); it does not work on macOS.',
          },
          { label: 'Open the BLE scanner in this admin UI to relay the enrollment.', href: '/onboard/ble' },
        ],
      };
    }
    if (knowledge === 'identity') {
      return {
        method: 'allowlist',
        title: 'Allowlist by MAC / serial',
        rationale:
          'You already know the device identity from procurement. Add it to the allowlist and the server will auto-approve the first matching enrollment with no human in the loop.',
        allowStyleToggle: true,
        steps: [
          { label: 'Add an allowlist entry (MAC and/or serial, optional device-id binding).', href: '/allowlist' },
          {
            label: 'Boot the device and run the agent.',
            cmd: style === 'shell' ? shellCmd() : binaryCmd(),
          },
        ],
      };
    }
    if (knowledge === 'secret') {
      return {
        method: 'token',
        title: 'Bootstrap token',
        rationale:
          'You can hand the installer (or imaging script) a short-lived secret. The token can be one-shot, multi-use, or bound to a specific device-id.',
        allowStyleToggle: true,
        steps: [
          { label: 'Generate a token, choose max-uses + TTL, copy the secret.', href: '/tokens' },
          {
            label: 'Pass the token to the agent on first boot.',
            cmd:
              style === 'shell'
                ? shellCmd(['ZTP_TOKEN=$ZTP_TOKEN'])
                : binaryCmd(['-token "$ZTP_TOKEN"']),
            cmdNote: 'Set `ZTP_TOKEN` in the environment from your imaging pipeline / installer.',
          },
        ],
      };
    }
    if (trust === 'manual') {
      return {
        method: 'manual',
        title: 'Manual approval (Pending queue)',
        rationale:
          'You know nothing about the device beforehand and want a human to confirm each enrollment. The agent posts its request and waits; an operator approves or rejects in the UI.',
        allowStyleToggle: true,
        steps: [
          {
            label: 'Boot the agent — it will show up under Pending within seconds.',
            cmd: style === 'shell' ? shellCmd() : binaryCmd(),
          },
          { label: 'Review the device fingerprint and approve.', href: '/pending' },
        ],
      };
    }
    return {
      method: 'allowlist',
      title: 'Allowlist (requires identity)',
      rationale:
        'Fully unattended onboarding needs at least one identifying fact (MAC, serial, or a bootstrap token). Capture identities during procurement, or fall back to manual approval.',
      allowStyleToggle: false,
      steps: [
        { label: 'Set up allowlist entries up-front.', href: '/allowlist' },
        { label: 'Or accept manual approval as a fallback.', href: '/pending' },
      ],
    };
  })());

  function copy(s: string) {
    navigator.clipboard?.writeText(s);
  }
</script>

<h2>Onboard a device</h2>

<!-- ─── Global server URL (persisted, visible at all wizard stages) ────── -->
<section class="server-config card">
  <div class="server-config-row">
    <span class="server-config-label">Device reaches server at</span>
    <div class="presets">
      <label>
        <input type="radio" bind:group={serverPreset} value="origin" />
        <span>This UI <small>{originURL}</small></span>
      </label>
      <label>
        <input type="radio" bind:group={serverPreset} value="localhost" />
        <span>Host network <small>localhost:8080</small></span>
      </label>
      <label>
        <input type="radio" bind:group={serverPreset} value="compose" />
        <span>Compose bridge <small>server:8080</small></span>
      </label>
      <label>
        <input type="radio" bind:group={serverPreset} value="custom" />
        <span>Custom</span>
      </label>
    </div>
    {#if serverPreset === 'custom'}
      <input
        class="custom-server"
        type="url"
        bind:value={customServer}
        placeholder="https://ztp.example.com"
      />
    {/if}
    <label class="insecure-check">
      <input type="checkbox" bind:checked={insecure} />
      <span>Skip TLS verification</span>
    </label>
  </div>
  <p class="server-url-display">
    <code>{serverURL}</code>
    {#if insecure}<span class="warn-badge">insecure</span>{/if}
  </p>
</section>

{#if info}
  <details class="serverinfo">
    <summary>
      Server key: <code>{info.key_id}</code> · pubkey <code>{info.public_key.slice(0, 12)}…</code>
    </summary>
    <dl>
      <dt>Wire protocol</dt><dd><code>v{info.protocol_version}</code></dd>
      <dt>Signing public key</dt>
      <dd>
        <code class="full">{info.public_key}</code>
        <button class="copy" onclick={() => copy(info!.public_key)}>Copy</button>
      </dd>
      {#if info.agent_script_url}
        <dt>Hosted agent script</dt>
        <dd>
          <code class="full">{info.agent_script_url}</code>
          <button class="copy" onclick={() => copy(info!.agent_script_url!)}>Copy</button>
        </dd>
      {/if}
    </dl>
  </details>
{:else if infoErr}
  <p class="warn">Could not fetch server info: {infoErr} (commands will use placeholders).</p>
{/if}

<!-- ─── Wizard ──────────────────────────────────────────────────────────── -->
<ol class="stepper">
  <li class:done={step > 1} class:active={step === 1}>1. Network</li>
  <li class:done={step > 2} class:active={step === 2}>2. Identity</li>
  <li class:done={step > 3} class:active={step === 3}>3. Trust</li>
  <li class:active={step === 4}>4. Result</li>
</ol>

{#if step === 1}
  <section class="card">
    <h3>Where will the device be when it first contacts the server?</h3>
    <div class="choices">
      <button onclick={() => (network = 'lan')}>
        <strong>Same LAN</strong>
        <span>Device boots in the same network segment as the ZTP server.</span>
      </button>
      <button onclick={() => (network = 'cloud')}>
        <strong>Cloud reachable</strong>
        <span>Device has internet access and the ZTP server has a public hostname.</span>
      </button>
      <button onclick={() => (network = 'offline')}>
        <strong>No network</strong>
        <span>An operator-held device bridges enrollment over Bluetooth.</span>
      </button>
    </div>
  </section>
{:else if step === 2}
  <section class="card">
    <div class="card-nav">
      <h3>What do you know about the device <em>before</em> it boots?</h3>
      <button class="back-btn" onclick={back}>← Back</button>
    </div>
    <div class="choices">
      <button onclick={() => (knowledge = 'identity')}>
        <strong>Its MAC or serial</strong>
        <span>Captured during procurement, printed on a label, or read from a barcode.</span>
      </button>
      <button onclick={() => (knowledge = 'secret')}>
        <strong>Can hand it a secret</strong>
        <span>Typed by an installer or baked into an image build.</span>
      </button>
      <button onclick={() => (knowledge = 'nothing')}>
        <strong>Nothing — anonymous</strong>
        <span>Brand-new hardware, factory defaults, no preconfiguration.</span>
      </button>
    </div>
  </section>
{:else if step === 3}
  <section class="card">
    <div class="card-nav">
      <h3>Who decides whether to admit the device?</h3>
      <button class="back-btn" onclick={back}>← Back</button>
    </div>
    <div class="choices">
      <button onclick={() => (trust = 'manual')}>
        <strong>Human reviews each one</strong>
        <span>Highest assurance. Operator confirms fingerprint in the Pending queue.</span>
      </button>
      <button onclick={() => (trust = 'automatic')}>
        <strong>Auto-approve on rules</strong>
        <span>Lower friction at scale. Requires identity facts or a token in advance.</span>
      </button>
    </div>
  </section>
{:else if recommendation}
  <section class="card result">
    <div class="card-nav">
      <h3>{recommendation.title}</h3>
      <div class="result-actions">
        <button class="back-btn" onclick={back}>← Back</button>
        <button class="reset" onclick={reset}>Start over</button>
      </div>
    </div>
    <p class="rationale">{recommendation.rationale}</p>

    {#if profiles.length > 0}
      <div class="profile-row">
        <label for="profile-pick">Provisioning profile <small>(advisory hint)</small></label>
        <select id="profile-pick" bind:value={profile}>
          <option value="">— let the server decide —</option>
          {#each profiles as p (p.name)}
            <option value={p.name}>{p.name}{p.priority ? ` (priority ${p.priority})` : ''}</option>
          {/each}
        </select>
      </div>
    {/if}

    {#if recommendation.allowStyleToggle}
      <div class="style-toggle" role="tablist" aria-label="Agent style">
        <button
          role="tab"
          aria-selected={style === 'shell'}
          class:active={style === 'shell'}
          onclick={() => (style = 'shell')}
        >
          Shell one-liner <small>curl | sh</small>
        </button>
        <button
          role="tab"
          aria-selected={style === 'binary'}
          class:active={style === 'binary'}
          onclick={() => (style = 'binary')}
        >
          Go binary <small>ztp-agent</small>
        </button>
      </div>
    {/if}

    <ol class="steps">
      {#each recommendation.steps as s, i (i)}
        <li>
          <p>{s.label}</p>
          {#if s.cmd}
            <pre><code>{s.cmd}</code></pre>
            <button class="copy" onclick={() => copy(s.cmd!)}>Copy</button>
            {#if s.cmdNote}<small class="note">{s.cmdNote}</small>{/if}
          {/if}
          {#if s.href}
            <a class="cta" href={s.href}>Go to {s.href.replace('/', '')} →</a>
          {/if}
        </li>
      {/each}
    </ol>
  </section>
{/if}

<aside class="cheatsheet">
  <h3>Methods at a glance</h3>
  <table>
    <thead><tr><th>Method</th><th>Best when…</th><th>Approval</th></tr></thead>
    <tbody>
      <tr>
        <td><a href="/allowlist">Allowlist</a></td>
        <td>You have MACs/serials from procurement</td>
        <td>Automatic on match</td>
      </tr>
      <tr>
        <td><a href="/tokens">Bootstrap token</a></td>
        <td>Imaging script or installer can carry a secret</td>
        <td>Automatic on token use</td>
      </tr>
      <tr>
        <td><a href="/pending">Manual approval</a></td>
        <td>Anonymous devices, security-sensitive sites</td>
        <td>Human, fingerprint-checked</td>
      </tr>
      <tr>
        <td><a href="/onboard/ble">BLE relay</a></td>
        <td>Device has no network</td>
        <td>Either, plus operator-mediated bridge</td>
      </tr>
    </tbody>
  </table>
</aside>

<style>
  h2 { margin-top: 0; }

  /* ── Global server URL card ── */
  .server-config {
    margin-bottom: 1rem;
    padding: 0.75rem 1rem;
  }
  .server-config-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.5rem 1rem;
  }
  .server-config-label {
    font-size: 0.85rem;
    color: #8b949e;
    white-space: nowrap;
  }
  .presets { display: flex; flex-wrap: wrap; gap: 0.3rem 0.9rem; }
  .presets label { display: flex; align-items: center; gap: 0.3rem; cursor: pointer; font-size: 0.9rem; }
  .presets span { display: inline-flex; flex-direction: column; line-height: 1.15; }
  .presets small { color: #8b949e; font-family: ui-monospace, monospace; font-size: 0.72rem; }
  .custom-server {
    padding: 0.3rem 0.5rem;
    background: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
    width: 22ch;
  }
  .insecure-check {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    color: #d29922;
    font-size: 0.85rem;
    cursor: pointer;
  }
  .server-url-display {
    margin: 0.35rem 0 0;
    font-size: 0.85rem;
    color: #8b949e;
  }
  .server-url-display code {
    color: #58a6ff;
    font-family: ui-monospace, monospace;
  }
  .warn-badge {
    display: inline-block;
    background: #d29922;
    color: #0d1117;
    font-size: 0.7rem;
    border-radius: 3px;
    padding: 0.05rem 0.35rem;
    margin-left: 0.4rem;
    vertical-align: middle;
    font-weight: 600;
    letter-spacing: 0.03em;
  }

  .serverinfo {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-bottom: 1rem;
  }
  .serverinfo summary {
    padding: 0.5rem 0.75rem;
    cursor: pointer;
    color: #8b949e;
    font-size: 0.9rem;
  }
  .serverinfo summary code { color: #58a6ff; }
  .serverinfo dl {
    margin: 0;
    padding: 0 1rem 0.75rem 1.25rem;
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.4rem 1rem;
  }
  .serverinfo dt { color: #8b949e; font-size: 0.9rem; }
  .serverinfo dd { margin: 0; word-break: break-all; font-size: 0.9rem; }
  .serverinfo code.full { font-size: 0.85rem; }
  .warn { color: #d29922; }

  .stepper { display: flex; gap: 0.5rem; padding: 0; list-style: none; margin: 1.25rem 0; }
  .stepper li {
    flex: 1;
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    background: #161b22;
    border: 1px solid #30363d;
    color: #8b949e;
    font-size: 0.85rem;
  }
  .stepper li.active { color: #fff; border-color: #1f6feb; }
  .stepper li.done { color: #3fb950; }

  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
  }
  .card h3 { margin-top: 0; margin-bottom: 1rem; }

  /* card-nav keeps the heading and back/reset buttons on the same line */
  .card-nav {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    margin-bottom: 0.75rem;
  }
  .card-nav h3 { margin: 0; }
  .result-actions { display: flex; gap: 0.5rem; flex-shrink: 0; }

  .back-btn {
    background: transparent;
    color: #58a6ff;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.2rem 0.65rem;
    cursor: pointer;
    font-size: 0.85rem;
    white-space: nowrap;
  }
  .back-btn:hover { background: #21262d; }
  .reset {
    background: transparent;
    color: #8b949e;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.2rem 0.65rem;
    cursor: pointer;
    font-size: 0.85rem;
  }
  .reset:hover { background: #21262d; }

  .choices { display: grid; grid-template-columns: 1fr; gap: 0.65rem; }
  @media (min-width: 720px) { .choices { grid-template-columns: 1fr 1fr 1fr; } }
  .choices button {
    text-align: left;
    background: #0d1117;
    border: 1px solid #30363d;
    color: #e6edf3;
    border-radius: 6px;
    padding: 0.9rem 1rem;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    font: inherit;
    transition: border-color 0.15s, background 0.15s;
  }
  .choices button:hover { border-color: #1f6feb; background: #1f2a37; }
  .choices button strong { font-size: 0.95rem; }
  .choices button span { color: #8b949e; font-size: 0.85rem; line-height: 1.35; }

  /* result card */
  .rationale { color: #c9d1d9; max-width: 70ch; margin: 0 0 1rem; font-size: 0.95rem; }

  .profile-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin: 0.75rem 0;
  }
  .profile-row label { font-size: 0.85rem; color: #8b949e; white-space: nowrap; }
  .profile-row small { color: #6e7681; }
  .profile-row select {
    padding: 0.3rem 0.5rem;
    background: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
  }

  .style-toggle {
    display: inline-flex;
    border: 1px solid #30363d;
    border-radius: 6px;
    overflow: hidden;
    margin: 0.75rem 0 0.5rem;
  }
  .style-toggle button {
    background: #0d1117;
    color: #8b949e;
    border: 0;
    padding: 0.4rem 0.9rem;
    cursor: pointer;
    font: inherit;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    border-right: 1px solid #30363d;
    font-size: 0.9rem;
  }
  .style-toggle button:last-child { border-right: 0; }
  .style-toggle button.active { background: #1f6feb; color: #fff; }
  .style-toggle button small { font-size: 0.75rem; opacity: 0.85; font-family: ui-monospace, monospace; }

  .steps { padding-left: 1.25rem; margin-top: 0.5rem; }
  .steps li { margin: 1rem 0; }
  .steps pre {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.75rem 1rem;
    overflow-x: auto;
    font-size: 0.85rem;
  }
  .copy {
    background: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.2rem 0.6rem;
    cursor: pointer;
    margin-right: 0.5rem;
    font-size: 0.85rem;
  }
  .note { color: #8b949e; font-size: 0.85rem; display: block; margin-top: 0.4rem; }
  .cta { color: #58a6ff; text-decoration: none; font-weight: 600; }
  .cta:hover { text-decoration: underline; }

  .cheatsheet { margin-top: 1.5rem; }
  .cheatsheet h3 { font-size: 1rem; color: #8b949e; font-weight: normal; margin-bottom: 0.5rem; }
  .cheatsheet table { width: 100%; border-collapse: collapse; }
  .cheatsheet th, .cheatsheet td {
    padding: 0.5rem;
    text-align: left;
    border-bottom: 1px solid #30363d;
    font-size: 0.9rem;
  }
  .cheatsheet th { color: #8b949e; font-weight: normal; }
  .cheatsheet a { color: #58a6ff; text-decoration: none; }
  .cheatsheet a:hover { text-decoration: underline; }
</style>

