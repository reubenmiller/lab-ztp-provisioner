<script lang="ts">
  // Onboarding wizard: walks an operator through three short questions and
  // recommends the most appropriate enrollment method. Each result links to
  // the page where they actually do the work (Pending / Allowlist / Tokens /
  // BLE scanner) and shows a copy-pasteable agent invocation tailored to
  // the choice.
  //
  // The wizard is purely client-side; no API calls happen until the user
  // navigates to a recommended action. We do, however, fetch /v1/server-info
  // on mount so the rendered commands inline the *actual* server pubkey and
  // hosted-script URL — operators don't have to paste them in by hand.

  import { onMount } from 'svelte';
  import { api, type ServerInfo, type ProfileSummary } from '$lib/api';

  type Network = 'lan' | 'cloud' | 'offline';
  type Knowledge = 'nothing' | 'identity' | 'secret';
  type Trust = 'manual' | 'automatic';
  type Style = 'binary' | 'shell';

  let network = $state<Network | null>(null);
  let knowledge = $state<Knowledge | null>(null);
  let trust = $state<Trust | null>(null);
  // Which agent variant the operator wants to deploy. Defaults to the
  // shell-agent curl one-liner because it's the most copy-paste friendly.
  let style = $state<Style>('shell');
  // When true, -k / ZTP_INSECURE=1 is injected into the generated command.
  // Useful for self-signed / mkcert certs on the LAN.
  let insecure = $state(false);
  let info = $state<ServerInfo | null>(null);
  let infoErr = $state<string | null>(null);
  // Available provisioning profiles, fetched on mount. The wizard passes the
  // chosen name to the agent as an advisory hint (--profile / ZTP_PROFILE);
  // the server resolves the final profile via its own precedence chain so a
  // misbehaving device can never escape an allowlist/token binding by
  // claiming a different profile.
  let profiles = $state<ProfileSummary[]>([]);
  let profile = $state<string>('');

  // The server URL the device should reach. The wizard renders this into
  // every command, so getting it right is critical. Operators see a preset
  // dropdown plus a free-form override because the right answer depends on
  // *how* the device reaches the server, not where the admin UI is hosted:
  //   - "this UI's origin" works for typical reverse-proxy setups
  //   - "localhost:8080" is correct when the device shares the host network
  //     (e.g. `docker run --network host` or running natively on the same box)
  //   - "server:8080" is the Compose-bridge service name
  //   - custom is for cloud / LAN hostnames
  type ServerPreset = 'origin' | 'localhost' | 'compose' | 'custom';
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

  onMount(async () => {
    try {
      info = await api.serverInfo();
    } catch (e: any) {
      infoErr = e.message;
    }
    try {
      profiles = await api.profiles();
    } catch {
      // Profile picker is optional; missing /v1/admin/profiles (older server,
      // or admin endpoints disabled) is silently ignored.
      profiles = [];
    }
  });

  // Step is derived from how many questions have been answered.
  const step = $derived(network == null ? 1 : knowledge == null ? 2 : trust == null ? 3 : 4);

  const pubkey = $derived(info?.public_key ?? '<paste server pubkey here>');
  // Prefer the absolute URL the server reports, but rebase it onto the
  // selected serverURL so a "localhost" preset doesn't point curl back at
  // the admin origin.
  const scriptURL = $derived(`${serverURL}/v1/agent.sh`);

  function reset() {
    network = null;
    knowledge = null;
    trust = null;
  }

  // ---- command builders ---------------------------------------------------
  // Two flavours the wizard renders based on the `style` toggle:
  //
  //   shell  — `curl -fsSL .../v1/agent.sh | env … sh`. Zero-install: ideal
  //            for first-boot scripts, kickstart, cloud-init, Ansible.
  //   binary — `ztp-agent` Go binary. Required for BLE, mDNS discovery, and
  //            X25519+ChaCha20 encrypted bundles.
  //
  // The shell agent auto-creates its identity key on first run; the Go
  // agent's `-identity` flag is a *path* (LoadOrCreateFile creates the file
  // and parent directory if absent), not a pre-existing file the operator
  // must provide.
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
      // -identity is a *destination* path; the agent generates the key on
      // first run if the file does not yet exist.
      '-identity /var/lib/ztp/identity.key',
      '-appliers /etc/ztp/appliers.d',
    ].join(' \\\n  ');
    return `ztp-agent ${flags}`;
  }
  // BLE transport is compiled in at build time (go build -tags ble), so the
  // binary is named ztp-agent-ble. There is no runtime -transport flag.
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
  // Mapping is intentionally simple: keep the rules explainable rather than
  // exhaustively covering every combination. The "rationale" string is shown
  // beside the recommendation so the operator can sanity-check it.
  type Recommendation = {
    method: 'allowlist' | 'token' | 'manual' | 'ble';
    title: string;
    rationale: string;
    steps: { label: string; href?: string; cmd?: string; cmdNote?: string }[];
    // BLE is the only path that requires the Go binary; for everything else
    // we surface the shell/binary toggle.
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
    // trust === 'automatic' but no identity / no secret — recommend allowlist
    // with a hint that it requires *some* identity.
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

<h2>Onboarding wizard</h2>
<p class="lede">
  ZTP supports four ways to bring a fresh device into the fleet. Answer up to three questions and we'll point you at the right one.
</p>

{#if info}
  <details class="serverinfo">
    <summary>
      Server: <code>{info.key_id}</code> · pubkey <code>{info.public_key.slice(0, 12)}…</code>
      {#if info.agent_script_url}· hosted agent script available{/if}
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
        <span>Device boots in the same network segment as the ZTP server. Discovers it via mDNS or a fixed URL.</span>
      </button>
      <button onclick={() => (network = 'cloud')}>
        <strong>Cloud reachable</strong>
        <span>Device has internet access and the ZTP server has a public hostname.</span>
      </button>
      <button onclick={() => (network = 'offline')}>
        <strong>No network at all</strong>
        <span>Factory floor, vehicle, or shipboard install. An operator-held phone bridges the enrollment over Bluetooth.</span>
      </button>
    </div>
  </section>
{:else if step === 2}
  <section class="card">
    <h3>What do you know about the device <em>before</em> it boots?</h3>
    <div class="choices">
      <button onclick={() => (knowledge = 'identity')}>
        <strong>Its MAC address or serial number</strong>
        <span>Captured during procurement, printed on a label, or read from a barcode.</span>
      </button>
      <button onclick={() => (knowledge = 'secret')}>
        <strong>I can hand it a one-time secret</strong>
        <span>Either typed by an installer or baked into an image build.</span>
      </button>
      <button onclick={() => (knowledge = 'nothing')}>
        <strong>Nothing — it's anonymous</strong>
        <span>Brand-new hardware, factory defaults, no preconfiguration.</span>
      </button>
    </div>
  </section>
{:else if step === 3}
  <section class="card">
    <h3>Who decides whether to admit the device?</h3>
    <div class="choices">
      <button onclick={() => (trust = 'manual')}>
        <strong>A human reviews each one</strong>
        <span>Highest assurance. Recommended when devices are anonymous and you want defense-in-depth.</span>
      </button>
      <button onclick={() => (trust = 'automatic')}>
        <strong>Auto-approve if it matches my rules</strong>
        <span>Lower friction at scale. Requires you to have identity facts or a token in advance.</span>
      </button>
    </div>
  </section>
{:else if recommendation}
  <section class="card result">
    <header>
      <h3>{recommendation.title}</h3>
      <button class="reset" onclick={reset}>Start over</button>
    </header>
    <p class="rationale">{recommendation.rationale}</p>

    <fieldset class="server-picker">
      <legend>Server URL the device should reach</legend>
      <div class="presets">
        <label>
          <input type="radio" bind:group={serverPreset} value="origin" />
          <span>This admin UI <small>{originURL}</small></span>
        </label>
        <label>
          <input type="radio" bind:group={serverPreset} value="localhost" />
          <span>Host networking <small>http://localhost:8080</small></span>
        </label>
        <label>
          <input type="radio" bind:group={serverPreset} value="compose" />
          <span>Compose bridge <small>http://server:8080</small></span>
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
        <span>Skip TLS verification
          <small>For self-signed or mkcert certs on the LAN. Never use in production.</small>
        </span>
      </label>
      <small class="hint">
        Pick what the <em>device</em> sees, which is not always what your browser sees. Use
        <code>localhost:8080</code> when the device shares the host network (e.g. <code>docker run --network host</code>),
        <code>server:8080</code> when both run in the same Compose project, or a public hostname for cloud deployments.
      </small>
    </fieldset>

    {#if profiles.length > 0}
      <fieldset class="profile-picker">
        <legend>Provisioning profile <small>(optional, advisory)</small></legend>
        <select bind:value={profile}>
          <option value="">— let the server decide —</option>
          {#each profiles as p (p.name)}
            <option value={p.name}>{p.name}{p.priority ? ` (priority ${p.priority})` : ''}</option>
          {/each}
        </select>
        <small class="hint">
          The agent sends this as a <em>hint</em>. The server's own resolution order
          (operator override → sticky persisted → allowlist/token binding → fact-based
          selector) wins over it, so a misbehaving device cannot escape its assignment by
          asking for a different profile. Most deployments leave this blank and configure
          the binding on the <a href="/allowlist">allowlist</a> or <a href="/tokens">token</a> instead.
        </small>
      </fieldset>
    {/if}

    {#if recommendation.allowStyleToggle}
      <div class="style-toggle" role="tablist" aria-label="Agent style">
        <button
          role="tab"
          aria-selected={style === 'shell'}
          class:active={style === 'shell'}
          onclick={() => (style = 'shell')}
        >
          Shell one-liner
          <small>curl | sh</small>
        </button>
        <button
          role="tab"
          aria-selected={style === 'binary'}
          class:active={style === 'binary'}
          onclick={() => (style = 'binary')}
        >
          Go binary
          <small>ztp-agent</small>
        </button>
      </div>
      <p class="hint">
        {#if style === 'shell'}
          Zero-install: pipes the canonical script straight into <code>sh</code>. Needs <code>curl</code>, <code>openssl</code> (Ed25519), and <code>base64</code> on the device.
          The script auto-generates an Ed25519 key under <code>/var/lib/ztp/identity.pem</code> on first run.
        {:else}
          Static binary. The <code>-identity</code> flag is a destination path — the agent generates the keypair (and creates the parent directory) on first run if the file does not yet exist.
        {/if}
      </p>
      {#if style === 'shell'}
        <p class="hint debug-hint">
          <strong>Debugging tip:</strong> prepend <code>ZTP_DEBUG=only</code> to dump the signed manifest the
          server delivered (and decode each module payload) without invoking any appliers — useful for verifying
          server config before installing real handlers under <code>/etc/ztp/appliers.d</code>.
        </p>
      {/if}
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
  <h3>At-a-glance</h3>
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
  .lede { color: #8b949e; max-width: 60ch; }

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
  }
  .serverinfo summary code { color: #58a6ff; }
  .serverinfo dl {
    margin: 0;
    padding: 0 1rem 0.75rem 1.25rem;
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.4rem 1rem;
  }
  .serverinfo dt { color: #8b949e; }
  .serverinfo dd { margin: 0; word-break: break-all; }
  .serverinfo code.full { font-size: 0.85rem; }
  .warn { color: #d29922; }

  .stepper { display: flex; gap: 0.5rem; padding: 0; list-style: none; margin: 1.5rem 0; }
  .stepper li {
    flex: 1;
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    background: #161b22;
    border: 1px solid #30363d;
    color: #8b949e;
    font-size: 0.9rem;
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
  .card h3 { margin-top: 0; }

  .choices { display: grid; grid-template-columns: 1fr; gap: 0.75rem; }
  @media (min-width: 720px) { .choices { grid-template-columns: 1fr 1fr 1fr; } }
  .choices button {
    text-align: left;
    background: #0d1117;
    border: 1px solid #30363d;
    color: #e6edf3;
    border-radius: 6px;
    padding: 1rem;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    font: inherit;
    transition: border-color 0.15s, background 0.15s;
  }
  .choices button:hover { border-color: #1f6feb; background: #1f2a37; }
  .choices button strong { font-size: 1rem; }
  .choices button span { color: #8b949e; font-size: 0.9rem; line-height: 1.4; }

  .style-toggle {
    display: inline-flex;
    border: 1px solid #30363d;
    border-radius: 6px;
    overflow: hidden;
    margin: 1rem 0 0.5rem;
  }
  .style-toggle button {
    background: #0d1117;
    color: #8b949e;
    border: 0;
    padding: 0.5rem 1rem;
    cursor: pointer;
    font: inherit;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.1rem;
    border-right: 1px solid #30363d;
  }
  .style-toggle button:last-child { border-right: 0; }
  .style-toggle button.active { background: #1f6feb; color: #fff; }
  .style-toggle button small { font-size: 0.75rem; opacity: 0.85; font-family: ui-monospace, monospace; }

  .hint { color: #8b949e; font-size: 0.9rem; max-width: 70ch; }
  .hint code { background: #0d1117; padding: 0.05rem 0.3rem; border-radius: 3px; color: #c9d1d9; }
  .debug-hint { border-left: 3px solid #1f6feb; padding-left: 0.6rem; margin-top: 0.2rem; }

  .server-picker {
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.6rem 0.8rem 0.7rem;
    margin: 0.6rem 0 0.8rem;
  }
  .server-picker legend { padding: 0 0.4rem; font-size: 0.85rem; color: #8b949e; }
  .profile-picker {
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.6rem 0.8rem 0.7rem;
    margin: 0.6rem 0 0.8rem;
  }
  .profile-picker legend { padding: 0 0.4rem; font-size: 0.85rem; color: #8b949e; }
  .profile-picker legend small { color: #6e7681; }
  .profile-picker select {
    display: block;
    width: 100%;
    margin: 0.3rem 0 0.4rem;
    padding: 0.35rem 0.5rem;
    background: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    font-family: ui-monospace, monospace;
  }
  .server-picker .presets { display: flex; flex-wrap: wrap; gap: 0.4rem 1rem; margin-bottom: 0.4rem; }
  .server-picker .presets label { display: flex; align-items: center; gap: 0.35rem; cursor: pointer; }
  .server-picker .presets span { display: inline-flex; flex-direction: column; line-height: 1.15; }
  .server-picker .presets small { color: #8b949e; font-family: ui-monospace, monospace; font-size: 0.75rem; }
  .server-picker .custom-server {
    display: block;
    width: 100%;
    margin: 0.3rem 0 0.4rem;
    padding: 0.35rem 0.5rem;
    background: #0d1117;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    font-family: ui-monospace, monospace;
  }
  .insecure-check {
    display: flex;
    align-items: flex-start;
    gap: 0.45rem;
    margin: 0.5rem 0 0.1rem;
    cursor: pointer;
    color: #d29922;
  }
  .insecure-check input { margin-top: 0.2rem; flex-shrink: 0; }
  .insecure-check span { display: block; }
  .insecure-check small { display: block; color: #8b949e; font-size: 0.8rem; margin-top: 0.1rem; }

  .result header { display: flex; justify-content: space-between; align-items: center; }
  .reset {
    background: transparent;
    color: #8b949e;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 0.25rem 0.75rem;
    cursor: pointer;
  }
  .rationale { color: #c9d1d9; max-width: 70ch; }
  .steps { padding-left: 1.25rem; }
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
  .note { color: #8b949e; display: block; margin-top: 0.4rem; }
  .cta { color: #58a6ff; text-decoration: none; font-weight: 600; }
  .cta:hover { text-decoration: underline; }

  .cheatsheet { margin-top: 2rem; }
  .cheatsheet table { width: 100%; border-collapse: collapse; }
  .cheatsheet th, .cheatsheet td {
    padding: 0.5rem;
    text-align: left;
    border-bottom: 1px solid #30363d;
  }
  .cheatsheet th { color: #8b949e; font-weight: normal; }
  .cheatsheet a { color: #58a6ff; text-decoration: none; }
  .cheatsheet a:hover { text-decoration: underline; }
</style>

