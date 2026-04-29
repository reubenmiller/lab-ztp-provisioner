<script lang="ts">
  // Profile editor.
  //
  // Two views layered on the same data:
  //
  //   1. Structured forms (default) — one collapsible section per built-in
  //      provider (wifi/ssh/cumulocity/files/hook). Each section has an
  //      "Enable" checkbox: clearing it removes the entire provider from the
  //      payload, ticking it adds an empty stub. Inside each section the
  //      operator gets typed inputs, plus +/- buttons for the array-shaped
  //      providers (wifi networks, ssh keys/users, files).
  //
  //   2. Advanced (raw JSON) — for power users and forward-compat: any keys
  //      not covered by the structured editor (future provider, custom
  //      fields, etc.) live here. The two views share a single $state
  //      object, so toggling between them is lossless.
  //
  // Sensitive fields are returned as "<redacted>" by the server. The editor
  // shows them in a disabled input with a "Set new value" toggle that
  // reveals an input the operator can replace.
  //
  // The Export button downloads a YAML representation suitable for dropping
  // into profiles_dir; secrets are redacted in the export so the operator
  // must edit before deploying (or pre-encrypt with SOPS).

  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import {
    api,
    type Profile,
    type PayloadSet,
    type Selector,
    type WiFiNetwork,
    type FileSpec,
    type PasswdUser,
  } from '$lib/api';
  import { wailsSaveFile } from '$lib/runtime';

  let name = $derived($page.params.name);
  let profile = $state<Profile | null>(null);
  let err = $state<string | null>(null);
  let saved = $state(false);

  // Form state. Mutated in place by the per-provider components below; the
  // top-level save() serialises this back into a ProfileWrite.
  let description = $state('');
  let priority = $state(0);
  let selector = $state<Selector>({});
  let payload = $state<PayloadSet>({});

  // Track unknown-keys (anything not in the structured editor) so they
  // round-trip through save/refresh.
  let extras = $state<Record<string, unknown>>({});

  // View toggle.
  type View = 'form' | 'json';
  let view = $state<View>('form');
  // Mirrored JSON text for the advanced editor. Kept in sync via $effect:
  // editing it in JSON mode and switching back to form mode parses; editing
  // form fields and switching to JSON mode re-stringifies.
  let payloadText = $state('{}');
  let jsonErr = $state<string | null>(null);

  // Track which sensitive fields the operator wants to overwrite.
  // Key format: dot path, e.g. "wifi.networks.0.password" or "hook.script".
  let sensitiveOverride = $state<Record<string, string>>({});
  function overrideKey(path: string): string {
    return sensitiveOverride[path] ?? '';
  }
  function setOverride(path: string, val: string) {
    sensitiveOverride = { ...sensitiveOverride, [path]: val };
  }
  function clearOverride(path: string) {
    const next = { ...sensitiveOverride };
    delete next[path];
    sensitiveOverride = next;
  }
  function isRedacted(v: unknown): boolean {
    return v === '<redacted>';
  }

  const KNOWN_KEYS = new Set(['wifi', 'ssh', 'cumulocity', 'files', 'hook', 'passwd']);

  async function refresh() {
    try {
      profile = await api.profile(name);
      description = profile.description ?? '';
      priority = profile.priority ?? 0;
      selector = profile.selector ?? {};
      const p = profile.payload ?? {};
      // Split known providers from extras so the JSON view shows only
      // the bits the structured editor doesn't cover.
      const known: PayloadSet = {};
      const rest: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(p)) {
        if (KNOWN_KEYS.has(k)) (known as Record<string, unknown>)[k] = v;
        else rest[k] = v;
      }
      payload = known;
      extras = rest;
      payloadText = JSON.stringify(p, null, 2);
      sensitiveOverride = {};
      err = null;
    } catch (e: any) {
      err = e.message;
    }
  }

  function buildPayload(): PayloadSet {
    // Merge structured + extras + apply sensitive overrides. Empty provider
    // shells (e.g. cumulocity with all empty strings) are kept as-is — the
    // user explicitly enabled them, removing them silently would be
    // surprising.
    const out: PayloadSet = { ...extras };
    for (const [k, v] of Object.entries(payload)) {
      out[k] = v as never;
    }
    // Apply sensitive-field overrides. We mutate a deep copy.
    const cloned: PayloadSet = JSON.parse(JSON.stringify(out));
    // wifi network passwords
    if (cloned.wifi?.networks) {
      for (let i = 0; i < cloned.wifi.networks.length; i++) {
        const path = `wifi.networks.${i}.password`;
        if (path in sensitiveOverride) {
          cloned.wifi.networks[i].password = sensitiveOverride[path];
        } else if (isRedacted(cloned.wifi.networks[i].password)) {
          // Strip the placeholder so we don't write "<redacted>" back to the
          // server — that would clobber the real secret.
          delete cloned.wifi.networks[i].password;
        }
      }
    }
    // c8y static_token
    if (cloned.cumulocity?.issuer) {
      const path = 'cumulocity.issuer.static_token';
      if (path in sensitiveOverride) {
        cloned.cumulocity.issuer.static_token = sensitiveOverride[path];
      } else if (isRedacted(cloned.cumulocity.issuer.static_token)) {
        delete cloned.cumulocity.issuer.static_token;
      }
    }
    // hook script
    if (cloned.hook) {
      const path = 'hook.script';
      if (path in sensitiveOverride) {
        cloned.hook.script = sensitiveOverride[path];
      } else if (isRedacted(cloned.hook.script)) {
        delete cloned.hook.script;
      }
    }
    // passwd user passwords
    if (cloned.passwd?.users) {
      for (let i = 0; i < cloned.passwd.users.length; i++) {
        const path = `passwd.users.${i}.password`;
        if (path in sensitiveOverride) {
          cloned.passwd.users[i].password = sensitiveOverride[path];
        } else if (isRedacted(cloned.passwd.users[i].password)) {
          delete cloned.passwd.users[i].password;
        }
      }
    }
    // file contents / base64
    if (cloned.files?.files) {
      for (let i = 0; i < cloned.files.files.length; i++) {
        const cPath = `files.files.${i}.contents`;
        const bPath = `files.files.${i}.base64`;
        if (cPath in sensitiveOverride) cloned.files.files[i].contents = sensitiveOverride[cPath];
        else if (isRedacted(cloned.files.files[i].contents)) delete cloned.files.files[i].contents;
        if (bPath in sensitiveOverride) cloned.files.files[i].base64 = sensitiveOverride[bPath];
        else if (isRedacted(cloned.files.files[i].base64)) delete cloned.files.files[i].base64;
      }
    }
    return cloned;
  }

  async function save(e: Event) {
    e.preventDefault();
    saved = false;
    let body: PayloadSet;
    if (view === 'json') {
      // Operator was in raw mode; trust their JSON.
      try {
        body = JSON.parse(payloadText);
      } catch (ex: any) {
        err = `Payload is not valid JSON: ${ex.message}`;
        return;
      }
    } else {
      body = buildPayload();
    }
    try {
      await api.updateProfile(name, {
        description,
        priority,
        payload: body,
        selector: hasSelector(selector) ? selector : undefined,
        labels: profile?.labels,
      });
      saved = true;
      await refresh();
    } catch (ex: any) {
      err = ex.message;
    }
  }

  function hasSelector(s: Selector): boolean {
    return !!(
      s.match_model ||
      s.match_hostname ||
      (s.match_mac_oui && s.match_mac_oui.length > 0) ||
      (s.match_labels && Object.keys(s.match_labels).length > 0)
    );
  }

  function switchView(target: View) {
    if (target === view) return;
    if (target === 'json') {
      payloadText = JSON.stringify(buildPayload(), null, 2);
    } else {
      // form mode — try to parse current JSON back into structured state.
      try {
        const parsed: PayloadSet = JSON.parse(payloadText);
        const known: PayloadSet = {};
        const rest: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(parsed)) {
          if (KNOWN_KEYS.has(k)) (known as Record<string, unknown>)[k] = v;
          else rest[k] = v;
        }
        payload = known;
        extras = rest;
        sensitiveOverride = {};
        jsonErr = null;
      } catch (ex: any) {
        jsonErr = ex.message;
        return;
      }
    }
    view = target;
  }

  // ---- provider toggles --------------------------------------------------
  function toggleWifi(on: boolean) {
    if (on) payload = { ...payload, wifi: payload.wifi ?? { networks: [] } };
    else { const next = { ...payload }; delete next.wifi; payload = next; }
  }
  function toggleSSH(on: boolean) {
    if (on) payload = { ...payload, ssh: payload.ssh ?? { keys: [] } };
    else { const next = { ...payload }; delete next.ssh; payload = next; }
  }
  function toggleC8y(on: boolean) {
    if (on) payload = { ...payload, cumulocity: payload.cumulocity ?? { issuer: { mode: '' } } };
    else { const next = { ...payload }; delete next.cumulocity; payload = next; }
  }
  function toggleFiles(on: boolean) {
    if (on) payload = { ...payload, files: payload.files ?? { files: [] } };
    else { const next = { ...payload }; delete next.files; payload = next; }
  }
  function toggleHook(on: boolean) {
    if (on) payload = { ...payload, hook: payload.hook ?? { script: '', interpreter: '/bin/sh' } };
    else { const next = { ...payload }; delete next.hook; payload = next; }
  }
  function togglePasswd(on: boolean) {
    if (on) payload = { ...payload, passwd: payload.passwd ?? { users: [] } };
    else { const next = { ...payload }; delete next.passwd; payload = next; }
  }

  // ---- WiFi helpers ------------------------------------------------------
  function addWifiNetwork() {
    const w = payload.wifi ?? { networks: [] };
    const networks = [...(w.networks ?? []), { ssid: '', key_mgmt: 'WPA-PSK' } as WiFiNetwork];
    payload = { ...payload, wifi: { ...w, networks } };
  }
  function removeWifiNetwork(i: number) {
    if (!payload.wifi?.networks) return;
    const networks = payload.wifi.networks.filter((_, j) => j !== i);
    payload = { ...payload, wifi: { ...payload.wifi, networks } };
    clearOverride(`wifi.networks.${i}.password`);
  }

  // ---- SSH helpers -------------------------------------------------------
  // Keys are edited as a single textarea (one OpenSSH line per row); same
  // for github_users (one username per row). This is dramatically friendlier
  // than the per-row +/- UI for the common case of pasting in a block.
  let sshKeysText = $derived((payload.ssh?.keys ?? []).join('\n'));
  let sshUsersText = $derived((payload.ssh?.github_users ?? []).join('\n'));
  function setSSHKeys(text: string) {
    const keys = text.split('\n').map((s) => s.trim()).filter((s) => s !== '');
    payload = { ...payload, ssh: { ...(payload.ssh ?? {}), keys } };
  }
  function setSSHUsers(text: string) {
    const users = text.split('\n').map((s) => s.trim()).filter((s) => s !== '');
    payload = { ...payload, ssh: { ...(payload.ssh ?? {}), github_users: users } };
  }

  // ---- Passwd helpers ----------------------------------------------------
  function addPasswdUser() {
    const pw = payload.passwd ?? { users: [] };
    const users = [...(pw.users ?? []), { name: '' } as PasswdUser];
    payload = { ...payload, passwd: { ...pw, users } };
  }
  function removePasswdUser(i: number) {
    if (!payload.passwd?.users) return;
    const users = payload.passwd.users.filter((_, j) => j !== i);
    payload = { ...payload, passwd: { ...payload.passwd, users } };
    clearOverride(`passwd.users.${i}.password`);
  }

  // ---- Files helpers -----------------------------------------------------
  function addFile() {
    const f = payload.files ?? { files: [] };
    const files = [...(f.files ?? []), { path: '' } as FileSpec];
    payload = { ...payload, files: { ...f, files } };
  }
  function removeFile(i: number) {
    if (!payload.files?.files) return;
    const files = payload.files.files.filter((_, j) => j !== i);
    payload = { ...payload, files: { ...payload.files, files } };
    clearOverride(`files.files.${i}.contents`);
    clearOverride(`files.files.${i}.base64`);
  }

  // ---- Selector MAC-OUI list (csv-edited) -------------------------------
  let macOUIText = $derived((selector.match_mac_oui ?? []).join(', '));
  function setMacOUI(text: string) {
    const list = text.split(',').map((s) => s.trim()).filter((s) => s !== '');
    selector = { ...selector, match_mac_oui: list.length ? list : undefined };
  }

  onMount(refresh);

  let readOnly = $derived(profile?.source === 'file');

  async function exportYAML() {
    const url = api.exportProfileURL(name);
    const save = wailsSaveFile();
    if (save) {
      try {
        const res = await fetch(url);
        if (!res.ok) {
          err = `Export failed: ${res.status} ${res.statusText}`;
          return;
        }
        const text = await res.text();
        await save(`${name}.yaml`, text);
      } catch (e: any) {
        err = `Export failed: ${e.message ?? e}`;
      }
      return;
    }
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.yaml`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
</script>

<a href="/profiles" class="back">&larr; All profiles</a>

{#if err}<p class="err">{err}</p>{/if}

{#if profile}
  <header class="title">
    <h2><code>{profile.name}</code> <span class="src src-{profile.source}">{profile.source}</span></h2>
    <button type="button" class="export" onclick={exportYAML}>Export YAML</button>
  </header>

  {#if readOnly}
    <p class="warn">
      This is a <strong>file-backed profile</strong> from <code>profiles_dir</code>.
      Edit the YAML on disk and reload (<code>kill -HUP</code> the server,
      or click "Reload from disk" on the profiles list). The form below is
      read-only; use <strong>Export YAML</strong> as a starting point.
    </p>
  {/if}

  <form onsubmit={save}>
    <fieldset class="meta">
      <legend>Metadata</legend>
      <div class="field">
        <label for="desc">Description</label>
        <input id="desc" bind:value={description} disabled={readOnly} />
      </div>
      <div class="field">
        <label for="prio">Priority</label>
        <input id="prio" type="number" bind:value={priority} disabled={readOnly} />
        <small>Higher values are evaluated first when matching by selector.</small>
      </div>
    </fieldset>

    <fieldset class="meta">
      <legend>Selector <small>(optional, fact-based auto-assignment)</small></legend>
      <div class="field">
        <label for="m-model">Model regex</label>
        <input id="m-model" bind:value={selector.match_model} disabled={readOnly} placeholder="e.g. ^rpi-(3|4)" />
      </div>
      <div class="field">
        <label for="m-host">Hostname regex</label>
        <input id="m-host" bind:value={selector.match_hostname} disabled={readOnly} placeholder="e.g. ^lab-" />
      </div>
      <div class="field">
        <label for="m-mac">MAC OUI list</label>
        <input id="m-mac" value={macOUIText} oninput={(e) => setMacOUI((e.target as HTMLInputElement).value)} disabled={readOnly} placeholder="aa:bb:cc, dd:ee:ff" />
        <small>Comma-separated list of 3-byte OUI prefixes (with or without colons).</small>
      </div>
    </fieldset>

    <!-- ============================================================== -->
    <!-- View toggle                                                    -->
    <!-- ============================================================== -->
    <div class="view-toggle" role="tablist">
      <button type="button" role="tab" aria-selected={view === 'form'} class:active={view === 'form'} onclick={() => switchView('form')}>Form</button>
      <button type="button" role="tab" aria-selected={view === 'json'} class:active={view === 'json'} onclick={() => switchView('json')}>Advanced (raw JSON)</button>
    </div>
    {#if jsonErr}<p class="err">JSON parse error: {jsonErr}</p>{/if}

    {#if view === 'json'}
      <div class="field">
        <label for="payload">Payload (JSON)</label>
        <textarea id="payload" bind:value={payloadText} rows="20" disabled={readOnly} spellcheck="false"></textarea>
        <small>
          Sensitive fields are returned as <code>&lt;redacted&gt;</code>. Replace the
          placeholder with the new plaintext to rotate a secret; remove the
          line entirely to keep the existing value.
        </small>
      </div>
    {:else}
      <!-- ========================================================== -->
      <!-- Provider blocks                                            -->
      <!-- ========================================================== -->

      <fieldset class="provider" class:enabled={!!payload.wifi}>
        <legend>
          <label><input type="checkbox" checked={!!payload.wifi} disabled={readOnly} onchange={(e) => toggleWifi((e.target as HTMLInputElement).checked)} /> WiFi</label>
        </legend>
        {#if payload.wifi}
          {#each payload.wifi.networks ?? [] as net, i (i)}
            <div class="row">
              <div class="row-head">
                <strong>Network #{i + 1}</strong>
                <button type="button" class="remove" disabled={readOnly} onclick={() => removeWifiNetwork(i)}>Remove</button>
              </div>
              <div class="grid">
                <div class="field">
                  <label>SSID</label>
                  <input bind:value={net.ssid} disabled={readOnly} />
                </div>
                <div class="field">
                  <label>Key management</label>
                  <select bind:value={net.key_mgmt} disabled={readOnly}>
                    <option value="WPA-PSK">WPA-PSK</option>
                    <option value="WPA-EAP">WPA-EAP</option>
                    <option value="NONE">NONE (open)</option>
                  </select>
                </div>
                <div class="field">
                  <label>Priority</label>
                  <input type="number" bind:value={net.priority} disabled={readOnly} />
                </div>
                <div class="field hidden-toggle">
                  <label><input type="checkbox" bind:checked={net.hidden} disabled={readOnly} /> Hidden SSID</label>
                </div>
                <div class="field full">
                  {#if isRedacted(net.password) && !(`wifi.networks.${i}.password` in sensitiveOverride)}
                    <label>Password</label>
                    <div class="redacted-row">
                      <input value="<redacted>" disabled />
                      <button type="button" disabled={readOnly} onclick={() => setOverride(`wifi.networks.${i}.password`, '')}>Set new value</button>
                    </div>
                  {:else if `wifi.networks.${i}.password` in sensitiveOverride}
                    <label>Password (new value)</label>
                    <div class="redacted-row">
                      <input value={overrideKey(`wifi.networks.${i}.password`)} oninput={(e) => setOverride(`wifi.networks.${i}.password`, (e.target as HTMLInputElement).value)} disabled={readOnly} />
                      <button type="button" disabled={readOnly} onclick={() => clearOverride(`wifi.networks.${i}.password`)}>Cancel</button>
                    </div>
                    <small>Will replace the existing password on save.</small>
                  {:else}
                    <label>Password</label>
                    <input bind:value={net.password} disabled={readOnly} placeholder="(none)" />
                  {/if}
                </div>
              </div>
            </div>
          {/each}
          <button type="button" class="add" disabled={readOnly} onclick={addWifiNetwork}>+ Add network</button>
        {/if}
      </fieldset>

      <fieldset class="provider" class:enabled={!!payload.ssh}>
        <legend>
          <label><input type="checkbox" checked={!!payload.ssh} disabled={readOnly} onchange={(e) => toggleSSH((e.target as HTMLInputElement).checked)} /> SSH authorized_keys</label>
        </legend>
        {#if payload.ssh}
          <div class="grid">
            <div class="field">
              <label>Target user</label>
              <input bind:value={payload.ssh.user} disabled={readOnly} placeholder="root (default)" />
            </div>
            <div class="field full">
              <label>OpenSSH public keys (one per line)</label>
              <textarea rows="4" value={sshKeysText} oninput={(e) => setSSHKeys((e.target as HTMLTextAreaElement).value)} disabled={readOnly} spellcheck="false" placeholder="ssh-ed25519 AAAA…"></textarea>
            </div>
            <div class="field full">
              <label>GitHub usernames (fetch keys from https://github.com/&lt;user&gt;.keys, one per line)</label>
              <textarea rows="3" value={sshUsersText} oninput={(e) => setSSHUsers((e.target as HTMLTextAreaElement).value)} disabled={readOnly} spellcheck="false" placeholder="alice"></textarea>
            </div>
            <div class="field">
              <label>GitHub API URL</label>
              <input bind:value={payload.ssh.github_api_url} disabled={readOnly} placeholder="https://github.com (default)" />
            </div>
          </div>
        {/if}
      </fieldset>

      <fieldset class="provider" class:enabled={!!payload.cumulocity}>
        <legend>
          <label><input type="checkbox" checked={!!payload.cumulocity} disabled={readOnly} onchange={(e) => toggleC8y((e.target as HTMLInputElement).checked)} /> Cumulocity</label>
        </legend>
        {#if payload.cumulocity}
          <div class="grid">
            <div class="field">
              <label>URL</label>
              <input bind:value={payload.cumulocity.url} disabled={readOnly} placeholder="https://example.cumulocity.com" />
            </div>
            <div class="field">
              <label>Tenant</label>
              <input bind:value={payload.cumulocity.tenant} disabled={readOnly} />
            </div>
            <div class="field">
              <label>External ID prefix</label>
              <input bind:value={payload.cumulocity.external_id_prefix} disabled={readOnly} />
            </div>
            <div class="field">
              <label>Token TTL</label>
              <input bind:value={payload.cumulocity.token_ttl} disabled={readOnly} placeholder="e.g. 5m, 1h" />
            </div>
          </div>
          <h4>Issuer</h4>
          <div class="grid">
            <div class="field">
              <label>Mode</label>
              <select bind:value={payload.cumulocity.issuer!.mode} disabled={readOnly}>
                <option value="">(none — token must come out-of-band)</option>
                <option value="local">local — server holds c8y creds</option>
                <option value="remote">remote — sidecar over mTLS</option>
                <option value="static">static — fixed token (INSECURE, dev only)</option>
              </select>
            </div>
            {#if payload.cumulocity.issuer?.mode === 'local'}
              <div class="field"><label>Base URL</label><input bind:value={payload.cumulocity.issuer.base_url} disabled={readOnly} /></div>
              <div class="field"><label>Tenant</label><input bind:value={payload.cumulocity.issuer.tenant} disabled={readOnly} /></div>
              <div class="field full"><label>Credentials file</label><input bind:value={payload.cumulocity.issuer.credentials_file} disabled={readOnly} placeholder="/etc/ztp/c8y.json (mode 0600)" /></div>
            {:else if payload.cumulocity.issuer?.mode === 'remote'}
              <div class="field full"><label>Endpoint</label><input bind:value={payload.cumulocity.issuer.endpoint} disabled={readOnly} placeholder="https://issuer.internal:9443" /></div>
              <div class="field"><label>Client cert</label><input bind:value={payload.cumulocity.issuer.client_cert} disabled={readOnly} /></div>
              <div class="field"><label>Client key</label><input bind:value={payload.cumulocity.issuer.client_key} disabled={readOnly} /></div>
              <div class="field full"><label>CA cert</label><input bind:value={payload.cumulocity.issuer.ca_cert} disabled={readOnly} /></div>
            {:else if payload.cumulocity.issuer?.mode === 'static'}
              <div class="field full">
                {#if isRedacted(payload.cumulocity.issuer.static_token) && !('cumulocity.issuer.static_token' in sensitiveOverride)}
                  <label>Static token</label>
                  <div class="redacted-row">
                    <input value="<redacted>" disabled />
                    <button type="button" disabled={readOnly} onclick={() => setOverride('cumulocity.issuer.static_token', '')}>Set new value</button>
                  </div>
                {:else if 'cumulocity.issuer.static_token' in sensitiveOverride}
                  <label>Static token (new value)</label>
                  <div class="redacted-row">
                    <input value={overrideKey('cumulocity.issuer.static_token')} oninput={(e) => setOverride('cumulocity.issuer.static_token', (e.target as HTMLInputElement).value)} disabled={readOnly} />
                    <button type="button" disabled={readOnly} onclick={() => clearOverride('cumulocity.issuer.static_token')}>Cancel</button>
                  </div>
                {:else}
                  <label>Static token</label>
                  <input bind:value={payload.cumulocity.issuer.static_token} disabled={readOnly} />
                {/if}
              </div>
            {/if}
          </div>
        {/if}
      </fieldset>

      <fieldset class="provider" class:enabled={!!payload.files}>
        <legend>
          <label><input type="checkbox" checked={!!payload.files} disabled={readOnly} onchange={(e) => toggleFiles((e.target as HTMLInputElement).checked)} /> Files</label>
        </legend>
        {#if payload.files}
          {#each payload.files.files ?? [] as f, i (i)}
            <div class="row">
              <div class="row-head">
                <strong>File #{i + 1}</strong>
                <button type="button" class="remove" disabled={readOnly} onclick={() => removeFile(i)}>Remove</button>
              </div>
              <div class="grid">
                <div class="field full"><label>Path</label><input bind:value={f.path} disabled={readOnly} placeholder="/etc/example.conf" /></div>
                <div class="field"><label>Mode</label><input bind:value={f.mode} disabled={readOnly} placeholder="0644" /></div>
                <div class="field"><label>Owner</label><input bind:value={f.owner} disabled={readOnly} placeholder="root:root" /></div>
                <div class="field full">
                  {#if isRedacted(f.contents) && !(`files.files.${i}.contents` in sensitiveOverride)}
                    <label>Contents</label>
                    <div class="redacted-row">
                      <input value="<redacted>" disabled />
                      <button type="button" disabled={readOnly} onclick={() => setOverride(`files.files.${i}.contents`, '')}>Set new value</button>
                    </div>
                  {:else if `files.files.${i}.contents` in sensitiveOverride}
                    <label>Contents (new value)</label>
                    <textarea rows="4" value={overrideKey(`files.files.${i}.contents`)} oninput={(e) => setOverride(`files.files.${i}.contents`, (e.target as HTMLTextAreaElement).value)} disabled={readOnly} spellcheck="false"></textarea>
                    <button type="button" class="cancel-inline" disabled={readOnly} onclick={() => clearOverride(`files.files.${i}.contents`)}>Cancel override</button>
                  {:else}
                    <label>Contents (text)</label>
                    <textarea rows="4" bind:value={f.contents} disabled={readOnly} spellcheck="false"></textarea>
                  {/if}
                </div>
              </div>
            </div>
          {/each}
          <button type="button" class="add" disabled={readOnly} onclick={addFile}>+ Add file</button>
        {/if}
      </fieldset>

      <fieldset class="provider" class:enabled={!!payload.hook}>
        <legend>
          <label><input type="checkbox" checked={!!payload.hook} disabled={readOnly} onchange={(e) => toggleHook((e.target as HTMLInputElement).checked)} /> Post-bundle hook</label>
        </legend>
        {#if payload.hook}
          <div class="grid">
            <div class="field">
              <label>Interpreter</label>
              <input bind:value={payload.hook.interpreter} disabled={readOnly} placeholder="/bin/sh (default)" />
            </div>
            <div class="field full">
              {#if isRedacted(payload.hook.script) && !('hook.script' in sensitiveOverride)}
                <label>Script</label>
                <div class="redacted-row">
                  <input value="<redacted>" disabled />
                  <button type="button" disabled={readOnly} onclick={() => setOverride('hook.script', '')}>Set new value</button>
                </div>
              {:else if 'hook.script' in sensitiveOverride}
                <label>Script (new value)</label>
                <textarea rows="6" value={overrideKey('hook.script')} oninput={(e) => setOverride('hook.script', (e.target as HTMLTextAreaElement).value)} disabled={readOnly} spellcheck="false"></textarea>
                <button type="button" class="cancel-inline" disabled={readOnly} onclick={() => clearOverride('hook.script')}>Cancel override</button>
              {:else}
                <label>Script</label>
                <textarea rows="6" bind:value={payload.hook.script} disabled={readOnly} spellcheck="false"></textarea>
              {/if}
            </div>
          </div>
        {/if}
      </fieldset>

      <fieldset class="provider" class:enabled={!!payload.passwd}>
        <legend>
          <label><input type="checkbox" checked={!!payload.passwd} disabled={readOnly} onchange={(e) => togglePasswd((e.target as HTMLInputElement).checked)} /> User passwords (passwd)</label>
        </legend>
        {#if payload.passwd}
          {#each payload.passwd.users ?? [] as u, i (i)}
            <div class="row">
              <div class="row-head">
                <strong>User #{i + 1}</strong>
                <button type="button" class="remove" disabled={readOnly} onclick={() => removePasswdUser(i)}>Remove</button>
              </div>
              <div class="grid">
                <div class="field">
                  <label>Username</label>
                  <input bind:value={u.name} disabled={readOnly} placeholder="e.g. root" />
                </div>
                <div class="field">
                  {#if isRedacted(u.password) && !(`passwd.users.${i}.password` in sensitiveOverride)}
                    <label>Password</label>
                    <div class="redacted-row">
                      <input value="<redacted>" disabled />
                      <button type="button" disabled={readOnly} onclick={() => setOverride(`passwd.users.${i}.password`, '')}>Set new value</button>
                    </div>
                  {:else if `passwd.users.${i}.password` in sensitiveOverride}
                    <label>Password (new value)</label>
                    <div class="redacted-row">
                      <input type="password" value={overrideKey(`passwd.users.${i}.password`)} oninput={(e) => setOverride(`passwd.users.${i}.password`, (e.target as HTMLInputElement).value)} disabled={readOnly} />
                      <button type="button" disabled={readOnly} onclick={() => clearOverride(`passwd.users.${i}.password`)}>Cancel</button>
                    </div>
                    <small>Will replace the existing password on save.</small>
                  {:else}
                    <label>Password</label>
                    <input type="password" bind:value={u.password} disabled={readOnly} placeholder="(none)" />
                  {/if}
                </div>
              </div>
            </div>
          {/each}
          <button type="button" class="add" disabled={readOnly} onclick={addPasswdUser}>+ Add user</button>
        {/if}
      </fieldset>

      {#if Object.keys(extras).length > 0}
        <p class="extras-note">
          This profile contains extra payload keys not handled by the structured editor:
          <code>{Object.keys(extras).join(', ')}</code>. Switch to <strong>Advanced (raw JSON)</strong> to view or edit them.
        </p>
      {/if}
    {/if}

    {#if !readOnly}
      <div class="actions">
        <button type="submit">Save</button>
        {#if saved}<span class="ok">Saved.</span>{/if}
      </div>
    {/if}
  </form>
{:else if !err}
  <p>Loading…</p>
{/if}

<style>
  .back { color: #58a6ff; text-decoration: none; }
  .back:hover { text-decoration: underline; }
  .err { color: #f85149; }
  .ok { color: #3fb950; margin-left: 0.5rem; }
  .warn { background: #f0883e22; border: 1px solid #f0883e; padding: 0.75rem; border-radius: 6px; }
  .title { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; }
  h2 { display: flex; align-items: center; gap: 0.75rem; margin: 0; }
  .export {
    background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px;
    padding: 0.35rem 0.8rem; text-decoration: none; font-size: 0.9rem;
  }
  .export:hover { background: #30363d; }
  code { background: #161b22; padding: 0.1rem 0.3rem; border-radius: 3px; }
  .src { padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.75rem; font-weight: normal; }
  .src-file { background: #1f6feb33; color: #58a6ff; }
  .src-db { background: #3fb95033; color: #3fb950; }

  fieldset.meta, fieldset.provider {
    border: 1px solid #30363d; border-radius: 6px;
    padding: 0.6rem 0.9rem 0.8rem;
    margin: 0.7rem 0;
  }
  fieldset.provider:not(.enabled) { background: #0d1117aa; opacity: 0.85; }
  legend { padding: 0 0.4rem; color: #c9d1d9; font-weight: 500; }
  legend small { color: #8b949e; font-weight: normal; }
  legend label { display: inline-flex; align-items: center; gap: 0.4rem; cursor: pointer; }

  .field { display: flex; flex-direction: column; margin-bottom: 0.6rem; }
  .field label { font-size: 0.85rem; color: #c9d1d9; margin-bottom: 0.25rem; }
  .field small { color: #8b949e; font-size: 0.75rem; margin-top: 0.25rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem 0.8rem; }
  .field.full { grid-column: 1 / -1; }
  .hidden-toggle label { flex-direction: row; align-items: center; gap: 0.4rem; cursor: pointer; }

  input, textarea, select {
    background: #0d1117; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 4px; padding: 0.35rem 0.5rem; box-sizing: border-box;
    font-family: ui-monospace, SFMono-Regular, monospace;
  }
  input { width: 100%; }
  textarea { width: 100%; resize: vertical; }
  select { width: 100%; }
  input:focus, textarea:focus, select:focus { outline: none; border-color: #58a6ff; }
  input:disabled, textarea:disabled, select:disabled { opacity: 0.7; }

  .redacted-row { display: flex; gap: 0.4rem; align-items: center; }
  .redacted-row input { flex: 1; }
  .redacted-row button { white-space: nowrap; }
  .cancel-inline { align-self: flex-start; margin-top: 0.3rem; background: #30363d; }

  button {
    padding: 0.35rem 0.9rem; border-radius: 4px; border: 1px solid #30363d;
    cursor: pointer; background: #21262d; color: #c9d1d9; font: inherit;
  }
  button:hover { background: #30363d; }
  button[type="submit"] { background: #238636; color: white; border-color: #238636; padding: 0.4rem 1.2rem; }
  button[type="submit"]:hover { background: #2ea043; }
  button.remove { background: #b62324; color: white; border-color: #b62324; }
  button.remove:hover { background: #da3633; }
  button.add { background: #1f6feb22; color: #58a6ff; border-color: #1f6feb55; margin-top: 0.3rem; }
  button.add:hover { background: #1f6feb44; }

  .row { border: 1px solid #30363d; border-radius: 4px; padding: 0.5rem 0.7rem; margin-bottom: 0.5rem; }
  .row-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem; }

  .view-toggle { display: inline-flex; gap: 0; border: 1px solid #30363d; border-radius: 4px; overflow: hidden; margin: 0.5rem 0 0.7rem; }
  .view-toggle button { border: none; border-radius: 0; padding: 0.4rem 1rem; }
  .view-toggle button.active { background: #1f6feb; color: white; }

  .extras-note { background: #1f6feb22; border-left: 3px solid #1f6feb; padding: 0.5rem 0.7rem; border-radius: 4px; }
  .actions { display: flex; align-items: center; gap: 0.5rem; margin-top: 1rem; }
  h4 { margin: 0.5rem 0 0.3rem; color: #c9d1d9; font-size: 0.95rem; }
</style>
