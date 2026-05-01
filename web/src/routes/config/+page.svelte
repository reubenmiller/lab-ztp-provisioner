<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { EditorState } from '@codemirror/state';
  import { EditorView, keymap } from '@codemirror/view';
  import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
  import { autocompletion, completionKeymap, startCompletion } from '@codemirror/autocomplete';
  import { indentUnit } from '@codemirror/language';
  import { oneDark } from '@codemirror/theme-one-dark';
  import { yamlSchema } from 'codemirror-json-schema/yaml';
  import { profileSchema } from '$lib/profile-schema';
  import { api } from '$lib/api';
  import {
    detect,
    type C8YCredential,
    type DesktopRuntimeInfo,
    wailsDeleteC8YCredential,
    wailsDeleteProfileFile,
    wailsListC8YCredentials,
    wailsListProfileFiles,
    wailsOpenConfigDirectory,
    wailsReadProfileFile,
    wailsRevealSealedProfile,
    wailsSetC8YCredential,
    wailsSealProfileForSave,
    wailsWriteProfileFile
  } from '$lib/runtime';

  let desktop = $state<DesktopRuntimeInfo | null>(null);
  // null = probing, true = available, false = not configured
  let configApiAvailable = $state<boolean | null>(null);
  let err = $state<string | null>(null);
  let msg = $state<string | null>(null);
  let recipients = $state<string[]>([]);
  let c8yCredentials = $state<C8YCredential[]>([]);
  let credentialId = $state('');
  let credentialURL = $state('');
  let credentialUsername = $state('');
  let credentialPassword = $state('');
  let selectedFile = $state('');
  let files = $state<string[]>([]);
  let content = $state('');
  let editorHost = $state<HTMLDivElement | null>(null);
  let editorView: EditorView | null = null;

  // Derive a filename from the YAML `name:` field so new profiles can be
  // saved without first picking a file from the dropdown.
  let derivedFileName = $derived.by(() => {
    const m = /^name:\s*["']?([A-Za-z0-9_][A-Za-z0-9_-]*)/m.exec(content);
    return m ? `${m[1]}.yaml` : '';
  });

  // The effective filename to write to: selected dropdown value wins; if the
  // editor has a name: field, use that as a fallback for new files.
  let effectiveFile = $derived(selectedFile || derivedFileName);

  // Auto-load file content whenever the dropdown selection changes.
  $effect(() => {
    if (selectedFile) loadFile();
  });

  function initEditor() {
    if (!editorHost || editorView) return;
    editorView = new EditorView({
      state: EditorState.create({
        doc: content,
        extensions: [
          history(),
          autocompletion({ icons: false }),
          indentUnit.of('  '),
          keymap.of([
            // Custom bindings first so they shadow defaults with the same key.
            // Cmd+I on macOS (Ctrl+I on Win/Linux) — override selectLine to trigger completion instead
            { key: 'Mod-i', run: startCompletion },
            // After Enter, fire completion on the next frame so the parser sees
            // the new indentation and can resolve the schema path for the new key.
            {
              key: 'Enter',
              run: (view) => {
                requestAnimationFrame(() => startCompletion(view));
                return false; // let the default newline handler run
              }
            },
            ...completionKeymap,
            ...defaultKeymap,
            ...historyKeymap,
            indentWithTab,
          ]),
          ...yamlSchema(profileSchema),
          oneDark,
          EditorView.lineWrapping,
          EditorView.updateListener.of((update) => {
            if (update.docChanged) {
              content = update.state.doc.toString();
            }
          })
        ]
      }),
      parent: editorHost
    });
  }

  function setEditorContent(next: string) {
    content = next;
    if (!editorView) return;
    const current = editorView.state.doc.toString();
    if (current === next) return;
    editorView.dispatch({
      changes: { from: 0, to: editorView.state.doc.length, insert: next }
    });
  }

  function getEditorContent(): string {
    if (!editorView) return content;
    return editorView.state.doc.toString();
  }

  // ── Indent detection & normalisation ─────────────────────────────────────
  // Snippets are stored canonically with 2-space indentation. Before inserting
  // we detect the indent unit already in use in the document (could be 2, 4
  // spaces, or a tab) so the snippet blends in seamlessly.

  /** Return the indent unit string used by the document, defaulting to '  '. */
  function detectIndent(doc: string): string {
    // The indent unit is the minimum non-zero indent seen anywhere in the file.
    // For a consistently-formatted YAML document the shallowest indented line
    // is always exactly one indent unit deep, making this approach simpler and
    // more reliable than GCD (which breaks when mixing depths like 2+4 spaces).
    let minIndent = Infinity;
    for (const line of doc.split('\n')) {
      if (line.trim() === '') continue;
      if (/^\t/.test(line)) return '\t';
      const m = /^( +)/.exec(line);
      if (m && m[1].length < minIndent) minIndent = m[1].length;
    }
    return minIndent === Infinity ? '  ' : ' '.repeat(minIndent);
  }

  /**
   * Re-express `yaml` (written in canonical 2-space indentation) using `toIndent`
   * as the indent unit. Lines in literal-block scalars (after `|` or `>`) keep
   * their indent relative to the key so content isn't corrupted.
   */
  function reindent(yaml: string, toIndent: string): string {
    if (toIndent === '  ') return yaml;
    const lines = yaml.split('\n');
    let inLiteral = false;
    let literalBaseLevel = 0; // canonical 2-space level of the scalar key
    return lines.map((line, i) => {
      // Detect a line that opens a literal/folded scalar
      if (!inLiteral) {
        const keyMatch = /^( *)\S.*[|>]\s*$/.exec(line);
        if (keyMatch) {
          inLiteral = true;
          literalBaseLevel = keyMatch[1].length / 2;
          return convertLine(line, toIndent);
        }
        return convertLine(line, toIndent);
      }
      // Inside a literal block: keep relative indentation intact.
      // A line at or below the block's base indent ends the literal.
      const spaceMatch = /^( *)/.exec(line);
      const lineLevel = spaceMatch ? spaceMatch[1].length / 2 : 0;
      if (line.trim() === '' || lineLevel > literalBaseLevel) {
        // Re-derive absolute indent for the part inside the literal:
        // preserve the spaces that go beyond the block scalar indent level.
        const extraSpaces = spaceMatch ? spaceMatch[1].length - (literalBaseLevel + 1) * 2 : 0;
        const baseIndent = toIndent.repeat(literalBaseLevel + 1);
        return baseIndent + ' '.repeat(Math.max(0, extraSpaces)) + line.trimStart();
      }
      inLiteral = false;
      return convertLine(line, toIndent);
    }).join('\n');
  }

  function convertLine(line: string, toIndent: string): string {
    let levels = 0;
    let rest = line;
    while (rest.startsWith('  ')) {
      levels++;
      rest = rest.slice(2);
    }
    return toIndent.repeat(levels) + rest;
  }

  // ── Snippet insertion ──────────────────────────────────────────────────────
  // Snippets know their own kind so insertSnippet can place them correctly:
  //   'skeleton' — only used on a blank doc (name/description/payload scaffold)
  //   'payload'  — child of the payload: block (ssh, wifi, etc.)
  //   'top'      — top-level key (selector, priority, …)
  type Snippet =
    | { kind: 'skeleton'; label: string; title: string; yaml: string }
    | { kind: 'payload';  label: string; title: string; key: string; yaml: string }
    | { kind: 'top';      label: string; title: string; key: string; yaml: string };

  const snippets: Snippet[] = [
    {
      kind: 'skeleton',
      label: '+ skeleton',
      title: 'New profile skeleton (blank editor only)',
      yaml:
`name: my-profile
description: ""
priority: 0
payload:
`
    },
    {
      kind: 'payload',
      label: '+ ssh',
      title: 'SSH authorized_keys section',
      key: 'ssh',
      yaml:
`  ssh:
    user: root
    keys:
      - "ssh-ed25519 AAAA... user@host"
    github_users: []
`
    },
    {
      kind: 'payload',
      label: '+ wifi',
      title: 'Wi-Fi networks section',
      key: 'wifi',
      yaml:
`  wifi:
    networks:
      - ssid: "MyNetwork"
        password: "changeme"
        key_mgmt: "WPA-PSK"
`
    },
    {
      kind: 'payload',
      label: '+ cumulocity',
      title: 'Cumulocity IoT section',
      key: 'cumulocity',
      yaml:
`  cumulocity:
    url: "https://example.cumulocity.com"
    external_id_prefix: ""
    token_ttl: "10m"
    issuer:
      mode: "local"
`
    },
    {
      kind: 'payload',
      label: '+ files',
      title: 'File delivery section',
      key: 'files',
      yaml:
`  files:
    files:
      - path: /etc/example.conf
        mode: "0644"
        contents: |
          key=value
`
    },
    {
      kind: 'payload',
      label: '+ hook',
      title: 'Post-provision hook script',
      key: 'hook',
      yaml:
`  hook:
    interpreter: /bin/sh
    script: |
      #!/bin/sh
      echo "provisioned" > /tmp/ztp-done
`
    },
    {
      kind: 'payload',
      label: '+ passwd',
      title: 'Set user passwords',
      key: 'passwd',
      yaml:
`  passwd:
    users:
      - name: root
        password: "changeme"
`
    },
    {
      kind: 'top',
      label: '+ selector',
      title: 'Device selector for auto-matching',
      key: 'selector',
      yaml:
`selector:
  match_model: "^rpi-"
  match_hostname: "^lab-"
  match_mac_oui:
    - "dc:a6:32"
`
    }
  ];

  function insertSnippet(s: Snippet) {
    const doc = getEditorContent();
    err = null;
    const ind = doc.trim() ? detectIndent(doc) : '  ';

    // ── skeleton ─────────────────────────────────────────────────────────────
    if (s.kind === 'skeleton') {
      if (doc.trim().length > 0) {
        err = 'Cannot insert skeleton: editor already has content.';
        return;
      }
      setEditorContent(reindent(s.yaml, ind));
      editorView?.focus();
      return;
    }

    // ── payload sub-section ───────────────────────────────────────────────────
    if (s.kind === 'payload') {
      // Guard: key already present anywhere under payload (1 indent level deep)
      const escapedKey = s.key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const escapedInd = ind.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (new RegExp(`^${escapedInd}${escapedKey}:`, 'm').test(doc)) {
        err = `'payload.${s.key}' already exists — edit it directly.`;
        return;
      }
      const snippet = reindent(s.yaml, ind);
      const payloadMatch = /^payload:\s*$/m.exec(doc);
      let newDoc: string;
      if (payloadMatch !== null) {
        // payload: block exists — insert right before the next top-level key
        const afterStart = payloadMatch.index + payloadMatch[0].length;
        const rest = doc.slice(afterStart);
        const nextTopLevel = /\n(?=[a-zA-Z0-9])/.exec(rest);
        if (nextTopLevel !== null) {
          const insertAt = afterStart + nextTopLevel.index + 1;
          newDoc = doc.slice(0, insertAt) + snippet + doc.slice(insertAt);
        } else {
          newDoc = doc + (doc.endsWith('\n') ? '' : '\n') + snippet;
        }
      } else {
        // No payload: block yet — append one
        const sep = doc.trim() === '' ? '' : (doc.endsWith('\n') ? '\npayload:\n' : '\n\npayload:\n');
        newDoc = doc + sep + snippet;
      }
      setEditorContent(newDoc);
      editorView?.focus();
      return;
    }

    // ── top-level key ─────────────────────────────────────────────────────────
    if (s.kind === 'top') {
      const escapedKey = s.key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (new RegExp(`^${escapedKey}:`, 'm').test(doc)) {
        err = `'${s.key}' already exists — edit it directly.`;
        return;
      }
      const snippet = reindent(s.yaml, ind);
      let newDoc: string;
      // selector looks better sitting just before payload:
      if (s.key === 'selector') {
        const payloadMatch = /^payload:\s*$/m.exec(doc);
        if (payloadMatch !== null) {
          const before = doc.slice(0, payloadMatch.index);
          const sep = before.endsWith('\n') ? '' : '\n';
          newDoc = before + sep + snippet + '\n' + doc.slice(payloadMatch.index);
        } else {
          const sep = doc.trim() === '' ? '' : (doc.endsWith('\n') ? '' : '\n');
          newDoc = doc + sep + snippet;
        }
      } else {
        const sep = doc.trim() === '' ? '' : (doc.endsWith('\n') ? '' : '\n');
        newDoc = doc + sep + snippet;
      }
      setEditorContent(newDoc);
      editorView?.focus();
      return;
    }
  }

  async function loadDesktopContext() {
    const info = await detect();
    if (info.mode === 'desktop') {
      desktop = info as DesktopRuntimeInfo;
    }
  }

  async function loadRecipients() {
    try {
      const keyInfo = await api.profileEncryptionKey();
      recipients = keyInfo.recipients ?? [];
    } catch (e: any) {
      err = `Could not load encryption recipients: ${e.message ?? e}`;
    }
  }

  async function refreshFiles() {
    // Desktop mode: use Wails binding.
    const listFn = wailsListProfileFiles();
    if (listFn) {
      try {
        files = await listFn();
        if (files.length > 0 && !selectedFile) selectedFile = files[0];
        configApiAvailable = true;
      } catch (e: any) {
        err = `Could not list profile files: ${e.message ?? e}`;
      }
      return;
    }
    // Server mode: use REST API.
    try {
      files = await api.configFiles();
      if (files.length > 0 && !selectedFile) selectedFile = files[0];
      configApiAvailable = true;
    } catch (e: any) {
      configApiAvailable = false;
    }
  }

  async function refreshC8YCredentials() {
    const fn = wailsListC8YCredentials();
    if (!fn) return;
    try {
      c8yCredentials = await fn();
    } catch (e: any) {
      err = `Could not list Cumulocity credentials: ${e.message ?? e}`;
    }
  }

  async function saveC8YCredential() {
    const fn = wailsSetC8YCredential();
    if (!fn) return;
    msg = null;
    err = null;
    try {
      await fn(credentialId, credentialURL, credentialUsername, credentialPassword);
      credentialPassword = '';
      msg = `Saved credential ${credentialId}`;
      await refreshC8YCredentials();
    } catch (e: any) {
      err = `Could not save Cumulocity credential: ${e.message ?? e}`;
    }
  }

  async function deleteC8YCredential(id: string) {
    const fn = wailsDeleteC8YCredential();
    if (!fn) return;
    msg = null;
    err = null;
    try {
      await fn(id);
      msg = `Deleted credential ${id}`;
      await refreshC8YCredentials();
    } catch (e: any) {
      err = `Could not delete Cumulocity credential: ${e.message ?? e}`;
    }
  }

  async function openConfigDir() {
    const fn = wailsOpenConfigDirectory();
    if (!fn) return;
    try {
      await fn();
    } catch (e: any) {
      err = `Could not open config directory: ${e.message ?? e}`;
    }
  }

  function newFile() {
    selectedFile = '';
    setEditorContent('');
    msg = null;
    err = null;
  }

  async function loadFile() {    if (!selectedFile) return;
    msg = null;
    err = null;
    // Desktop mode.
    const fn = wailsReadProfileFile();
    if (fn) {
      try {
        setEditorContent(await fn(selectedFile));
        msg = `Loaded ${selectedFile}`;
      } catch (e: any) {
        err = `Could not read file: ${e.message ?? e}`;
      }
      return;
    }
    // Server mode.
    try {
      setEditorContent(await api.configFileGet(selectedFile));
      msg = `Loaded ${selectedFile}`;
    } catch (e: any) {
      err = `Could not read file: ${e.message ?? e}`;
    }
  }

  async function saveFile() {
    if (!effectiveFile) return;
    msg = null;
    err = null;
    // Desktop mode: seal locally then write.
    const sealForSaveFn = wailsSealProfileForSave();
    const writeFn = wailsWriteProfileFile();
    if (sealForSaveFn && writeFn) {
      try {
        const sealed = await sealForSaveFn(getEditorContent());
        setEditorContent(sealed);
        await writeFn(effectiveFile, sealed);
        selectedFile = effectiveFile;
        msg = `Saved ${effectiveFile} (sealed)`;
        await refreshFiles();
      } catch (e: any) {
        err = `Could not write file: ${e.message ?? e}`;
      }
      return;
    }
    // Server mode: server auto-seals on PUT.
    try {
      await api.configFilePut(effectiveFile, getEditorContent());
      selectedFile = effectiveFile;
      msg = `Saved ${effectiveFile}`;
      await refreshFiles();
      // Re-fetch to show the server-sealed (encrypted) content.
      const sealed = await api.configFileGet(effectiveFile);
      setEditorContent(sealed);
    } catch (e: any) {
      err = `Could not write file: ${e.message ?? e}`;
    }
  }

  async function deleteFile() {
    if (!selectedFile) return;
    if (!confirm(`Delete profile "${selectedFile}"? This cannot be undone.`)) return;
    msg = null;
    err = null;
    const toDelete = selectedFile;
    // Desktop mode.
    const deleteFn = wailsDeleteProfileFile();
    if (deleteFn) {
      try {
        await deleteFn(toDelete);
        selectedFile = '';
        setEditorContent('');
        msg = `Deleted ${toDelete}`;
        await refreshFiles();
      } catch (e: any) {
        err = `Could not delete file: ${e.message ?? e}`;
      }
      return;
    }
    // Server mode.
    try {
      await api.configFileDelete(toDelete);
      selectedFile = '';
      setEditorContent('');
      msg = `Deleted ${toDelete}`;
      await refreshFiles();
    } catch (e: any) {
      err = `Could not delete file: ${e.message ?? e}`;
    }
  }

  async function reveal() {    msg = null;
    err = null;
    // Desktop mode.
    const fn = wailsRevealSealedProfile();
    if (fn) {
      try {
        setEditorContent(await fn(getEditorContent()));
        msg = 'Revealed decrypted YAML in the editor';
      } catch (e: any) {
        err = `Reveal failed: ${e.message ?? e}`;
      }
      return;
    }
    // Server mode.
    try {
      setEditorContent(await api.configReveal(getEditorContent()));
      msg = 'Revealed decrypted YAML in the editor';
    } catch (e: any) {
      err = `Reveal failed: ${e.message ?? e}`;
    }
  }

  onMount(async () => {
    await loadDesktopContext();
    await loadRecipients();
    await refreshC8YCredentials();
    await refreshFiles();
  });

  $effect(() => {
    if (editorHost && !editorView) {
      initEditor();
    }
  });

  onDestroy(() => {
    editorView?.destroy();
    editorView = null;
  });
</script>

<h2>Config and Secrets</h2>

{#if desktop != null}
  <section class="card">
    <h3>Storage</h3>
    <p>Config directory: <code>{desktop.configDir ?? 'n/a'}</code></p>
    <p>Profiles directory: <code>{desktop.profilesDir ?? 'n/a'}</code></p>
    <p>Age key file: <code>{desktop.ageKeyFile ?? 'n/a'}</code></p>
    <button onclick={openConfigDir}>Open Config Directory</button>
  </section>
{/if}

<section class="card">
  <h3>Encryption Recipients</h3>
  <p>Recipients are loaded from the admin API endpoint used by ztpctl.</p>
  {#if recipients.length === 0}
    <p class="warn">No recipients found.</p>
  {:else}
    <ul>
      {#each recipients as r (r)}
        <li><code>{r}</code></li>
      {/each}
    </ul>
  {/if}
</section>

{#if desktop != null}
  <section class="card">
    <h3>Cumulocity Credentials</h3>
    <p class="hint">Credentials are stored in the OS keyring. You can manage multiple entries and reference them from profile targets.</p>
    <div class="grid">
      <div class="field">
        <label for="c8y-credential-id">Credential ID</label>
        <input id="c8y-credential-id" bind:value={credentialId} placeholder="e.g. c8y-prod-eu" />
      </div>
      <div class="field">
        <label for="c8y-credential-url">Cumulocity URL</label>
        <input id="c8y-credential-url" bind:value={credentialURL} placeholder="https://example.cumulocity.com" />
      </div>
      <div class="field">
        <label for="c8y-credential-user">Username</label>
        <input id="c8y-credential-user" bind:value={credentialUsername} placeholder="service-user" />
      </div>
      <div class="field">
        <label for="c8y-credential-password">Password</label>
        <input id="c8y-credential-password" type="password" bind:value={credentialPassword} placeholder="••••••••" autocomplete="new-password" />
      </div>
    </div>
    <div class="row">
      <button onclick={saveC8YCredential}>Save Credential</button>
      <button onclick={refreshC8YCredentials}>Refresh</button>
    </div>
    {#if c8yCredentials.length === 0}
      <p class="warn">No stored Cumulocity credentials.</p>
    {:else}
      <table class="cred-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>URL</th>
            <th>Username</th>
            <th>Secret</th>
            <th>Updated</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each c8yCredentials as c (c.id)}
            <tr>
              <td><code>{c.id}</code></td>
              <td>{c.url || '-'}</td>
              <td>{c.username || '-'}</td>
              <td>{c.hasSecret ? 'stored' : 'missing'}</td>
              <td>{c.updatedAt || '-'}</td>
              <td><button onclick={() => deleteC8YCredential(c.id)}>Delete</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
{/if}

{#if configApiAvailable === false}
  <section class="card">
    <p class="warn">Profile file management is not available. Set <code>profiles_dir</code> in <code>ztp-server.yaml</code> to enable it.</p>
  </section>
{:else}
  <section class="card">
    <h3>Profile File Editor</h3>
    <div class="row">
      <select bind:value={selectedFile}>
        <option value="">— select to load an existing profile —</option>
        {#each files as f (f)}
          <option value={f}>{f}</option>
        {/each}
      </select>
      <button onclick={refreshFiles}>Refresh Files</button>
      <button onclick={newFile}>New</button>
      <button onclick={loadFile} disabled={!selectedFile}>Load</button>
      <button onclick={saveFile} disabled={!effectiveFile}
        title={effectiveFile && effectiveFile !== selectedFile ? `Save as new file: ${effectiveFile}` : ''}>
        {effectiveFile && effectiveFile !== selectedFile ? `Save as ${effectiveFile}` : 'Save'}
      </button>
      <button onclick={deleteFile} disabled={!selectedFile}>Delete</button>
      <button onclick={reveal}>Reveal</button>
    </div>
    <div class="editor-area">
      <div class="snippet-bar">
        <p class="snippet-hint">Insert snippet</p>
        {#each snippets as s}
          <button class="snippet-btn" title={s.title} onclick={() => insertSnippet(s)}>{s.label}</button>
        {/each}
      </div>
      <div class="editor-shell">
        <div class="editor" bind:this={editorHost}></div>
      </div>
    </div>
    <p class="hint">
      Save always seals automatically (tag-based when present, otherwise default regex).
      {#if desktop != null}Default regex: <code>{desktop.defaultSealRegex ?? 'n/a'}</code>.{/if}
    </p>
  </section>
{/if}

{#if msg}<p class="ok">{msg}</p>{/if}
{#if err}<p class="err">{err}</p>{/if}

<style>
  h2 { margin-top: 0; }
  .card {
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
    background: #0f141b;
  }
  .row {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 0.6rem;
    flex-wrap: wrap;
  }
  select {
    background: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
  }
  input {
    background: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 0.45rem 0.55rem;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 0.6rem;
    margin-bottom: 0.6rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }
  .field label {
    color: #8b949e;
    font-size: 0.85rem;
  }
  .editor-area {
    display: flex;
    gap: 0.5rem;
    align-items: flex-start;
  }
  .snippet-bar {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    min-width: 7.5rem;
    flex-shrink: 0;
  }
  .snippet-hint {
    color: #8b949e;
    font-size: 0.75rem;
    margin: 0 0 0.15rem 0;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .snippet-btn {
    background: #161b22;
    border: 1px solid #30363d;
    color: #79c0ff;
    border-radius: 5px;
    padding: 0.35rem 0.55rem;
    cursor: pointer;
    font-size: 0.8rem;
    text-align: left;
    white-space: nowrap;
  }
  .snippet-btn:hover {
    background: #1f2937;
    border-color: #58a6ff;
    color: #58a6ff;
  }
  .editor-shell {
    flex: 1;
    min-width: 0;
    width: 100%;
    min-height: 28rem;
    border: 1px solid #30363d;
    border-radius: 6px;
    overflow: hidden;
    background: #0d1117;
  }
  .editor {
    min-height: 28rem;
  }
  .editor :global(.cm-editor) {
    height: 28rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
    font-size: 13px;
  }
  .editor :global(.cm-scroller) {
    overflow: auto;
  }
  .editor :global(.cm-content) {
    box-sizing: border-box;
    padding: 0.75rem;
  }
  button {
    background: #21262d;
    border: 1px solid #30363d;
    color: #e6edf3;
    border-radius: 6px;
    padding: 0.45rem 0.7rem;
    cursor: pointer;
  }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .hint { color: #8b949e; font-size: 0.85rem; }
  .warn { color: #f0883e; }
  .ok { color: #3fb950; }
  .err { color: #f85149; }
  .cred-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 0.4rem;
  }
  .cred-table th,
  .cred-table td {
    border-bottom: 1px solid #30363d;
    padding: 0.45rem;
    text-align: left;
  }
  .cred-table th {
    color: #8b949e;
    font-weight: 600;
  }
  code {
    background: #161b22;
    padding: 0.1rem 0.3rem;
    border-radius: 4px;
  }

  /* ── CodeMirror autocomplete popup — dark theme ─────────────────────────── */
  :global(.cm-tooltip) {
    background: #1c2128 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    box-shadow: 0 8px 24px rgba(0,0,0,0.5) !important;
  }
  :global(.cm-tooltip-autocomplete > ul) {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Courier New', monospace;
    font-size: 13px;
    max-height: 16rem;
  }
  :global(.cm-tooltip-autocomplete > ul > li) {
    padding: 4px 10px !important;
    color: #e6edf3 !important;
    line-height: 1.5;
  }
  /* Clearly highlight the selected item */
  :global(.cm-tooltip-autocomplete > ul > li[aria-selected="true"]) {
    background: #1f6feb !important;
    color: #ffffff !important;
  }
  /* Key name */
  :global(.cm-completionLabel) {
    color: inherit;
  }
  /* Type hint (e.g. "integer", "string") */
  :global(.cm-completionDetail) {
    color: #8b949e !important;
    font-style: italic;
    margin-left: 0.5em;
  }
  :global(.cm-tooltip-autocomplete > ul > li[aria-selected="true"] .cm-completionDetail) {
    color: #a8c4e8 !important;
  }
  /* Description / hover tooltip */
  :global(.cm-completionInfo) {
    background: #1c2128 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    color: #c9d1d9 !important;
    padding: 6px 10px !important;
    font-size: 12px;
    max-width: 28rem;
    line-height: 1.5;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4) !important;
  }
</style>
