<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { EditorState } from '@codemirror/state';
  import { EditorView, keymap } from '@codemirror/view';
  import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
  import { yaml } from '@codemirror/lang-yaml';
  import { oneDark } from '@codemirror/theme-one-dark';
  import { api } from '$lib/api';
  import {
    detect,
    type C8YCredential,
    type DesktopRuntimeInfo,
    wailsDeleteC8YCredential,
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

  function initEditor() {
    if (!editorHost || editorView) return;
    editorView = new EditorView({
      state: EditorState.create({
        doc: content,
        extensions: [
          history(),
          keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
          yaml(),
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
    const listFn = wailsListProfileFiles();
    if (!listFn) return;
    try {
      files = await listFn();
      if (files.length > 0 && !selectedFile) selectedFile = files[0];
    } catch (e: any) {
      err = `Could not list profile files: ${e.message ?? e}`;
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

  async function loadFile() {
    if (!selectedFile) return;
    const fn = wailsReadProfileFile();
    if (!fn) return;
    msg = null;
    err = null;
    try {
      setEditorContent(await fn(selectedFile));
      msg = `Loaded ${selectedFile}`;
    } catch (e: any) {
      err = `Could not read file: ${e.message ?? e}`;
    }
  }

  async function saveFile() {
    if (!selectedFile) return;
    const sealForSaveFn = wailsSealProfileForSave();
    const fn = wailsWriteProfileFile();
    if (!fn || !sealForSaveFn) return;
    msg = null;
    err = null;
    try {
      const sealed = await sealForSaveFn(getEditorContent());
      setEditorContent(sealed);
      await fn(selectedFile, sealed);
      msg = `Saved ${selectedFile} (sealed)`;
      await refreshFiles();
    } catch (e: any) {
      err = `Could not write file: ${e.message ?? e}`;
    }
  }

  async function reveal() {
    const fn = wailsRevealSealedProfile();
    if (!fn) return;
    msg = null;
    err = null;
    try {
      setEditorContent(await fn(getEditorContent()));
      msg = 'Revealed decrypted YAML in the editor';
    } catch (e: any) {
      err = `Reveal failed: ${e.message ?? e}`;
    }
  }

  onMount(async () => {
    initEditor();
    await loadDesktopContext();
    await loadRecipients();
    await refreshC8YCredentials();
    await refreshFiles();
    initEditor();
  });

  $effect(() => {
    if (desktop && editorHost && !editorView) {
      initEditor();
    }
  });

  onDestroy(() => {
    editorView?.destroy();
    editorView = null;
  });
</script>

<h2>Config and Secrets</h2>

{#if desktop == null}
  <p class="warn">This page is only available in the desktop app.</p>
{:else}
  <section class="card">
    <h3>Storage</h3>
    <p>Config directory: <code>{desktop.configDir ?? 'n/a'}</code></p>
    <p>Profiles directory: <code>{desktop.profilesDir ?? 'n/a'}</code></p>
    <p>Age key file: <code>{desktop.ageKeyFile ?? 'n/a'}</code></p>
    <button onclick={openConfigDir}>Open Config Directory</button>
  </section>

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

  <section class="card">
    <h3>Profile File Editor</h3>
    <div class="row">
      <select bind:value={selectedFile}>
        <option value="">Select profile file</option>
        {#each files as f (f)}
          <option value={f}>{f}</option>
        {/each}
      </select>
      <button onclick={refreshFiles}>Refresh Files</button>
      <button onclick={loadFile} disabled={!selectedFile}>Load</button>
      <button onclick={saveFile} disabled={!selectedFile}>Save</button>
      <button onclick={reveal}>Reveal</button>
    </div>
    <div class="editor-shell">
      <div class="editor" bind:this={editorHost}></div>
    </div>
    <p class="hint">
      Save always seals automatically (tag-based when present, otherwise default regex).
      Default regex mode uses <code>{desktop.defaultSealRegex ?? 'n/a'}</code>.
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
  .editor-shell {
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
</style>
