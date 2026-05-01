// Tiny REST client for the ZTP server. All endpoints under /v1/admin/*
// require a bearer token stored in localStorage under the key "ztp-token".
//
// On first load the layout checks for the token; if absent it shows a login
// modal. Any 401 response clears the stored token and fires a custom
// "ztp:auth-required" event on window so the modal re-appears.

const STORAGE_KEY = 'ztp-token';

export function getToken(): string {
  return localStorage.getItem(STORAGE_KEY) ?? '';
}
export function setToken(t: string): void {
  localStorage.setItem(STORAGE_KEY, t.trim());
}
export function clearToken(): void {
  localStorage.removeItem(STORAGE_KEY);
}

/** Thrown (and re-thrown) whenever the server returns 401. */
export class AuthError extends Error {}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const token = getToken();
  const res = await fetch(path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    body: body == null ? undefined : JSON.stringify(body)
  });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new CustomEvent('ztp:auth-required'));
    throw new AuthError(`${method} ${path}: 401 Unauthorized`);
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path}: ${res.status} ${text}`);
  }
  // 204 No Content — and any 2xx with an empty body — should not be JSON-parsed.
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (text === '') return undefined as T;
  return JSON.parse(text) as T;
}

export const api = {
  // Public — no admin token required. Operators paste this data into the
  // device's environment / installer when bootstrapping an agent.
  serverInfo: () => call<ServerInfo>('GET', '/v1/server-info'),

  pending: () => call<PendingRequest[]>('GET', '/v1/admin/pending'),
  approve: (id: string, profile?: string) =>
    call<void>('POST', `/v1/admin/pending/${id}/approve`, profile ? { profile } : undefined),
  reject: (id: string) => call<void>('POST', `/v1/admin/pending/${id}/reject`),
  devices: () => call<Device[]>('GET', '/v1/admin/devices'),
  deleteDevice: (id: string) => call<void>('DELETE', `/v1/admin/devices/${id}`),
  patchDevice: (id: string, body: { profile?: string }) =>
    call<Device>('PATCH', `/v1/admin/devices/${id}`, body),
  allowlist: () => call<AllowlistEntry[]>('GET', '/v1/admin/allowlist'),
  addAllow: (e: Partial<AllowlistEntry>) => call<void>('POST', '/v1/admin/allowlist', e),
  removeAllow: (id: string) => call<void>('DELETE', `/v1/admin/allowlist/${id}`),
  tokens: () => call<BootstrapToken[]>('GET', '/v1/admin/tokens'),
  createToken: (b: { device_id?: string; profile?: string; max_uses?: number; ttl_seconds?: number }) =>
    call<{ id: string; secret: string }>('POST', '/v1/admin/tokens', b),
  revokeToken: (id: string) => call<void>('DELETE', `/v1/admin/tokens/${id}`),
  audit: (limit = 100) => call<AuditEntry[]>('GET', `/v1/admin/audit?limit=${limit}`),

  // Provisioning profiles (read-only via API; edit via Config/Secrets).
  profiles: () => call<ProfileSummary[]>('GET', '/v1/admin/profiles'),
  profile: (name: string) => call<Profile>('GET', `/v1/admin/profiles/${encodeURIComponent(name)}`),
  reloadProfiles: () => call<{ loaded: number }>('POST', '/v1/admin/profiles/reload'),
  profileEncryptionKey: () => call<ProfileEncryptionKey>('GET', '/v1/admin/profiles/encryption-key'),
  // exportProfileURL builds the URL for a YAML download. Browsers can't
  // attach an Authorization header to <a download> navigation, so the
  // bearer token is passed as ?token=… (the admin auth middleware accepts
  // both forms; the SSE stream relies on the same fallback).
  exportProfileURL: (name: string): string => {
    const url = new URL(`/v1/admin/profiles/${encodeURIComponent(name)}/export`, window.location.origin);
    const t = getToken();
    if (t) url.searchParams.set('token', t);
    return url.toString();
  },

  // Config-file management (profiles_dir filesystem CRUD + seal/reveal).
  configFiles: () => call<string[]>('GET', '/v1/admin/config/files'),
  configFileGet: (name: string) => {
    const token = getToken();
    return fetch(`/v1/admin/config/files/${encodeURIComponent(name)}`, {
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) }
    }).then(async (res) => {
      if (res.status === 401) { clearToken(); window.dispatchEvent(new CustomEvent('ztp:auth-required')); throw new AuthError('401'); }
      if (!res.ok) { const t = await res.text(); throw new Error(t); }
      return res.text();
    });
  },
  configFilePut: (name: string, content: string) => {
    const token = getToken();
    return fetch(`/v1/admin/config/files/${encodeURIComponent(name)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: content
    }).then(async (res) => {
      if (res.status === 401) { clearToken(); window.dispatchEvent(new CustomEvent('ztp:auth-required')); throw new AuthError('401'); }
      if (!res.ok) { const t = await res.text(); throw new Error(t); }
    });
  },
  configSeal: (content: string) => {
    const token = getToken();
    return fetch('/v1/admin/config/seal', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: content
    }).then(async (res) => {
      if (res.status === 401) { clearToken(); window.dispatchEvent(new CustomEvent('ztp:auth-required')); throw new AuthError('401'); }
      if (!res.ok) { const t = await res.text(); throw new Error(t); }
      return res.text();
    });
  },
  configReveal: (content: string) => {
    const token = getToken();
    return fetch('/v1/admin/config/reveal', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: content
    }).then(async (res) => {
      if (res.status === 401) { clearToken(); window.dispatchEvent(new CustomEvent('ztp:auth-required')); throw new AuthError('401'); }
      if (!res.ok) { const t = await res.text(); throw new Error(t); }
      return res.text();
    });
  },

  // Server-Sent Events stream of newly pending requests.
  pendingStream(onEvent: (p: PendingRequest) => void): EventSource {
    const url = new URL('/v1/admin/pending/stream', window.location.origin);
    const token = getToken();
    if (token) url.searchParams.set('token', token); // SSE can't set custom headers
    const es = new EventSource(url.toString());
    const handler = (m: MessageEvent) => {
      try {
        onEvent(JSON.parse(m.data));
      } catch {}
    };
    es.addEventListener('pending', handler as EventListener);
    return es;
  }
};

export interface PendingRequest {
  id: string;
  device_id: string;
  public_key: string;
  fingerprint: string;
  facts: { mac_addresses?: string[]; serial?: string; model?: string; hostname?: string };
  first_seen: string;
  last_seen: string;
  reason: string;
}

export interface Device {
  id: string;
  public_key: string;
  facts: PendingRequest['facts'];
  profile_name?: string;
  overrides?: Record<string, unknown>;
  enrolled_at: string;
  last_seen: string;
}

export interface AllowlistEntry {
  device_id: string;
  mac?: string;
  serial?: string;
  note?: string;
  profile?: string;
  created_at: string;
}

export interface BootstrapToken {
  id: string;
  device_id?: string;
  profile?: string;
  expires_at?: string;
  uses: number;
  max_uses: number;
  created_at: string;
}

export interface AuditEntry {
  at: string;
  actor: string;
  action: string;
  device_id?: string;
  details?: string;
}

// Returned by GET /v1/server-info. Exposes the few public details a device
// needs to verify bundles signed by this server, plus an optional URL to a
// hosted POSIX shell agent for `curl … | sh`-style bootstrap.
export interface ServerInfo {
  protocol_version: string;
  public_key: string; // base64 Ed25519
  key_id: string;
  agent_script_url?: string;
}

// Provisioning profiles.
//
// `Source` is "file" for git-managed YAML profiles (read-only via this API)
// and "db" for profiles created/edited from the UI.
//
// `payload` in a fetched Profile has every secret leaf replaced with
// "<redacted>" — write-only fields. The UI shows them disabled with a
// "Set new value" toggle that, when activated, sends the new plaintext on
// PUT.
export type ProfileSource = 'file' | 'db';

export interface ProfileSummary {
  name: string;
  description?: string;
  source: ProfileSource;
  labels?: Record<string, string>;
  priority?: number;
  updated_at?: string;
  updated_by?: string;
}

export interface Selector {
  match_labels?: Record<string, string>;
  match_model?: string;
  match_mac_oui?: string[];
  match_hostname?: string;
}

export interface Profile extends ProfileSummary {
  selector?: Selector;
  // Opaque-ish: shape mirrors the server's payload.Set struct, but the
  // editor treats it as JSON to avoid duplicating Go types client-side.
  payload?: PayloadSet;
}

// PayloadSet mirrors internal/server/payload/set.go. Each provider is
// optional (nil-pointer in Go = absent here). The structured editor in
// /profiles/[name] toggles each block on/off via these keys.
export interface PayloadSet {
  wifi?: WiFiPayload;
  ssh?: SSHPayload;
  cumulocity?: CumulocityPayload;
  files?: FilesPayload;
  hook?: HookPayload;
  passwd?: PasswdPayload;
  // Forward-compat: any unknown keys the operator pasted in the JSON
  // editor are preserved on save so a future provider added on the server
  // doesn't get stripped by an old browser session.
  [k: string]: unknown;
}

export interface WiFiPayload {
  networks?: WiFiNetwork[];
}
export interface WiFiNetwork {
  ssid: string;
  password?: string;       // sensitive; comes back as "<redacted>" on GET
  hidden?: boolean;
  priority?: number;
  key_mgmt?: string;       // e.g. "WPA-PSK", "NONE"
}

export interface SSHPayload {
  user?: string;
  keys?: string[];
  github_users?: string[];
  github_api_url?: string;
}

export interface CumulocityPayload {
  url?: string;
  tenant?: string;
  external_id_prefix?: string;
  device_id_prefix?: string;
  token_ttl?: string; // Go time.Duration string, e.g. "5m"
  issuer?: CumulocityIssuer;
}
export interface CumulocityIssuer {
  mode?: '' | 'local' | 'remote' | 'static';
  base_url?: string;
  tenant?: string;
  credentials_file?: string;
  endpoint?: string;
  client_cert?: string;
  client_key?: string;
  ca_cert?: string;
  static_token?: string; // sensitive
}

export interface FilesPayload {
  files?: FileSpec[];
}
export interface FileSpec {
  path: string;
  mode?: string;     // e.g. "0644"
  owner?: string;    // e.g. "root:root"
  contents?: string; // sensitive
  base64?: string;   // sensitive
}

export interface HookPayload {
  script?: string;       // sensitive
  interpreter?: string;  // default "/bin/sh"
}

export interface PasswdPayload {
  users?: PasswdUser[];
}
export interface PasswdUser {
  name: string;
  password?: string; // sensitive; comes back as "<redacted>" on GET
}

export interface ProfileWrite {
  name?: string;
  description?: string;
  labels?: Record<string, string>;
  priority?: number;
  selector?: Selector;
  payload?: PayloadSet;
}

export interface ProfileEncryptionKey {
  alg: string;
  recipients: string[];
}
