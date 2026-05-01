// Runtime detection: at boot the SPA asks the server (or the Wails
// host, if present) what context it's running in. Two outcomes
// matter to the UI:
//
//   browser  → render the login modal so the operator can paste an
//              admin token; persist it in localStorage as before.
//   desktop  → the Wails host hands us an in-memory token over a
//              Go-binding; never touch localStorage in this mode.
//
// Capabilities is a forward-compatible string list ("ble.central.native"
// once PR 4 lands). Components feature-detect rather than version-check
// so the desktop binary can advertise new bindings without an SPA
// rebuild.
//
// Important: this module must be free of top-level side effects so it
// can be imported from anywhere without forcing the detect to run.
// detect() is explicit and idempotent.

export type RuntimeMode = 'browser' | 'desktop';

export interface RuntimeInfo {
  mode: RuntimeMode;
  capabilities: string[];
}

export interface DesktopRuntimeInfo extends RuntimeInfo {
  mode: 'desktop';
  token: string;
  baseURL: string;
  signingKey: string;
  defaultSealRegex?: string;
  configDir?: string;
  configPath?: string;
  adminTokenFile?: string;
  signingKeyFile?: string;
  ageKeyFile?: string;
  profilesDir?: string;
  firstRun?: boolean;
  bootstrappedFiles?: string[];
}

export interface C8YCredential {
  id: string;
  url?: string;
  username?: string;
  hasSecret: boolean;
  updatedAt?: string;
}

let cached: RuntimeInfo | null = null;

// Wails injects a Go binding at window.go.<package>.<Type>.<Method>.
// We name our binding App in package desktop, so:
//
//   window.go?.desktop?.App?.GetRuntimeInfo()
//
// Wrapping the access in optional chaining keeps the SPA a single
// codebase: in a regular browser there is no window.go, so the
// expression is undefined and we fall back to HTTP.
function wailsBinding(): (() => Promise<DesktopRuntimeInfo>) | null {
  const w = (window as unknown as { go?: { desktop?: { App?: { GetRuntimeInfo?: () => Promise<DesktopRuntimeInfo> } } } });
  return w.go?.desktop?.App?.GetRuntimeInfo ?? null;
}

// wailsSaveFile returns the desktop binding that pops a native save
// dialog and writes content to the chosen path; null in browser mode
// (where <a download> works natively). The binding resolves with the
// absolute path on success or "" if the operator cancelled.
export function wailsSaveFile(): ((suggestedName: string, content: string) => Promise<string>) | null {
  const w = (window as unknown as { go?: { desktop?: { App?: { SaveFile?: (n: string, c: string) => Promise<string> } } } });
  return w.go?.desktop?.App?.SaveFile ?? null;
}

type DesktopBindings = {
  OpenConfigDirectory?: () => Promise<void>;
  ListProfileFiles?: () => Promise<string[]>;
  ReadProfileFile?: (name: string) => Promise<string>;
  WriteProfileFile?: (name: string, content: string) => Promise<void>;
  DeleteProfileFile?: (name: string) => Promise<void>;
  RevealSealedProfile?: (content: string) => Promise<string>;
  SealProfile?: (content: string, encryptedRegex: string) => Promise<string>;
  SealProfileForSave?: (content: string) => Promise<string>;
  ListC8YCredentials?: () => Promise<C8YCredential[]>;
  SetC8YCredential?: (id: string, url: string, username: string, password: string) => Promise<void>;
  DeleteC8YCredential?: (id: string) => Promise<void>;
};

function desktopBindings(): DesktopBindings | null {
  const w = (window as unknown as { go?: { desktop?: { App?: DesktopBindings } } });
  return w.go?.desktop?.App ?? null;
}

export function wailsOpenConfigDirectory(): (() => Promise<void>) | null {
  return desktopBindings()?.OpenConfigDirectory ?? null;
}

export function wailsListProfileFiles(): (() => Promise<string[]>) | null {
  return desktopBindings()?.ListProfileFiles ?? null;
}

export function wailsReadProfileFile(): ((name: string) => Promise<string>) | null {
  return desktopBindings()?.ReadProfileFile ?? null;
}

export function wailsWriteProfileFile(): ((name: string, content: string) => Promise<void>) | null {
  return desktopBindings()?.WriteProfileFile ?? null;
}

export function wailsDeleteProfileFile(): ((name: string) => Promise<void>) | null {
  return desktopBindings()?.DeleteProfileFile ?? null;
}

export function wailsRevealSealedProfile(): ((content: string) => Promise<string>) | null {
  return desktopBindings()?.RevealSealedProfile ?? null;
}

export function wailsSealProfile(): ((content: string, encryptedRegex: string) => Promise<string>) | null {
  return desktopBindings()?.SealProfile ?? null;
}

export function wailsSealProfileForSave(): ((content: string) => Promise<string>) | null {
  return desktopBindings()?.SealProfileForSave ?? null;
}

export function wailsListC8YCredentials(): (() => Promise<C8YCredential[]>) | null {
  return desktopBindings()?.ListC8YCredentials ?? null;
}

export function wailsSetC8YCredential(): ((id: string, url: string, username: string, password: string) => Promise<void>) | null {
  return desktopBindings()?.SetC8YCredential ?? null;
}

export function wailsDeleteC8YCredential(): ((id: string) => Promise<void>) | null {
  return desktopBindings()?.DeleteC8YCredential ?? null;
}

export async function detect(): Promise<RuntimeInfo> {
  if (cached) return cached;

  const binding = wailsBinding();
  if (binding) {
    const info = await binding();
    cached = info;
    return info;
  }

  // Browser path — server endpoint is unauthenticated by design.
  const res = await fetch('/v1/runtime-config', { headers: { Accept: 'application/json' } });
  if (!res.ok) {
    // If the server is too old to expose this endpoint, fall back to
    // the historical browser flow rather than blocking the SPA.
    cached = { mode: 'browser', capabilities: [] };
    return cached;
  }
  const data = (await res.json()) as RuntimeInfo;
  cached = { mode: data.mode ?? 'browser', capabilities: data.capabilities ?? [] };
  return cached;
}

// hasCapability is the narrow check components should prefer over
// inspecting mode directly — it survives advertised feature flips
// without code changes.
export function hasCapability(info: RuntimeInfo, name: string): boolean {
  return info.capabilities.includes(name);
}
