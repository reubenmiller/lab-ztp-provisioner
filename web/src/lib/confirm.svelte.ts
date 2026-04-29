// Module-scoped confirmation dialog state. The single <ConfirmDialog />
// mounted in +layout.svelte renders whatever request is active, and any
// component can `await confirmDialog(...)` to ask for it.
//
// Reason this exists: Wails' WKWebView on macOS ignores window.confirm()
// (it returns false without showing anything), so every Delete button
// that gated on `if (!confirm(...)) return` was silently a no-op in the
// desktop app.

export type ConfirmRequest = {
  title?: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
};

type Pending = ConfirmRequest & { resolve: (ok: boolean) => void };

let active = $state<Pending | null>(null);

export function getActive(): Pending | null {
  return active;
}

export function decide(ok: boolean): void {
  const p = active;
  if (!p) return;
  active = null;
  p.resolve(ok);
}

export function confirmDialog(req: ConfirmRequest): Promise<boolean> {
  if (active) {
    const prev = active;
    active = null;
    prev.resolve(false);
  }
  return new Promise<boolean>((resolve) => {
    active = { ...req, resolve };
  });
}
