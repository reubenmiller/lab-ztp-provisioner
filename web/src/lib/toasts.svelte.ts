// Module-scoped toast notification state. The single <Toasts /> mounted in
// +layout.svelte renders all active toasts; any module can call addToast() to
// push one. Toasts auto-dismiss after `duration` ms (default 6 s).

export type ToastKind = 'enrolled' | 'pending' | 'info' | 'error';

export type Toast = {
  id: number;
  kind: ToastKind;
  title: string;
  body?: string;
  href?: string; // optional navigation target when clicked
  duration: number;
};

let seq = 0;
let toasts = $state<Toast[]>([]);

export function getToasts(): Toast[] {
  return toasts;
}

export function addToast(opts: Omit<Toast, 'id'>): void {
  const id = ++seq;
  toasts.push({ id, ...opts });
  setTimeout(() => removeToast(id), opts.duration);
}

export function removeToast(id: number): void {
  const idx = toasts.findIndex((t) => t.id === id);
  if (idx !== -1) toasts.splice(idx, 1);
}
