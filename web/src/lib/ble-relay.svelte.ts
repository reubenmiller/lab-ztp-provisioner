// Shared reactive singleton for BLE relay status.
// Both the BLE page (writer) and the layout (reader) import this module.
// Because it is a .svelte.ts file, $state creates a reactive proxy that
// propagates updates to every component that reads it.
// The BleRelayController (always mounted in the layout) registers start/stop
// so the sidebar toggle can drive the relay without navigating anywhere.

function getInitialEnabled(): boolean {
  const saved = typeof localStorage !== 'undefined'
    ? localStorage.getItem('ztp-ble-relay-enabled')
    : null;
  // Default is true (on) — only disable when the user has explicitly saved 'false'.
  return saved === null ? true : saved === 'true';
}

export const bleRelay = $state<{
  relaying: boolean;
  /** Persistent user preference — defaults to true (on). */
  enabled: boolean;
  start: (() => void) | null;
  stop: (() => void) | null;
  /** Last few activity events, shared with the Fleet page. */
  activity: { time: string; msg: string }[];
  /** Human-readable relay status string set by the controller. */
  status: string;
}>({ relaying: false, enabled: getInitialEnabled(), start: null, stop: null, activity: [], status: '' });
