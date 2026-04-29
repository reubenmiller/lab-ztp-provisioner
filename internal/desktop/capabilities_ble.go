//go:build ble

package desktop

// Capabilities is the list of feature flags this binary advertises
// to the SPA. Exposed (a) via the App.GetRuntimeInfo Wails binding
// for desktop callers and (b) via runtime.Options.RuntimeCapabilities
// → GET /v1/runtime-config so plain HTTP callers see the same set.
//
// Constant-string capability names are deliberately stable: a new
// binary advertising "ble.central.native" must keep speaking the
// same Wails-binding shape the SPA expects (BleEnroll). If the
// shape ever changes, bump the suffix (e.g. ble.central.native.v2)
// rather than redefining the existing one.
func Capabilities() []string { return []string{"ble.central.native"} }

// bleCapabilities is the in-package alias used by App.GetRuntimeInfo.
// Identical to Capabilities so cmd/ztp-app and the binding stay in sync.
func bleCapabilities() []string { return Capabilities() }
