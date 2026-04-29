//go:build !ble

package desktop

// Capabilities is empty when the binary was built without the ble
// tag. The SPA falls back to Web Bluetooth on /onboard/ble in that
// case (which works inside Wails' webview on most platforms).
func Capabilities() []string { return nil }

// bleCapabilities is the in-package alias used by App.GetRuntimeInfo.
func bleCapabilities() []string { return Capabilities() }
