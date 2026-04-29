//go:build !windows

package main

// attachParentConsole is a no-op on non-Windows platforms — Linux/macOS
// GUI apps inherit the launching terminal's stdio when started from a
// shell, so subcommand output already flows naturally.
func attachParentConsole() {}
