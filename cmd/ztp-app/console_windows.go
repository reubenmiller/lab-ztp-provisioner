//go:build windows

package main

import (
	"os"
	"syscall"
)

// attachParentConsole pulls the GUI binary's stdout/stderr back to the
// console that launched it, so subcommand output (e.g. `ztp-app init`)
// is visible to the operator. Wails apps on Windows are built with
// `-H windowsgui` which detaches the binary from any console; without
// this, fmt.Println goes to /dev/null and the user sees nothing —
// indistinguishable from "the command didn't run".
//
// Best-effort: if there's no parent console (e.g. double-click from
// Explorer) AttachConsole returns 0 and we silently no-op. The Wails
// path that follows doesn't depend on stdout, so this never harms the
// GUI mode.
func attachParentConsole() {
	const attachParentProcess = ^uintptr(0) // -1 as uintptr — ATTACH_PARENT_PROCESS
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("AttachConsole")
	r1, _, _ := proc.Call(attachParentProcess)
	if r1 == 0 {
		return
	}
	if h, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE); err == nil && h != 0 && h != syscall.InvalidHandle {
		os.Stdout = os.NewFile(uintptr(h), "stdout")
	}
	if h, err := syscall.GetStdHandle(syscall.STD_ERROR_HANDLE); err == nil && h != 0 && h != syscall.InvalidHandle {
		os.Stderr = os.NewFile(uintptr(h), "stderr")
	}
}
