//go:build !windows

package main

import "errors"

// isWindowsService returns false on non-Windows platforms. Callers use
// this to decide whether to dispatch into svc.Run() or run interactively;
// off Windows we always run interactively.
func isWindowsService() bool { return false }

// runAsWindowsService is unreachable on non-Windows platforms (main()
// gates its call on isWindowsService). Defined as a no-op stub so
// main.go can reference it without build tags.
func runAsWindowsService() {}

// runServiceCmd handles the install/uninstall subcommands, which are
// Windows-only. On any other platform we return an error and the
// calling shell gets a clear message.
func runServiceCmd(_ string, _ []string) error {
	return errors.New("install/uninstall subcommands are only available on Windows; on Linux use systemd (see contrib/systemd/)")
}
