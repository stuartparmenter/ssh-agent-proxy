//go:build !linux && !darwin && !windows

package main

// hardenProcess is a no-op on platforms without a hardening
// implementation (currently: everything that isn't Linux, macOS, or
// Windows). Keeping this stub lets `go build` and `go vet` work on
// other platforms during development without build-tag gymnastics.
func hardenProcess() {}
