//go:build darwin

package main

import (
	"log"
	"syscall"

	"golang.org/x/sys/unix"
)

// ptDenyAttach is the Darwin ptrace(2) request code for PT_DENY_ATTACH,
// defined in <sys/ptrace.h>. Calling it tells the kernel that this
// process may not be attached to by a debugger from that point on. It
// is officially deprecated in recent macOS versions (Apple recommends
// the hardened runtime via code signing for the same purpose) but it
// still works on current systems and costs nothing to attempt.
const ptDenyAttach = 31

// hardenProcess applies macOS-specific process hardening. It is
// best-effort: individual steps log a warning and continue on failure.
//
// What this defends against:
//   - A debugger attaching to this process via ptrace, which on macOS
//     is the normal path for one-off memory inspection (blocked by
//     PT_DENY_ATTACH).
//   - Key material landing in a core dump under /cores/ (blocked by
//     RLIMIT_CORE=0).
//   - Key material landing in a swap file on disk (blocked by mlockall).
//
// What this does NOT defend against:
//   - Root using EndpointSecurity, /dev/mem, or a kernel extension to
//     inspect process memory.
//   - Hardware attacks.
//   - The 1Password SDK's internal copies of the PEM string — we don't
//     control those and Go strings are immutable.
//
// Call this as early as possible in main(), before any heap allocations
// that might later hold sensitive data.
func hardenProcess() {
	// Disable core dumps. On macOS they land in /cores/core.<pid>.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Printf("hardening: setrlimit(RLIMIT_CORE, 0): %v", err)
	}

	// Lock all current and future pages in RAM so transient key material
	// can't be paged out to swap. On Darwin this doesn't require special
	// caps for small processes; under memory pressure it may still fail,
	// in which case we log and continue without swap protection.
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		log.Printf("hardening: mlockall: %v", err)
	}

	// ptrace(PT_DENY_ATTACH, 0, 0, 0): marks this process as
	// un-attachable from this point forward. Must be called before any
	// debugger attaches; after the fact it has no effect. There is no
	// unix.PtraceDenyAttach helper in golang.org/x/sys/unix, so we use
	// the raw syscall.
	if _, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, ptDenyAttach, 0, 0, 0, 0, 0); errno != 0 {
		log.Printf("hardening: ptrace(PT_DENY_ATTACH): %v", errno)
	}
}
