//go:build linux

package main

import (
	"log"

	"golang.org/x/sys/unix"
)

// hardenProcess applies Linux-specific process hardening to reduce the
// risk of leaking the private key material that transits through this
// process. It is best-effort: each step logs a warning and continues on
// failure. A hardening failure is not a reason to refuse to start — the
// proxy still works and the user is better off knowing their mitigations
// are partial than getting a startup failure they can't diagnose.
//
// What this defends against:
//   - Unprivileged local processes reading /proc/$pid/mem or attaching
//     via ptrace (blocked by PR_SET_DUMPABLE=0).
//   - Key material landing in a swap file on disk (blocked by mlockall).
//   - Key material landing in a core dump (blocked by RLIMIT_CORE=0 and
//     PR_SET_DUMPABLE=0, which is belt-and-suspenders).
//   - Re-gaining privileges on exec (blocked by PR_SET_NO_NEW_PRIVS).
//
// What this does NOT defend against:
//   - Root on the same host (root can read /proc/$pid/mem regardless).
//   - Hardware attacks (cold boot, DMA, TEE escapes).
//   - The 1Password SDK's internal copies of the PEM before it reaches
//     us as a Go string — we can't zero Go strings and can't see inside
//     the SDK's state.
//
// Call this as early as possible in main(), before any heap allocations
// that might later hold sensitive data.
func hardenProcess() {
	// Disable core dumps via rlimit. Redundant with PR_SET_DUMPABLE=0
	// below for the kernel-triggered case, but this also covers
	// `gcore`-style user-triggered dumps and makes the intent explicit
	// in tools like `prlimit`.
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Printf("hardening: setrlimit(RLIMIT_CORE, 0): %v", err)
	}

	// PR_SET_DUMPABLE=0:
	//   * makes /proc/$pid/mem readable only by root (owner drops to root)
	//   * blocks ptrace(PTRACE_ATTACH) from non-root processes
	//   * disables core dumps for this process (even without RLIMIT_CORE)
	// This is the single highest-ROI mitigation against another
	// unprivileged process on the same host dumping our memory.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("hardening: prctl(PR_SET_DUMPABLE, 0): %v", err)
	}

	// PR_SET_NO_NEW_PRIVS=1: if we ever exec a setuid binary, it cannot
	// gain privileges. We don't exec anything today, but this is cheap
	// defense-in-depth and matches systemd's NoNewPrivileges= directive
	// when running outside of systemd.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Printf("hardening: prctl(PR_SET_NO_NEW_PRIVS, 1): %v", err)
	}

	// mlockall(MCL_CURRENT|MCL_FUTURE) keeps all of this process's pages
	// resident in RAM so key material held transiently during a request
	// cannot be paged out to a swap file. Requires RLIMIT_MEMLOCK to be
	// large enough; the systemd unit sets LimitMEMLOCK=infinity. When
	// running manually under a restrictive ulimit this may fail — we log
	// and continue, leaving swap protection off.
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		log.Printf("hardening: mlockall: %v (swap protection disabled; set LimitMEMLOCK=infinity in the systemd unit or raise RLIMIT_MEMLOCK to fix)", err)
	}
}
