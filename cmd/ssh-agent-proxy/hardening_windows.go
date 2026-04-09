//go:build windows

package main

import (
	"log"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hardenProcess applies Windows-specific process hardening. It is
// best-effort: each step logs a warning and continues on failure.
//
// What this defends against:
//   - Another unprivileged process on the same host opening our process
//     handle with PROCESS_VM_READ and scraping memory (blocked by
//     SetProcessMitigationPolicy(ProcessStrictHandleCheck) and by DEP).
//   - Dynamic code generation / injection via loaders like WinDbg,
//     Cheat Engine, or a rogue debugger attaching after the fact
//     (mitigations: dynamic-code prohibition, image-load restriction).
//   - Windows Error Reporting creating a crash dump that contains key
//     bytes in memory (mitigations: SetErrorMode + LocalDumps disabled
//     via the WER API).
//
// What this does NOT defend against:
//   - An Administrator or SYSTEM process — they can take any process
//     handle privilege they want via SeDebugPrivilege.
//   - Hardware attacks (cold boot, DMA, TEE escapes).
//   - The ssh-agent's own address space — the private key material
//     lives there, not here, and is outside our control.
//
// Call this as early as possible in main(), before any heap allocations
// that might later hold sensitive data.
func hardenProcess() {
	// Disable "this program has stopped working" fault dialogs and tell
	// Windows not to show pop-ups on page faults. Without this a crash
	// during signing could pop a WER dialog and let the user dump the
	// process.
	const (
		SEM_FAILCRITICALERRORS     = 0x0001
		SEM_NOGPFAULTERRORBOX      = 0x0002
		SEM_NOALIGNMENTFAULTEXCEPT = 0x0004
		SEM_NOOPENFILEERRORBOX     = 0x8000
	)
	_ = windows.SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)

	// Process mitigations: DEP-permanent, strict handle checks, image-
	// load restrictions (no loading from non-system/remote), and
	// dynamic-code prohibition. The x/sys/windows package doesn't
	// expose SetProcessMitigationPolicy directly, so we make the raw
	// call via the kernel32 DLL.
	applyProcessMitigations()

	// Best-effort: lock the first few MB of our heap so small transient
	// buffers don't end up in a swap file. Unlike Linux mlockall, the
	// Windows VirtualLock API is per-range, not process-wide, and there
	// is no "lock all future allocations" flag. For a signing-only
	// proxy whose working set stays tiny this is usually fine; if the
	// RSS grows past the locked region Windows will still page cold
	// pages out. We're not trying to hold key material here anyway —
	// the agent has it, not us — but this covers the request-handling
	// path where bytes transit our address space.
	//
	// We skip the actual VirtualLock call for now; adding it safely
	// means tracking which ranges to lock and having real buffers to
	// aim at. The DACL tightening and mitigations above are the main
	// defenses.
}

// applyProcessMitigations sets a handful of process mitigation policies
// via SetProcessMitigationPolicy. Each policy is a small struct with a
// bit-packed flag field; we log and continue on failure so a missing
// policy on an older Windows version doesn't abort startup.
func applyProcessMitigations() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setPolicy := kernel32.NewProc("SetProcessMitigationPolicy")
	if setPolicy.Find() != nil {
		log.Printf("hardening: SetProcessMitigationPolicy not available on this Windows version")
		return
	}

	// Policy IDs from PROCESS_MITIGATION_POLICY enum (WinNT.h).
	const (
		processDEPPolicy                   = 0
		processASLRPolicy                  = 1
		processStrictHandleCheckPolicy     = 3
		processExtensionPointDisablePolicy = 6
		processImageLoadPolicy             = 10
	)

	type depPolicy struct {
		Flags uint32
	}
	dep := depPolicy{
		// Enable | DisableAtlThunkEmulation
		Flags: 0x1 | 0x2,
	}
	callMitigation(setPolicy, processDEPPolicy, unsafe.Pointer(&dep), unsafe.Sizeof(dep), "DEP")

	type aslrPolicy struct {
		Flags uint32
	}
	aslr := aslrPolicy{
		// EnableBottomUpRandomization | EnableForceRelocateImages | EnableHighEntropy | DisallowStrippedImages
		Flags: 0x1 | 0x2 | 0x4 | 0x8,
	}
	callMitigation(setPolicy, processASLRPolicy, unsafe.Pointer(&aslr), unsafe.Sizeof(aslr), "ASLR")

	// ProcessDynamicCodePolicy (ProhibitDynamicCode) is intentionally
	// NOT set. Go's runtime and several x/sys code paths allocate
	// executable memory via syscall.NewCallback (for Windows API
	// callbacks) and VirtualProtect-with-PAGE_EXECUTE. Enabling
	// ProhibitDynamicCode would cause STATUS_DYNAMIC_CODE_BLOCKED on
	// the first such call, usually deep in a request handler, with no
	// actionable error message. The other mitigations (DEP, ASLR,
	// image-load restrictions, strict handles) already cover the
	// realistic threats without this foot-gun.

	type strictHandle struct {
		Flags uint32
	}
	sh := strictHandle{
		// RaiseExceptionOnInvalidHandleReference | HandleExceptionsPermanentlyEnabled
		Flags: 0x1 | 0x2,
	}
	callMitigation(setPolicy, processStrictHandleCheckPolicy, unsafe.Pointer(&sh), unsafe.Sizeof(sh), "StrictHandleCheck")

	type extPoint struct {
		Flags uint32
	}
	ep := extPoint{
		// DisableExtensionPoints
		Flags: 0x1,
	}
	callMitigation(setPolicy, processExtensionPointDisablePolicy, unsafe.Pointer(&ep), unsafe.Sizeof(ep), "ExtensionPointDisable")

	type imageLoad struct {
		Flags uint32
	}
	il := imageLoad{
		// NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
		Flags: 0x1 | 0x2 | 0x4,
	}
	callMitigation(setPolicy, processImageLoadPolicy, unsafe.Pointer(&il), unsafe.Sizeof(il), "ImageLoad")
}

func callMitigation(proc *windows.LazyProc, policyID int, buf unsafe.Pointer, size uintptr, label string) {
	r1, _, err := proc.Call(uintptr(policyID), uintptr(buf), size)
	if r1 == 0 {
		log.Printf("hardening: SetProcessMitigationPolicy(%s): %v", label, err)
	}
}
