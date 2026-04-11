use log::warn;
use nix::sys::resource::{Resource, setrlimit};

/// PT_DENY_ATTACH prevents debuggers from attaching to this process.
const PT_DENY_ATTACH: libc::c_int = 31;

pub fn harden() {
    // 1. RLIMIT_CORE = 0 (no core dumps)
    if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
        warn!("failed to set RLIMIT_CORE to 0: {e}");
    }

    // 2. mlockall(MCL_CURRENT | MCL_FUTURE) (keep pages in RAM, no swap)
    unsafe {
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            warn!("failed to mlockall: {}", std::io::Error::last_os_error());
        }
    }

    // 3. ptrace(PT_DENY_ATTACH, 0, 0, 0) (prevent debugger attachment)
    unsafe {
        if libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut::<libc::c_void>(), 0) != 0 {
            warn!(
                "failed to set PT_DENY_ATTACH: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}
