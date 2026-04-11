use log::warn;
use nix::sys::resource::{Resource, setrlimit};

pub fn harden() {
    // 1. RLIMIT_CORE = 0 (no core dumps)
    if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
        warn!("failed to set RLIMIT_CORE to 0: {e}");
    }

    // 2. PR_SET_DUMPABLE = 0 (block /proc/$pid/mem, ptrace)
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            warn!(
                "failed to set PR_SET_DUMPABLE: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // 3. PR_SET_NO_NEW_PRIVS = 1 (prevent privilege escalation on exec)
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            warn!(
                "failed to set PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    // 4. mlockall(MCL_CURRENT | MCL_FUTURE) (keep pages in RAM, no swap)
    unsafe {
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            warn!("failed to mlockall: {}", std::io::Error::last_os_error());
        }
    }
}
