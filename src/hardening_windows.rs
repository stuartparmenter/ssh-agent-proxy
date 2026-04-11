use log::warn;
use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;

// Error mode flags
const SEM_FAILCRITICALERRORS: u32 = 0x0001;
const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;

// Process mitigation policy IDs
const PROCESS_DEP_POLICY: i32 = 0;
const PROCESS_ASLR_POLICY: i32 = 1;
const PROCESS_STRICT_HANDLE_CHECK_POLICY: i32 = 3;
const PROCESS_EXTENSION_POINT_DISABLE_POLICY: i32 = 6;
const PROCESS_IMAGE_LOAD_POLICY: i32 = 10;

unsafe extern "system" {
    fn SetProcessMitigationPolicy(policy: i32, buffer: *const u8, length: usize) -> i32;
}

fn set_mitigation_policy(name: &str, policy_id: i32, flags: u32) {
    let result = unsafe {
        SetProcessMitigationPolicy(
            policy_id,
            &flags as *const u32 as *const u8,
            std::mem::size_of::<u32>(),
        )
    };
    if result == 0 {
        warn!(
            "failed to set {name} mitigation policy: {}",
            std::io::Error::last_os_error()
        );
    }
}

pub fn harden() {
    // 1. SetErrorMode to suppress error dialogs
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }

    // 2. Process mitigation policies
    // a. DEP (Data Execution Prevention)
    set_mitigation_policy("DEP", PROCESS_DEP_POLICY, 0x1 | 0x2);

    // b. ASLR (Address Space Layout Randomization)
    set_mitigation_policy("ASLR", PROCESS_ASLR_POLICY, 0x1 | 0x2 | 0x4 | 0x8);

    // c. Strict handle checking
    set_mitigation_policy(
        "StrictHandleCheck",
        PROCESS_STRICT_HANDLE_CHECK_POLICY,
        0x1 | 0x2,
    );

    // d. Extension point disable
    set_mitigation_policy(
        "ExtensionPointDisable",
        PROCESS_EXTENSION_POINT_DISABLE_POLICY,
        0x1,
    );

    // e. Image load restrictions
    set_mitigation_policy("ImageLoad", PROCESS_IMAGE_LOAD_POLICY, 0x1 | 0x2 | 0x4);
}
