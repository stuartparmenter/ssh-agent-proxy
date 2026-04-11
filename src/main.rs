mod agent;
mod agent_source;
mod sshsig;

#[cfg(target_os = "linux")]
mod hardening_linux;
#[cfg(target_os = "macos")]
mod hardening_macos;
#[cfg(target_os = "windows")]
mod hardening_windows;

fn harden_process() {
    #[cfg(target_os = "linux")]
    hardening_linux::harden();
    #[cfg(target_os = "macos")]
    hardening_macos::harden();
    #[cfg(target_os = "windows")]
    hardening_windows::harden();
}

fn main() {
    harden_process();
    println!("ssh-agent-proxy (rust)");
}
