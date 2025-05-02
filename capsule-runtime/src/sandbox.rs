use anyhow::Result;
/// seccompiler
/// https://docs.rs/seccompiler/latest/seccompiler/#structs
///
/// provides easy-to-use linux seccomp-bpf jailing.
///
/// seccomp is a linux kernel security feature which enables
/// a tight control over what kernel-level mechanisms a process
/// has access to.
///
/// this is typically used to reduce the attack surface and exposed resources
/// when running untrusted code. All code that an unknown AI agent runs is untrusted.
///
/// We will write and set a Berkeley Packet Filter (BPF) which will allow us
/// to intercept syscalls for  each program or thread and decide if that call
/// is unsafe to execute.
///
/// This crate provides high-level wrappers for working with syscall filtering.
///
///
use seccompiler::{SeccompAction, SeccompFilter};
use std::{collections::BTreeMap, error::Error};

/// install a seccomp-BPF filter that kills the process
/// on any syscall except: read, write, fstat, close, exit, exit_group
pub fn apply_seccomp_echo_only() -> Result<(), Box<dyn Error>> {
    // build the rule map: syscall -> empty Vec (match anything -> allow)
    let mut rules: BTreeMap<i64, Vec<_>> = BTreeMap::new();
    for &sc in &[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_fstat,
        libc::SYS_close,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        filter.add_rule(sc, SeccompAction::Allow)?;
    }
    // create the filter: on match Allow; on mismatch: kill process
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompActoin::Allow,
        std::env::constants::ARCH.try_into()?,
    )?;
    // enforce the filter immediately
    filter.load()?;
    Ok(())
}
