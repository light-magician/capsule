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
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::{collections::BTreeMap, convert::TryInto, error::Error};

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
        // sc is an index, and its a vector of
        rules.insert(sc as i64, Vec::new());
    }
    // create the filter: on match Allow; on mismatch: kill process
    // the doc on how this was built
    // https://docs.rs/seccompiler/latest/seccompiler/
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()?,
    )
    .unwrap()
    .try_into()
    .unwrap();
    // enforce the filter immediately
    seccompiler::apply_filter(&filter).unwrap();
    Ok(())
}
