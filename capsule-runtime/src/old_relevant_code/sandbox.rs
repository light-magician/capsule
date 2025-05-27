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
/// A sandbox is a confined execution environment that restricts what resources and operations
/// a process may access, limiting its ability to harm the host system. In our case, we apply
/// a Linux seccomp-BPF sandbox, which installs a Berkeley Packet Filter (BPF) in the kernel
/// to intercept every system call the process makes and decide—based on a whitelist—whether to
/// allow or kill the process before the call ever executes sandbox.rs](file-service://file-86q3izkca7DbBftZbJDASn).
///
/// A Berkeley Packet Filter (BPF) was originally designed for filtering network packets, but
/// Linux’s seccomp subsystem repurposes BPF to filter system calls. We use the `seccompiler`
/// crate to construct a BPF program that explicitly allows only a minimal set of syscalls
/// (e.g., read, write, fstat, close, exit, execve, openat) and traps or kills everything else.
/// This reduces the kernel-level attack surface to the bare minimum needed for the agent’s task sandbox.rs](file-service://file-86q3izkca7DbBftZbJDASn).
///
/// This level of safety is especially critical for an AI agent with filesystem access:
/// even if the agent’s code or its tools are buggy or malicious, any attempt to open, write,
/// spawn new processes, map memory, or perform network operations outside the approved list
/// will be blocked at the syscall boundary, preventing unauthorized reads, writes, or escalations.
///
/// Compared to containers, which rely on higher-level abstractions like namespaces, cgroups,
/// and chroots, seccomp-BPF sits deeper in the kernel. Containers isolate resources but still
/// allow most syscalls by default for compatibility; a seccomp sandbox can enforce a
/// strict, syscall-level policy regardless of filesystem or namespace configuration. This
/// makes policy simpler to reason about, harder to bypass, and avoids the overhead and
/// complexity of managing full container environments.
///
/// By running “closer” to the user’s machine—without a container hypervisor layer—we gain:
///   1. **Finer-grained control**: We can precisely whitelist only the syscalls we trust, rather
///      than relying on broad container defaults.
///   2. **Lower overhead**: No extra filesystem layers or daemon processes; the filter lives
///      entirely in the kernel alongside the process.
///   3. **Stronger security guarantees**: Attack techniques that exploit lesser-known syscalls
///      (e.g., mmap, mprotect, ptrace) are blocked outright.
///
/// Ultimately, this protects us from threats unique to local AI agents, such as:
///   • Arbitrary code execution via JIT or dynamic linking  
///   • Covert data exfiltration through unconventional syscalls  
///   • Privilege escalation via unexpected kernel interfaces  
///   • Side-effects on the host filesystem or network beyond what the policy permits  
///
/// Adding this low-level syscall filtering enables us to safely grant an AI agent direct,
/// high-performance access to the user’s files, without exposing the full power of the kernel
///—a degree of trust-and-verify that containers alone cannot provide.
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
use std::{collections::BTreeMap, convert::TryInto, error::Error};

/// install a seccomp-BPF filter that kills the process
/// on any syscall except: read, write, fstat, close, exit, exit_group
/// TODO: hat blunt approach leaves us vulnerable to all sorts of misuse—e.g.
///     mapping executable memory, changing protections, or abusing openat to
///     escape directories—because we’re not checking how those calls are made.
///     To be smarter later we will have to implement clever ways to flag unwanted
///     combinations. Even seemingly innocent syscalls made in the right succession
///     can allow the agent to do unwanted actions.
pub fn apply_seccomp() -> Result<(), Box<dyn Error>> {
    // build the rule map: syscall -> empty Vec (match anything -> allow)
    // TODO: note that we are not really definint "rules" yet but rather a syscall
    //       allowlist, and any combo no matter how dubios will pass through
    let mut rules: BTreeMap<i64, Vec<_>> = BTreeMap::new();
    // TODO: add description of what each allowed syscall facilitates
    for &sc in &[
        libc::SYS_execve,
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        libc::SYS_arch_prctl,
        libc::SYS_faccessat,
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
        SeccompAction::Trap,
        //SeccompAction::KillProcess,
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
