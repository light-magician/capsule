/* ======================  src/sandbox.rs  ====================== */
//! Cross‑arch ptrace‑based syscall tracer for Capsule.
//! Uses safe `nix` wrappers—no raw libc.
//!
//! * Creates the log file **before** forking, so it exists even if the
//!   child fails immediately.
//! * Surfaces common ptrace / exec errors with clear `❌` messages.
//!
//!   capsule trace <target> [ARG…] [--log <file>]
//!
//! Log default: `/tmp/capsule-trace-<YYYYMMDDThhmmssZ>.log`
use crate::log;
use anyhow::{Context, Result};
use chrono::Utc;
use nix::{
    sys::{
        ptrace,
        signal::{self, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{execvp, fork, ForkResult, Pid},
};
use std::{ffi::CString, path::PathBuf, time::SystemTime};

//NOTE: we would only expect one target to be active at a time
#[cfg(target_arch = "x86_64")]
type Regs = libc::user_regs_struct;
#[cfg(target_arch = "aarch64")]
type Regs = libc::user_regs_struct;

fn decode_syscall_regs(r: &Regs) -> (u64, [u64; 6]) {
    #[cfg(target_arch = "x86_64")]
    {
        return (r.orig_rax, [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9]);
    }
    #[cfg(target_arch = "aarch64")]
    {
        return (
            r.regs[8],
            [
                r.regs[0], r.regs[1], r.regs[2], r.regs[3], r.regs[4], r.regs[5],
            ],
        );
    }
}

// ---------- portable helpers ----------

#[cfg(target_arch = "x86_64")]
fn extract(regs: libc::user_regs_struct) -> (i64, [u64; 6]) {
    (
        regs.orig_rax as i64,
        [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
    )
}

#[cfg(target_arch = "aarch64")]
fn extract(regs: libc::user_regs_struct) -> (i64, [u64; 6]) {
    (
        regs.regs[8] as i64, // x8 = syscall #
        [
            regs.regs[0],
            regs.regs[1],
            regs.regs[2],
            regs.regs[3],
            regs.regs[4],
            regs.regs[5],
        ],
    )
}

/// very cheap “name” stub – fill in with a real table later
fn syscall_name(num: i64) -> String {
    format!("syscall_{num}")
}

fn uptime_secs() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Trace `argv[0]` with its arguments; write log to `log_override` or default.
pub fn trace(argv: Vec<String>, log_override: Option<PathBuf>) -> Result<()> {
    if argv.is_empty() {
        anyhow::bail!("trace: empty argv");
    }
    // ---------------------------------------------------------------------
    // Fork
    // ---------------------------------------------------------------------
    match unsafe { fork() }? {
        ForkResult::Child => {
            // --- Child branch ------------------------------------------------
            if let Err(e) = child_exec(&argv) {
                eprintln!("❌ child error: {e:?}");
                std::process::exit(1);
            }
        }
        ForkResult::Parent { child } => {
            run_tracer(child, &argv)?;
        }
    }
    Ok(())
}

fn child_exec(argv: &[String]) -> Result<()> {
    ptrace::traceme().context("ptrace TRACEME")?;
    // stop so parent can attach
    signal::kill(Pid::this(), Signal::SIGSTOP).context("SIGSTOP self")?;

    // Prepare CStrings for execvp
    let cstrs: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_str()).expect("NUL in argv"))
        .collect();
    let program = &cstrs[0];
    let argv_c: Vec<&CString> = cstrs.iter().collect();

    execvp(program, &argv_c).context("execvp failed")?;
    Ok(())
}

/// drive ptrace, format each event, and stream to `log::append`.
///
/// * child - PID being traced
/// * argv  - original command line, used only for the START marker.
pub fn run_tracer(child: Pid, argv: &[String]) -> Result<()> {
    // Session marker
    log::append(format!(
        "### START {} pid={} cmd={}",
        Utc::now().to_rfc3339(),
        child,
        argv.join(" ")
    ));

    // Wait for the SIGSTOP from ptrace::traceme() in the child
    waitpid(child, None)?;
    // Options Reference: https://docs.rs/nix/latest/nix/sys/ptrace/struct.Options.html
    //
    // TRACEGOOD: adds 0x80 to SIGTRAP signal when syscall trap occurs
    //            Lets the tracer distinguish between traps caused by syscalls
    //            vs other events (breakpoints or int 3, ect).
    //            Ensures that syscalls are easy to recognize in waitpid.
    // EXITKILL:  automatically kills traced child if tracer exits unexpectedly.
    //            Prevents orphaned traced processes from continuing execution
    //            without supervision. A containment failsafe.
    // TRACECLONE: notififes tracer (waitpid) when traced process calls clone(2).
    //             Let's you track new threads or lightweight processes, useful
    //             for multi-threaded programs.
    // TRACEFORK: notifies tracer when process calls fork(2).
    //            Allows tracer to track new child processes spawned via fork.
    // TRACEVFORK: notifies tracer on vfork(2) call.
    //            Like fork, but with shared address space.
    //             Important for detecting short lived child processes that run exec()
    //             soon after.
    // TRACEEXEC: notifies tracer when traced process calls execve(2) or equivalent.
    //            Allows for re-inspect memory, registers, or log that the process
    //            swapped out its binary image. Useful for trace / audit.
    let trace_opts: ptrace::Options = ptrace::Options::PTRACE_O_TRACESYSGOOD
        | ptrace::Options::PTRACE_O_EXITKILL
        | ptrace::Options::PTRACE_O_TRACECLONE
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK
        | ptrace::Options::PTRACE_O_TRACEEXEC;
    // enable options on the very first PID
    ptrace::setoptions(child, trace_opts)?;
    // NOTE: How virtual-env & poetry actually exec
    //
    //       Virtual Env (PEP 405):
    //       creates a private copy of the launcher binary (python, pip)
    //       and rewrites sys.path at startup. No extra sandboxing, just another execve().
    //
    //       Poetry:
    //       host interpreter runs /usr/local/bin/poetry (a python script).
    //       Poetry locates or creates a .venv/ and then execve()'s that environment's
    //       python with your script path.

    // first and only unconditional resume
    ptrace::syscall(child, None)?;

    loop {
        // -1 means "wait for any child we-re already tracing, not just the first one"
        // we need to be able to see not only child processes but grandchild processes
        // as this is where python environments will be executing the binaries that
        // we need to observe.
        let status = waitpid::<Option<Pid>>(None, Some(WaitPidFlag::WSTOPPED))?;

        match status {
            // ------------- CLONE / FORK / VFORK --------------
            WaitStatus::PtraceEvent(pid, _sig, event)
                if event as i32 == libc::PTRACE_EVENT_CLONE
                    || event as i32 == libc::PTRACE_EVENT_FORK
                    || event as i32 == libc::PTRACE_EVENT_VFORK =>
            {
                let new_raw = ptrace::getevent(pid)? as i32;
                let new_pid = Pid::from_raw(new_raw);
                ptrace::setoptions(new_pid, trace_opts)?;
                ptrace::syscall(new_pid, None)?;
                ptrace::syscall(pid, None)?;
            }
            // ------------------ EXEC ---------------------
            WaitStatus::PtraceEvent(pid, _, ev) if ev as i32 == libc::PTRACE_EVENT_EXEC => {
                // log_exec_transition(pid);   // TODO: implement or remove
                ptrace::syscall(pid, None)?;
            }
            // ------------------ SYSCALL STOP -------------
            WaitStatus::PtraceSyscall(pid) => {
                let (nr, args) = extract(ptrace::getregs(pid)?);
                log::append(format!(
                    "{:.6} {:5} syscall_{nr}({:#x},{:#x},{:#x},{:#x},{:#x},{:#x})",
                    uptime_secs(),
                    pid.as_raw(),
                    args[0],
                    args[1],
                    args[2],
                    args[3],
                    args[4],
                    args[5],
                ));
                ptrace::syscall(pid, None)?; // continue to next half-stop
            }
            // ------------------ NORMAL EXIT --------------
            WaitStatus::Exited(pid, code) => {
                log::append(format!(
                    "{:.6} {:5} exited({})",
                    uptime_secs(),
                    pid.as_raw(),
                    code
                ));
                break;
            }
            // ------------------ KILLED BY SIGNAL ---------
            WaitStatus::Signaled(pid, sig, _core_dumped) => {
                log::append(format!(
                    "{:.6} {:5} signaled({})",
                    uptime_secs(),
                    pid.as_raw(),
                    sig as i32
                ));
                break;
            }
            // ------------------ OTHER STOPS --------------
            _ => {
                // plain SIGTRAP, job control stop, ect.
                // just loop back, we'll resume at the top with the next
                // ptrace::syscall()
            }
        }
    }
    Ok(())
}

fn seconds_since_epoch() -> f64 {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_secs() as f64 + f64::from(dur.subsec_micros()) / 1_000_000.0
}
