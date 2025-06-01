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
use std::{
    ffi::CString,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    time::SystemTime,
};
use syscalls::Sysno;

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

/// Trace `argv[0]` with its arguments; write log to `log_override` or default.
pub fn trace(argv: Vec<String>, log_override: Option<PathBuf>) -> Result<()> {
    if argv.is_empty() {
        anyhow::bail!("trace: empty argv");
    }

    // ---------------------------------------------------------------------
    // 1. Prepare logfile (always create, even if later steps fail)
    // ---------------------------------------------------------------------
    let default_name = PathBuf::from(format!(
        "/tmp/capsule-trace-{}.log",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    let log_path = log_override.unwrap_or(default_name);
    let mut log = BufWriter::new(File::create(&log_path).context("create log file")?);

    // ---------------------------------------------------------------------
    // 2. Fork
    // ---------------------------------------------------------------------
    match unsafe { fork() }? {
        ForkResult::Child => {
            // --- Child branch ------------------------------------------------
            if let Err(e) = child_exec(&argv) {
                eprintln!("❌ child error: {e:?}");
                std::process::exit(1);
            }
            unreachable!();
        }
        ForkResult::Parent { child } => {
            run_tracer(child, &mut log).context("tracer loop")?;
            log.flush().ok();
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

fn run_tracer(child: Pid, log: &mut BufWriter<File>) -> Result<()> {
    // Wait for initial SIGSTOP
    waitpid(child, None).context("wait initial stop")?;

    // Tag syscall stops + kill child if tracer dies
    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_EXITKILL,
    )
    .context("setoptions")?;

    loop {
        // Resume until next syscall entry/exit
        ptrace::syscall(child, None).context("resume child")?;
        let status = waitpid(child, Some(WaitPidFlag::WSTOPPED)).context("waitpid")?;

        match status {
            WaitStatus::PtraceSyscall(pid) => {
                let regs = ptrace::getregs(pid).context("getregs")?;
                let (nr, args) = decode_syscall_regs(&regs);
                let name = Sysno::from(nr as i32).name();
                writeln!(
                    log,
                    "{:.6} {:5} {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                    seconds_since_epoch(),
                    pid,
                    name,
                    args[0],
                    args[1],
                    args[2],
                    args[3],
                    args[4],
                    args[5]
                )?;
            }
            WaitStatus::Exited(_, code) => {
                writeln!(log, "# child exited with code {code}")?;
                break;
            }
            WaitStatus::Signaled(_, sig, _) => {
                writeln!(log, "# child killed by signal {sig}")?;
                break;
            }
            _ => {}
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
