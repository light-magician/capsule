//! Sandbox module: unified ptrace tracing with named syscalls

use std::io::{self, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output, Stdio};
use std::thread;

use nix::sys::{
    ptrace,
    signal::Signal,
    wait::{waitpid, WaitStatus},
};
use nix::unistd::Pid;

use crate::log::log_syscall_event;
use syscalls::Sysno; // for mapping syscall number to name
use uuid::Uuid;

/// Run `cmd` under ptrace, log each syscall by name, and return Output.
pub fn run_and_trace(session_id: &Uuid, cmd: &[String]) -> io::Result<Output> {
    // 1. Spawn child with piped stdout/stderr
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = Pid::from_raw(child.id() as i32);

    // 2. Attach and configure ptrace
    ptrace::attach(pid).expect("ptrace attach failed");
    waitpid(pid, None).expect("wait for child stop failed");
    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_TRACESYSGOOD,
    )
    .expect("ptrace setoptions failed");
    ptrace::syscall(pid, None).expect("ptrace restart failed");

    // 3. Capture stdout/stderr in background threads
    let mut out_reader = child.stdout.take().unwrap();
    let out_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        out_reader.read_to_end(&mut buf).ok();
        buf
    });

    let mut err_reader = child.stderr.take().unwrap();
    let err_handle = thread::spawn(move || {
        let mut buf = Vec::new();
        err_reader.read_to_end(&mut buf).ok();
        buf
    });

    // 4. Single waitpid loop: handle syscalls and detect exit
    let mut exit_code = 0;
    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, code)) => {
                exit_code = code;
                break;
            }
            Ok(WaitStatus::Signaled(_, sig, _)) => {
                exit_code = 128 + (sig as i32);
                break;
            }
            Ok(WaitStatus::PtraceSyscall(_)) => {
                // Syscall entry/exit trap
                let regs = ptrace::getregs(pid).expect("getregs failed");
                let sysno = regs.regs[8] as u32; // ARM64: x8 holds syscall number

                // Map to named Sysno enum (guaranteed valid via From<u32>)
                let sysno_enum = Sysno::from(sysno);
                let name = sysno_enum.name().to_string();

                let args: Vec<String> = Vec::new(); // TODO: decode regs.regs[0..6]

                // Log the syscall event with named syscall
                log_syscall_event(session_id, pid.as_raw(), &name, &args, None)
                    .expect("log_syscall_event failed");

                // Resume to next syscall trap
                ptrace::syscall(pid, None).expect("ptrace syscall resume failed");
            }
            Ok(_) => {
                // Other ptrace events (fork, exec)
                ptrace::syscall(pid, None).ok();
            }
            Err(err) => {
                eprintln!("tracer waitpid error: {}", err);
                break;
            }
        }
    }

    // 5. Collect stdout/stderr data
    let stdout = out_handle.join().unwrap_or_default();
    let stderr = err_handle.join().unwrap_or_default();

    // 6. Build and return Output
    Ok(Output {
        status: std::process::ExitStatus::from_raw(exit_code << 8),
        stdout,
        stderr,
    })
}
