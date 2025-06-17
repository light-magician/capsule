//! Run.rs facilitates the `capsule run agent.py` command sequence
//! Run is similar to trace, but rather than just tracing syscalls into
//!     a file, the syscall sequences are converted into event summaries.
//!
//! Goal is to turn This
//! 1697451234.001  4321  read(3, 8192)          = 4096
//! 1697451234.002  4321  read(3, 8192)          = 4096
//! 1697451234.049  4321  read(3, 8192)          = 4096
//!
//! Into this:
//! {
//!  "ts_first": 1697451234001,
//!  "ts_last": 1697451234049,
//!  "pid": 4321,
//!  "action": "FileRead",
//!  "path": "/home/app/.cache/model.bin",
//!  "bytes": 12288,
//!  "calls": 3
//!}

// src/run.rs
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

//TODO: sort by PID later
// -ttt gives monotonic nanoseconds
// -yy makes the file descriptor to path mapping
//      easier because strace emits the resolved
//      pathname/socket tuple inline.
const STRACE_FLAGS: &[&str] = &[
    "-f",     // follow children
    "-ttt",   // monotonic nsec timestamps
    "-yy",    // show FD → path/socket
    "-s1000", // enlarge string prints
    "-e",
    "trace=all",
];

pub fn run(cmd: &[String]) -> anyhow::Result<()> {
    let mut child = Command::new("strace")
        .args(STRACE_FLAGS)
        .arg("--")
        .args(cmd)
        .stdout(Stdio::inherit()) // agent stdout/err stay live
        .stderr(Stdio::piped()) // strace feed
        .spawn()?;

    let stderr = child.stderr.take().unwrap();
    let reader = BufReader::new(stderr);

    // Stream directly to parser via channel; in MVP we just write to disk.
    let mut logfile = std::fs::File::create("/tmp/capsule_syscalls.log")?;
    thread::spawn(move || {
        for line in reader.lines().flatten() {
            use std::io::Write;
            writeln!(logfile, "{line}").ok();
        }
    });

    let status = child.wait()?;
    println!("capsule-run: traced process exited with {status}");
    Ok(())
}
