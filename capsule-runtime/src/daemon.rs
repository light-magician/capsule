//! Tiny always-on daemon.
//! protocol:  "<cmd args…>\n"  → run, log, reply exit-code\n
//!            "shutdown\n"     → exit 0

use anyhow::Result;
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
};

use crate::{log::Logger, policy::Policy, profile};

const SOCK: &str = "/tmp/capsule.sock";
const TRACE_DIR: &str = "/tmp/capsule_traces";

pub fn run(_opt: Option<String>, log: &Path, pol: Policy) -> Result<()> {
    let _ = std::fs::remove_file(SOCK);
    let lis = UnixListener::bind(SOCK)?;
    println!("🛡  capsule daemon listening on {SOCK}");

    for s in lis.incoming() {
        let mut c = s?;
        let mut req = String::new();
        c.read_to_string(&mut req)?;
        let line = req.trim();
        if line == "shutdown" {
            writeln!(c, "ok")?;
            break;
        }

        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap().to_string();
        let args: Vec<String> = parts.map(|s| s.into()).collect();

        let code = exec(&cmd, &args, log, &pol)?;
        writeln!(c, "{code}")?;
    }
    Ok(())
}

fn exec(cmd: &str, args: &[String], log: &Path, pol: &Policy) -> Result<i32> {
    // always write start
    let mut lg = Logger::new(log)?;
    lg.log_invocation_start(
        std::iter::once(cmd.into())
            .chain(args.iter().cloned())
            .collect(),
    )?;

    if !pol.validate(cmd) {
        lg.log_invocation_end(1)?;
        return Ok(1);
    }

    // syscall list via strace → Merkle
    for sc in profile::trace_single(cmd, args, Path::new(TRACE_DIR))? {
        lg.log_syscall(-1, sc, Vec::new(), 0)?;
    }
    lg.log_invocation_end(0)?;
    Ok(0)
}
