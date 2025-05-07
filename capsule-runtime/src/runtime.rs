// src/runtime.rs

use anyhow::Result;
use serde_json::json;
use std::{path::Path, process::Command};

use crate::log::{append_event, last_hash, CapsuleEvent};
use crate::policy::Policy;
use crate::sandbox::apply_seccomp;

/// Execute a whitelisted command under seccomp, then append it to the Merkle‐chained log.
pub fn run_command(policy_path: &Path, cmd: Vec<String>) -> Result<()> {
    // 1) Extract program name and its args
    let program = cmd
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("No command provided"))?;
    let args = &cmd[1..];

    // 2) Enforce policy (only allowed commands get through)
    let policy = Policy;
    if !policy.validate(program, args) {
        anyhow::bail!("Command '{}' not allowed by policy", program);
    }

    // 3) Install seccomp filter (deny‐by‐default, allow only syscalls in sandbox.rs)
    apply_seccomp()?;

    // 4) Spawn the actual process under our filter
    let output = Command::new(program).args(args).output()?;

    // 5) Print its stdout to the user
    print!("{}", String::from_utf8_lossy(&output.stdout));

    // 6) Log this invocation into the Merkle chain
    let log_path = policy_path.with_extension("log");
    let parent_root = last_hash(&log_path)?;
    let payload = json!({ "cmd": cmd });
    let event = CapsuleEvent {
        parent_root,
        payload,
    };
    append_event(&event, &log_path)?;

    Ok(())
}

/// Called by your CLI’s `verify` subcommand.
pub fn verify_log(log_path: &Path) -> Result<()> {
    crate::log::verify(log_path)
}
