// src/runtime.rs

use anyhow::Result;
use serde_json::json;
use std::path::Path;
use std::process::Command;

use crate::log::{append_event, last_hash, CapsuleEvent};
use crate::policy::Policy;
use crate::sandbox::apply_seccomp_echo_only;

/// Execute a whitelisted command under seccomp, then append it to the Merkle-chained log.
pub fn run_command(policy_path: &Path, cmd: Vec<String>) -> Result<()> {
    // 1) Get program + args
    let program = &cmd
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("No command provided"))?;
    let args = &cmd[1..];

    // 2) Policy check (only “echo” currently allowed)
    if !Policy.validate(program, args) {
        anyhow::bail!("Command '{}' not allowed by policy", program);
    }

    // 3) Install our “echo‐only” seccomp filter
    apply_seccomp_echo_only()?;

    // 4) Spawn the real program under the filter
    let output = Command::new(program).args(args).output()?;

    // 5) Print stdout
    print!("{}", String::from_utf8_lossy(&output.stdout));

    // 6) Append to Merkle log
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

/// Verify the integrity of the Merkle-chain log
pub fn verify_log(log_path: &Path) -> Result<()> {
    crate::log::verify(log_path)
}
