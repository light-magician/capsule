//! capsule-runtime core modules
pub mod policy;
pub mod sandbox;

use policy::Policy;
use sandbox::apply_seccomp_echo_only;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // collect args: capsule <cmd>
    let mut args = std::env::args();
    let _exe = args.next();
    let cmd = match args.next() {
        Some(cmd) => cmd,
        None => {
            eprintln("usage: capsule <cmd> [args...]");
            std::process::exit(1);
        }
    };
    // policy check
    let rest: Vec<&str> = args.map(|s| s.as_str()).collect();
    if !Policy::validate_call(&cmd, &rest) {
        eprintln!("cmmand '{}' not allowed by policy", cmd);
        std::process::exit(1);
    }
    // apply sandbox
    apply_seccomp_echo_only();
    // execute
    let status = std::process::Command::new(cmd).args(&rest).status()?;
    // TODO: append Merkle-chained audit log via blake3
    std::process::exit(status.code().unwrap_or(1));
}
