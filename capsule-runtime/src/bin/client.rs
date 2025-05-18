use capsule_runtime::log;
use serde::Serialize;
use std::env;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

/// RPC-only stub: send command to daemon and exit
///
/// Client is a basic RPC shell
///     only serializes a RunRequest (no local execve)
///
/// Daemon forks, filters, executes so you can insert
///     Berkeley Packet Filter seccomp right before execve.
///     Daemon still logs both the high-level command and the
///     low-level syscalls.
///
/// Client UX is `capsule run program [args...]`
///
/// RPC Stub:
///     decouples command submission (client-side) from
///     execution or logging.
///     Client only needs socket logic, not policy or
///     syscall handling.
///
/// Why RPC:
///     minimal footprint
///     zero dependencies
///     extensibility -> can extend DaemonRequest
///                     without changing shell hooks
///                     access user, PID, env

#[derive(Serialize)]
struct DaemonRequest {
    cmd: String,
    args: Vec<String>,
}

fn main() -> io::Result<()> {
    // collect all args after
    // "capsule-client" as the command to run
    let mut args = env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| {
        eprintln!("usage: capsule-client <program> [args...]");
        std::process::exit(1);
    });
    let args: Vec<String> = args.collect();

    // build and serialize RPC request
    let rpc = DaemonRequest { cmd, args };
    // convert to byte array
    let data = serde_json::to_vec(&rpc)?;

    // send to the daemon's socket
    let mut socket = UnixStream::connect("/tmp/capsule.sock")?;
    socket.write_all(&data)?;
    Ok(())
}
