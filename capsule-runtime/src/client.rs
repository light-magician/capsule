use crate::constants;
use crate::log;
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

pub fn send_run_request(cmd: Vec<String>) -> io::Result<()> {
    #[derive(Serialize)]
    struct RunRequest {
        cmd: Vec<String>,
    }

    let req = RunRequest { cmd: cmd.clone() };
    let payload = serde_json::to_vec(&req)?;

    // send to control socket
    // TODO: should be a match here to alert as to nature of connection failure
    // TODO: should also be a cert based handshake process here
    let mut control = UnixStream::connect(constants::SOCKET_PATH)?;
    control.write_all(&payload)?;

    // fire-and-forget to logger socket
    if let Ok(mut logger) = UnixStream::connect(constants::LOGGER_SOCKET_PATH) {
        let _ = logger.write_all(&payload);
    }

    Ok(())
}
