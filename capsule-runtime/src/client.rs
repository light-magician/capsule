use crate::constants;
use crate::log;
use serde::Serialize;
use std::env;
use std::io::{self, Read, Write};
use std::net::Shutdown;
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

    // Connect and send JSON payload, terminated by a newline
    let mut socket = UnixStream::connect(constants::SOCKET_PATH)?;
    socket.write_all(&payload)?;
    socket.write_all(b"\n")?; // delimiter for daemon.read_line()

    // Read back the streamed stdout/stderr until the server closes the socket
    let mut buf = [0u8; 4096];
    loop {
        let n = socket.read(&mut buf)?;
        if n == 0 {
            break; // EOF: daemon has finished and closed
        }
        io::stdout().write_all(&buf[..n])?;
    }

    Ok(())
}
