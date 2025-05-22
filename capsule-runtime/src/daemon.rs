use crate::constants::{ERR_LOG, OUT_LOG, PID_FILE, SOCKET_PATH};
use crate::log::start_rpc_logger;
use chrono::Local;
use daemonize::Daemonize;
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;
use serde::Deserialize;
use std::fs::remove_file;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{exit, Command, Output, Stdio};
use std::{fs, thread};
// placeholder struct for the string array that
// comes in from the client. Likely a command or random
// text.
#[derive(Deserialize)]
struct RunRequest {
    cmd: Vec<String>,
}
// start the capsule daemon:
// fork & detach
// spawn RPC logger thread
// bund UDS & set perms
// accept + handle each client
pub fn start_daemon() -> Result<()> {
    // remove a stale Process ID file if present
    let _ = std::fs::remove_file(PID_FILE);
    // daemonize: detach, write PID, redirect stdout/stderr
    Daemonize::new()
        .pid_file(PID_FILE)
        .chown_pid_file(true)
        .working_directory("/")
        .umask(0)
        .stdout(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(OUT_LOG)
                .unwrap(),
        )
        .stderr(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(ERR_LOG)
                .unwrap(),
        )
        .start()
        .unwrap_or_else(|e| {
            eprintln!("Failed to daemonize: {}", e);
            exit(1);
        });

    thread::spawn(|| {
        if let Err(e) = start_rpc_logger() {
            eprintln!("logger thread failed: {}", e);
        }
    });

    // prep socket
    let _ = fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o700))?;

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle_client(stream) {
                    eprintln!("client handler error: {}", e);
                }
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
    Ok(())
}

pub fn stop_daemon() -> Result<()> {
    //TODO: Not prod quality
    //Relying on SIGTERM via kill is a temporary workaround
    //
    // Best practice is to expose a controlled shutdown
    // RPC over IPC channel aka "shutdown" message
    // over Unix socket, or maybe integrate with
    // service manager (systemd/launchd) so that it
    // handles stop signals cleanly

    // First try graceful shutdown via socket
    if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH) {
        // Send shutdown message
        let _ = stream.write_all(b"shutdown");
        println!("Sent shutdown command to daemon via socket");
        return Ok(());
    }

    // If socket unavailable, fallback to PID/SIGTERM
    let pid_str = fs::read_to_string(PID_FILE).unwrap_or_else(|e| {
        eprintln!("Could not read PID file: {}", e);
        exit(1)
    });
    let pid = pid_str.trim().parse::<i32>().unwrap_or_else(|e| {
        eprintln!("Invalid PID: {}", e);
        exit(1)
    });

    // Send SIGTERM
    kill(Pid::from_raw(pid), SIGTERM).unwrap_or_else(|e| {
        eprintln!("Failed to send SIGTERM: {}", e);
        exit(1)
    });
    println!("Sent SIGTERM to {}", pid);

    // Cleanup PID file
    remove_file(PID_FILE).ok();
    // Optionally remove socket if left behind
    remove_file(SOCKET_PATH).ok();
    Ok(())
}

pub fn status() -> Result<()> {
    // if there is no PID, its not running
    if Path::new(PID_FILE).exists() {
        if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH) {
            // send the literal "status" query
            stream.write_all(b"status")?;
            // close the write-half so the daemon's read_to_string() will return
            stream.shutdown(Shutdown::Write)?;
            // read daemon's reply to a string
            let mut resp = String::new();
            stream.read_to_string(&mut resp)?;
            // if daemon answer's "running", echo the PID
            if resp.trim() == "running" {
                let pid = fs::read_to_string(PID_FILE).unwrap_or_default();
                println!("capsule daemon running (PID {})", pid.trim());
                return Ok(());
            }
        }
    }
    // fallback, either socket failed or reply wasn't running
    println!("capsule daemon not running ...");
    Ok(())
}

fn execute_command(cmd: &[String]) -> Result<Output> {
    // TODO: what is best practice for where these commands should be executed on the container?
    // where this is executed will matter relative to the client process
    Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

fn run_request(req: RunRequest) -> Result<()> {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let cmd_line = req.cmd.join(" ");

    // 1) record what was requested
    let mut logf = OpenOptions::new().create(true).append(true).open(OUT_LOG)?;
    writeln!(logf, "{} Requested: {}", now, cmd_line)?;

    // 2) open the two log files for capture
    let out = OpenOptions::new().create(true).append(true).open(OUT_LOG)?;
    let err = OpenOptions::new().create(true).append(true).open(ERR_LOG)?;

    // 3) spawn the process
    match Command::new(&req.cmd[0])
        .args(&req.cmd[1..])
        .stdout(out)
        .stderr(err)
        .spawn()
    {
        Ok(child) => {
            let mut logf = OpenOptions::new().create(true).append(true).open(OUT_LOG)?;
            writeln!(logf, "{} Spawned `{}` (pid={})", now, cmd_line, child.id())?;
        }
        Err(e) => {
            let mut logf = OpenOptions::new().create(true).append(true).open(OUT_LOG)?;
            writeln!(logf, "{} Failed to spawn `{}`: {}", now, cmd_line, e)?;
        }
    }

    Ok(())
}

/// Handle one “run” RPC:
/// 1. read all JSON from the socket
/// 2. parse it into RunRequest
/// 3. log the JSON text
/// 4. spawn the child with piped stdout/stderr
/// 5. copy from those pipes back into the socket
fn handle_client(mut sock: UnixStream) -> Result<()> {
    // 1. Read JSON request until client closes the write half
    let mut buf = String::new();
    sock.read_to_string(&mut buf)?;
    // short circuit for status and shutdown
    let message = buf.trim_end();
    match message {
        "status" => {
            // client asked “are you alive?”
            sock.write_all(b"running")?;
            return Ok(());
        }
        "shutdown" => {
            // client asked us to exit
            sock.write_all(b"shutting down")?;
            std::process::exit(0);
        }
        _ => {} // otherwise fall through to JSON path
    }

    // 2. Deserialize command
    let req: RunRequest =
        serde_json::from_str(&buf).map_err(|e| Error::new(ErrorKind::Other, e))?;

    // 3. Log raw request for auditing
    let mut logf = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUT_LOG)?;
    writeln!(logf, "REQUEST: {}", buf.trim_end()).ok();

    // 4. Spawn the requested program
    let mut child = Command::new(&req.cmd[0])
        .args(&req.cmd[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // 5. Stream stdout → socket
    if let Some(mut out) = child.stdout.take() {
        let mut w = sock.try_clone()?;
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = out.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let _ = w.write_all(&chunk[..n]);
            }
        });
    }

    //    …and stderr → socket
    if let Some(mut err) = child.stderr.take() {
        let mut w = sock;
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = err.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let _ = w.write_all(&chunk[..n]);
            }
        });
    }

    // wait for the child to exit (threads will finish when pipes close)
    let _ = child.wait();
    Ok(())
}
