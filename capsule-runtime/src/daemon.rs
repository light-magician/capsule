use crate::constants::{AUDIT_LOG, ERR_LOG, OUT_LOG, PID_FILE, SOCKET_PATH};
use crate::log::{log_audit, log_event};
use chrono::Local;
use daemonize::Daemonize;
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;
use serde::Deserialize;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{exit, Command, Stdio};
use std::thread;

#[derive(Deserialize)]
struct RunRequest {
    cmd: Vec<String>,
}

/// start the capsule daemon:
/// - fork & detach
/// - bind UDS & set perms
/// - accept + handle each client
pub fn start_daemon() -> Result<()> {
    // remove a stale Process ID file if present
    let _ = fs::remove_file(PID_FILE);

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

    // log startup event
    log_event(&format!("Daemon started on {}", SOCKET_PATH))?;

    // prep socket
    let _ = fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o700))?;

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                if let Err(e) = handle_client(stream) {
                    log_event(&format!("client handler error: {}", e)).ok();
                }
            }
            Err(e) => {
                log_event(&format!("accept error: {}", e)).ok();
            }
        }
    }
    Ok(())
}
pub fn stop_daemon() -> Result<()> {
    // 1) Try graceful shutdown via RPC socket
    if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH) {
        // send shutdown request
        stream.write_all(b"shutdown")?;
        // signal EOF so daemon's read_to_string returns
        stream.shutdown(Shutdown::Write)?;
        // optionally read daemon's goodbye message
        let mut resp = String::new();
        if stream.read_to_string(&mut resp).is_ok() {
            println!("{}", resp.trim());
        } else {
            println!("Sent shutdown command to daemon via socket");
        }
        // cleanup local socket file and PID file
        fs::remove_file(PID_FILE).ok();
        fs::remove_file(SOCKET_PATH).ok();
        return Ok(());
    }

    // 2) Fallback: PID/SIGTERM if RPC socket didn't connect
    let pid_str = fs::read_to_string(PID_FILE).unwrap_or_else(|e| {
        eprintln!("Could not read PID file: {}", e);
        exit(1)
    });
    let pid = pid_str.trim().parse::<i32>().unwrap_or_else(|e| {
        eprintln!("Invalid PID: {}", e);
        exit(1)
    });
    // send SIGTERM
    kill(Pid::from_raw(pid), SIGTERM).unwrap_or_else(|e| {
        eprintln!("Failed to send SIGTERM: {}", e);
        exit(1)
    });
    println!("Sent SIGTERM to {}", pid);

    // cleanup after kill
    fs::remove_file(PID_FILE).ok();
    fs::remove_file(SOCKET_PATH).ok();
    Ok(())
}

pub fn status() -> Result<()> {
    // if there is no PID, it's not running
    if Path::new(PID_FILE).exists() {
        if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH) {
            stream.write_all(b"status")?;
            stream.shutdown(Shutdown::Write)?;
            let mut resp = String::new();
            stream.read_to_string(&mut resp)?;
            if resp.trim() == "running" {
                let pid = fs::read_to_string(PID_FILE).unwrap_or_default();
                println!("capsule daemon running (PID {})", pid.trim());
                return Ok(());
            }
        }
    }
    println!("capsule daemon not running ...");
    Ok(())
}

/// Handle one “run” RPC:
/// 1. read all JSON from the socket
/// 2. parse it into RunRequest
/// 3. audit-log the raw JSON
/// 4. spawn the child with piped stdout/stderr
/// 5. copy from those pipes back into the socket
fn handle_client(mut sock: UnixStream) -> Result<()> {
    let mut buf = String::new();
    sock.read_to_string(&mut buf)?;
    let message = buf.trim_end();

    match message {
        "status" => {
            sock.write_all(b"running")?;
            return Ok(());
        }
        "shutdown" => {
            log_event("Daemon stopping via socket")?;
            sock.write_all(b"shutting down")?;
            exit(0);
        }
        _ => {}
    }

    // audit the JSON command
    log_audit(&buf)?;

    // deserialize and execute
    let req: RunRequest =
        serde_json::from_str(&buf).map_err(|e| Error::new(ErrorKind::Other, e))?;

    let mut child = Command::new(&req.cmd[0])
        .args(&req.cmd[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

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

    let _ = child.wait();
    Ok(())
}
