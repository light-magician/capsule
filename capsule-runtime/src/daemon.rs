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
use std::io::{Read, Result, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{exit, Command, Output, Stdio};
use std::{fs, thread};

pub fn start_daemon() {
    /// using the daemonizer crate to make a daemon more easily
    /// handles ->
    /// - double forking:
    ///     detaches process from controlling terminal
    ///     ensures it doesn't acquire a new one
    /// - session leadership:
    ///     creates a new session, making the process
    ///     the session leader
    /// - working directory:
    ///     changes the working directory to the root(/)
    ///     to avoid locking directories
    /// - file mode creation mask:
    ///     sets the file mode creation mask to zero,
    ///     ensuring files are created with the desired
    ///     permissions
    /// - standard file descriptors:
    ///     redirects standard input, output, and
    ///     error to /dev/bull or specified files
    /// - PID File Creation:
    ///     write's the daemons process ID to a file
    ///     for management of process
    // prepare log files for stdout and stderr
    // 1) daemonize the process
    Daemonize::new()
        .pid_file(PID_FILE)
        .chown_pid_file(true)
        .start()
        .unwrap_or_else(|e| {
            eprintln!("Failed to daemonize: {}", e);
            exit(1);
        });

    // 2) launch the logger thread
    thread::spawn(|| {
        if let Err(e) = start_rpc_logger() {
            eprintln!("Logger thread failed: {}", e);
        }
    });

    // 3) ensure old socket is gone, then bind
    if Path::new(SOCKET_PATH).exists() {
        fs::remove_file(SOCKET_PATH).ok();
    }
    let listener = UnixListener::bind(SOCKET_PATH).unwrap_or_else(|e| {
        eprintln!("Failed to bind {}: {}", SOCKET_PATH, e);
        exit(1);
    });

    // 4) main RPC loop
    for stream in listener.incoming() {
        match stream {
            Ok(mut sock) => {
                let mut buf = [0u8; 2048];
                if let Ok(n) = sock.read(&mut buf) {
                    if n == 0 {
                        continue;
                    }
                    let msg = String::from_utf8_lossy(&buf[..n]).trim().to_string();

                    match msg.as_str() {
                        "status" => {
                            let _ = sock.write_all(b"running");
                        }
                        "shutdown" => {
                            let now = Local::now().format("%Y-%m-%d %H:%M:%S");
                            let mut lf = OpenOptions::new().append(true).open(OUT_LOG).unwrap();
                            writeln!(lf, "{} Daemon stopping via socket", now).ok();
                            break;
                        }
                        _ => {
                            // JSON → offload to run_request (preserves old logging)
                            if let Ok(req) = serde_json::from_str::<RunRequest>(&msg) {
                                thread::spawn(move || {
                                    if let Err(e) = run_request(req) {
                                        eprintln!("run_request error: {}", e);
                                    }
                                });
                            } else {
                                // unrecognized payload → log it
                                let now = Local::now().format("%Y-%m-%d %H:%M:%S");
                                let mut lf = OpenOptions::new().append(true).open(OUT_LOG).unwrap();
                                writeln!(lf, "{} Unrecognized request: {}", now, msg).ok();
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

pub fn stop_daemon() {
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
        return;
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
}

pub fn status() {
    // Check PID file existence
    if Path::new(PID_FILE).exists() {
        // Attempt socket status query
        if let Ok(mut stream) = UnixStream::connect(SOCKET_PATH) {
            // Send status message
            let _ = stream.write_all(b"status");
            let mut resp = String::new();
            if stream.read_to_string(&mut resp).is_ok() && resp == "running" {
                let pid = fs::read_to_string(PID_FILE).unwrap_or_default();
                println!("Running (PID {})", pid.trim());
                return;
            }
        }
    }
    println!("Not running");
}
#[derive(Deserialize)]
struct RunRequest {
    cmd: Vec<String>,
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

/// handle one client connectoin
/// - read request
/// - log it
/// - spawn child with piped stdout/stderr
/// - stream stdout/stderr in chunks
/// - send exitcode then close
fn handle_client(mut stream: UnixStream) -> Result<()> {
    let req: request = read_frame(&mut stream)?;
    info!("incoming command: {:?}", req);
    let mut child = Command::new(&req.cmd[0])
        .args(&req.cmd[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // stdout thread
    if let Some(mut out) = child.stdout.take() {
        let mut w = stream.try_clone()?;
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = out.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = write_frame(
                    &mut w,
                    &ResponseFrame {
                        channel: Stream::Stdout,
                        data: Some(buf[..n].to_vec()),
                    },
                );
            }
        });
    }

    // stderr thread
    if let Some(mut err) = child.stderr.take() {
        let mut w = stream.try_clone()?;
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = write_frame(
                    &mut w,
                    &ResponseFrame {
                        channel: Stream::Stderr,
                        data: Some(buf[..n].to_vec()),
                    },
                );
            }
        });
    }

    // wait and send exit code
    let status = child.wait()?;
    let code = status.code().unwrap_or(-1);
    write_frame(
        &mut stream,
        &ResponseFrame {
            channel: Stream::ExitCode(code),
            data: None,
        },
    )?;

    Ok(())
}
