use chrono::Local;
use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;
use std::io::prelude::*;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::{
    fs::{self, remove_file, File, OpenOptions},
    process,
};

//TODO: insert these
const PID_FILE: &str = "/tmp/capsule.pid";
const OUT_LOG: &str = "/tmp/capsule.out";
const ERR_LOG: &str = "/tmp/capsule.err";
const SOCKET_PATH: &str = "/tmp/capsule.sock";

#[derive(Parser)]
#[command(name = "capsule-daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as background daemon
    Daemon {
        #[arg(long)]
        daemon: bool,
    },
    /// Stop the running daemon (gracefully via socket, fallback to SIGTERM)
    Shutdown,
    /// Verify daemon is running
    Status,
}

/// installing on the path
/// cargo install --path . --force --bin capsule

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Daemon { daemon: _ } => start_daemon(),
        Command::Shutdown => stop_daemon(),
        Command::Status => status(),
    }
}

fn start_daemon() {
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
    let stdout = File::create("/tmp/capsule.out").unwrap_or_else(|e| {
        eprintln!("stdout log error: {}", e);
        process::exit(1)
    });
    let stderr = File::create("/tmp/capsule.err").unwrap_or_else(|e| {
        eprintln!("stderr log error: {}", e);
        process::exit(1)
    });

    let daemonize = Daemonize::new()
        .pid_file("/tmp/capsule.pid")
        .stdout(stdout)
        .stderr(stderr);

    match daemonize.start() {
        Ok(_) => {
            let now = Local::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} Daemon started on /tmp/capsule.sock", now);
        }
        Err(e) => {
            eprintln!("failed to daemonize: {}", e);
            process::exit(1);
        }
    }

    // Remove old socket if exists
    if Path::new(SOCKET_PATH).exists() {
        let _ = remove_file(SOCKET_PATH);
    }

    // Bind to Unix domain socket
    let listener = UnixListener::bind(SOCKET_PATH).unwrap_or_else(|e| {
        eprintln!("failed to bind socket: {}", e);
        process::exit(1);
    });

    // Set permissions so other processes can connect if needed (optional)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(SOCKET_PATH).unwrap().permissions();
        perms.set_mode(0o766);
        fs::set_permissions(SOCKET_PATH, perms).unwrap_or_default();
    }

    // Event loop: accept connections for status or shutdown
    for stream in listener.incoming() {
        match stream {
            Ok(mut sock) => {
                let mut buf = [0u8; 16];
                // Read command message
                if let Ok(n) = sock.read(&mut buf) {
                    let msg = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    if msg == "shutdown" {
                        // Client requested graceful shutdown
                        let now = Local::now().format("%Y-%m-%d %H:%M:%S");
                        let mut log_file = OpenOptions::new().append(true).open(OUT_LOG).unwrap();
                        writeln!(log_file, "{} Daemon stopping via socket", now).ok();
                        // Cleanup
                        let _ = remove_file(PID_FILE);
                        let _ = remove_file(SOCKET_PATH);
                        process::exit(0);
                    } else if msg == "status" {
                        // Respond to status
                        let _ = sock.write_all("running".as_bytes());
                    }
                }
            }
            Err(err) => {
                eprintln!("socket accept error: {}", err);
            }
        }
    }
}

fn stop_daemon() {
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
        process::exit(1)
    });
    let pid = pid_str.trim().parse::<i32>().unwrap_or_else(|e| {
        eprintln!("Invalid PID: {}", e);
        process::exit(1)
    });

    // Send SIGTERM
    kill(Pid::from_raw(pid), SIGTERM).unwrap_or_else(|e| {
        eprintln!("Failed to send SIGTERM: {}", e);
        process::exit(1)
    });
    println!("Sent SIGTERM to {}", pid);

    // Cleanup PID file
    remove_file(PID_FILE).ok();
    // Optionally remove socket if left behind
    remove_file(SOCKET_PATH).ok();
}

fn status() {
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
