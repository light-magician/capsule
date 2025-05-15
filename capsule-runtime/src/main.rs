use chrono::Local;
use clap::{Parser, Subcommand};
use daemonize::Daemonize;
use nix::sys::signal::{kill, SIGTERM};
use nix::unistd::Pid;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    process,
};

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
    /// Stop the running daemon
    Shutdown,
    // verify daemon is running
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

    // read PID file
    let pid_str = fs::read_to_string("/tmp/capsule.pid").unwrap_or_else(|e| {
        eprintln!("Could not read PID file: {}", e);
        process::exit(1)
    });
    let pid = pid_str.trim().parse::<i32>().unwrap_or_else(|e| {
        eprintln!("Invalid PID: {}", e);
        process::exit(1)
    });

    // send SIGTERM
    kill(Pid::from_raw(pid), SIGTERM).unwrap_or_else(|e| {
        eprintln!("Failed to send SIGTERM: {}", e);
        process::exit(1)
    });

    // remove PID file
    fs::remove_file("/tmp/capsule.pid").unwrap_or_else(|e| {
        eprintln!("Failed to remove PID file: {}", e);
    });

    // log shutdown timestamp
    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let mut log_file = OpenOptions::new()
        .append(true)
        .open("/tmp/capsule.out")
        .unwrap_or_else(|e| {
            eprintln!("Failed to open log file: {}", e);
            process::exit(1)
        });
    writeln!(log_file, "{} Daemon stopped", now).unwrap_or_else(|e| {
        eprintln!("Failed to write shutdown log: {}", e);
    });

    println!("Sent SIGTERM to {}", pid);
}

fn status() {
    match fs::read_to_string("/tmp/capsule.pid") {
        Ok(s) if kill(Pid::from_raw(s.trim().parse().unwrap()), None).is_ok() => {
            println!("Running (PID {})", s.trim())
        }
        _ => println!("Not running"),
    }
}
