// src/main.rs
mod cli;
mod daemon;
mod log;
mod policy;
mod profile;

use clap::Parser;
use cli::{Cli, Commands};
use policy::Policy;
use std::{io::Write, path::Path, process::exit};

fn main() {
    let cli = Cli::parse();

    match cli.cmd {
        // ─────────────────────────── daemon ────────────────────────────────
        Commands::Daemon {
            socket: _,
            log,
            policy,
        } => {
            let pol = Policy::from_arg(policy.as_deref());
            if let Err(e) = daemon::run(None, Path::new(&log), pol) {
                eprintln!("daemon error: {e}");
            }
        }

        // ─────────────────────────── verify ────────────────────────────────
        Commands::Verify { log } => {
            if let Err(e) = log::Logger::verify_chain(Path::new(&log)) {
                eprintln!("failed hash: {e}");
                std::io::stderr().flush().ok();
                exit(1);
            }
            println!("✔ log ok");
        }

        // ────────────────────── shortcut client (`capsule …`) ──────────────
        Commands::External(mut ext) => {
            use std::io::{BufRead, BufReader, Write};
            use std::os::unix::net::UnixStream;

            // build the request line
            let line = if ext.len() == 1 && ext[0] == "shutdown" {
                "shutdown\n".to_string()
            } else {
                let cmd = ext.remove(0);
                std::iter::once(cmd)
                    .chain(ext.into_iter())
                    .collect::<Vec<_>>()
                    .join(" ")
                    + "\n"
            };

            // send it to the daemon
            match UnixStream::connect("/tmp/capsule.sock") {
                Ok(mut sock) => {
                    let _ = sock.write_all(line.as_bytes());
                    let _ = sock.shutdown(std::net::Shutdown::Write);

                    let mut resp = String::new();
                    let _ = BufReader::new(sock).read_line(&mut resp);
                    if !resp.trim().is_empty() {
                        println!("{}", resp.trim_end());
                    }
                }
                Err(e) => eprintln!("could not reach daemon: {e}"),
            }
        }
    }
}
