mod aggregator;
mod cli;
mod constants;
mod io;
mod model;
mod parser;
mod tail;
mod trace;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Cmd};
use std::fs;
use std::thread;
use std::time::Duration;
use tokio::sync::broadcast;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run { program, args } => run_transient(program, args).await,
        Cmd::Tail { stream, run } => tail::tail(&stream, run),
        Cmd::Stop { run } => stop_run(run),
    }
}

async fn run_transient(program: String, args: Vec<String>) -> Result<()> {
    // ~/.capsule/run/<uuid>
    let uid = Uuid::new_v4().to_string();
    let run_dir = constants::RUN_ROOT.join(&uid);
    fs::create_dir_all(&run_dir)?;

    println!("Capsule run {uid} launching…");

    let mut cmdline = vec![program];
    cmdline.extend(args);

    // Create broadcast channels for inter-task communication
    let (tx_raw, _) = broadcast::channel::<String>(4096);
    let (tx_evt, _) = broadcast::channel::<model::SyscallEvent>(2048);
    let (tx_act, _) = broadcast::channel::<model::Action>(1024);

    // Spawn concurrent tasks
    let t_tracer = tokio::spawn(trace::run(cmdline, tx_raw.clone()));
    let t_parser = tokio::spawn(parser::run(tx_raw.subscribe(), tx_evt.clone()));
    let t_aggr = tokio::spawn(aggregator::run(tx_evt.subscribe(), tx_act.clone()));
    let t_log = tokio::spawn(io::logger(
        tx_raw.subscribe(),
        tx_evt.subscribe(),
        tx_act.subscribe(),
    ));

    // Wait for all tasks to complete (program exit drives everything)
    let _ = tokio::join!(t_tracer, t_parser, t_aggr, t_log);
    Ok(())
}

fn stop_run(run_uuid: Option<String>) -> Result<()> {
    // pick explicit UUID or the newest run
    let run_dir = match run_uuid {
        Some(u) => constants::RUN_ROOT.join(u),
        None => tail::newest_run_dir()?,
    };
    let pid_path = run_dir.join(constants::PID_FILE);
    let pid: i32 = fs::read_to_string(&pid_path)?.trim().parse()?;

    use nix::{
        sys::signal::{kill, Signal},
        unistd::Pid,
    };
    kill(Pid::from_raw(pid), Signal::SIGTERM)?;

    // wait for graceful exit
    for _ in 0..100 {
        if !pid_path.exists() {
            println!("Capsule run stopped.");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    // escalate
    kill(Pid::from_raw(pid), Signal::SIGKILL)?;
    println!("Forced kill sent.");
    Ok(())
}
