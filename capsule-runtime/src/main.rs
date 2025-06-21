mod aggregator;
mod cli;
mod constants;
mod enricher;
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
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run { program, args } => run_transient(program, args).await,
        Cmd::Tail { stream, run } => tail::tail(&stream, run),
    }
}

async fn run_transient(program: String, args: Vec<String>) -> Result<()> {
    // ~/.capsule/run/<uuid>
    let uid = Uuid::new_v4().to_string();
    let run_dir = constants::RUN_ROOT.join(&uid);
    fs::create_dir_all(&run_dir)?;

    let mut cmdline = vec![program];
    cmdline.extend(args);

    // Create broadcast channels for inter-task communication
    let (tx_raw, _) = broadcast::channel::<String>(4096);
    let (tx_evt, _) = broadcast::channel::<model::SyscallEvent>(2048);
    let (tx_enriched, _) = broadcast::channel::<model::SyscallEvent>(2048);
    let (tx_act, _) = broadcast::channel::<model::Action>(1024);

    // Create ALL receivers BEFORE spawning any tasks to ensure no messages are lost
    let rx_raw_parser = tx_raw.subscribe();
    let rx_raw_logger = tx_raw.subscribe();
    let rx_evt_enricher = tx_evt.subscribe();
    let rx_evt_logger = tx_evt.subscribe();
    let rx_enriched_aggr = tx_enriched.subscribe();
    let rx_enriched_logger = tx_enriched.subscribe();
    let rx_act_logger = tx_act.subscribe();

    // Create synchronization channels to ensure tasks are ready (now 4 tasks)
    let (ready_tx, mut ready_rx) = tokio::sync::mpsc::channel::<()>(4);

    // Spawn downstream tasks with pre-created receivers
    let t_parser = tokio::spawn(parser::run_with_ready(
        rx_raw_parser,
        tx_evt.clone(),
        ready_tx.clone(),
    ));
    let t_enricher = tokio::spawn(enricher::run_with_ready(
        enricher::Enricher::new(),
        rx_evt_enricher,
        tx_enriched.clone(),
        ready_tx.clone(),
    ));
    let t_aggr = tokio::spawn(aggregator::run_with_ready(
        rx_enriched_aggr,
        tx_act.clone(),
        ready_tx.clone(),
    ));
    let t_log = tokio::spawn(io::logger_with_ready(
        rx_raw_logger,
        rx_evt_logger,
        rx_enriched_logger,
        rx_act_logger,
        ready_tx,
        run_dir.clone(),
    ));

    // Wait for all downstream tasks to signal they're ready
    for _ in 0..4 {
        ready_rx
            .recv()
            .await
            .expect("Ready signal from downstream task");
    }

    // Now start the tracer - guaranteed that all processors are ready
    let t_tracer = tokio::spawn(trace::run(cmdline, tx_raw.clone()));

    // Wait for all tasks to complete (program exit drives everything)
    let _ = tokio::join!(t_tracer, t_parser, t_enricher, t_aggr, t_log);
    Ok(())
}
