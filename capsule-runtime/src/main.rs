mod aggregator;
mod cli;
mod constants;
mod enricher;
mod io;
mod model;
mod parser;
mod risk;
mod tail;
mod trace;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Cmd};
use std::fs;
use std::thread;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
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

    // Create cancellation token for structured concurrency
    let cancellation_token = CancellationToken::new();

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

    // Create JoinSet for structured concurrency
    let mut task_set = JoinSet::new();

    // Spawn downstream tasks with cancellation support
    task_set.spawn(run_parser_with_cancellation(
        rx_raw_parser,
        tx_evt.clone(),
        ready_tx.clone(),
        cancellation_token.clone(),
    ));
    
    task_set.spawn(run_enricher_with_cancellation(
        rx_evt_enricher,
        tx_enriched.clone(),
        ready_tx.clone(),
        cancellation_token.clone(),
    ));
    
    task_set.spawn(run_aggregator_with_cancellation(
        rx_enriched_aggr,
        tx_act.clone(),
        ready_tx.clone(),
        cancellation_token.clone(),
    ));
    
    task_set.spawn(run_logger_with_cancellation(
        rx_raw_logger,
        rx_evt_logger,
        rx_enriched_logger,
        rx_act_logger,
        ready_tx,
        run_dir.clone(),
        cancellation_token.clone(),
    ));

    // Wait for all downstream tasks to signal they're ready
    for _ in 0..4 {
        ready_rx
            .recv()
            .await
            .expect("Ready signal from downstream task");
    }

    // Setup Ctrl+C handler
    let cancellation_token_ctrlc = cancellation_token.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            println!("\nReceived Ctrl+C, initiating graceful shutdown...");
            cancellation_token_ctrlc.cancel();
        }
    });

    // Now start the tracer - this drives the entire pipeline
    let tracer_result = trace::run_with_cancellation(cmdline, tx_raw.clone(), cancellation_token.clone()).await;

    // When tracer completes (program exit or error), initiate graceful shutdown
    if !cancellation_token.is_cancelled() {
        println!("Tracer completed, initiating graceful shutdown...");
        cancellation_token.cancel();
    }

    // Wait for all tasks to complete gracefully with timeout
    let shutdown_result = tokio::time::timeout(
        Duration::from_secs(5),
        shutdown_tasks_gracefully(&mut task_set)
    ).await;

    match shutdown_result {
        Ok(_) => println!("All tasks shut down gracefully"),
        Err(_) => {
            println!("Shutdown timeout reached, aborting remaining tasks");
            task_set.abort_all();
        }
    }

    // Return the tracer result (main program exit status)
    tracer_result
}

/// Gracefully shutdown all tasks with proper cleanup ordering
async fn shutdown_tasks_gracefully(task_set: &mut JoinSet<Result<()>>) -> Result<()> {
    // Wait for all tasks to complete (they should handle cancellation gracefully)
    while let Some(result) = task_set.join_next().await {
        match result {
            Ok(Ok(())) => {}, // Task completed successfully
            Ok(Err(e)) => eprintln!("Task error during shutdown: {}", e),
            Err(e) => eprintln!("Task panic during shutdown: {}", e),
        }
    }
    Ok(())
}

/// Parser task with cancellation support
async fn run_parser_with_cancellation(
    rx_raw: broadcast::Receiver<String>,
    tx_evt: broadcast::Sender<model::SyscallEvent>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    parser::run_with_ready_and_cancellation(
        rx_raw,
        tx_evt,
        ready_tx,
        cancellation_token,
    ).await
}

/// Enricher task with cancellation support
async fn run_enricher_with_cancellation(
    rx_evt: broadcast::Receiver<model::SyscallEvent>,
    tx_enriched: broadcast::Sender<model::SyscallEvent>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    enricher::run_with_ready_and_cancellation(
        enricher::Enricher::new(),
        rx_evt,
        tx_enriched,
        ready_tx,
        cancellation_token,
    ).await
}

/// Aggregator task with cancellation support
async fn run_aggregator_with_cancellation(
    rx_enriched: broadcast::Receiver<model::SyscallEvent>,
    tx_act: broadcast::Sender<model::Action>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    aggregator::run_with_ready_and_cancellation(
        rx_enriched,
        tx_act,
        ready_tx,
        cancellation_token,
    ).await
}

/// Logger task with cancellation support
async fn run_logger_with_cancellation(
    rx_raw: broadcast::Receiver<String>,
    rx_evt: broadcast::Receiver<model::SyscallEvent>,
    rx_enriched: broadcast::Receiver<model::SyscallEvent>,
    rx_act: broadcast::Receiver<model::Action>,
    ready_tx: mpsc::Sender<()>,
    run_dir: std::path::PathBuf,
    cancellation_token: CancellationToken,
) -> Result<()> {
    tokio::select! {
        result = io::logger_with_ready(
            rx_raw,
            rx_evt, 
            rx_enriched,
            rx_act,
            ready_tx,
            run_dir
        ) => result,
        _ = cancellation_token.cancelled() => {
            println!("Logger shutting down gracefully...");
            // Note: LogWriter tasks should flush their buffers here
            Ok(())
        }
    }
}
