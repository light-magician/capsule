
//! Command implementations for capsule CLI

use anyhow::Result;
use tracing::{info, error};
use crate::{pipeline::Pipeline, session::{SessionManager, SessionStatus}};

/// Run program with full pipeline: trace → parse → track
pub async fn run_with_pipeline(program: String, args: Vec<String>) -> Result<()> {
    // Build command line
    let mut cmdline = vec![program];
    cmdline.extend(args);

    info!("Starting capsule session for command: {:?}", cmdline);

    // Create session directory and metadata
    let mut session_metadata = SessionManager::create_session(cmdline.clone()).await?;
    let session_dir = SessionManager::session_dir_string(&session_metadata);
    
    info!("Created session: {} at {}", session_metadata.session_id, session_dir);

    // Create and run the pipeline
    let mut pipeline = Pipeline::new();
    let result = pipeline.run(cmdline, session_dir).await;

    // Update session status based on result
    let final_status = match &result {
        Ok(()) => {
            info!("Session completed successfully: {}", session_metadata.session_id);
            SessionStatus::Completed
        },
        Err(e) => {
            error!("Session failed: {} - {}", session_metadata.session_id, e);
            SessionStatus::Failed(e.to_string())
        }
    };

    // Update session metadata
    SessionManager::update_session_status(&mut session_metadata, final_status).await?;

    result
}

/// Legacy run command for backwards compatibility (kept for reference)
#[allow(dead_code)]
pub async fn run_transient(program: String, args: Vec<String>) -> Result<()> {
    use tokio::sync::broadcast;
    use tokio_util::sync::CancellationToken;

    // build command line 
    let mut cmdline = vec![program];
    cmdline.extend(args);

    // create cancellation token for graceful shutdown
    let cancellation_token = CancellationToken::new();

    // create the broadcast channel for strace output
    let (tx_raw, mut rx_raw) = broadcast::channel::<String>(1024);
 
    // setup the Ctrl + C handler
    let cancellation_token_ctrlc = cancellation_token.clone();
    // setup closure to always listen for cancellation token 
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            tracing::info!("received Ctrl+C, shutting down...");
            cancellation_token_ctrlc.cancel();
        }
    });

    // start the tracer
    let tracer_task = tokio::spawn(async move {
        trace::LinuxTracer::run_with_cancellation(
            cmdline,
            tx_raw,
            cancellation_token,
        ).await
    });

    // simple output handler for now - just print the trace lines
    let output_task = tokio::spawn(async move {
        while let Ok(line) = rx_raw.recv().await {
            println!("TRACE: {}", line);
        }
    });

    // Wait for both tasks to complete
    let (tracer_result, _) = tokio::join!(tracer_task, output_task);

    match tracer_result {
          Ok(Ok(())) => {
              tracing::info!("Tracing completed successfully");
              Ok(())
          },
          Ok(Err(e)) => {
              tracing::error!("Tracer error: {}", e);
              Err(e)
          },
          Err(e) => {
              tracing::error!("Task join error: {}", e);
              Err(e.into())
          }
      }
}
