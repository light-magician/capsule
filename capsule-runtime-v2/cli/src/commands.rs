
//! Command implementations for capsule CLI

use anyhow::Result;
use tracing::{info, error};
use crate::{ipc::SessionLockManager, monitor, pipeline::Pipeline, session::{SessionManager, SessionStatus}};
use state::AgentState;
use std::sync::{Arc, RwLock};

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

/// Run monitor TUI to show live processes
pub async fn run_monitor(_session: Option<String>) -> Result<()> {
    info!("Checking for active session...");
    
    // Check for active session
    let session_lock = match SessionLockManager::get_active_session().await {
        Ok(lock) => {
            info!("Found active session: {} (PID {})", lock.session_id, lock.pid);
            lock
        }
        Err(e) => {
            error!("No active session found: {}", e);
            println!("No active capsule session found.");
            println!("Start a session with: capsule run <command>");
            return Ok(());
        }
    };
    
    // Connect to the session's state
    info!("Connecting to session state socket...");
    match monitor::run_monitor_live(&session_lock.socket_path).await {
        Ok(()) => {
            info!("Monitor TUI exited normally");
        }
        Err(e) => {
            error!("Monitor failed: {}", e);
            println!("Failed to connect to session: {}", e);
            println!("The session may have ended or crashed.");
        }
    }
    
    Ok(())
}

/// Create demo state for testing the TUI
fn create_demo_state() -> Arc<RwLock<AgentState>> {
    let mut state = AgentState::new(Some("claude".to_string()));
    
    // Add some demo processes
    use core::events::{ProcessEvent, ProcessEventType};
    let now = chrono::Utc::now().timestamp_micros() as u64;
    
    // Simulate adding processes
    let demo_processes = vec![
        ProcessEvent::exec(
            now - 5_000_000, // 5 seconds ago
            1234,
            1000,
            vec!["claude".to_string(), "--version".to_string()],
            Some("/home/user".to_string()),
        ),
        ProcessEvent::exec(
            now - 3_000_000, // 3 seconds ago
            1235,
            1234,
            vec!["python3".to_string(), "script.py".to_string()],
            Some("/home/user/project".to_string()),
        ),
        ProcessEvent::exec(
            now - 1_000_000, // 1 second ago
            1236,
            1234,
            vec!["git".to_string(), "status".to_string()],
            Some("/home/user/project".to_string()),
        ),
    ];
    
    // Process events to populate state
    for event in demo_processes {
        match event.event_type {
            ProcessEventType::Exec => {
                let name = state::LiveProcess::generate_name(&event.command_line, state.capsule_target.as_deref());
                let process = state::LiveProcess {
                    pid: event.pid,
                    ppid: event.ppid,
                    name,
                    command_line: event.command_line,
                    start_time: event.timestamp,
                    end_time: None,
                };
                
                state.processes.insert(event.pid, process);
                state.active_pids.insert(event.pid);
            }
            _ => {
                // Handle other event types if needed
            }
        }
    }
    
    state.last_updated = now;
    Arc::new(RwLock::new(state))
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
