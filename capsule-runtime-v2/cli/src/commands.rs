

use anyhow::Result;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// run program with process tracing
pub async fn run_transient(program: String, args: Vec<String>) -> Result<()> {
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
