//! Modular strace parser with focused sub-components

mod classification;
mod forensic;
mod network;
mod semantic;
mod strace;

use crate::model::SyscallEvent;
use crate::pipeline::{AsyncPipeline, RunOptions, signal_ready};
use crate::risk;
use anyhow::Result;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

/// Parse counter for monitoring (replaces unsafe static)
static PARSE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Parser component that implements the AsyncPipeline trait
pub struct Parser;

impl AsyncPipeline for Parser {
    type Input = Receiver<String>;
    type Output = Sender<SyscallEvent>;
    
    async fn run(self, input: Self::Input, output: Self::Output) -> Result<()> {
        run_with_cancellation(input, output, CancellationToken::new()).await
    }
    
    async fn run_with_options(
        self,
        input: Self::Input,
        output: Self::Output,
        options: RunOptions,
    ) -> Result<()> {
        signal_ready(&options.ready_tx).await;
        
        let cancellation_token = options.cancellation_token.unwrap_or_else(CancellationToken::new);
        run_with_cancellation(input, output, cancellation_token).await
    }
}

/// Public entry: consumes raw strace lines, emits typed events.
pub async fn run(mut rx: Receiver<String>, tx_evt: Sender<SyscallEvent>) -> Result<()> {
    run_with_cancellation(rx, tx_evt, CancellationToken::new()).await
}

/// Parser with cancellation support
pub async fn run_with_cancellation(
    mut rx: Receiver<String>,
    tx_evt: Sender<SyscallEvent>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    let mut line_count = 0;
    let mut event_count = 0;
    let mut parse_error_count = 0;

    // Create parse error log file
    let error_log = create_parse_error_log().await?;

    loop {
        tokio::select! {
            recv_result = rx.recv() => {
                match recv_result {
                    Ok(line) => {
                        line_count += 1;

                        match parse_line(&line) {
                            Some(evt) => {
                                event_count += 1;
                                if let Err(_) = tx_evt.send(evt) {
                                    // Failed to send event
                                }
                            },
                            None => {
                                // Log parse failures for analysis
                                if !line.trim().is_empty() &&
                                   !line.contains("strace:") &&
                                   !line.trim_start().starts_with('{') {
                                    parse_error_count += 1;
                                    log_parse_error(&error_log, line_count, &line).await;
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                }
            },
            _ = cancellation_token.cancelled() => break
        }
    }
    Ok(())
}

/// Main parsing function - now much cleaner and focused
fn parse_line(line: &str) -> Option<SyscallEvent> {
    let line = line.trim();
    if line.is_empty() || line.starts_with("strace:") {
        return None;
    }

    // Clean concatenated strace messages
    let clean_line = if let Some(strace_pos) = line.find("strace:") {
        line[..strace_pos].trim_end()
    } else {
        line
    };

    // Skip lines without syscall completion marker
    if !clean_line.contains(" = ") {
        return None;
    }

    // Increment parse counter (replaces unsafe block)
    PARSE_COUNTER.fetch_add(1, Ordering::Relaxed);

    // Extract strace data using focused parser
    let strace_data = strace::parse_strace_line(clean_line)?;

    // Parse semantic arguments
    let semantic_data =
        semantic::parse_syscall_semantics(&strace_data.syscall_name, clean_line, &strace_data.args);

    // Enhanced classification with human descriptions
    let classification = classification::classify_syscall_enhanced(
        &strace_data.syscall_name,
        semantic_data.fd.as_ref(),
        semantic_data.abs_path.as_ref(),
        strace_data.retval,
    );
    
    // Legacy classification for backward compatibility
    let (operation, resource_type) = (Some(classification.legacy_operation.clone()), classification.resource_type.clone());

    // Parse network information for socket syscalls
    let net_info =
        network::parse_network_info(&strace_data.syscall_name, clean_line, &resource_type);
        
    // Parse forensic context for detailed behavioral analysis
    let forensic_context = forensic::parse_forensic_context(
        &strace_data.syscall_name,
        clean_line,
        &strace_data.args,
        strace_data.retval,
    );

    // Analyze security risks and categorize behavior
    let risk_tags = risk::analyze_risk_tags(
        &strace_data.syscall_name,
        semantic_data.abs_path.as_ref(),
        &operation,
        &resource_type,
        &strace_data.args,
        strace_data.retval,
    );
    let high_level_kind =
        risk::categorize_high_level_kind(&strace_data.syscall_name, &operation, &resource_type);

    Some(SyscallEvent {
        ts: (strace_data.timestamp * 1_000_000.0) as u64,
        pid: strace_data.pid,
        call: strace_data.syscall_name,
        args: strace_data.args,
        retval: strace_data.retval,
        raw_line: line.to_string(),

        // Semantic data
        tid: strace_data.tid,
        ppid: None,
        exe_path: None,
        cwd: None,
        argv: None,
        uid: None,
        gid: None,
        euid: None,
        egid: None,
        caps: None,
        fd: semantic_data.fd,
        abs_path: semantic_data.abs_path,
        fd_map: std::collections::HashMap::new(),
        resource_type,
        operation,
        perm_bits: semantic_data.perm_bits,
        byte_count: semantic_data.byte_count,
        latency_us: None,
        net: net_info,
        risk_tags,
        high_level_kind,
        
        // Enhanced classification
        syscall_category: Some(classification.category),
        syscall_operation: Some(classification.operation),
        human_description: Some(classification.human_description),
        
        // Forensic tracking fields (populated from parser-level analysis)
        process_forensics: forensic_context.process_context,
        file_forensics: forensic_context.file_context,
        network_forensics: forensic_context.network_context,
        memory_forensics: forensic_context.memory_context,
        security_forensics: forensic_context.security_context,
        signal_forensics: forensic_context.signal_context,
        environment_forensics: forensic_context.environment_context,
        permission_analysis: forensic_context.permission_analysis,
        forensic_summary: None, // Will be generated by enricher with complete context

    })
}

pub async fn run_with_ready(
    mut rx: Receiver<String>,
    tx_evt: Sender<SyscallEvent>,
    ready_tx: mpsc::Sender<()>,
) -> Result<()> {
    ready_tx.send(()).await.ok();
    run(rx, tx_evt).await
}

pub async fn run_with_ready_and_cancellation(
    rx: Receiver<String>,
    tx_evt: Sender<SyscallEvent>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    ready_tx.send(()).await.ok();
    run_with_cancellation(rx, tx_evt, cancellation_token).await
}

/// Create parse error log file
async fn create_parse_error_log() -> Result<Arc<Mutex<tokio::fs::File>>> {
    use crate::constants::LOG_ROOT;

    tokio::fs::create_dir_all(&*LOG_ROOT).await?;

    let timestamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let error_file_path = LOG_ROOT.join(format!("parse_errors_{}.log", timestamp));

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&error_file_path)
        .await?;

    Ok(Arc::new(Mutex::new(file)))
}

/// Log a parse error to the error log file
async fn log_parse_error(error_log: &Arc<Mutex<tokio::fs::File>>, line_num: u32, line: &str) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let truncated_line = if line.len() > 500 {
        format!("{}... (truncated from {} chars)", &line[..500], line.len())
    } else {
        line.to_string()
    };

    let error_entry = format!("{} [Line {}] {}\n", timestamp, line_num, truncated_line);

    let mut file = error_log.lock().await;
    let _ = file.write_all(error_entry.as_bytes()).await;
    let _ = file.flush().await;
}
