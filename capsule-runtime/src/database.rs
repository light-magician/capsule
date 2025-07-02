//! Database operations for sending run data to Supabase.

use crate::runs::*;
use crate::model::*;
use anyhow::Result;
use tokio_postgres::{Client, NoTls};
use std::fs;
use chrono::Utc;
use uuid::Uuid;

/// Database configuration
pub struct DatabaseConfig {
    pub connection_string: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            // Default to container database
            connection_string: std::env::var("SUPABASE_DB_URL")
                .or_else(|_| std::env::var("DATABASE_URL"))
                .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:54322/postgres".to_string()),
        }
    }
}

/// Send a run's data to the database
pub async fn send_run_to_database(run_id: Option<String>, config: DatabaseConfig) -> Result<()> {
    // Determine which run to send
    let uuid = match run_id {
        Some(id) if id == "last" => get_last_run()?.ok_or_else(|| anyhow::anyhow!("No runs found"))?,
        Some(id) => id,
        None => get_last_run()?.ok_or_else(|| anyhow::anyhow!("No runs found"))?,
    };

    println!("📤 Sending run {} to database...", uuid);
    
    // Connect to database
    let (client, connection) = tokio_postgres::connect(&config.connection_string, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Database connection error: {}", e);
        }
    });
    
    // Get run metadata  
    let run_info = get_run_info(&uuid)?;
    println!("  📁 Log directory: {:?}", run_info.log_directory);
    println!("  🕐 Created: {:?}", run_info.created_at);
    
    // Insert run metadata
    insert_run_metadata(&client, &uuid, &run_info).await?;
    
    // Insert log data if available
    if let Some(log_dir) = &run_info.log_directory {
        insert_log_data(&client, &uuid, log_dir).await?;
        update_run_statistics(&client, &uuid).await?;
    }
    
    println!("✅ Successfully sent run {} to database", uuid);
    Ok(())
}

/// Get detailed run information
fn get_run_info(uuid: &str) -> Result<RunInfo> {
    let run_dir = crate::constants::RUN_ROOT.join(uuid);
    if !run_dir.exists() {
        return Err(anyhow::anyhow!("Run directory not found: {:?}", run_dir));
    }

    RunInfo::from_run_dir(uuid.to_string(), &run_dir)
}

/// Insert run metadata into database
async fn insert_run_metadata(client: &Client, uuid: &str, run_info: &RunInfo) -> Result<()> {
    let run_uuid = Uuid::parse_str(uuid)?;
    
    // Extract command from log directory or use placeholder
    let command_line = extract_command_from_logs(run_info)
        .unwrap_or_else(|| "capsule run <unknown>".to_string());
    
    let query = r#"
        INSERT INTO runs (id, command_line, working_directory, start_time, log_directory, agent_type)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (id) DO UPDATE SET
            command_line = EXCLUDED.command_line,
            start_time = EXCLUDED.start_time,
            log_directory = EXCLUDED.log_directory
    "#;

    client.execute(query, &[
        &run_uuid,
        &command_line,
        &"/unknown", // working_directory - TODO: extract from logs
        &run_info.created_at.unwrap_or_else(|| Utc::now()),
        &run_info.log_directory.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        &"unknown", // agent_type - TODO: implement detection
    ]).await?;
    
    println!("  📊 Inserted run metadata");
    Ok(())
}

/// Extract command from log files (stub for now)
fn extract_command_from_logs(_run_info: &RunInfo) -> Option<String> {
    // TODO: Parse first line of syscalls.log or events.jsonl to extract command
    None
}

/// Insert log data from JSONL files
async fn insert_log_data(client: &Client, run_uuid: &str, log_dir: &std::path::PathBuf) -> Result<()> {
    let uuid = Uuid::parse_str(run_uuid)?;
    
    // Insert enriched events (most complete data)
    let enriched_file = log_dir.join(crate::constants::ENRICHED_FILE);
    if enriched_file.exists() {
        insert_events_from_file(client, &uuid, &enriched_file).await?;
    }

    // Insert actions
    let actions_file = log_dir.join(crate::constants::ACTION_FILE);
    if actions_file.exists() {
        insert_actions_from_file(client, &uuid, &actions_file).await?;
    }

    Ok(())
}

/// Insert events from enriched JSONL file
async fn insert_events_from_file(client: &Client, run_uuid: &Uuid, file_path: &std::path::PathBuf) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let mut count = 0;

    for line in content.lines() {
        if line.trim().is_empty() || line.contains("\"start\":") || line.contains("\"session\":") {
            continue; // Skip headers
        }

        // Extract JSON part after Blake3 hash (format: "hash {json}")
        let json_part = if let Some(space_pos) = line.find(' ') {
            &line[space_pos + 1..]
        } else {
            line // Fallback to full line if no space found
        };

        match serde_json::from_str::<SyscallEvent>(json_part) {
            Ok(event) => {
                insert_single_event(client, run_uuid, &event).await?;
                count += 1;
            }
            Err(_) => continue, // Skip malformed lines
        }
    }

    println!("  📊 Inserted {} events from {:?}", count, file_path.file_name().unwrap_or_default());
    Ok(())
}

/// Insert single syscall event
async fn insert_single_event(client: &Client, run_uuid: &Uuid, event: &SyscallEvent) -> Result<()> {
    let query = r#"
        INSERT INTO syscall_events (
            run_id, timestamp_us, pid, syscall, args, return_value, raw_line,
            tid, ppid, exe_path, cwd, argv, uid, gid, euid, egid, capabilities,
            fd, abs_path, fd_map, resource_type, operation,
            permission_bits, byte_count, latency_us, network_info, risk_tags, high_level_kind
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
            $18, $19, $20, $21, $22,
            $23, $24, $25, $26, $27, $28
        )
    "#;

    // Convert Rust types to PostgreSQL types
    let args_array: Vec<i64> = event.args.iter().map(|&x| x as i64).collect();
    let network_json = event.net.as_ref().map(|net| serde_json::to_value(net).unwrap());
    let fd_map_json = if event.fd_map.is_empty() { None } else { Some(serde_json::to_value(&event.fd_map).unwrap()) };

    client.execute(query, &[
        &run_uuid,                                                             // $1
        &(event.ts as i64),                                                   // $2
        &(event.pid as i32),                                                  // $3
        &event.call,                                                          // $4
        &args_array,                                                          // $5
        &event.retval,                                                        // $6
        &event.raw_line,                                                      // $7
        &event.tid.map(|x| x as i32),                                        // $8
        &event.ppid.map(|x| x as i32),                                       // $9
        &event.exe_path,                                                      // $10
        &event.cwd,                                                           // $11
        &event.argv,                                                          // $12
        &event.uid.map(|x| x as i32),                                        // $13
        &event.gid.map(|x| x as i32),                                        // $14
        &event.euid.map(|x| x as i32),                                       // $15
        &event.egid.map(|x| x as i32),                                       // $16
        &event.caps.map(|x| x as i64),                                       // $17
        &event.fd,                                                            // $18
        &event.abs_path,                                                      // $19
        &fd_map_json,                                                         // $20
        &event.resource_type.as_ref().map(|rt| format!("{:?}", rt)),        // $21
        &event.operation.as_ref().map(|op| format!("{:?}", op)),            // $22
        &event.perm_bits.map(|x| x as i32),                                  // $23
        &event.byte_count.map(|x| x as i64),                                 // $24
        &event.latency_us.map(|x| x as i64),                                 // $25
        &network_json,                                                        // $26
        &event.risk_tags,                                                     // $27
        &event.high_level_kind,                                              // $28
    ]).await?;

    Ok(())
}

/// Insert actions from JSONL file
async fn insert_actions_from_file(client: &Client, run_uuid: &Uuid, file_path: &std::path::PathBuf) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let mut count = 0;

    for line in content.lines() {
        if line.trim().is_empty() || line.contains("\"start\":") || line.contains("\"session\":") {
            continue;
        }

        // Extract JSON part after Blake3 hash (format: "hash {json}")
        let json_part = if let Some(space_pos) = line.find(' ') {
            &line[space_pos + 1..]
        } else {
            line // Fallback to full line if no space found
        };

        match serde_json::from_str::<Action>(json_part) {
            Ok(action) => {
                insert_single_action(client, run_uuid, &action).await?;
                count += 1;
            }
            Err(_) => continue,
        }
    }

    println!("  📊 Inserted {} actions from {:?}", count, file_path.file_name().unwrap_or_default());
    Ok(())
}

/// Insert single action
async fn insert_single_action(client: &Client, run_uuid: &Uuid, action: &Action) -> Result<()> {
    let pids_array: Vec<i32> = action.pids.iter().map(|&x| x as i32).collect();
    let (action_type, action_data) = action_kind_to_json(&action.kind)?;

    let query = r#"
        INSERT INTO actions (run_id, first_timestamp_us, last_timestamp_us, pids, action_type, action_data)
        VALUES ($1, $2, $3, $4, $5, $6)
    "#;

    client.execute(query, &[
        &run_uuid,
        &(action.first_ts as i64),
        &(action.last_ts as i64),
        &pids_array,
        &action_type,
        &action_data,
    ]).await?;

    Ok(())
}

/// Convert ActionKind to (type_string, data_json)
fn action_kind_to_json(kind: &ActionKind) -> Result<(String, serde_json::Value)> {
    match kind {
        ActionKind::FileRead { path, bytes } => Ok(("FileRead".to_string(), serde_json::json!({"path": path, "bytes": bytes}))),
        ActionKind::FileWrite { path, bytes } => Ok(("FileWrite".to_string(), serde_json::json!({"path": path, "bytes": bytes}))),
        ActionKind::DirectoryList { path, entries } => Ok(("DirectoryList".to_string(), serde_json::json!({"path": path, "entries": entries}))),
        ActionKind::SocketConnect { addr, protocol } => Ok(("SocketConnect".to_string(), serde_json::json!({"addr": addr.to_string(), "protocol": protocol}))),
        ActionKind::SocketBind { addr, protocol } => Ok(("SocketBind".to_string(), serde_json::json!({"addr": addr.to_string(), "protocol": protocol}))),
        ActionKind::SocketAccept { local_addr, remote_addr } => Ok(("SocketAccept".to_string(), serde_json::json!({"local_addr": local_addr.to_string(), "remote_addr": remote_addr.to_string()}))),
        ActionKind::ProcessSpawn { pid, argv, parent_pid } => Ok(("ProcessSpawn".to_string(), serde_json::json!({"pid": pid, "argv": argv, "parent_pid": parent_pid}))),
        ActionKind::ProcessExec { argv } => Ok(("ProcessExec".to_string(), serde_json::json!({"argv": argv}))),
        ActionKind::ProcessExit { pid, exit_code } => Ok(("ProcessExit".to_string(), serde_json::json!({"pid": pid, "exit_code": exit_code}))),
        ActionKind::SignalSend { target_pid, signal } => Ok(("SignalSend".to_string(), serde_json::json!({"target_pid": target_pid, "signal": signal}))),
        ActionKind::SignalReceive { signal } => Ok(("SignalReceive".to_string(), serde_json::json!({"signal": signal}))),
        ActionKind::MemoryMap { addr, size, prot } => Ok(("MemoryMap".to_string(), serde_json::json!({"addr": addr, "size": size, "prot": prot}))),
        ActionKind::MemoryUnmap { addr, size } => Ok(("MemoryUnmap".to_string(), serde_json::json!({"addr": addr, "size": size}))),
        ActionKind::FileOpen { path, flags } => Ok(("FileOpen".to_string(), serde_json::json!({"path": path, "flags": flags}))),
        ActionKind::FileClose { path } => Ok(("FileClose".to_string(), serde_json::json!({"path": path}))),
        ActionKind::FileStat { path } => Ok(("FileStat".to_string(), serde_json::json!({"path": path}))),
        ActionKind::FileChmod { path, mode } => Ok(("FileChmod".to_string(), serde_json::json!({"path": path, "mode": mode}))),
        ActionKind::FileChown { path, uid, gid } => Ok(("FileChown".to_string(), serde_json::json!({"path": path, "uid": uid, "gid": gid}))),
        ActionKind::Other { syscall, describe } => Ok(("Other".to_string(), serde_json::json!({"syscall": syscall, "describe": describe}))),
    }
}

/// Update run statistics
async fn update_run_statistics(client: &Client, run_uuid: &str) -> Result<()> {
    let uuid = Uuid::parse_str(run_uuid)?;
    
    client.execute("SELECT update_run_stats($1)", &[&uuid]).await?;
    println!("  📈 Updated run statistics");
    Ok(())
}