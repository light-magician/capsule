# Capsule Send Implementation Guide

## Overview

This document provides step-by-step instructions for implementing the actual database insertion logic for the `capsule send` command.

## Current State

✅ **Completed:**
- Command structure (`capsule send [run_id]`)
- Database schema (runs, syscall_events, actions tables)
- Run discovery (`capsule last`, `capsule list`)
- JSONL file parsing logic
- Database connection configuration

⚠️ **TODO:** Actual database insertion in `src/database.rs`

## Implementation Steps

### 1. Add Database Dependencies

Add to `Cargo.toml`:
```toml
tokio-postgres = "0.7"
postgres-types = { version = "0.2", features = ["derive", "with-chrono-0_4", "with-uuid-1", "with-serde_json-1"] }
```

### 2. Update Database Module

Replace the stub in `src/database.rs` with actual implementation:

```rust
use tokio_postgres::{Client, NoTls, types::ToSql};
use serde_json;
use std::fs;

pub async fn send_run_to_database(run_id: Option<String>, config: DatabaseConfig) -> Result<()> {
    // 1. Determine run UUID
    let uuid = match run_id {
        Some(id) => id,
        None => get_last_run()?.ok_or_else(|| anyhow::anyhow!("No runs found"))?,
    };

    println!("📤 Sending run {} to database...", uuid);

    // 2. Connect to database
    let (client, connection) = tokio_postgres::connect(&config.connection_string, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Database connection error: {}", e);
        }
    });

    // 3. Get run metadata and insert
    let run_info = get_run_info(&uuid)?;
    insert_run_metadata(&client, &uuid, &run_info).await?;
    
    // 4. Insert log data
    if let Some(log_dir) = &run_info.log_directory {
        insert_log_data(&client, &uuid, log_dir).await?;
        update_run_statistics(&client, &uuid).await?;
    }

    println!("✅ Successfully sent run {} to database", uuid);
    Ok(())
}
```

### 3. Implement Core Insert Functions

#### 3.1 Insert Run Metadata
```rust
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
        &"/unknown", // working_directory
        &run_info.created_at.unwrap_or_else(|| Utc::now()),
        &run_info.log_directory.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
        &"unknown", // agent_type - TODO: infer from command
    ]).await?;

    Ok(())
}
```

#### 3.2 Insert Events from JSONL
```rust
async fn insert_log_data(client: &Client, run_uuid: &str, log_dir: &PathBuf) -> Result<()> {
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

async fn insert_events_from_file(client: &Client, run_uuid: &Uuid, file_path: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let mut count = 0;

    for line in content.lines() {
        if line.trim().is_empty() || line.contains("\"start\":") || line.contains("\"session\":") {
            continue; // Skip headers
        }

        match serde_json::from_str::<SyscallEvent>(line) {
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
```

#### 3.3 Insert Single Event
```rust
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
```

#### 3.4 Insert Actions
```rust
async fn insert_actions_from_file(client: &Client, run_uuid: &Uuid, file_path: &PathBuf) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    let mut count = 0;

    for line in content.lines() {
        if line.trim().is_empty() || line.contains("\"start\":") || line.contains("\"session\":") {
            continue;
        }

        match serde_json::from_str::<Action>(line) {
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
```

#### 3.5 Update Statistics
```rust
async fn update_run_statistics(client: &Client, run_uuid: &str) -> Result<()> {
    let uuid = Uuid::parse_str(run_uuid)?;
    
    client.execute("SELECT update_run_stats($1)", &[&uuid]).await?;
    println!("  📈 Updated run statistics");
    Ok(())
}
```

### 4. Testing Steps

#### 4.1 Build and Test
```bash
# In Docker container
cd capsule-runtime
cargo build

# Create test run
capsule run echo "Hello Database Test"

# Check runs exist
capsule list

# Send to database
capsule send
```

#### 4.2 Verify in Supabase
```sql
-- Check run was inserted
SELECT * FROM recent_runs ORDER BY start_time DESC LIMIT 5;

-- Check events were inserted
SELECT COUNT(*) as event_count, syscall, COUNT(DISTINCT pid) as process_count
FROM syscall_events 
WHERE run_id = (SELECT id FROM runs ORDER BY start_time DESC LIMIT 1)
GROUP BY syscall 
ORDER BY event_count DESC;

-- Check for interesting events (non-polling)
SELECT syscall, operation, abs_path, risk_tags
FROM syscall_events 
WHERE run_id = (SELECT id FROM runs ORDER BY start_time DESC LIMIT 1)
AND syscall NOT IN ('epoll_wait', 'epoll_pwait', 'futex', 'select', 'poll')
ORDER BY timestamp_us;
```

### 5. Error Handling

Add proper error handling for:
- **Database connection failures**
- **Malformed JSONL lines** 
- **Missing log files**
- **UUID parsing errors**
- **Type conversion errors**

### 6. Performance Optimizations

For production use:
- **Batch inserts** (insert multiple events per query)
- **Connection pooling**
- **Async file reading**
- **Progress indicators** for large runs

### 7. Command Variations

Ensure these work:
```bash
capsule send                    # Send latest run
capsule send $(capsule last)    # Send specific run by ID  
capsule send abc123-def456...   # Send by full UUID
```

## Success Criteria

✅ Run metadata appears in `runs` table  
✅ Syscall events appear in `syscall_events` table  
✅ Actions appear in `actions` table  
✅ Statistics are updated correctly  
✅ AI queries work in Supabase Studio  
✅ No data corruption or missing fields  

## Next Phase

After basic insertion works:
1. **Add agent type detection** from command line
2. **Implement command extraction** from log metadata
3. **Add filtering options** (e.g., `--skip-polling`)
4. **Performance optimization** for large runs
5. **Retry logic** for failed insertions