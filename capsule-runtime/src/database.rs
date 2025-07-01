//! Database operations for sending run data to Supabase.

use crate::runs::*;
use anyhow::Result;

/// Database configuration
pub struct DatabaseConfig {
    pub connection_string: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            // Default to container database
            connection_string: "postgresql://postgres:postgres@localhost:54322/postgres".to_string(),
        }
    }
}

/// Send a run's data to the database
pub async fn send_run_to_database(run_id: Option<String>, _config: DatabaseConfig) -> Result<()> {
    // Determine which run to send
    let uuid = match run_id {
        Some(id) => id,
        None => get_last_run()?.ok_or_else(|| anyhow::anyhow!("No runs found"))?,
    };

    println!("📤 Sending run {} to database...", uuid);
    
    // Get run metadata  
    let run_info = get_run_info(&uuid)?;
    println!("  📁 Log directory: {:?}", run_info.log_directory);
    println!("  🕐 Created: {:?}", run_info.created_at);
    
    // TODO: Implement actual database insertion
    println!("  ⚠️  Database insertion not yet implemented");
    println!("✅ Command structure working! Ready for database implementation.");
    
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