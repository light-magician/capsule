use anyhow::{Context, Result};
use blake3::{Hash, Hasher};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Represents one logged event with a link to the previous root
#[derive(Serialize, Deserialize)]
pub struct CapsuleEvent {
    pub parent_root: Hash,
    pub payload: Value,
}

impl CapsuleEvent {
    /// Compute the Blake3 hash over parent_root and payload
    pub fn compute_hash(&self) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(self.parent_root.as_bytes());
        let payload_bytes = serde_json::to_vec(&self.payload).unwrap();
        hasher.update(&payload_bytes);
        hasher.finalize()
    }
}

/// Verifies a newline-delimited JSON log of `(event, hash)` pairs
pub fn verify(logfile: &std::path::Path) -> Result<()> {
    let file = File::open(logfile).context("Opening log file failed")?;
    let reader = BufReader::new(file);
    let mut line_num = 0usize;
    let mut last_root = Hash::from([0u8; 32]);

    for line in reader.lines() {
        let line = line.context("Reading log line failed")?;
        let (event_json, expected_hash_hex) = line
            .split_once('|')
            .context("Malformed log entry: missing '|' separator")?;

        let event: CapsuleEvent =
            serde_json::from_str(event_json).context("Deserializing CapsuleEvent failed")?;
        let expected_hash =
            Hash::from_hex(expected_hash_hex).context("Parsing expected hash failed")?;

        let computed = event.compute_hash();
        if computed != expected_hash {
            anyhow::bail!("Integrity check failed at line {}", line_num);
        }
        // Chain: ensure the parent matches our last root
        if event.parent_root != last_root {
            anyhow::bail!("Parent root mismatch at line {}", line_num);
        }

        // Advance
        last_root = computed;
        line_num += 1;
    }

    println!(
        "Log verified: {} entries, final root {}",
        line_num,
        hex::encode(last_root.as_bytes())
    );
    Ok(())
}
