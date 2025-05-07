use anyhow::{Context, Result};
use blake3::{Hash, Hasher};
use serde::de::{self, Deserializer, Error as DeError};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
/// Represents one logged event with a link to the previous root
#[derive(Serialize, Deserialize)]
pub struct CapsuleEvent {
    #[serde(serialize_with = "as_hex", deserialize_with = "from_hex")]
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

fn as_hex<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hash.to_hex().to_string())
}

fn from_hex<'de, D>(deserializer: D) -> Result<Hash, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Hash::from_hex(&s).map_err(D::Error::custom)
}

/// Appends an event to the log with hash
pub fn append_event(event: &CapsuleEvent, log_path: &std::path::Path) -> Result<()> {
    let hash = event.compute_hash();
    let json = serde_json::to_string(event)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    writeln!(file, "{}|{}", json, hash.to_hex())?;
    Ok(())
}

/// Extracts the last hash in the log, or returns 0 hash if empty
pub fn last_hash(log_path: &std::path::Path) -> Result<Hash> {
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);
    let mut last = Hash::from([0u8; 32]);
    for line in reader.lines() {
        let line = line?;
        let (_event_json, hash_hex) = line
            .split_once('|')
            .context("Malformed log entry: missing '|'")?;
        last = Hash::from_hex(hash_hex)?;
    }
    Ok(last)
}
