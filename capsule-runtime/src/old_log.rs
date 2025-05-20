//! src/log.rs
//! Tamper-evident, append-only Merkle log for capsule-runtime.
use blake3;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::Path,
};
/// `Logger` provides a tamper-evident, append-only audit log of all capsule invocations (and,
/// optionally, individual syscalls). Each record is a JSON line containing:
///
/// - `prev_hash`: Blake3 hash chaining to the previous entry  
/// - `timestamp`: RFC-3339 timestamp of the event  
/// - `pid`: process ID of the caller  
/// - `event`: one of  
///     - `InvocationStart { cmd: Vec<String> }`  
///     - `Syscall { number, name, args, ret }`  
///     - `InvocationEnd { status }`  
///
/// On each `.log(...)` call, the payload is serialized, hashed together with the prior root, and
/// appended (with flush) to ensure on-disk integrity. This Merkle-chain approach makes any
/// modification, deletion, or insertion of log lines detectable via recomputing the chain.
///
/// **What it adds to the project:**  
/// - A cryptographically strong, forward-only audit trail of every allowed agent action  
/// - The foundation for a `capsule verify` command to attest that no post-hoc tampering occurred  
/// - Transparency and compliance guarantees for teams embedding AI-driven workflows
///
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    InvocationStart {
        cmd: Vec<String>,
    },
    Syscall {
        number: i64,
        name: String,
        args: Vec<String>,
        ret: i64,
    },
    InvocationEnd {
        status: i32,
    },
}

#[derive(Serialize, Deserialize)]
struct Entry {
    prev_hash: String,
    timestamp: String,
    pid: u32,
    event: Event,
}

pub struct Logger {
    file: File,
    current_hash: Vec<u8>,
}

impl Logger {
    /// Open (or create) `capsule.log`, read its last hash (or use all-zeros), return Logger.
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;
        let last = Self::read_last_hash(path)?;
        Ok(Logger {
            file,
            current_hash: last,
        })
    }

    fn read_last_hash(path: &Path) -> anyhow::Result<Vec<u8>> {
        let f = File::open(path)?;
        let mut last = vec![0u8; 32]; // genesis = 32 zero bytes
        for line in BufReader::new(f).lines() {
            let e: Entry = serde_json::from_str(&line?)?;
            last = hex::decode(e.prev_hash)?;
        }
        Ok(last)
    }

    /// Append a new Event, chaining via Blake3(prev_hash ∥ payload).
    pub fn log(&mut self, event: Event) -> anyhow::Result<()> {
        let ts = Utc::now().to_rfc3339();
        let pid = std::process::id();
        let payload = serde_json::json!({
            "timestamp": ts,
            "pid": pid,
            "event": event,
        });
        let payload_bytes = serde_json::to_vec(&payload)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.current_hash);
        hasher.update(&payload_bytes);
        let new_hash = hasher.finalize();
        let hex = new_hash.to_hex().to_string();

        let entry = Entry {
            prev_hash: hex,
            timestamp: ts,
            pid,
            event,
        };
        let line = serde_json::to_string(&entry)?;
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.current_hash = new_hash.as_bytes().to_vec();
        Ok(())
    }

    pub fn log_invocation_start(&mut self, cmd: Vec<String>) -> anyhow::Result<()> {
        self.log(Event::InvocationStart { cmd })
    }

    pub fn log_syscall(
        &mut self,
        number: i64,
        name: String,
        args: Vec<String>,
        ret: i64,
    ) -> anyhow::Result<()> {
        self.log(Event::Syscall {
            number,
            name,
            args,
            ret,
        })
    }

    pub fn log_invocation_end(&mut self, status: i32) -> anyhow::Result<()> {
        self.log(Event::InvocationEnd { status })
    }

    // inside impl Logger in src/log.rs

    /// Recompute and check every hash link in the log at `path`.
    /// Returns Ok(()) if the chain is intact, Err(_) if any link fails.
    pub fn verify_chain(path: &Path) -> anyhow::Result<()> {
        let file = File::open(path)?;
        let mut prev = vec![0u8; 32]; // genesis
        for (i, line_res) in BufReader::new(file).lines().enumerate() {
            let line = line_res?;
            let entry: Entry = serde_json::from_str(&line)?;
            // reconstruct the same payload we hashed on write:
            let payload = json!({
                "timestamp": entry.timestamp,
                "pid": entry.pid,
                "event": entry.event,
            });
            let payload_bytes = serde_json::to_vec(&payload)?;
            let mut hasher = blake3::Hasher::new();
            hasher.update(&prev);
            hasher.update(&payload_bytes);
            let computed = hasher.finalize().as_bytes().to_vec();

            // decode the recorded hash
            let recorded = hex::decode(&entry.prev_hash)?;
            if recorded != computed {
                return Err(anyhow::anyhow!(
                    "hash mismatch at entry #{}, expected {} but got {}",
                    i,
                    hex::encode(&computed),
                    entry.prev_hash
                ));
            }
            prev = computed;
        }
        Ok(())
    }
}
