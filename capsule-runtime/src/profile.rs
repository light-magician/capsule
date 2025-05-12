// src/profile.rs
use anyhow::Result;
use chrono::Local;
use serde::Serialize;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

#[derive(Serialize)]
struct Entry {
    command: String,
    syscalls: Vec<String>,
}

/// For each line in `input_path` (a newline-separated list of shell commands),
/// runs strace, captures the syscalls, writes per-command `.log` files
/// into `out_dir`, then emits a single summary JSON in `out_dir`.
pub fn profile_commands(input_path: &str, out_dir: &str) -> Result<()> {
    // 0. Base name
    let path = Path::new(input_path);
    let base = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("commands");

    // 1. Timestamp & ensure output directory exists
    let ts = Local::now().format("%Y%m%dT%H%M%S").to_string();
    let out_dir = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir)?;

    // 2. Read all commands
    let content = fs::read_to_string(input_path)?;
    let mut results = Vec::new();

    for (i, raw) in content.lines().enumerate() {
        let cmd = raw.trim();
        if cmd.is_empty() {
            continue;
        }

        // 3. Trace each command
        let trace_file = out_dir.join(format!("{}_{}_{}.log", base, ts, i));
        let status = Command::new("strace")
            .args(&[
                "-f",
                "-e",
                "trace=all",
                "-o",
                trace_file.to_str().unwrap(),
                "sh",
                "-c",
                cmd,
            ])
            .status()?;

        if !status.success() {
            eprintln!("⚠️  `{}` exited with {:?}", cmd, status);
        }

        // 4. Parse unique syscall names
        let file = File::open(&trace_file)?;
        let reader = BufReader::new(file);
        let mut seen = HashSet::new();
        for line in reader.lines() {
            let line = line?;
            if let Some(pos) = line.find('(') {
                seen.insert(line[..pos].to_string());
            }
        }
        let mut syscalls: Vec<_> = seen.into_iter().collect();
        syscalls.sort();

        results.push(Entry {
            command: cmd.to_string(),
            syscalls,
        });
    }

    // 5. Serialize summary JSON
    let json_file = out_dir.join(format!("{}_{}.json", base, ts));
    let pretty = serde_json::to_string_pretty(&results)?;
    fs::write(&json_file, pretty)?;

    println!(
        "✅ Wrote {} entries\n  • logs: {}/\n  • summary: {}",
        results.len(),
        out_dir.display(),
        json_file.display()
    );

    Ok(())
}

// ─── reusable one-command tracer ───────────────────────────────────────────
use std::process::Command; // already in scope earlier

pub fn trace_single(cmd: &str, args: &[String], trace_dir: &Path) -> anyhow::Result<Vec<String>> {
    use std::{
        collections::HashSet,
        fs,
        io::{BufRead, BufReader},
    };

    fs::create_dir_all(trace_dir)?;
    let ts = chrono::Local::now().format("%Y%m%dT%H%M%S").to_string();
    let file = trace_dir.join(format!("{}_{}.log", cmd.replace('/', "_"), ts));

    Command::new("strace")
        .args(&["-f", "-e", "trace=all", "-o", file.to_str().unwrap(), cmd])
        .args(args)
        .status()?;

    let fd = fs::File::open(&file)?;
    let mut uniq = HashSet::new();
    for line in BufReader::new(fd).lines().flatten() {
        if let Some(p) = line.find('(') {
            uniq.insert(
                line[..p]
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .to_string(),
            );
        }
    }
    let mut list: Vec<_> = uniq.into_iter().collect();
    list.sort();
    Ok(list)
}
