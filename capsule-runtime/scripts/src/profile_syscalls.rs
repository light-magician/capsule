use anyhow::Result;
use chrono::Local;
use serde::Serialize;
use std::{
    env,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::Path,
    process::Command,
};

#[derive(Serialize)]
struct Entry {
    command: String,
    syscalls: Vec<String>,
}

fn main() -> Result<()> {
    // 0. Input file and base name
    let input_path = env::args().nth(1).unwrap_or_else(|| "commands.txt".into());
    let path = Path::new(&input_path);
    let base = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("commands");

    // 1. Timestamp and output dir
    let ts = Local::now().format("%Y%m%dT%H%M%S").to_string();
    let out_dir = Path::new("cmd_traces");
    fs::create_dir_all(&out_dir)?;

    // 2. Read commands
    let content = fs::read_to_string(&input_path)?;
    let mut results = Vec::new();

    for (i, raw) in content.lines().enumerate() {
        let cmd = raw.trim();
        if cmd.is_empty() {
            continue;
        }

        // 3. Trace log per command
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

        // 4. Parse syscalls
        let file = File::open(&trace_file)?;
        let reader = BufReader::new(file);
        let mut seen = std::collections::HashSet::new();
        for line in reader.lines() {
            let line = line?;
            if let Some(pos) = line.find('(') {
                seen.insert(line[..pos].to_string());
            }
        }
        let mut syscalls: Vec<_> = seen.into_iter().collect();
        syscalls.sort();

        results.push(Entry {
            command: cmd.into(),
            syscalls,
        });
    }

    // 5. Write summary JSON into cmd_traces/
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
