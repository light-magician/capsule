# cmd_syscall_tracer

A lightweight Rust utility that wraps `strace` to audit syscalls for arbitrary shell commands and produces a clean JSON report.

## What it does

1. **Reads** a newline-separated list of shell commands from a file (default: `commands.txt`, or specify your own).
2. **Spawns** each command under `strace -f -e trace=all`, capturing every syscall (including child processes).
3. **Deduplicates** and **sorts** the syscall names for each command.
4. **Emits** per-command `strace` logs and a single summary JSON into a timestamped `cmd_traces/` directory.

## How it works

1. **Input file**
   - Default: `commands.txt` in the project root.
   - You can pass a different path as the first CLI argument:
     ```bash
     cargo run --release -- other_commands.txt
     ```
2. **Timestamp & output directory**
   - On each run, the script builds `cmd_traces/` (if needed) and generates a timestamp `YYYYMMDDTHHMMSS`.
3. **Tracing commands**
   - For each non-empty line in the input, it runs:
     ```bash
     strace -f -e trace=all -o cmd_traces/<base>_<timestamp>_<index>.log sh -c "<command>"
     ```
   - `<base>` is the input file’s stem (e.g. `commands`), `<index>` is the line number.
4. **Parsing syscalls**
   - The script scans each `.log`, extracts everything before the first `(` on each line, and builds a unique, sorted list.
5. **Summary JSON**
   - Writes `cmd_traces/<base>_<timestamp>.json`, containing an array of
     ```json
     [
       {
         "command": "ls -l /",
         "syscalls": ["access", "arch_prctl", "brk", …]
       },
       …
     ]
     ```

## Where the files go

All outputs live under `cmd_traces/`:

- **`.log` files**
