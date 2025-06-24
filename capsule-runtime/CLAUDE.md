# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Capsule is a Rust-based syscall tracing sandbox that uses `strace` to monitor and log system calls from arbitrary CLI programs. It runs programs under ptrace supervision, enriches syscall data with process context, and outputs structured logs for security analysis and seccomp profile generation.

## Build and Development Commands

**Container Development:**
```bash
# Build and run development container
docker compose up --build -d
# Access container shell
docker exec -it capsule-dev bash
```

**Local Build:**
```bash
# Debug build
cargo build
# Release build  
cargo build --release
# Global install
cargo install --path . --force
```

**Testing:**
```bash
# Run tests (uses assert_cmd and predicates)
cargo test
```

## Architecture Overview

The system uses a **4-stage async pipeline** with structured concurrency:

1. **Tracer** (`trace.rs`): Spawns `strace` subprocess, captures raw syscall traces from stderr
2. **Parser** (`parser.rs`): Converts raw strace lines into structured `SyscallEvent`s
3. **Enricher** (`enricher.rs`): Adds `/proc` filesystem metadata to create `EnrichedEvent`s
4. **Aggregator** (`aggregator.rs`): Groups related syscalls into semantic `Action`s using sliding windows
5. **Logger** (`io.rs`): Writes structured data to multiple log streams with hash-chained integrity

**Data Flow:**
```
Raw strace lines → SyscallEvent → EnrichedEvent → Action → Log files
    (Tracer)      (Parser)       (Enricher)    (Aggregator) (Logger)
```

**Key Architectural Features:**
- **Structured Concurrency**: Uses Tokio JoinSet and cancellation tokens for graceful shutdown
- **Ready Synchronization**: Ensures all downstream tasks are listening before upstream starts
- **Broadcast Channels**: Tokio broadcast channels for inter-task communication
- **Hash Chaining**: Blake3-based integrity verification for all log streams
- **Process Context Enrichment**: Comprehensive `/proc` metadata collection with caching

## Core Data Structures (`model.rs`)

**SyscallEvent**: Raw syscall with timestamp, PID, call name, args, return value, and enrichment capability

**ProcessContext**: Rich metadata from `/proc` filesystem:
- Process info: exe_path, cwd, argv, uid, gid, ppid
- File descriptors: fd_map (fd → path/socket descriptions)
- Security context: capabilities, namespaces

**Action**: High-level semantic operations with time ranges and process context

**ActionKind**: 16 syscall classifications (Read, Write, Open, Close, Stat, Chmod, Chown, List, Connect, Bind, Accept, Spawn, Exec, Exit, Send, Receive, Map, Unmap, Other)

## Component Details

**Tracer** (`trace.rs`):
- Spawns strace with flags: `-f -tt -yy -v -x -s 1000`
- Process group management with SIGTERM → SIGKILL escalation
- Preserves program stdout while capturing stderr traces

**Parser** (`parser.rs`):
- Extracts timestamps and syscall names from strace output
- Error logging with timestamped failure files
- Debug counters for monitoring parse success rates

**Enricher** (`enricher.rs`):
- Process context caching with 5-second TTL
- Concurrent `/proc` lookups with semaphore rate limiting
- Reads: exe, cwd, cmdline, status, fd/, ns/ from `/proc/PID/`

**Aggregator** (`aggregator.rs`):
- Sliding window aggregation using AggregationKey (PID + FD/path + operation)
- Groups bursty operations (read/write) while preserving critical events (spawn/exit)
- 100ms flush interval for pending actions

**Logger** (`io.rs`):
- Separate Tokio tasks for each log stream
- Four log types: raw syscalls, parsed events, enriched events, actions
- Blake3 hash chaining for tamper detection
- JSONL format for structured logs

## CLI Commands

- `capsule run <program> [args...]` - Trace a program execution
- `capsule tail <stream> [--run uuid]` - Live tail logs
  - Streams: "syscalls", "events", "actions"

## Directory Structure

**Logs**: `~/.capsule/logs/<timestamp-uuid>/`
- `syscalls.log` - Raw strace output
- `events.jsonl` - Parsed syscall events  
- `enriched.jsonl` - Events with process context
- `actions.jsonl` - Aggregated semantic actions

**Run Metadata**: `~/.capsule/run/<uuid>/`
- `log_dir.txt` - Links to corresponding log directory

## File Structure

- `src/main.rs` - Entry point with structured concurrency orchestration
- `src/cli.rs` - Command line interface (clap-based)
- `src/trace.rs` - strace subprocess management with signal handling
- `src/parser.rs` - strace line parsing with error tracking
- `src/enricher.rs` - Process context collection from `/proc`
- `src/aggregator.rs` - Sliding window syscall aggregation
- `src/model.rs` - Core data structures and serialization
- `src/constants.rs` - File paths and directory constants
- `src/io.rs` - Multi-stream logging with hash chaining
- `src/tail.rs` - Log file tailing functionality

## Dependencies

**Core Runtime**: tokio (full features), anyhow, uuid, chrono
**System**: nix (ptrace/signals), syscalls, libc
**CLI**: clap (derive)
**Serialization**: serde, serde_json
**Security**: blake3 (hash chaining)
**Performance**: smallvec (efficient collections)
**Testing**: assert_cmd, predicates

## Development Notes

- **Platform**: Linux container only (requires strace and /proc filesystem)
- **Concurrency**: Uses structured concurrency patterns with graceful shutdown
- **Error Handling**: anyhow throughout with comprehensive error logging
- **Performance**: Cached process context, efficient aggregation, concurrent enrichment
- **Integrity**: Hash-chained logs for tamper detection
- **Current Branch**: `event_aggregation` with recent sliding window implementation

## Development Workflow

When implementing new features:
1. Use TodoWrite tool to plan multi-step tasks
2. Complete each implementation step fully
3. Run `cargo build` and `cargo test` to verify correctness
4. Notify when step is complete for build verification
5. After build confirmation, provide concise commit message following format:
   ```
   feat: brief description of main changes
   
   - Key implementation detail
   - Another architectural change
   - Future preparation note (if applicable)
   ```

## Current Limitations

- Parser extracts only timestamp and syscall name (not full argument parsing)
- No eBPF implementation (uses strace approach)
- Tail functionality is file-based, not live broadcast integration
- Linux-only due to strace and /proc dependencies