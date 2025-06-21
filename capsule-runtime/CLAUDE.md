# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Capsule-runtime is a Rust-based syscall tracing sandbox that uses `strace` to monitor and log system calls from arbitrary CLI programs. It runs programs under ptrace supervision and outputs structured logs for security analysis and seccomp profile generation.

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

The system uses a multi-stage async pipeline architecture:

1. **Tracer** (`trace.rs`): Spawns `strace` subprocess, captures raw syscall traces from stderr
2. **Parser** (`parser.rs`): Converts raw strace text lines into structured `SyscallEvent`s  
3. **Aggregator** (`aggregator.rs`): Groups syscalls into semantic `Action`s (currently 1:1 passthrough)
4. **Logger** (`io.rs`): Writes structured data to multiple log files

**Data Flow:**
```
Raw strace lines → SyscallEvent structs → Action structs → Log files
```

**Key Components:**
- Uses Tokio broadcast channels for inter-task communication
- Ready synchronization ensures all downstream tasks are listening before tracing starts
- Logs are written to `~/.capsule/run/<uuid>/` directory structure
- Three log types: raw syscalls, structured events (JSONL), semantic actions (JSONL)

## CLI Commands

- `capsule run <program> [args...]` - Trace a program execution
- `capsule tail <stream> [--run uuid]` - Live tail logs (syscalls/events/actions)

## File Structure

- `src/main.rs` - Entry point and async task orchestration
- `src/cli.rs` - Command line argument parsing  
- `src/trace.rs` - strace subprocess management
- `src/parser.rs` - Raw strace line parsing (currently stub implementation)
- `src/aggregator.rs` - Event aggregation (placeholder for future windowing logic)
- `src/model.rs` - Core data structures (SyscallEvent, Action, ActionKind)
- `src/constants.rs` - File paths and directory management
- `src/io.rs` - Log file writing and management
- `src/tail.rs` - Log tailing functionality

## Development Notes

- Currently Linux container only (uses strace)
- Parser is a stub - intended to be replaced with proper nom-based state machine
- Aggregator is 1:1 passthrough - intended for sliding window coalescing  
- Uses structured logging with timestamps and UUIDs for run identification
- Error handling uses anyhow crate throughout

## Development Workflow

When implementing new features:
1. Complete each implementation step fully
2. Notify when step is complete for build verification
3. After build confirmation, provide a concise commit message following the format:
   ```
   feat: brief description of main changes
   
   - Bullet point of key implementation detail
   - Another key architectural change
   - Preparation note for future eBPF integration (if applicable)
   ```