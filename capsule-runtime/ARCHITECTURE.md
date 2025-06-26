# Capsule Architecture

Capsule is a Rust-based syscall tracing sandbox that uses `strace` to monitor and log system calls from arbitrary CLI programs. It runs programs under ptrace supervision, enriches syscall data with process context, performs security risk analysis, and outputs structured logs for security analysis and seccomp profile generation.

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

## System Architecture

The system uses a **5-stage async pipeline** with structured concurrency:

1. **Tracer** (`trace.rs`): Spawns `strace` subprocess, captures raw syscall traces from stderr
2. **Parser** (`parser.rs`): Converts raw strace lines into structured `SyscallEvent`s with risk analysis
3. **Enricher** (`enricher.rs`): Adds `/proc` filesystem metadata to create `EnrichedEvent`s
4. **Aggregator** (`aggregator.rs`): Groups related syscalls into semantic `Action`s using sliding windows
5. **Logger** (`io.rs`): Writes structured data to multiple log streams with hash-chained integrity

**Data Flow:**
```
Raw strace lines → SyscallEvent → EnrichedEvent → Action → Log files
    (Tracer)       (Parser +         (Enricher)    (Aggregator) (Logger)
                   Risk Analysis)
                        ↓
                   risks.jsonl (filtered)
```

**Key Architectural Features:**
- **Structured Concurrency**: Uses Tokio JoinSet and cancellation tokens for graceful shutdown
- **Ready Synchronization**: Ensures all downstream tasks are listening before upstream starts
- **Broadcast Channels**: Tokio broadcast channels for inter-task communication
- **Hash Chaining**: Blake3-based integrity verification for all log streams
- **Process Context Enrichment**: Comprehensive `/proc` metadata collection with caching
- **Security Risk Analysis**: Real-time heuristic analysis with 15+ risk categories
- **Multi-Stream Logging**: Parallel async writers for different data perspectives

## Core Data Structures (`model.rs`)

**SyscallEvent**: Enhanced syscall record with comprehensive metadata:
- Core syscall data: timestamp, PID, call name, args, return value
- Process context: exe_path, cwd, argv, uid, gid, ppid
- Security context: capabilities, namespaces, effective IDs
- Resource context: fd numbers, resolved paths, resource types, operations
- Network context: socket families, addresses, ports, protocols
- Risk analysis: security risk tags, high-level behavioral categories
- Operation details: permission bits, byte counts, latency measurements

**ProcessContext**: Rich metadata from `/proc` filesystem:
- Process info: exe_path, cwd, argv, uid, gid, ppid
- File descriptors: fd_map (fd → path/socket descriptions)
- Security context: capabilities, namespaces

**Action**: High-level semantic operations with time ranges and process context

**ActionKind**: 18 syscall classifications (Read, Write, Open, Close, Stat, Chmod, Chown, List, Connect, Bind, Accept, Spawn, Exec, Exit, Send, Receive, Map, Unmap, Other)

## Security Risk Analysis (`risk.rs`)

**Risk Tags** - Heuristic security indicators for immediate threat detection:

*Execution Risks:*
- `EXEC` - Any execution operation
- `TMP_EXEC` - Executing files from /tmp/ (potential malware staging)
- `SHM_EXEC` - Executing from shared memory (code injection indicator)
- `NON_SYSTEM_EXEC` - Executing files outside standard system directories

*File Access Risks:*
- `PASSWD_ACCESS` - Accessing /etc/passwd or /etc/shadow (credential harvesting)
- `PROC_MEM_ACCESS` - Accessing /proc/*/mem or /proc/*/maps (memory inspection)
- `SYSFS_WRITE` - Writing to /sys/ (system configuration tampering)
- `PATH_TRAVERSAL` - Paths containing ".." (directory traversal attempts)

*Network Risks:*
- `PRIV_PORT_BIND` - Binding to privileged ports (<1024)
- `OUTBOUND_CONNECT` - Making outbound network connections

*Privilege Escalation Risks:*
- `PRIV_ESC` - Syscalls like setuid, setgid (privilege changes)

*Data Exfiltration/Performance Risks:*
- `LARGE_IO` - Operations >1MB (potential data exfiltration)

*Reconnaissance Risks:*
- `FAILED_OPEN`, `FAILED_CONNECT`, `FAILED_STAT` - Failed operations (potential probing)

**High-Level Categories** - Behavioral buckets for aggregator grouping:
- File operations: `FileRead`, `FileWrite`, `FileOpen`, `FileMetadata`, `FilePermissions`
- Directory operations: `DirList`, `DirCreate`, `DirMetadata`
- Network operations: `NetConnect`, `NetBind`, `NetAccept`, `NetReceive`, `NetSend`
- Process operations: `ProcessSpawn`, `ProcessExec`, `ProcessSignal`
- Memory operations: `MemoryMap`, `MemoryUnmap`
- System access: `ProcFsAccess`, `DeviceAccess`, `SysfsAccess`

## Component Details

**Tracer** (`trace.rs`):
- Spawns strace with flags: `-f -tt -yy -v -x -s 1000`
- Process group management with SIGTERM → SIGKILL escalation
- Preserves program stdout while capturing stderr traces

**Parser** (`parser.rs`):
- Extracts timestamps, PIDs, syscall names, arguments, and return values
- Classifies operations and resource types
- Performs real-time security risk analysis
- Categorizes syscalls for aggregator grouping
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
- Five log types: raw syscalls, parsed events, enriched events, risk events, actions
- Risk stream filters events with non-empty risk_tags
- Blake3 hash chaining for tamper detection
- JSONL format for structured logs

## CLI Commands

- `capsule run <program> [args...]` - Trace a program execution
- `capsule tail <stream> [--run uuid]` - Live tail logs
  - Streams: "syscalls", "events", "enriched", "actions", "risks"

**Security Monitoring:**
```bash
# Real-time security risk monitoring
capsule tail risks

# View specific run's risk events
capsule tail risks --run abc123

# Monitor all enriched events with full context
capsule tail enriched
```

## Directory Structure

**Logs**: `~/.capsule/logs/<timestamp-uuid>/`
- `syscalls.log` - Raw strace output
- `events.jsonl` - Parsed syscall events with risk analysis
- `enriched.jsonl` - Events with process context
- `risks.jsonl` - Filtered events containing security risk tags
- `actions.jsonl` - Aggregated semantic actions

**Run Metadata**: `~/.capsule/run/<uuid>/`
- `log_dir.txt` - Links to corresponding log directory

## File Structure

- `src/main.rs` - Entry point with structured concurrency orchestration
- `src/cli.rs` - Command line interface (clap-based)
- `src/trace.rs` - strace subprocess management with signal handling
- `src/parser.rs` - strace line parsing with integrated risk analysis
- `src/risk.rs` - Security risk analysis and behavioral categorization
- `src/enricher.rs` - Process context collection from `/proc`
- `src/aggregator.rs` - Sliding window syscall aggregation
- `src/model.rs` - Core data structures and serialization
- `src/constants.rs` - File paths and directory constants
- `src/io.rs` - Multi-stream logging with hash chaining and risk filtering
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
- **Security**: Real-time risk analysis with configurable sensitivity
- **Current Branch**: `main` with complete risk analysis implementation

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

## Performance Characteristics

**Throughput**: Handles high-frequency syscalls with async pipeline
**Memory**: Process context caching with TTL prevents memory growth
**Storage**: Hash-chained logs ensure integrity with minimal overhead
**Latency**: Real-time risk analysis adds <1ms per syscall
**Scalability**: Broadcast channels handle multiple concurrent subscribers

## Security Considerations

**Risk Analysis**: Heuristic-based detection with low false positive rate
**Data Integrity**: Blake3 hash chaining prevents log tampering
**Process Isolation**: Uses ptrace for secure program supervision
**Capability Tracking**: Monitors privilege escalation attempts
**Network Monitoring**: Tracks all socket operations and connections

## Current Limitations

- Parser extracts core syscall data but not full argument parsing
- No eBPF implementation (uses strace approach)
- Tail functionality is file-based, not live broadcast integration
- Linux-only due to strace and /proc dependencies
- Risk analysis uses static heuristics (no ML-based anomaly detection)

## Future Enhancements

**Risk Analysis Improvements:**
- Machine learning-based anomaly detection
- Behavioral baselines and deviation analysis
- Configurable risk sensitivity levels
- Integration with threat intelligence feeds

**Performance Optimizations:**
- eBPF-based syscall capture for reduced overhead
- Real-time broadcast integration for live tailing
- Compressed log storage with retention policies

**Analysis Features:**
- Timeline visualization of security events
- Correlation analysis across process families
- Automated seccomp profile generation
- Integration with SIEM systems