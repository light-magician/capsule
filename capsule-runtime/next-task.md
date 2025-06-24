## EnhancedEvent – formal requirements

_Must_ = mandatory for v1  *Should* = strongly recommended  *May* = optional / future-proof

### 1. Purpose

A single EnhancedEvent is the canonical, self-contained record for one syscall after the Enricher stage. It carries all data required by downstream Aggregator, Reporter and Policy-Generator tasks without additional /proc look-ups.

### 2. Structural rules

1. **JSON object** written one-per-line to `enriched.jsonl`.
2. Keys never removed once published; new keys added only with `null` default for backward compatibility.
3. Entire object **Clone + Send + Sync** in Rust; target size ≤ 1 KiB (typical ≈ 300 B).
4. All time values are **µs since tracer start** (`u64`).
5. Optional fields that do not apply are encoded as JSON `null`.

### 3. Field specification

| Key               | Type                  | Must/Should/May | Description / Source                                        |           |                            |          |     |        |                                              |
| ----------------- | --------------------- | --------------- | ----------------------------------------------------------- | --------- | -------------------------- | -------- | --- | ------ | -------------------------------------------- |
| `ts`              | `u64`                 | Must            | Microsecond timestamp (from strace `-tt`).                  |           |                            |          |     |        |                                              |
| `pid`             | `u32`                 | Must            | Linux PID of calling thread (parsed).                       |           |                            |          |     |        |                                              |
| `tid`             | `u32`                 | Should          | TID when different from PID (clone).                        |           |                            |          |     |        |                                              |
| `ppid`            | `u32`                 | Should          | Parent PID snapshot (`/proc/<pid>/status`).                 |           |                            |          |     |        |                                              |
| `call`            | `String`              | Must            | Syscall name (`openat`, `connect`, …).                      |           |                            |          |     |        |                                              |
| `args`            | `[u64;6]`             | Must            | Raw six argument words (unchanged).                         |           |                            |          |     |        |                                              |
| `retval`          | `i64`                 | Must            | Return value as printed by strace.                          |           |                            |          |     |        |                                              |
| `raw_line`        | `String`              | Must            | Original strace line for provenance.                        |           |                            |          |     |        |                                              |
| `raw_hash`        | `String` (hex-blake3) | Should          | `blake3(raw_line)`, builds hash-chain.                      |           |                            |          |     |        |                                              |
| `exe_path`        | `String`              | Should          | Absolute path of `/proc/<pid>/exe`.                         |           |                            |          |     |        |                                              |
| `cwd`             | `String`              | Should          | Current working directory (`/proc/<pid>/cwd`).              |           |                            |          |     |        |                                              |
| `uid` / `gid`     | `u32`                 | Should          | Real UID / GID at event time.                               |           |                            |          |     |        |                                              |
| `euid` / `egid`   | `u32`                 | May             | Effective IDs if different.                                 |           |                            |          |     |        |                                              |
| `caps`            | `u64` bit-mask        | May             | `CapEff` bitmap from status (Linux ≤ 64 caps).              |           |                            |          |     |        |                                              |
| `fd`              | `i32`                 | May             | FD number referenced by the syscall (−1 if none).           |           |                            |          |     |        |                                              |
| `abs_path`        | `String`              | May             | Resolved absolute path for pathname or FD.                  |           |                            |          |     |        |                                              |
| `resource_type`   | \`"FILE"              | "DIR"           | "SOCKET"                                                    | "PIPE"    | "SHM"                      | "PROCFS" | …\` | Should | High-level kind after resolution.            |
| `operation`       | \`"READ"              | "WRITE"         | "EXEC"                                                      | "CONNECT" | "BIND"                     | "STAT"   | …\` | Should | Semantic intent derived from `call` + flags. |
| `perm_bits`       | `u32`                 | May             | Octal mode from `openat`, `chmod`, etc.                     |           |                            |          |     |        |                                              |
| `byte_count`      | `u64`                 | May             | Size requested / transferred (read, write, send…).          |           |                            |          |     |        |                                              |
| `net`             | object or `null`      | May             | Populated for socket syscalls → see below.                  |           |                            |          |     |        |                                              |
| `latency_us`      | `u64`                 | May             | Δ between entry/exit lines when captured.                   |           |                            |          |     |        |                                              |
| `risk_tags`       | `Vec<String>`         | May             | Zero-or-more heuristic flags (`"TMP_EXEC"`, `"PRIV_ESC"`…). |           |                            |          |     |        |                                              |
| `high_level_kind` | \`"FileRead"          | "NetConnect"    | …\`                                                         | Should    | Bucket used by Aggregator. |          |     |        |                                              |

`net` sub-object (present only when `resource_type=="SOCKET"`):

```json
{
  "family": "AF_INET"|"AF_INET6"|"AF_UNIX"|"AF_NETLINK",
  "protocol": "TCP"|"UDP"|...,
  "local_addr": "127.0.0.1",
  "local_port": 8000,
  "remote_addr": "1.2.3.4",
  "remote_port": 443
}
```

### 4. Mapping & enrichment logic (non-blocking)

1. Resolver keeps **Process table** and **FD table** in-memory (updated on `open*`, `socket`, `connect`, `chdir`, `execve`, `close`, …).
2. Enricher receives `SyscallEvent`, clones read-only snapshots of both tables, fills as many fields as possible synchronously.
3. Heavy work (SHA-256 of large binaries, DNS reverse look-ups) is _off-loaded_ to a low-priority background task that patches events _in-place_ before the Logger task flushes its buffer.
4. If enrichment fails within 2 ms budget, leave optional fields `null` and set `risk_tags += ["ENRICH_TIMEOUT"]`.

### 5. Concurrency & back-pressure guarantees

- Enricher must never await on blocking FS I/O without a timeout; all `/proc` reads go through `tokio::fs` and are governed by a `Semaphore` (N = 32).
- On `broadcast::error::Lagged`, skip enrichment altogether and set `risk_tags += ["PIPE_BACKPRESSURE"]`.
- Logger owns the Blake3 rolling hash; it appends `raw_hash` from each event into `state = blake3::keyed(state, raw_hash)` before writing, ensuring tamper-evident chain across log streams.

### 6. Example (abridged)

```json
{
  "ts": 4768313139,
  "pid": 1351,
  "tid": 1351,
  "ppid": 1340,
  "call": "newfstatat",
  "args": [-100, 139890402500864, 139755259461984, 0, 0, 0],
  "retval": 0,
  "raw_line": "[pid 1351] 01:19:28.313139 newfstatat(AT_FDCWD, \"/capsule/.../__init__.py\", ... ) = 0",
  "raw_hash": "76fa63e8…",
  "exe_path": "/usr/bin/python3.9",
  "cwd": "/capsule/capsule-agents/catalog/base",
  "uid": 0,
  "gid": 0,
  "caps": 0,
  "fd": -1,
  "abs_path": "/capsule/capsule-agents/catalog/base/.venv/lib/python3.9/site-packages/langchain_core/_api/__init__.py",
  "resource_type": "FILE",
  "operation": "STAT",
  "perm_bits": null,
  "byte_count": null,
  "net": null,
  "latency_us": 47,
  "risk_tags": [],
  "high_level_kind": "FileMetadata"
}
```

This schema gives every downstream stage enough semantic signal to:

- build human-readable timelines,
- collapse correlated calls into Actions,
- auto-derive a least-privilege seccomp profile, and
- flag dangerous behaviour in real time—while staying small, immutable and friendly to our all-async pipeline.

Let's Execute this in testable PIECES, and commit each one.
After each piece of this is added, tell me to verify, once verified
give a commit message.
