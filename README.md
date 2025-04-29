# capsule

(should have appache 2.0 License)

# Capsule — Deterministic Security Layer for LLM Agents

## Architecture & Demo Specification (v0.1, 2025-04-29)

---

## 0 · Purpose & Non-Goals

| Item                                                       | In scope by **2025-05-13**               | Out of scope (later)                 |
| ---------------------------------------------------------- | ---------------------------------------- | ------------------------------------ |
| Protect host OS & data from autonomous agent misuse        | ✅                                       | Kernel exploits, memory-safe runtime |
| Fine-grained capability policy (tool + args + paths + net) | ✅                                       | GPU/devfs isolation                  |
| Cryptographically verifiable audit log                     | ✅                                       | Remote attestation service           |
| Cross-platform sandbox (macOS + Linux)                     | ✅ (macOS Seatbelt **or** Linux seccomp) | Windows WDAC                         |
| Integration with a LangGraph Python agent                  | ✅                                       | GUIs, Gateway SaaS, billing          |

---

## 1 · High-Level Diagram

---

## 2 · Key Components

| ID     | Component                  | Language | Crates / Py libs                                               | Purpose                                               |
| ------ | -------------------------- | -------- | -------------------------------------------------------------- | ----------------------------------------------------- |
| **C1** | `capsule.yaml`             | YAML     | —                                                              | Human-authored capability DSL                         |
| **C2** | Policy Compiler            | Python   | `pydantic`, `pyyaml`, `rstr`                                   | Validate & emit `policy.json`                         |
| **C3** | Runtime / CLI              | Rust     | `cap-std`, `seccomp`, `blake3`, `serde_json`, `anyhow`, `clap` | Enforce policy, execute tool, append log              |
| **C4** | Sandbox Adapter            | Rust     | `libseccomp-sys`, `roll::seatbelt` (stub)                      | Generate per-tool syscall / mount rules               |
| **C5** | Merkle Log                 | Rust     | `blake3`, `serde_json`                                         | Append `{parent_hash, entry}`; output JSONL           |
| **C6** | Verifier CLI               | Rust     | same as C5                                                     | Replay log, validate chain and policy conformity      |
| **C7** | Python SDK (`capsule_sdk`) | Python   | `subprocess`, `inspect`                                        | Decorator `@capsule.tool(...)` that shells out to CLI |
| **C8** | Demo Agent Fork            | Python   | `langgraph`, `rich`                                            | Replace direct `subprocess.run` with SDK              |

---

## 3 · `capsule.yaml` v0.1 Schema (example)

````yaml
version: 0.1
tools:
  convert_png_jpg:
    argv_pattern: ["convert", "${SRC:regex:^.*\\.png$}", "${DST:regex:^.*\\.jpg$}"]
    read:  ["/Users/alice/Pictures/**/*.png"]
    write: ["/Users/alice/Pictures/**/*.jpg"]
    net: false
  grep_logs:
    argv_pattern: ["grep", "${PATTERN}", "${FILE:regex:^/var/log/.*\\.log$}"]
    read:  ["/var/log/**/*.log"]
    write: []
    net: false

compiler output `policy.json`
```json
{
  "tool": "convert_png_jpg",
  "argv_regex": ["^convert$", "^.*\\.png$", "^.*\\.jpg$"],
  "read": ["/Users/alice/Pictures"],
  "write": ["/Users/alice/Pictures"],
  "net": false,
  "hash": "sha256:f2b3…"
}
````

runtime flow sdk call

```Python
@capsule.tool("convert_png_jpg")
def resize(src: str, dst: str):
    pass  # body ignored; runtime executes
```

```bash
capsule run \
  --policy-hash f2b3… \
  --json '{"argv": ["convert","a.png","b.jpg"]}'
```

runtime steps
1
Load policy.json; verify hash matches input --policy-hash.
2
Regex-match argv vs policy.
3
Apply seccomp filter: whitelist read, write, fstat, etc.
4
Bind-mount allowed paths (-o ro or rw).
5
Spawn child via std::process::Command.
6
Append log entry â†’ ~/.capsule/log.jsonl.
7
Return child exit status + stdout/stderr to SDK.

log entry

```json
{
  "ts": "2025-05-01T12:00:03Z",
  "parent": "eeae…",
  "entry": {
    "tool": "convert_png_jpg",
    "argv": ["convert", "a.png", "b.jpg"],
    "exit": 0,
    "stdout_hash": "sha256:…",
    "stderr_hash": "sha256:…"
  }
}
```

verifier CLI

```bash
capsule verify ~/.capsule/log.jsonl
> OK (58 entries, root a1f2…)
```

Dependencies and toolchain

Domain
Tooling
Rust
rustc 1.78, cargo, clippy, rustfmt
Python
python 3.11, poetry, mypy, ruff
Sandbox libs
libseccomp (Linux), seatbelt.h via Security.framework (macOS stub)
Build/CI
GitHub Actions (Ubuntu + macOS runners), cargo test, pytest
Hashes
blake3 (fast, strong)
License
Apache-2.0 for core

Testing

Policy compiler
Unit â€“ valid/invalid YAML fixtures
pytest
Runtime happy-path
Unit â€“ convert & grep succeed
cargo test
Deny rules
Integration â€“ attempt network, forbidden path
Red-team script (tests/red_team.sh)
Log integrity
Unit â€“ corrupt one entry; verifier fails
cargo test
Performance
Bench â€“ cold-start <200 ms
Criterion benchmark
CVE smoke
cargo audit, pip-audit
â€”

