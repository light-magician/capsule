# Capsule Runtime <sup>by Ghostlock</sup>

Rust‑powered syscall tracing sandbox for Linux programs.

---

## 1 — Why Capsule?

- **Transparent execution:** Every file read, network connect, fork, and UID change is logged in real time.
- **Forensic integrity:** Blake3 hash‑chained records prevent tampering.
- **Drop‑in usage:** Wrap any CLI (`capsule trace <cmd …>`)—no code changes required.

## 2 — Architecture

| Stage | Component  | Purpose                                          |
| ----- | ---------- | ------------------------------------------------ |
|  1    | Tracer     | Launches target under `strace -f -tt -s 1k`      |
|  2    | Parser     | Turns raw strace lines → `SyscallEvent` objects  |
|  3    | Enricher   | Adds `/proc` metadata (cwd, exe, UID, etc.)      |
|  4    | Aggregator | Collapses bursts → high‑level **Action** records |
|  5    | Logger     | Writes Blake3‑chained JSONL to `/tmp`            |

<sub>Measured at < 100 ms median end‑to‑end on a 4‑core laptop.</sub>

## 2.5 — Project Status (June 2025)

Capsule Runtime is currently **alpha‑quality** and operates in _observe‑only_ mode:

- Focused on **syscall collection, enrichment, and aggregation**.
- **No enforcement** yet—seccomp/eBPF blocking and live policy generation are in active development.
- Use it to **profile syscall sequences**, generate draft allow‑lists, and gain visibility into unknown binaries.
- Expect breaking changes until we tag v0.1.0.

---

## 3 — Quickstart

```bash
# Build and enter the dev container
docker compose up --build -d
docker exec -it capsule-dev bash

# Build the binary
cargo build --release        # → ./target/release/capsule

# Trace a script
cd scripts
capsule trace python3 hello.py

# Tail the audit log
capsule tail
```

## 4 — Platform Support

Capsule Runtime currently targets **Linux (x86‑64)** only and has been tested on Ubuntu 22.04 with kernel 5.15. Running inside WSL2 or macOS/Linux containers is supported so long as the underlying kernel is Linux.

## 5 — Related Repositories

- **[capsule-agents](https://github.com/ghostlock/capsule-agents)** – curated examples of wrapping AI agents and other CLI tools with Capsule Runtime for security auditing.

---

<sub>Looking for contribution guidelines, licensing details, or overall project roadmap? See the top‑level **ghostlock** repository.</sub>
