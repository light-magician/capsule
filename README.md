# Capsule

Trace agents from the kernel. Human readable reports. Dynamic security policy.

![status: pre-alpha](https://img.shields.io/badge/status-pre--alpha-orange)
![arch: aarch64](https://img.shields.io/badge/arch-aarch64-blue)
![platform: linux](https://img.shields.io/badge/platform-Linux-green)
![license: tbd](https://img.shields.io/badge/license-TBD-lightgrey)

Kernel-First Security and Observability for AI Agents

Made by Ghostlock, Corp.

**Capsule** is a security and observability runtime for AI agents that traces system calls and resource usage in the **operating system kernel** and emits **human-readable**, **real-time** logs of agent actions.

---

## TL;DR

Capsule watches agent behavior from the kernel (eBPF/LSM), enriches events into human-readable timelines, and lays the groundwork for dynamic, policy-driven security backed by small ML models. It’s **pre-alpha**, **Linux aarch64 only** right now, written in **Rust**.

---

## Why we are building Capsule

At Ghostlock, Corp., we believe that:

- Agents will become the basis of an increasing amount of human–computer interaction over the next decade.
- Agents will have increasing autonomy to write code to solve problems and make decisions in critical situations with less human oversight over time.
- Monitoring the behavior and intent of intelligent agents will become a major part of the human role in computing-based pursuits, at work and at home.
- The [application layer](https://www.first.org/resources/papers/telaviv2019/Ensilo-Omri-Misgav-Udi-Yavo-Analyzing-Malware-Evasion-Trend-Bypassing-User-Mode-Hooks.pdf) is trivially easy for an attacker or intelligent AI to circumvent, and observability and security tools that only run in userspace are effectively useless in an era approaching some version of AGI.
- Attackers will have increasing access to powerful models that will be able to [analyze systems and networks for vulnerabilities](https://arxiv.org/abs/2404.08144), essentially making complex cybercrimes as accessible as scam calls are today. Similar concerns have been raised by [DeepMind](https://deepmind.google/discover/blog/evaluating-potential-cybersecurity-threats-of-advanced-ai/) and observed by [Google](https://therecord.media/google-llm-sqlite-vulnerability-artificial-intelligence); see also recent work on teams of LLM agents exploiting zero-day [vulnerabilities/exploits](https://arxiv.org/html/2406.01637v2).
- Companies, even in highly regulated sectors, still have insufficient or inconsistent observability trails for the software they rely on and sell. This will become a huge issue in the near future as powerful AI models become more widely adopted and understood.
- Kernel-level tracing is not accessible enough, requiring too much configuration and system-level knowledge to get started.

---

## Quickstart

> Works today on **Linux aarch64** only.

**Prerequisites (Ubuntu/Debian)**

```bash
sudo apt-get update && sudo apt-get install -y \
  clang llvm libelf-dev linux-headers-$(uname -r) build-essential pkg-config
```

**Build & run**

```bash
# From repo root
cargo build --release

# Run a process under Capsule (examples)
capsule run python3 agent.py
capsule run claude
capsule run codex
capsule run gemini
```

---

## What Capsule observes

| Area                 | In plain terms                                              |
| -------------------- | ----------------------------------------------------------- |
| Process execution    | When programs start, fork, or become backgroud processes    |
| Network              | All network communication—who talks to whom.                |
| File I/O             | Read/write/create/delete/move files and folders.            |
| Credentials          | Changes to identity (UID/GID/capabilities).                 |
| Memory / code        | Risky mappings (e.g., W+X), code loading.                   |
| IPC orchestration    | Local process-to-process comms (pipes, UNIX sockets, etc.). |
| Device access        | Access to `/dev/*` (KVM, tun/tap, GPU, disks, USB/TTY).     |
| System configuration | Mounts, chroot/pivot_root, persistence paths.               |
| Containers & cgroups | Enter/leave namespaces; resource limits and cgroup changes. |
| Signals              | Software interrupts (SIGKILL, SIGTERM, etc.).               |

---

## Architecture

- **Kernel Probes**: eBPF kprobes/tracepoints/LSM hooks (Linux) capture syscall-level and semantic events.
- **Userspace Daemon**: stream ingestion, async enrichment of syscalls for better readability.
- **Policy/ML Layer**: deterministic rules + sequence/graph model that categorizes prompt, syscall sequence, and resource utilization combinations as risky or harmless.

**Data path:** eBPF/LSM → ring buffer → userspace daemon → enrichment → stdout/log → (optional policy/ML).
_Diagram coming soon._

---

## Roadmap

1. Phase 1: **Kernel Monitoring** - CURRENTLY IMPLEMENTING

- human-readable summary of actions streamed to userspace in real time
- detailed logging stored in log files

2. Phase 2: **Queryability / Summary Rollup / Static Security / Risk Assessment** — FUTURE

- report rollups to various regulatory framework templates (SOC 2, etc.) or to custom configs
  so that auditing agent actions is effortless
- capsule.yml files for static seccomp configuration
- potential risk sequences reported to user in live watch, risk log file, and can be easily added
  to capsule.yml security profile

3. Phase 3: **Dynamic Security Policy Enforcement** — FUTURE

- Risk sequences are dynamically flagged based on sequences of syscall + resource utilization
  deemed to be outside the bounds of

---

## Support matrix

| Arch    | Platform | Status | Notes                |
| ------- | -------- | ------ | -------------------- |
| aarch64 | Linux    | ✅     | Working in pre-alpha |
| x86_64  | Linux    | ❌     | Planned              |

---

## Policy preview

_Coming soon._ (Sample `capsule.yml` stub will live here once implemented.)

---

## Build from source

**Requirements**

- Linux (aarch64) with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)
- Root/admin privileges (recommended: disable unprivileged BPF on production)
- `clang`/`llvm`, `libelf-dev`, matching kernel headers

**Install dependencies (Ubuntu/Debian)**

```bash
sudo apt-get update && sudo apt-get install -y \
  clang llvm libelf-dev linux-headers-$(uname -r) build-essential pkg-config
```

**Build**

```bash
cargo build --release
```

---

## Contributing / License / Code of Conduct

PRs welcome. Please file issues with kernel version, distro, and repro steps. Threat research, policy packs, and dataset contributions are especially valuable.

- **License:** TBD
- **Code of Conduct:** coming soon
