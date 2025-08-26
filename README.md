# Capsule

_Trace agents from the kernel. Human readable reports. Dynamic security policy._

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

## Quickstart

> Works today on **Linux aarch64** only.

**Prerequisites (Ubuntu/Debian)**

```bash
sudo apt-get update && sudo apt-get install -y \
  clang llvm libelf-dev linux-headers-$(uname -r) build-essential pkg-config
```
