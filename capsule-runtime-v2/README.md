# Capsule Runtime V2 - Process Monitoring & Analysis

## Overview

Capsule Runtime V2 provides real-time process monitoring and analysis through kernel-level syscall tracing. Features live TUI monitoring, process state tracking, and comprehensive syscall analysis.

## Quick Start

### Installation

```bash
cargo install --path cli --force
```

### Usage

```bash
# Run a program with monitoring
capsule run {program}

# Monitor live processes in TUI
capsule monitor

# Demo TUI with sample data
capsule demo
```

## Features

### Live Process Monitoring
- Real-time TUI with process list and syscall stream
- Process state tracking (Spawning → Active → Exited)
- Keyboard navigation and auto-scroll controls
- Session management with persistent state

### Syscall Analysis
- Comprehensive parsing of process lifecycle events
- Real-time risk analysis and security monitoring
- Multi-stream logging (syscalls, events, risks)
- Hash-chained integrity verification

### maintenance

Most of what is added to the project
will be a new lib. Libs have no main.

create a new lib with

```bash
cargo new --lib libname
```

and a new bin with

```bash
cargo new --bin binname
```

though, the cli should be the only bin.
