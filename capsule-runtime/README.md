# capsule-runtime

## What Is Capsule?

Capsule is a Rust-based **syscall tracing sandbox** that provides comprehensive runtime security monitoring and behavioral analysis for arbitrary Linux programs. Think of it as a "flight recorder" for process execution that captures every system interaction with forensic-grade integrity guarantees.

### Core Value Proposition

**Security:** Capsule transforms opaque program execution into transparent, auditable behavioral signatures. Every file access, network connection, process spawn, and permission change is captured with full context, enabling detection of privilege escalation, data exfiltration, and malicious behavior patterns.

**Observability:** The system provides multi-layered visibility from raw syscalls to semantic business actions. Security teams get both the granular detail needed for incident response and the high-level patterns required for threat hunting.

**Agent Monitoring:** Capsule acts as a universal monitoring agent that can wrap any CLI program without modification. It's designed for environments where you need to audit third-party tools, CI/CD pipelines, or untrusted code execution.

### Architecture: 4-Stage Async Pipeline

The system employs **structured concurrency** with Tokio to ensure data integrity and graceful shutdown:

1. **Tracer** - Spawns target program under `strace` with comprehensive syscall capture
2. **Parser** - Converts raw strace output into structured `SyscallEvent` records  
3. **Enricher** - Enriches syscalls with `/proc` filesystem metadata and security context
4. **Aggregator** - Groups related syscalls into semantic **Actions** using sliding windows
5. **Logger** - Multi-stream output with Blake3 hash-chaining for tamper detection

### Security Features

- **Tamper-Evident Logging:** Blake3 hash chaining for cryptographic integrity
- **Privilege Monitoring:** Track UID/GID changes and capability usage
- **Attack Surface Mapping:** Automatic resource classification and path resolution
- **Real-time Analysis:** Sub-100ms latency from syscall to structured log

### Use Cases

- **CI/CD Pipeline Security:** Audit build scripts for unexpected network connections or privilege escalation
- **Third-Party Tool Auditing:** Analyze untrusted binaries for backdoors or credential harvesting
- **Container Escape Detection:** Monitor for namespace boundary violations and runtime exploitation

capsule-runtime is a minimal Rust sandbox that executes any CLI command
under `ptrace`, intercepts every system call in real time, and appends a timestamped
trace line to a unified log file. When a user runs `capsule trace <cmd>` the program forks
and the child enables `ptrace::traceme()` and executes the target. The parent becomes the
tracer, resuming the child for each syscall stop and recoridng syscall metadata.
A dedicated background thread owns the log file. For the time being, a non-blocking
logger implementation is used, but that is likely not practical for a production build
due to the necessity of the malicious syscall trapping.

This version of Capsule provides deterministic syscall visibility which will be
leveraged for building seccomp profiles.

Right now capsule-runtime runs only in linux containers.

### Running the linux container

```bash
# build container
docker compose up --build -d
# exec into container to run capsule-runtime with scripts
docker exec -it capsule-dev bash
```

### Building & Installation CLI

Once you have built the container and exec'd into it
you should be in the `/usr/src/app/` directory.
You can build the the project and install the CLI from there.
The demo scripts are located in `usr/src/app/scripts/` and
the logs will be generated inside `/tmp/`.

**Local build**:

```bash
# Binary at target/release/capsule
cargo build --release
```

**Global install** (runs from anywhere):

```bash
# Installs `capsule` into your cargo bin directory (usually ~/.cargo/bin)
cargo install --path . --force
# verify installation
capsule # should print help info
```

**Usage**:

test it out on a script

```bash
# move into scripts dir
cd scripts
# Run `capsule trace` to view options
capsule trace
# Run a script with capsule
capsule run python3 hello.py # should see `hello world` printed
# Verify an audit log
cd /tmp
cat capsule_syscalls.log
# or tail the log live
capsule tail # then run trace same as above
```
