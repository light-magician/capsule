# eBPF Hello World

## How This Project Works

This project demonstrates eBPF (Extended Berkeley Packet Filter) kernel tracing capabilities through a two-component architecture. **eBPF** is a kernel technology that allows safe execution of programs in kernel space without modifying kernel code. The **kernelspace program** (`src/hello-ebpf-kernelspace/`) contains the actual eBPF code that runs inside the Linux kernel - it defines a tracepoint hook that intercepts `sys_enter_openat` syscalls (triggered whenever a file is opened) and prints a message using `bpf_printk!()`. The **userspace program** (`src/hello-ebpf-userspace/`) acts as the loader and controller - it compiles the kernelspace binary, loads it into the kernel via the Aya framework, attaches it to the specific tracepoint, and keeps the attachment alive. When files are accessed (like running `ls`), the kernel automatically executes our eBPF program at the syscall entry point, demonstrating how eBPF enables real-time kernel-level observability without performance penalties or security risks.

## Manual Test

```bash
# Mount debugfs (if needed)
mount -t debugfs debugfs /sys/kernel/debug

# Build and run eBPF program
make clean
make build
make run
make stop

# Watch logs
cat /sys/kernel/debug/tracing/trace_pipe

# Trigger syscalls (in another terminal)
ls /tmp
```

This program attaches to the `syscalls:sys_enter_openat` tracepoint, so any file access operations (`ls`, `cat`, `touch`, etc.) will trigger our eBPF program and generate "Hello from eBPF! openat syscall intercepted" messages in the trace pipe.

