# eBPF tracing

this project is practice to hone the details on the eBPF
portion of the `capsule-runtime` project. This is done
solely because

### running

have to mount (done at startup in Dockerfile)

```bash
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
```

verify tracepoint is active

```bash
grep '^syscalls:sys_enter_execve$' /sys/kernel/tracing/available_events || echo "missing tracepoint"
```

```bash
cargo build --release
RUST_LOG=info ./target/release/trace
```

in another shell run commands like `ls` to view syscalls logged.
