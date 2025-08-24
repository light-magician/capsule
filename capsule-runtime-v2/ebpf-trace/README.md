# eBPF tracing

this project is practice to hone the details on the eBPF
portion of the `capsule-runtime` project. This is done
solely because

### configuration

You may notice that aya makes your editor
not able to recognize your rust code. I
had to run

```bash
rustup override set nightly
```

in the project base to get the
rust-analyzer LSP to work with aya.

### running

have to mount (done at startup in Dockerfile)

```bash
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
```

verify tracepoints are active on container

```bash
grep raw_syscalls /sys/kernel/tracing/available_events
# expect: raw_syscalls:sys_enter and raw_syscalls:sys_exit
```

```bash
cargo build --release
RUST_LOG=info ./target/release/trace
```

in another shell run commands like `ls` to view syscalls logged.
