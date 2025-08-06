# eBPF Hello World

## Quick Test

```bash
# 1. Mount debugfs (if needed)
mount -t debugfs debugfs /sys/kernel/debug

# 2. Build and run eBPF program
make stop && make run &

# 3. Watch logs
cat /sys/kernel/debug/tracing/trace_pipe

# 4. Trigger (in another terminal)  
ls /tmp
```

Expected: "Hello from eBPF!" messages in trace pipe.