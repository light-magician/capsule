#!/bin/bash
set -e

echo "🧪 eBPF Hello World Test"
echo "========================"

# Build the project
echo "1. Building eBPF project..."
make build

echo ""
echo "2. Starting eBPF program in background..."
./target/debug/hello-eBPF &
EBPF_PID=$!

# Give it time to attach
sleep 2

echo "3. eBPF program running (PID: $EBPF_PID)"
echo "   - Attached to sys_enter_openat tracepoint"
echo "   - Will log messages when files are opened"

echo ""
echo "4. Testing tracepoint triggers..."
echo "   Running file operations to trigger syscalls..."

# Trigger some openat syscalls
ls /tmp > /dev/null
cat /etc/hostname > /dev/null  
touch /tmp/ebpf-test-file
ls -la /usr > /dev/null
rm -f /tmp/ebpf-test-file

echo "   ✅ Triggered multiple file operations"

echo ""
echo "5. Checking kernel logs for eBPF messages..."
echo "   Looking for 'Hello from eBPF' in recent kernel messages:"
echo ""

# Check for our messages in kernel log
dmesg | grep -i "hello from ebpf" | tail -5 || echo "   ❌ No eBPF messages found in kernel log"

echo ""
echo "6. Alternative: Check trace pipe output..."
echo "   (This may show more detailed tracing info)"
timeout 1 cat /sys/kernel/debug/tracing/trace_pipe 2>/dev/null | grep -i hello || echo "   No trace pipe output found"

echo ""
echo "7. Cleaning up..."
kill $EBPF_PID 2>/dev/null || true
wait $EBPF_PID 2>/dev/null || true

echo ""
echo "🏁 Test complete!"
echo ""
echo "Expected behavior:"
echo "   - eBPF program should attach successfully"
echo "   - File operations should trigger the tracepoint"  
echo "   - 'Hello from eBPF!' messages should appear in kernel logs"
echo ""
echo "If you don't see messages, try:"
echo "   - dmesg | grep -i hello"
echo "   - cat /sys/kernel/debug/tracing/trace_pipe (in another terminal)"