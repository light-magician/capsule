#!/usr/bin/env python3
# trace_open.py — prints every open() syscall with the filename
# enable this file to be run with chmod +x trace_open.py
# must run priviliged to work
# bcc needs access to host's BPF subsystem
# docker run --privileged --pid=host -it capsule-runtime
# bcc should be percieved as any C dep in python would be
#
# =================================================
# TEST SEQUENCE:
# =================================================
# docker exec -it capsule-dev bash
# cd scripts
# chmod +x trace_open.py
# ./trace_open.py
#
# (now need to open a second terminal)
# docker exec -it capsule-dev bash
# echo "hello" > /tmp/foo.txt
# cat /tmp/foo.txt
# ls /etc/passwd
# exit
from bcc import BPF

program = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/unistd.h>

// raw_syscalls:sys_enter exposes { id: syscall_nr, args: [arg0,arg1,...] }
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = args->id;
    // 257 = __NR_openat on x86_64 (on ARM it may differ, but glibc maps open->openat)
    if (id == __NR_openat) {
        char fname[256];
        // args->args[1] is the 'filename' pointer for openat
        bpf_probe_read_user_str(&fname, sizeof(fname), (void *)args->args[1]);
        bpf_trace_printk("OPENAT: %s\n", fname);
    }
    return 0;
}
"""

b = BPF(text=program)
print("Tracing openat() syscalls… Ctrl-C to stop.")
b.trace_print()
