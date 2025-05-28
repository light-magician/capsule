"""
to run this program you need bcc installed on the linux server
follow a doc on bcc with regards to your specific linux build
then run:
sudo python3 hello_bpf.py
"""

from bcc import BPF

bpf_code = """
int kprobe__sys_clone(void *ctx) {
    bpf_trace_printk("Hello, World\\n");
    return 0;
}
"""

b = BPF(text=bpf_code)

b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="kprobe__sys_clone")

b.trace_print()
