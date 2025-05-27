# Multipass VM Setup Guide (macOS)

A minimal, step-by-step walkthrough for running BCC/eBPF demos inside an Ubuntu VM on your Mac—edited locally, built & traced inside Linux.

---

## 1. Install Multipass

Easy Ubuntu VMs managed via Homebrew.

```bash
brew install --cask multipass


⸻

2. Launch & configure the VM

Pick Ubuntu 22.04 “jammy,” allocate 4 GB RAM & 20 GB disk.

multipass launch \
  --name capsule-vm \
  --memory 4G \
  --disk 20G \
  jammy

⚠️ Use --memory (not deprecated --mem), and alias jammy instead of “ubuntu:22.04.”

⸻

3. Mount your project folder

Sync your local code into the VM for instant edits.

multipass mount \
  ~/nocuments/code/turtle/capsule/capsule-runtime \
  capsule-vm:/home/ubuntu/capsule-runtime


⸻

4. Enter the VM shell

Get a root-capable shell to install packages & run demos.

multipass shell capsule-vm


⸻

5. Enable Ubuntu Universe repo

Some compilers live in “universe.” This ensures clang is available.

sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository universe
sudo apt update


⸻

6. Install build tools & headers

Provide gcc, kernel headers for your running kernel, and BPF tooling.

sudo apt install -y \
  build-essential \
  linux-headers-$(uname -r) \
  clang-14 libllvm14 llvm-14-dev libclang-14-dev \
  bpfcc-tools \
  python3-bpfcc

Creates /lib/modules/$(uname -r)/build and installs BCC + Python bindings.

Create symlinks so clang & clang++ invoke Clang 14:

sudo ln -sf /usr/bin/clang-14  /usr/bin/clang
sudo ln -sf /usr/bin/clang++-14 /usr/bin/clang++


⸻

7. Prepare your tracer script

Make your Python eBPF tracer executable:

cd /home/ubuntu/capsule-runtime/scripts
chmod +x trace_open.py


⸻

8. Run the eBPF tracer

Trace openat() calls as they happen (requires root):

sudo ./trace_open.py


⸻

9. Trigger some syscalls

In a second shell on your Mac, use multipass exec to exercise file opens:

multipass exec capsule-vm -- bash -c 'echo hello > /tmp/foo.txt'
multipass exec capsule-vm -- bash -c 'cat /tmp/foo.txt'
multipass exec capsule-vm -- bash -c 'ls /etc/passwd'

You’ll see lines like:

OPENAT: /tmp/foo.txt
OPENAT: /etc/ld.so.cache
OPENAT: /etc/passwd


⸻

10. Troubleshooting notes
	•	“jammy” not found?
Run multipass find and pick an available alias.
	•	“Unable to locate package clang”?
Ensure universe is enabled, or install clang-14 explicitly.
	•	Header errors on Docker Desktop ≠ VM:
Docker’s LinuxKit lacks headers—using Multipass VM with linux-headers-$(uname -r) fixes that.

⸻

Now you have a fully working Ubuntu VM with kernel headers & BCC, editing locally on macOS and tracing in Linux without missing dependencies. Happy hacking!

```

Install Rust

```
sudo apt update
sudo apt install -y curl build-essential libseccomp-dev pkg-config
curl https://sh.rustup.rs -sSf | sh -s -- -y
source $HOME/.cargo/en
```

```
# 1. Install deps & rustup
multipass exec capsule-vm -- bash -lc \
  "sudo apt update && \
   sudo apt install -y curl build-essential libseccomp-dev pkg-config && \
   curl https://sh.rustup.rs -sSf | sh -s -- -y"

# 2. Build & run
multipass exec capsule-vm -- bash -lc \
  "source \$HOME/.cargo/env && \
   cd /home/ubuntu/capsule-runtime && \
   cargo build --release && \
   ./target/release/<your_binary_name>"
```
