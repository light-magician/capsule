# syntax=docker/dockerfile:1

# 1. Base image with Rust (amd64/slim variant)
FROM rust:1.80-slim-bullseye

# 2. Install system deps for seccomp + BCC + Python
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libseccomp-dev \             # for your Rust seccomp bindings
      pkg-config \                 # for building C libraries
      strace \
      netcat \
      socat \
      bpfcc-tools \                # the BPF Compiler Collection tools  [oai_citation:0‡Debian Packages](https://packages.debian.org/bullseye/misc/bpfcc-tools?utm_source=chatgpt.com)
      python3 \                    # Python 3 runtime
      python3-pip \                # pip for Python 3 packages
      python3-bpfcc \              # Python 3 bindings for BCC  [oai_citation:1‡Debian Packages](https://packages.debian.org/bullseye/source/bpfcc?utm_source=chatgpt.com)
      vim \                        # simple editor so you can “vi myscript.py” inside the container
 && rm -rf /var/lib/apt/lists/*

# 3. Create and set working directory
WORKDIR /usr/src/app

# 4. Copy and build your Rust code
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# 5. Default to an interactive shell; run your Python/BCC demos here
CMD ["bash"]
