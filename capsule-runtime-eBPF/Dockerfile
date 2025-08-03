# Use Ubuntu for better ARM64 (M1 Mac) support
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install essential packages for eBPF development
RUN apt-get update && apt-get install -y \
    # Core build tools
    build-essential \
    clang \
    llvm \
    # eBPF essentials
    linux-headers-generic \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    # Additional eBPF tools
    bpfcc-tools \
    # SSL libraries for Rust dependencies
    libssl-dev \
    openssl \
    # Utilities
    curl \
    bash \
    git \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust with nightly toolchain for eBPF development
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Install nightly toolchain and essential eBPF tools
RUN rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly && \
    cargo install bpf-linker

# Set working directory
WORKDIR /workspace

# eBPF environment variables
ENV BPF_CLANG=clang
ENV LLVM_SYS_180_PREFIX=/usr

CMD ["/bin/bash"]
