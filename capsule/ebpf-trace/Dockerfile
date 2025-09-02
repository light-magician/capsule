# Dockerfile — Aya eBPF dev image (arm64-friendly), no bpftool

FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /workspace

# Build + eBPF tooling (no bpftool)
RUN apt-get update && apt-get install -y \
    build-essential clang llvm pkg-config git curl bash \
    libelf-dev zlib1g-dev libssl-dev openssl \
    bpfcc-tools \
    linux-headers-generic \
    man-db manpages manpages-dev less \
  && rm -rf /var/lib/apt/lists/*

# Rust (stable + nightly for eBPF targets)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup toolchain install nightly && \
    rustup component add rust-src --toolchain nightly && \
    cargo install bpf-linker

# Entrypoint mounts bpffs/tracefs at runtime (requires --privileged and /sys mounted)
RUN printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'echo "[entrypoint] Setting up eBPF filesystems..."' \
  'mkdir -p /sys/fs/bpf /sys/kernel/tracing' \
  'mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf || true' \
  'mountpoint -q /sys/kernel/tracing || mount -t tracefs tracefs /sys/kernel/tracing || true' \
  'echo "[entrypoint] Ready. Exec: $*"' \
  'exec "$@"' \
  > /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
