# syntax=docker/dockerfile:1

# 1. Base image with Rust (amd64/slim variant)
FROM rust:1.80-slim-bullseye

# 2. Install system deps for seccomp (libseccomp-dev, pkg-config) + strace
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libseccomp-dev \
      pkg-config \
      strace \
      netcat \
      socat \
 && rm -rf /var/lib/apt/lists/*

# 3. Create and set working directory
WORKDIR /usr/src/app

COPY Cargo.toml Cargo.lock ./ 
COPY src ./src 

RUN cargo build --release
# 4. Default to an interactive shell; Cargo commands run via docker-compose
CMD ["bash"]
