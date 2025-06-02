# syntax=docker/dockerfile:1

# 1. Base image with Rust (amd64/slim variant)
FROM rust:1.80-slim-bullseye

# 2. Install system deps for seccomp + BCC + Python
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libseccomp-dev \            
      strace \
      netcat \
      socat \
      python3 \                   
      python3-pip \           
      vim \ 
 && rm -rf /var/lib/apt/lists/*

# 3. Create and set working directory
WORKDIR /usr/src/app

# 4. Copy and build your Rust code
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# 5. Default to an interactive shell; run your Python/BCC demos here
CMD ["bash"]
