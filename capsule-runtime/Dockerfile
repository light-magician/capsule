
# syntax=docker/dockerfile:1

# 1. Base image with Rust (amd64/slim variant)
FROM rust:1.71-slim-buster

# 2. Install system deps for seccomp (libseccomp-dev, pkg-config)
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      libseccomp-dev \
      pkg-config \
 && rm -rf /var/lib/apt/lists/*

# 3. Create and set working directory
WORKDIR /usr/src/app

# 4. Default to an interactive shell; Cargo commands run via docker-compose
CMD ["bash"]
