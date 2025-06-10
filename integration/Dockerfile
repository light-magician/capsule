# syntax=docker/dockerfile:1

FROM rust:1.80-slim-bullseye

# Python and seccomp headers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip libseccomp-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /capsule
COPY capsule-runtime/ ./capsule-runtime
COPY capsule-agents/  ./capsule-agents

# Drop into a shell by default
CMD ["/bin/bash"]
