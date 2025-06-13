FROM rust:1.80-slim-bullseye

# Included:
#           python3
#           python3-venv
#           lsof
#           libseccomp-dev
#           strace
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip libseccomp-dev lsof strace && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /capsule
COPY capsule-runtime/ ./capsule-runtime
COPY capsule-agents/  ./capsule-agents

# ----------- INSTALL CAPSULE GLOBALLY --------------------
# Build and install capsule globally
RUN cd capsule-runtime && \
    cargo install --path . --force

# ----------- SET UP AGENT ENVS ----------------------------
# Set up a Python virtual environment in capsule-agents base
RUN cd capsule-agents/catalog/base && \
    python3 -m venv .venv && \
    .venv/bin/pip install --upgrade pip 


CMD ["/bin/bash"]
