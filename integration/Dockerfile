FROM rust:1.80-slim-bullseye

# Included:
#           python3
#           python3-venv
#           lsof
#           libseccomp-dev
#           strace
#           curl (for Node.js install)
#           ca-certificates (for HTTPS)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip libseccomp-dev lsof strace \
        curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# ----------- INSTALL NODE.JS 20.x LTS ---------------------
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# ----------- INSTALL CLAUDE CODE CLI ----------------------
RUN npm install -g @anthropic-ai/claude-code

WORKDIR /capsule
COPY capsule-runtime/ ./capsule-runtime
COPY capsule-agents/  ./capsule-agents
COPY capsule-runtime-v2/ ./capsule-runtime-v2
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
