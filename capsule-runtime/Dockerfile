# syntax=docker/dockerfile:1

FROM rust:1.80-slim-bullseye

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libseccomp-dev \
        strace netcat socat \
        python3 python3-pip python3-venv \
        vim git curl && \
    pip install --no-cache-dir pipx && \
    pipx install poetry==1.8.2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

CMD ["bash"]
