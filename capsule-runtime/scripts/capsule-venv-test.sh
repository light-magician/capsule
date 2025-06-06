#!/usr/bin/env bash
set -euo pipefail

python3 -m venv .venv
source .venv/bin/activate
capsule trace .venv/bin/python3 hello.py

# poetry init --name=poetrydemo -n --quiet
# poetry run capsule trace poetry run python hello.py
