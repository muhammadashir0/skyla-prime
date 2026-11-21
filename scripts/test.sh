#!/usr/bin/env bash
# SKYLA PRIME — test runner
set -e
cd "$(dirname "$0")/.."
python3 -m pytest tests/ -q
