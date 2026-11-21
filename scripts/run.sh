#!/usr/bin/env bash
# SKYLA PRIME — local dev launcher
set -e
cd "$(dirname "$0")/.."
python3 -m uvicorn skyla.api.app:app --host 0.0.0.0 --port 8000
