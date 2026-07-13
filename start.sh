#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 0 ]]; then
  exec python agentic_security_platform.py "$@"
fi

exec uvicorn app:app --host 127.0.0.1 --port 8000
