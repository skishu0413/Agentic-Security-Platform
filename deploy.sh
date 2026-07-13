#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="agentic-security-platform"
CONTAINER_PORT="8000"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to deploy this service." >&2
  exit 1
fi

docker build -t "$IMAGE_NAME" .
docker run -d --name "$IMAGE_NAME" -p "$CONTAINER_PORT:8000" "$IMAGE_NAME"
echo "Service started on http://localhost:$CONTAINER_PORT"
