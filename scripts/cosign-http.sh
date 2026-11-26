#!/usr/bin/env bash
# Cosign against the local HTTP registry (needs both flags).
set -euo pipefail
COSIGN_BIN="${COSIGN_BIN:-/tmp/cosign-2}"
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
exec "$COSIGN_BIN" "$@" --allow-insecure-registry --allow-http-registry
