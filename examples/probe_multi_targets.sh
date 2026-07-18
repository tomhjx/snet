#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

TARGETS=${TARGETS:-127.0.0.1,localhost}
PROTOCOLS=${PROTOCOLS:-ip,domain}

echo "Probe multiple targets once"
echo "targets=$TARGETS protocols=$PROTOCOLS"

go run ./cmd/snet \
  -config configs/probe.yaml \
  -targets "$TARGETS" \
  -P "$PROTOCOLS" \
  -probe-interval 0s \
  -count 1 \
  -f json \
  -fields timestamp,protocol,target,domain,addresses,success,error
