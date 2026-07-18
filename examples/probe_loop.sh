#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

TARGETS=${TARGETS:-127.0.0.1,localhost}
PROTOCOLS=${PROTOCOLS:-ip,domain}
INTERVAL=${INTERVAL:-2s}
COUNT=${COUNT:-3}

echo "Probe targets repeatedly"
echo "targets=$TARGETS protocols=$PROTOCOLS interval=$INTERVAL count=$COUNT"

go run ./cmd/snet \
  -config configs/probe.yaml \
  -targets "$TARGETS" \
  -P "$PROTOCOLS" \
  -probe-interval "$INTERVAL" \
  -count "$COUNT" \
  -f json \
  -fields timestamp,protocol,target,domain,addresses,success,error
