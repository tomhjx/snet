#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=${TMP_DIR:-/tmp/snet-example-proxy}
PORT=${PORT:-18080}
TARGET_URL=${TARGET_URL:-https://example.com/}

mkdir -p "$TMP_DIR"
cd "$ROOT_DIR"

echo "Build snet"
go build -o "$TMP_DIR/snet" ./cmd/snet

echo "Start HTTPS proxy on http://127.0.0.1:$PORT"
"$TMP_DIR/snet" \
  -config configs/proxy.yaml \
  -listen ":$PORT" \
  -f json \
  -fields timestamp,protocol,target,method,host,path,status,request_body,response_body,error \
  >"$TMP_DIR/events.jsonl" 2>"$TMP_DIR/proxy.err" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT INT TERM
sleep 1

echo "Request through proxy: $TARGET_URL"
curl -fsS \
  -x "http://127.0.0.1:$PORT" \
  --cacert "$HOME/.snet/snet-ca.pem" \
  "$TARGET_URL" >/dev/null

sleep 1
echo "Captured events:"
cat "$TMP_DIR/events.jsonl"
