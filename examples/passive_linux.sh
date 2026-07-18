#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

IFACE=${IFACE:-eth0}
PROTOCOLS=${PROTOCOLS:-tcp,udp,http,mysql,domain}
FIELDS=${FIELDS:-timestamp,protocol,source_ip,source_port,destination_ip,destination_port,host,path,query,account,transaction,status,error}

if [ "$(uname -s)" != "Linux" ]; then
  echo "Passive sniff requires Linux AF_PACKET. Current OS: $(uname -s)" >&2
  echo "Use Docker on Linux: docker compose up --build snet" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Passive sniff requires root or NET_RAW/NET_ADMIN." >&2
  echo "Try: sudo IFACE=$IFACE PROTOCOLS=$PROTOCOLS $0" >&2
  exit 1
fi

echo "Passive sniff on interface=$IFACE protocols=$PROTOCOLS"
go run ./cmd/snet \
  -config configs/passive.json \
  -iface "$IFACE" \
  -P "$PROTOCOLS" \
  -f json \
  -m full \
  -fields "$FIELDS"
