#!/bin/bash
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/canary/server_canary
ATT=$ROOT/canary/attack_canary.py
RES=$ROOT/results
mkdir -p "$RES"
WIN=$(nm "$BIN" | awk '/ win$/{print $1}')
echo "win=0x$WIN"
for i in $(seq 1 10); do
  port=$((10000+i))
  "$BIN" "$port" >"$RES/server-$i.log" 2>&1 &
  pid=$!
  sleep 0.5
  echo "===== TRIAL $i ====="
  timeout 600 python3 "$ATT" "$port" "0x$WIN"
  rc=$?
  echo "trial $i rc=$rc"
  kill "$pid" 2>/dev/null || true
  pkill -f "server_canary $port" 2>/dev/null || true
  sleep 0.3
done
pkill -x server_canary 2>/dev/null || true
