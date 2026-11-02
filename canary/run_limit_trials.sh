#!/bin/bash
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/canary/server_canary_limit
ATT=$ROOT/canary/attack_canary.py
RES=$ROOT/results
mkdir -p "$RES"
WIN=$(nm "$BIN" | awk '/ win$/{print $1}')
echo "win=0x$WIN"
for filter in 0 1; do
  for N in 1 4 16 64; do
    succ=0
    for t in $(seq 1 10); do
      port=$((11000 + filter * 1000 + N * 10 + t))
      "$BIN" "$port" "$N" "$filter" >"$RES/srv-$filter-$N-$t.log" 2>&1 &
      pid=$!
      sleep 0.3
      timeout 180 python3 "$ATT" "$port" "0x$WIN" >"$RES/att-$filter-$N-$t.log" 2>&1
      rc=$?
      if [ "$rc" -eq 0 ]; then succ=$((succ + 1)); fi
      kill "$pid" 2>/dev/null || true
      pkill -f "server_canary_limit $port" 2>/dev/null || true
      sleep 0.1
    done
    echo "filter=$filter N=$N success=$succ/10"
  done
done
