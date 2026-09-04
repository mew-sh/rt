#!/usr/bin/env bash
# Interoperability harness: rt against the real gost 2.12.0 binary.
#
# For each scheme, runs BOTH directions:
#   rt client -> gost server
#   gost client   -> rt server
#
# A "client" here is a plain http:// listener chained to the peer with -F, so a
# single curl through it exercises the whole path.

GOST=/tmp/gost.exe
RT=./target/release/rt.exe
TARGET_PORT=21000
BASE=21100
PIDS=()

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

spawn() { "$@" >/dev/null 2>&1 & PIDS+=($!); }

# Target the proxies fetch from.
mkdir -p /tmp/interop-www && echo "INTEROP-OK" > /tmp/interop-www/probe.txt
( cd /tmp/interop-www && python -m http.server "$TARGET_PORT" >/dev/null 2>&1 ) &
PIDS+=($!)
sleep 2

pass=0; fail=0; skipped=0

# try <label> <client-cmd...> -- runs a client on $cport and curls through it.
try() {
  local label="$1"; shift
  local cport="$1"; shift
  sleep 2
  local got
  got=$(curl -s --max-time 8 -x "http://127.0.0.1:$cport" \
        "http://127.0.0.1:$TARGET_PORT/probe.txt" 2>/dev/null)
  if [ "$got" = "INTEROP-OK" ]; then
    echo "  PASS  $label"; pass=$((pass+1))
  else
    echo "  FAIL  $label   (got: '${got:0:40}')"; fail=$((fail+1))
  fi
}

# case <scheme> -- both directions for one scheme.
case_both() {
  local scheme="$1"
  local sp=$((BASE++)) cp=$((BASE++))

  # Direction 1: rt dials a gost server.
  spawn "$GOST" -L "$scheme://127.0.0.1:$sp"
  sleep 2
  spawn "$RT" -L "http://127.0.0.1:$cp" -F "$scheme://127.0.0.1:$sp"
  try "$scheme  rt client -> gost server" "$cp"

  local sp2=$((BASE++)) cp2=$((BASE++))
  # Direction 2: gost dials an rt server.
  spawn "$RT" -L "$scheme://127.0.0.1:$sp2"
  sleep 2
  spawn "$GOST" -L "http://127.0.0.1:$cp2" -F "$scheme://127.0.0.1:$sp2"
  try "$scheme  gost client -> rt server" "$cp2"
}

echo "=== rt <-> gost 2.12.0 interoperability ==="
for s in "$@"; do
  echo "--- $s ---"
  case_both "$s"
done

echo
echo "=== $pass passed, $fail failed, $skipped skipped ==="
[ "$fail" -eq 0 ]
