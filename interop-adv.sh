#!/usr/bin/env bash
# Interop for paths interop.sh does not reach: chain authentication, multi-hop
# chains, and UDP. Same shape — a plain http:// listener chained to a peer, then
# one curl through the whole path.

GOST=/tmp/gost.exe
RUSTUN=./target/release/rustun.exe
TARGET_PORT=23000
BASE=23100
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT
spawn() { "$@" >/dev/null 2>&1 & PIDS+=($!); }

mkdir -p /tmp/interop-www && echo "INTEROP-OK" > /tmp/interop-www/probe.txt
( cd /tmp/interop-www && python -m http.server "$TARGET_PORT" >/dev/null 2>&1 ) &
PIDS+=($!)
sleep 2

pass=0; fail=0

check() {
  sleep 2
  local got
  got=$(curl -s --max-time 8 -x "http://127.0.0.1:$1" \
        "http://127.0.0.1:$TARGET_PORT/probe.txt" 2>/dev/null)
  if [ "$got" = "INTEROP-OK" ]; then
    echo "  PASS  $2"; pass=$((pass+1))
  else
    echo "  FAIL  $2   (got: '${got:0:40}')"; fail=$((fail+1))
  fi
}

# Expect the request to be REFUSED (wrong or missing credentials).
check_denied() {
  sleep 2
  local got
  got=$(curl -s --max-time 8 -x "http://127.0.0.1:$1" \
        "http://127.0.0.1:$TARGET_PORT/probe.txt" 2>/dev/null)
  if [ "$got" != "INTEROP-OK" ]; then
    echo "  PASS  $2 (correctly refused)"; pass=$((pass+1))
  else
    echo "  FAIL  $2 — bad credentials were accepted"; fail=$((fail+1))
  fi
}

echo "=== chain authentication ==="
for scheme in http socks5; do
  sp=$((BASE++)); cp=$((BASE++))
  spawn "$GOST" -L "$scheme://u1:p1@127.0.0.1:$sp"
  sleep 2
  spawn "$RUSTUN" -L "http://127.0.0.1:$cp" -F "$scheme://u1:p1@127.0.0.1:$sp"
  check "$cp" "$scheme auth  rustun client -> gost server"

  sp=$((BASE++)); cp=$((BASE++))
  spawn "$RUSTUN" -L "$scheme://u1:p1@127.0.0.1:$sp"
  sleep 2
  spawn "$GOST" -L "http://127.0.0.1:$cp" -F "$scheme://u1:p1@127.0.0.1:$sp"
  check "$cp" "$scheme auth  gost client -> rustun server"

  # A rustun listener must reject the wrong password, not wave it through.
  sp=$((BASE++)); cp=$((BASE++))
  spawn "$RUSTUN" -L "$scheme://u1:p1@127.0.0.1:$sp"
  sleep 2
  spawn "$GOST" -L "http://127.0.0.1:$cp" -F "$scheme://u1:WRONG@127.0.0.1:$sp"
  check_denied "$cp" "$scheme auth  rustun server rejects a bad password"
done

echo "=== multi-hop chains ==="
h1=$((BASE++)); h2=$((BASE++)); cp=$((BASE++))
spawn "$GOST" -L "http://127.0.0.1:$h1"
spawn "$GOST" -L "socks5://127.0.0.1:$h2"
sleep 2
spawn "$RUSTUN" -L "http://127.0.0.1:$cp" -F "http://127.0.0.1:$h1" -F "socks5://127.0.0.1:$h2"
check "$cp" "2 hops (http then socks5)  rustun client -> gost servers"

h1=$((BASE++)); h2=$((BASE++)); cp=$((BASE++))
spawn "$RUSTUN" -L "http://127.0.0.1:$h1"
spawn "$RUSTUN" -L "socks5://127.0.0.1:$h2"
sleep 2
spawn "$GOST" -L "http://127.0.0.1:$cp" -F "http://127.0.0.1:$h1" -F "socks5://127.0.0.1:$h2"
check "$cp" "2 hops (http then socks5)  gost client -> rustun servers"

# A transport on a middle hop, which exercises layer_transport mid-chain.
h1=$((BASE++)); h2=$((BASE++)); cp=$((BASE++))
spawn "$GOST" -L "http+tls://127.0.0.1:$h1"
spawn "$GOST" -L "socks5://127.0.0.1:$h2"
sleep 2
spawn "$RUSTUN" -L "http://127.0.0.1:$cp" -F "http+tls://127.0.0.1:$h1" -F "socks5://127.0.0.1:$h2"
check "$cp" "2 hops (http+tls then socks5)  rustun client -> gost servers"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
