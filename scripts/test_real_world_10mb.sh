#!/usr/bin/env bash
# test_real_world_10mb.sh — round-trip a 10 MiB file through the CLI, engine,
# and the public anonymous file host (litterbox.catbox.moe).
#
# Picked litterbox because:
#   * truly auth-less (no API key, no signup, no captcha)
#   * no published rate limit, no per-IP quota
#   * accepts up to 1 GiB
#   * temporary (1h–72h) which is fine for a smoke test that downloads
#     immediately after upload
#   * has been online and stable since at least 2018
#
# We chose it after probing 0x0.st (uploads disabled — AI bot spam),
# catbox.moe (paused — storage issues), transfer.sh (DNS dead), and
# bashupload.com (expired TLS cert). Litterbox is the working one as of run.
#
# Privacy: we ship ciphertext, not plaintext. The operator sees opaque bytes.

set -euo pipefail

PORT_OS="${PORT_OS:-7878}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d -t openstorage-realworld-XXXXXX)"
CLI="$ROOT/target/release/os"
ENGINE="$ROOT/target/release/openstorage"

BLUE='\033[1;34m'; GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; END='\033[0m'

OS_PID=""
cleanup() {
    set +e
    [[ -n "$OS_PID" ]] && kill "$OS_PID" 2>/dev/null
    wait 2>/dev/null
    [[ -n "${OLD_STATE:-}" ]] && mv "$OLD_STATE" "$STATE_FILE" 2>/dev/null
    [[ "${KEEP:-0}" != "1" ]] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Stash any existing CLI state.
STATE_DIR="$HOME/Library/Application Support/openstorage"
[[ -d "$HOME/.config/openstorage" ]] && STATE_DIR="$HOME/.config/openstorage"
STATE_FILE="$STATE_DIR/state.json"
if [[ -f "$STATE_FILE" ]]; then
    OLD_STATE="$STATE_FILE.bak.$$"
    mv "$STATE_FILE" "$OLD_STATE"
fi

[[ -x "$CLI" ]] || { echo "missing $CLI"; exit 2; }
[[ -x "$ENGINE" ]] || { echo "missing $ENGINE"; exit 2; }
pkill -f "target/release/openstorage" 2>/dev/null || true
sleep 1

echo -e "${BLUE}==> starting engine with public-host backend${END}"
OPENSTORAGE_BIND="127.0.0.1:$PORT_OS" \
OPENSTORAGE_DATA_DIR="$WORK_DIR/engine" \
OPENSTORAGE_MODE=dev OPENSTORAGE_BACKEND="zeroxst" \
    "$ENGINE" >"$WORK_DIR/engine.log" 2>&1 &
OS_PID=$!
for i in $(seq 1 40); do
    curl -sf "http://127.0.0.1:$PORT_OS/v1/system/status" >/dev/null && break
    sleep 0.5
    [[ $i -eq 40 ]] && { cat "$WORK_DIR/engine.log"; echo "engine did not start"; exit 1; }
done

export OPENSTORAGE_BASE="http://127.0.0.1:$PORT_OS"

echo -e "${BLUE}==> os init${END}"
OPENSTORAGE_PASSPHRASE='real-world-test' "$CLI" init

echo -e "${BLUE}==> generating 10 MiB random payload${END}"
PAYLOAD="$WORK_DIR/payload-10mb.bin"
head -c $((10 * 1024 * 1024)) /dev/urandom >"$PAYLOAD"
SRC_HASH=$(python3 -c "
import hashlib
h = hashlib.blake2b(digest_size=32)
with open('$PAYLOAD','rb') as f:
    while True:
        b = f.read(1024*1024)
        if not b: break
        h.update(b)
print(h.hexdigest())
")
echo "src hash: $SRC_HASH"

echo -e "${BLUE}==> os upload (chunked, 4 MiB shards → litterbox.catbox.moe)${END}"
T0=$(python3 -c 'import time;print(time.time())')
"$CLI" upload "$PAYLOAD" --as /real-world-10mb.bin
T1=$(python3 -c 'import time;print(time.time())')
PUT_S=$(python3 -c "print(f'{($T1)-($T0):.1f}')")
PUT_MBPS=$(python3 -c "print(f'{10.0/(($T1)-($T0)):.1f}')")
echo -e "${GREEN}upload ${PUT_S}s (~${PUT_MBPS} MB/s)${END}"

echo -e "${BLUE}==> shadow registry inspection${END}"
"$CLI" shadows ls

echo -e "${BLUE}==> os download${END}"
DOWN="$WORK_DIR/downloaded.bin"
T0=$(python3 -c 'import time;print(time.time())')
"$CLI" download real-world-10mb.bin --out "$DOWN"
T1=$(python3 -c 'import time;print(time.time())')
GET_S=$(python3 -c "print(f'{($T1)-($T0):.1f}')")
GET_MBPS=$(python3 -c "print(f'{10.0/(($T1)-($T0)):.1f}')")
echo -e "${GREEN}download ${GET_S}s (~${GET_MBPS} MB/s)${END}"

DST_HASH=$(python3 -c "
import hashlib
h = hashlib.blake2b(digest_size=32)
with open('$DOWN','rb') as f:
    while True:
        b = f.read(1024*1024)
        if not b: break
        h.update(b)
print(h.hexdigest())
")
DST_SIZE=$(wc -c <"$DOWN" | tr -d '[:space:]')

if [[ "$SRC_HASH" == "$DST_HASH" && "$DST_SIZE" == "$((10 * 1024 * 1024))" ]]; then
    echo -e "\n${GREEN}REAL-WORLD ROUND-TRIP OK${END}"
    echo "  src=$SRC_HASH"
    echo "  dst=$DST_HASH"
    echo "  size=$DST_SIZE"
    echo "  upload   ${PUT_S}s  (${PUT_MBPS} MB/s)"
    echo "  download ${GET_S}s  (${GET_MBPS} MB/s)"
    echo
    echo "Inspecting native handles stored on the public host:"
    grep "uploaded" "$WORK_DIR/engine.log" 2>/dev/null || true
    echo
    echo "  data is encrypted client-side; the public host operator sees only opaque bytes."
    exit 0
else
    echo -e "${RED}MISMATCH${END}"
    echo "  src=$SRC_HASH"
    echo "  dst=$DST_HASH"
    echo "  src_size=$((10 * 1024 * 1024))  dst_size=$DST_SIZE"
    exit 1
fi
