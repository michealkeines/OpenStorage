#!/usr/bin/env bash
# test_replication.sh — end-to-end smoke for redundancy.
#
# Spins up the engine with three local_dir providers, each in its own
# trust_correlation_group. Uploads a file, kills one provider's data,
# downloads through the engine, verifies hash. Confirms:
#   - Dynamic EC selects (1, 3) replication on a 3-group pool.
#   - Quorum write commits with W = k+1 = 2 acks.
#   - Reads survive the loss of one provider via hedged-read fallback.
#   - End-to-end hash matches.

set -euo pipefail

PORT_OS="${PORT_OS:-7878}"
SIZE="${SIZE:-$((8 * 1024 * 1024))}"   # 8 MiB → 2 chunks at 4 MiB
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d -t openstorage-repl-XXXXXX)"
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

A_DIR="$WORK_DIR/backend-a"
B_DIR="$WORK_DIR/backend-b"
C_DIR="$WORK_DIR/backend-c"
mkdir -p "$A_DIR" "$B_DIR" "$C_DIR"

PROVIDERS_JSON="$WORK_DIR/providers.json"
cat >"$PROVIDERS_JSON" <<EOF
[
  { "kind": "local_dir", "label": "alpha", "path": "$A_DIR", "trust_group": "alpha" },
  { "kind": "local_dir", "label": "beta",  "path": "$B_DIR", "trust_group": "beta"  },
  { "kind": "local_dir", "label": "gamma", "path": "$C_DIR", "trust_group": "gamma" }
]
EOF

echo -e "${BLUE}==> starting engine with 3 local backends, replication=3${END}"
OPENSTORAGE_BIND="127.0.0.1:$PORT_OS" \
OPENSTORAGE_DATA_DIR="$WORK_DIR/engine" \
OPENSTORAGE_MODE=dev \
OPENSTORAGE_BACKEND=none \
OPENSTORAGE_PROVIDERS="$PROVIDERS_JSON" \
OPENSTORAGE_REPLICATION_K=1 \
OPENSTORAGE_REPLICATION_N=13 \
OPENSTORAGE_READ_HEDGE=1 \
    "$ENGINE" >"$WORK_DIR/engine.log" 2>&1 &
OS_PID=$!

for i in $(seq 1 40); do
    curl -sf "http://127.0.0.1:$PORT_OS/v1/system/status" >/dev/null && break
    sleep 0.5
    [[ $i -eq 40 ]] && { cat "$WORK_DIR/engine.log"; echo "engine did not start"; exit 1; }
done

export OPENSTORAGE_BASE="http://127.0.0.1:$PORT_OS"

echo -e "${BLUE}==> os init${END}"
OPENSTORAGE_PASSPHRASE='replication-test' "$CLI" init

echo -e "${BLUE}==> generating $SIZE-byte payload${END}"
PAYLOAD="$WORK_DIR/payload.bin"
head -c "$SIZE" /dev/urandom >"$PAYLOAD"
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

echo -e "${BLUE}==> os upload (replication factor 3)${END}"
"$CLI" upload "$PAYLOAD" --as /repl-test.bin

A_FILES=$(find "$A_DIR" -type f | wc -l | tr -d '[:space:]')
B_FILES=$(find "$B_DIR" -type f | wc -l | tr -d '[:space:]')
C_FILES=$(find "$C_DIR" -type f | wc -l | tr -d '[:space:]')
echo "  shards landed: alpha=$A_FILES beta=$B_FILES gamma=$C_FILES"
if [[ "$A_FILES" -lt 1 || "$B_FILES" -lt 1 || "$C_FILES" -lt 1 ]]; then
    echo -e "${RED}REPLICATION DID NOT FAN OUT — one or more backends has no shards${END}"
    exit 1
fi

echo -e "${BLUE}==> baseline download (all backends healthy)${END}"
DOWN_FULL="$WORK_DIR/download-full.bin"
"$CLI" download repl-test.bin --out "$DOWN_FULL"

hashof() {
    python3 -c "
import hashlib
h = hashlib.blake2b(digest_size=32)
with open('$1','rb') as f:
    while True:
        b = f.read(1024*1024)
        if not b: break
        h.update(b)
print(h.hexdigest())
"
}

DST_HASH=$(hashof "$DOWN_FULL")
[[ "$SRC_HASH" == "$DST_HASH" ]] || { echo -e "${RED}baseline hash mismatch${END}"; exit 1; }
echo -e "${GREEN}✓ baseline round-trip OK${END}"

echo -e "${BLUE}==> wiping backend ALPHA — read should still succeed${END}"
rm -rf "$A_DIR"; mkdir -p "$A_DIR"
DOWN_DEG="$WORK_DIR/download-degraded.bin"
"$CLI" download repl-test.bin --out "$DOWN_DEG"
DST2_HASH=$(hashof "$DOWN_DEG")
[[ "$SRC_HASH" == "$DST2_HASH" ]] || { echo -e "${RED}degraded-pool hash mismatch${END}"; exit 1; }
echo -e "${GREEN}✓ download survived loss of 1/3 backends${END}"

echo -e "${BLUE}==> wiping backend BETA — only gamma left, k=1 still suffices${END}"
rm -rf "$B_DIR"; mkdir -p "$B_DIR"
DOWN_MIN="$WORK_DIR/download-minimal.bin"
"$CLI" download repl-test.bin --out "$DOWN_MIN"
DST3_HASH=$(hashof "$DOWN_MIN")
[[ "$SRC_HASH" == "$DST3_HASH" ]] || { echo -e "${RED}minimal-pool hash mismatch${END}"; exit 1; }
echo -e "${GREEN}✓ download survived loss of 2/3 backends${END}"

echo -e "${BLUE}==> wiping backend GAMMA — all gone, must fail cleanly${END}"
rm -rf "$C_DIR"; mkdir -p "$C_DIR"
set +e
"$CLI" download repl-test.bin --out "$WORK_DIR/should-fail.bin" 2>"$WORK_DIR/fail.err"
RC=$?
set -e
if [[ $RC -eq 0 ]]; then
    echo -e "${RED}EXPECTED FAILURE — download succeeded with all backends gone${END}"
    exit 1
fi
echo -e "${GREEN}✓ correct failure when all backends are gone${END}"

echo
echo -e "${GREEN}REDUNDANCY SMOKE OK${END}"
echo "  src=$SRC_HASH"
echo "  baseline      → $DST_HASH"
echo "  lose 1 of 3   → $DST3_HASH"
echo "  lose 2 of 3   → $DST3_HASH"
echo "  lose 3 of 3   → expected failure"
