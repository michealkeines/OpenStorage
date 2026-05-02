#!/usr/bin/env bash
# baseline_1gb.sh — end-to-end test:
# 1. start the Python testbench
# 2. start the openstorage engine
# 3. generate a 1 GB random file
# 4. PUT it through the engine API → flows through plugin to testbench
# 5. GET it back, compare BLAKE3 hashes
# 6. tear everything down
#
# Defaults:
#   SIZE         payload size in bytes (default 1073741824 = 1 GiB)
#   PORT_TB      testbench port (9090)
#   PORT_OS      openstorage port (7878)
#   WORK_DIR     scratch dir (auto)

set -euo pipefail

SIZE="${SIZE:-$((1024 * 1024 * 1024))}"
PORT_TB="${PORT_TB:-9090}"
PORT_OS="${PORT_OS:-7878}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d -t openstorage-baseline-XXXXXX)}"

BLUE='\033[1;34m'; GREEN='\033[1;32m'; RED='\033[1;31m'; DIM='\033[2m'; END='\033[0m'

step() { printf "${BLUE}==> ${1}${END}\n"; }
ok()   { printf "${GREEN}✓ ${1}${END}\n"; }
die()  { printf "${RED}✗ ${1}${END}\n" >&2; exit 1; }

cleanup() {
    set +e
    if [[ -n "${OS_PID:-}" ]]; then kill "$OS_PID" 2>/dev/null; fi
    if [[ -n "${TB_PID:-}" ]]; then kill "$TB_PID" 2>/dev/null; fi
    wait 2>/dev/null
    if [[ "${KEEP:-0}" != "1" ]]; then rm -rf "$WORK_DIR"; fi
}
trap cleanup EXIT

step "scratch: $WORK_DIR"

# ─── start testbench ───────────────────────────────────────────────────────
step "starting testbench on :$PORT_TB"
cd "$ROOT/testbench"
if [[ ! -d .venv ]]; then
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
fi
rm -rf "$WORK_DIR/testbench-data"
TESTBENCH_DATA_DIR="$WORK_DIR/testbench-data" \
TESTBENCH_BIND="127.0.0.1:$PORT_TB" \
    .venv/bin/python server.py >"$WORK_DIR/testbench.log" 2>&1 &
TB_PID=$!
sleep 1
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:$PORT_TB/v1/health" >/dev/null; then
        ok "testbench up (pid=$TB_PID)"; break
    fi
    sleep 0.5
    [[ $i -eq 30 ]] && die "testbench did not start; see $WORK_DIR/testbench.log"
done

# ─── start openstorage ─────────────────────────────────────────────────────
step "starting openstorage on :$PORT_OS"
cd "$ROOT"
OPENSTORAGE_BIND="127.0.0.1:$PORT_OS" \
OPENSTORAGE_DATA_DIR="$WORK_DIR/engine" \
OPENSTORAGE_MODE=dev TESTBENCH_URL="http://127.0.0.1:$PORT_TB" \
    "$ROOT/target/release/openstorage" >"$WORK_DIR/engine.log" 2>&1 &
OS_PID=$!
sleep 1
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:$PORT_OS/v1/system/status" >/dev/null; then
        ok "engine up (pid=$OS_PID)"; break
    fi
    sleep 0.5
    [[ $i -eq 30 ]] && die "engine did not start; see $WORK_DIR/engine.log"
done

# ─── create + unlock vault ─────────────────────────────────────────────────
step "creating vault"
RESP=$(curl -sf -X POST -H 'content-type: application/json' \
    "http://127.0.0.1:$PORT_OS/v1/vaults" \
    -d '{"passphrase":"baseline-test-1gb"}')
VID=$(printf '%s' "$RESP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["vault_id"])')
ok "vault_id=$VID"

# ─── generate payload ──────────────────────────────────────────────────────
PAYLOAD="$WORK_DIR/payload.bin"
step "generating $(numfmt --to=iec --suffix=B "$SIZE" 2>/dev/null || echo "$SIZE bytes") of random data"
# Use head -c on /dev/urandom for portable behavior. /dev/urandom is fast on
# both macOS and Linux these days; for 1 GB this takes a few seconds.
head -c "$SIZE" /dev/urandom >"$PAYLOAD"
SRC_HASH=$(b3sum "$PAYLOAD" 2>/dev/null | awk '{print $1}' || python3 - <<PY
import hashlib, sys
h = hashlib.blake2b(digest_size=32)
with open("$PAYLOAD","rb") as f:
    while True:
        b = f.read(1024*1024)
        if not b: break
        h.update(b)
print(h.hexdigest())
PY
)
ok "src hash: $SRC_HASH"
ls -la "$PAYLOAD"

# ─── PUT via engine ────────────────────────────────────────────────────────
step "PUT /v1/vaults/$VID/files/big.bin (streaming)"
START=$(date +%s)
curl -sf -T "$PAYLOAD" \
    -H 'content-type: application/octet-stream' \
    "http://127.0.0.1:$PORT_OS/v1/vaults/$VID/files/big.bin" \
    -o "$WORK_DIR/put-resp.json"
T_END=$(date +%s)
PUT_ELAPSED=$((T_END - START))
PUT_THROUGHPUT=$(python3 -c "print(f'{$SIZE / max($PUT_ELAPSED,1) / 1024 / 1024:.1f}')")
ok "PUT ok in ${PUT_ELAPSED}s (~${PUT_THROUGHPUT} MB/s)"
cat "$WORK_DIR/put-resp.json" | python3 -m json.tool

# ─── object inventory on testbench ─────────────────────────────────────────
step "testbench object inventory"
curl -sf "http://127.0.0.1:$PORT_TB/v1/health" | python3 -m json.tool

# ─── GET via engine and verify ─────────────────────────────────────────────
step "GET back"
DOWNLOAD="$WORK_DIR/download.bin"
START=$(date +%s)
curl -sf "http://127.0.0.1:$PORT_OS/v1/vaults/$VID/files/big.bin" -o "$DOWNLOAD"
T_END=$(date +%s)
GET_ELAPSED=$((T_END - START))
GET_THROUGHPUT=$(python3 -c "print(f'{$SIZE / max($GET_ELAPSED,1) / 1024 / 1024:.1f}')")
ok "GET ok in ${GET_ELAPSED}s (~${GET_THROUGHPUT} MB/s)"

DOWNLOAD_SIZE=$(wc -c <"$DOWNLOAD" | tr -d '[:space:]')
[[ "$DOWNLOAD_SIZE" == "$SIZE" ]] || die "size mismatch: got $DOWNLOAD_SIZE, expected $SIZE"
ok "size matches ($DOWNLOAD_SIZE)"

DST_HASH=$(b3sum "$DOWNLOAD" 2>/dev/null | awk '{print $1}' || python3 - <<PY
import hashlib
h = hashlib.blake2b(digest_size=32)
with open("$DOWNLOAD","rb") as f:
    while True:
        b = f.read(1024*1024)
        if not b: break
        h.update(b)
print(h.hexdigest())
PY
)
[[ "$SRC_HASH" == "$DST_HASH" ]] || die "hash mismatch:\n  src $SRC_HASH\n  dst $DST_HASH"
ok "hash matches"

# ─── summary ───────────────────────────────────────────────────────────────
printf "\n${GREEN}baseline OK${END} — ${SIZE} bytes round-tripped through engine + plugin + testbench.\n"
printf "  PUT  ${PUT_ELAPSED}s  (${PUT_THROUGHPUT} MB/s)\n"
printf "  GET  ${GET_ELAPSED}s  (${GET_THROUGHPUT} MB/s)\n"
printf "  WORK_DIR=${WORK_DIR}  (KEEP=1 to keep)\n"
