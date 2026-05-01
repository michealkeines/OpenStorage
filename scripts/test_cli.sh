#!/usr/bin/env bash
# test_cli.sh — drive the CLI end-to-end:
#   1. start testbench + engine
#   2. os init
#   3. os upload <file>
#   4. os ls
#   5. os download <name> --out <out>
#   6. compare BLAKE3
#
# Defaults to a 64 MB payload so the chunked path runs but the test stays fast.
# Override with SIZE=$((1024*1024*1024)) to repeat the 1 GB baseline.

set -euo pipefail
SIZE="${SIZE:-$((64 * 1024 * 1024))}"
PORT_TB="${PORT_TB:-9090}"
PORT_OS="${PORT_OS:-7878}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="${WORK_DIR:-$(mktemp -d -t openstorage-cli-XXXXXX)}"
CLI="$ROOT/target/release/os"
ENGINE="$ROOT/target/release/openstorage"

BLUE='\033[1;34m'; GREEN='\033[1;32m'; RED='\033[1;31m'; END='\033[0m'
step() { printf "${BLUE}==> %s${END}\n" "$1"; }
ok()   { printf "${GREEN}✓ %s${END}\n" "$1"; }
die()  { printf "${RED}✗ %s${END}\n" "$1" >&2; exit 1; }

cleanup() {
    set +e
    [[ -n "${OS_PID:-}" ]] && kill "$OS_PID" 2>/dev/null
    [[ -n "${TB_PID:-}" ]] && kill "$TB_PID" 2>/dev/null
    wait 2>/dev/null
    [[ -n "${OLD_STATE:-}" ]] && mv "$OLD_STATE" "$STATE_FILE" 2>/dev/null
    [[ "${KEEP:-0}" != "1" ]] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Move any existing CLI state aside so this test is self-contained.
STATE_FILE="$HOME/Library/Application Support/openstorage/state.json"
[[ -d "$HOME/.config/openstorage" ]] && STATE_FILE="$HOME/.config/openstorage/state.json"
if [[ -f "$STATE_FILE" ]]; then
    OLD_STATE="$STATE_FILE.bak.$$"
    mv "$STATE_FILE" "$OLD_STATE"
fi

step "scratch: $WORK_DIR"
[[ -x "$CLI" ]] || die "missing $CLI — run: cargo build --release"
[[ -x "$ENGINE" ]] || die "missing $ENGINE — run: cargo build --release --bin openstorage"

# ─── start testbench + engine ──────────────────────────────────────────────
step "starting testbench on :$PORT_TB"
cd "$ROOT/testbench"
[[ -d .venv ]] || (python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt)
TESTBENCH_DATA_DIR="$WORK_DIR/testbench-data" \
TESTBENCH_BIND="127.0.0.1:$PORT_TB" \
    .venv/bin/python server.py >"$WORK_DIR/testbench.log" 2>&1 &
TB_PID=$!
for i in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$PORT_TB/v1/health" >/dev/null && break
    sleep 0.5
    [[ $i -eq 30 ]] && die "testbench did not start"
done
ok "testbench up"

step "starting engine on :$PORT_OS"
OPENSTORAGE_BIND="127.0.0.1:$PORT_OS" \
OPENSTORAGE_DATA_DIR="$WORK_DIR/engine" \
TESTBENCH_URL="http://127.0.0.1:$PORT_TB" \
    "$ENGINE" >"$WORK_DIR/engine.log" 2>&1 &
OS_PID=$!
for i in $(seq 1 30); do
    curl -sf "http://127.0.0.1:$PORT_OS/v1/system/status" >/dev/null && break
    sleep 0.5
    [[ $i -eq 30 ]] && die "engine did not start"
done
ok "engine up"

export OPENSTORAGE_BASE="http://127.0.0.1:$PORT_OS"

# ─── init vault via CLI ────────────────────────────────────────────────────
step "os init"
OPENSTORAGE_PASSPHRASE='cli-test-passphrase' "$CLI" init
ok "init done"

# ─── prepare payload ───────────────────────────────────────────────────────
step "generating $(numfmt --to=iec --suffix=B "$SIZE" 2>/dev/null || echo "$SIZE bytes")"
PAYLOAD="$WORK_DIR/notes.bin"
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
ok "src hash: $SRC_HASH"

# ─── upload ────────────────────────────────────────────────────────────────
step "os upload $PAYLOAD"
"$CLI" upload "$PAYLOAD"

# ─── list ──────────────────────────────────────────────────────────────────
step "os ls"
"$CLI" ls

# ─── download ──────────────────────────────────────────────────────────────
step "os download notes.bin"
DST="$WORK_DIR/downloaded.bin"
"$CLI" download notes.bin --out "$DST"

DST_HASH=$(python3 -c "
import hashlib
h = hashlib.blake2b(digest_size=32)
with open('$DST','rb') as f:
    while True:
        b = f.read(1024*1024)
        if not b: break
        h.update(b)
print(h.hexdigest())
")
[[ "$SRC_HASH" == "$DST_HASH" ]] || die "hash mismatch:\n  src $SRC_HASH\n  dst $DST_HASH"
ok "hash matches"

DST_SIZE=$(wc -c <"$DST" | tr -d '[:space:]')
[[ "$DST_SIZE" == "$SIZE" ]] || die "size mismatch: got $DST_SIZE, want $SIZE"
ok "size matches ($DST_SIZE)"

# ─── round-trip via lock/unlock ────────────────────────────────────────────
step "os lock; os download (auto-unlock)"
"$CLI" lock
"$CLI" download notes.bin --out "$WORK_DIR/after-relock.bin"
RT_SIZE=$(wc -c <"$WORK_DIR/after-relock.bin" | tr -d '[:space:]')
[[ "$RT_SIZE" == "$SIZE" ]] || die "post-lock download size mismatch"
ok "auto-unlock + download path works"

printf "\n${GREEN}CLI baseline OK${END}\n  src=$SRC_HASH\n  dst=$DST_HASH\n"
