#!/usr/bin/env bash
# test_many_providers.sh — register N providers from a JSON file, upload a
# small file, verify it round-trips, and print which providers actually
# accepted shards (proves dispatcher fan-out across many backends).
#
# This is the practical "50 places" demonstration: most entries are
# anonymous Telegraph accounts (the engine mints them at startup), plus a
# handful of file hosts. Each entry is a separate provider with its own
# rate-limit middleware.

set -uo pipefail

PORT_OS="${PORT_OS:-7878}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d -t os-many-XXXXXX)"
PROVIDERS_FILE="${PROVIDERS_FILE:-$ROOT/scripts/providers.example.json}"
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
[[ -f "$STATE_FILE" ]] && { OLD_STATE="$STATE_FILE.bak.$$"; mv "$STATE_FILE" "$OLD_STATE"; }

[[ -x "$CLI" ]]    || { echo "missing $CLI"; exit 2; }
[[ -x "$ENGINE" ]] || { echo "missing $ENGINE"; exit 2; }
[[ -f "$PROVIDERS_FILE" ]] || { echo "missing providers file: $PROVIDERS_FILE"; exit 2; }
pkill -f "target/release/openstorage" 2>/dev/null || true
sleep 1

N=$(python3 -c "import json,sys;print(len(json.load(open('$PROVIDERS_FILE'))))")
echo -e "${BLUE}==> starting engine with $N providers from $PROVIDERS_FILE${END}"
OPENSTORAGE_BIND="127.0.0.1:$PORT_OS" \
OPENSTORAGE_DATA_DIR="$WORK_DIR/engine" \
OPENSTORAGE_MODE=dev OPENSTORAGE_BACKEND="zeroxst" \
OPENSTORAGE_PROVIDERS="$PROVIDERS_FILE" \
    "$ENGINE" >"$WORK_DIR/engine.log" 2>&1 &
OS_PID=$!
for i in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$PORT_OS/v1/system/status" >/dev/null && break
    sleep 0.5
    [[ $i -eq 60 ]] && { tail "$WORK_DIR/engine.log"; echo "engine did not start"; exit 1; }
done
sleep 5  # let multi-instance loader create Telegraph accounts
export OPENSTORAGE_BASE="http://127.0.0.1:$PORT_OS"

echo -e "${BLUE}==> os providers ls${END}"
OPENSTORAGE_PASSPHRASE='many-providers' "$CLI" init >/dev/null
"$CLI" providers ls

REGISTERED=$(curl -sf "http://127.0.0.1:$PORT_OS/v1/vaults/$(python3 -c "import json;print(json.load(open('$STATE_FILE'))['vault_id'])")/providers" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d.get("providers",[])))')
echo -e "${GREEN}registered: $REGISTERED providers${END}"
[[ "$REGISTERED" -ge 5 ]] || { echo -e "${RED}expected ≥5 providers, got $REGISTERED${END}"; exit 1; }

# Telegraph caps at ~48 KiB per page, so we keep the test payload tiny.
SIZE=$((10 * 1024))
PAY="$WORK_DIR/payload.bin"
head -c "$SIZE" /dev/urandom > "$PAY"
SRC=$(python3 -c "
import hashlib
h = hashlib.blake2b(digest_size=32)
with open('$PAY','rb') as f:
    while b := f.read(65536): h.update(b)
print(h.hexdigest())
")
echo "src hash: $SRC"

echo -e "${BLUE}==> os upload (single 10 KiB inline file)${END}"
"$CLI" upload "$PAY" --as /demo.bin
"$CLI" download demo.bin --out "$WORK_DIR/dl.bin"

DST=$(python3 -c "
import hashlib
h = hashlib.blake2b(digest_size=32)
with open('$WORK_DIR/dl.bin','rb') as f:
    while b := f.read(65536): h.update(b)
print(h.hexdigest())
")
[[ "$SRC" == "$DST" ]] && echo -e "${GREEN}✅ round-trip OK across $REGISTERED providers${END}" || { echo -e "${RED}hash mismatch${END}"; exit 1; }

echo -e "${BLUE}==> engine log (provider registrations)${END}"
grep "registered provider\|providers loaded" "$WORK_DIR/engine.log" | head -20
