#!/usr/bin/env bash
# test_messaging_backend.sh — round-trip a 5 MiB file through the CLI →
# engine → a messaging-app backend (Telegram or Discord), depending on
# which env vars are set.
#
#   Telegram: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
#       1. Talk to @BotFather, /newbot, save the token.
#       2. Send any message to your bot, then GET
#          https://api.telegram.org/bot<TOKEN>/getUpdates
#          and copy the chat.id field.
#
#   Discord:  DISCORD_WEBHOOK_URL
#       Channel → Integrations → Webhooks → New Webhook → Copy URL.
#
# If neither is set, the script picks the smallest non-zero set or exits
# with a helpful message.
#
# Why 5 MiB: chunked path runs (1 chunk at 4 MiB, second at 1 MiB) which
# exercises both single- and multi-chunk handling. Both backends have
# size limits (Telegram 50 MiB / Discord 25 MiB) so we stay polite.

set -uo pipefail

PORT_OS="${PORT_OS:-7878}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d -t openstorage-msg-XXXXXX)"
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

# Pick a backend based on env vars.
BACKEND=""
if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
    BACKEND="telegram"
elif [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
    BACKEND="discord"
fi
if [[ -z "$BACKEND" ]]; then
    echo -e "${YELLOW}no messaging backend env vars set${END}"
    echo "  Telegram: export TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=..."
    echo "  Discord:  export DISCORD_WEBHOOK_URL=..."
    exit 78  # EX_CONFIG
fi
echo -e "${BLUE}==> backend: $BACKEND${END}"

# Stash CLI state.
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

echo -e "${BLUE}==> starting engine with backend=$BACKEND${END}"
OPENSTORAGE_BIND="127.0.0.1:$PORT_OS" \
OPENSTORAGE_DATA_DIR="$WORK_DIR/engine" \
OPENSTORAGE_MODE=dev OPENSTORAGE_BACKEND="$BACKEND" \
    "$ENGINE" >"$WORK_DIR/engine.log" 2>&1 &
OS_PID=$!
for i in $(seq 1 40); do
    curl -sf "http://127.0.0.1:$PORT_OS/v1/system/status" >/dev/null && break
    sleep 0.5
    [[ $i -eq 40 ]] && { cat "$WORK_DIR/engine.log"; echo "engine did not start"; exit 1; }
done

export OPENSTORAGE_BASE="http://127.0.0.1:$PORT_OS"

OPENSTORAGE_PASSPHRASE='msg-backend-test' "$CLI" init

PAYLOAD="$WORK_DIR/payload-5m.bin"
head -c $((5 * 1024 * 1024)) /dev/urandom >"$PAYLOAD"
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

T0=$(python3 -c 'import time;print(time.time())')
"$CLI" upload "$PAYLOAD" --as /msg-test-5mb.bin
T1=$(python3 -c 'import time;print(time.time())')
PUT_S=$(python3 -c "print(f'{($T1)-($T0):.1f}')")

DOWN="$WORK_DIR/downloaded.bin"
T0=$(python3 -c 'import time;print(time.time())')
"$CLI" download msg-test-5mb.bin --out "$DOWN"
T1=$(python3 -c 'import time;print(time.time())')
GET_S=$(python3 -c "print(f'{($T1)-($T0):.1f}')")

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

if [[ "$SRC_HASH" == "$DST_HASH" && "$DST_SIZE" == "$((5 * 1024 * 1024))" ]]; then
    echo -e "\n${GREEN}MESSAGING-BACKEND ROUND-TRIP OK ($BACKEND)${END}"
    echo "  src=$SRC_HASH"
    echo "  dst=$DST_HASH"
    echo "  size=$DST_SIZE"
    echo "  upload   ${PUT_S}s"
    echo "  download ${GET_S}s"
    exit 0
else
    echo -e "${RED}MISMATCH${END}"
    echo "  src=$SRC_HASH  dst=$DST_HASH  src_size=$((5*1024*1024))  dst_size=$DST_SIZE"
    exit 1
fi
