#!/usr/bin/env bash
# cli_flow_tests.sh — exercise every CLI-reachable flow against a fresh
# engine + testbench, with real data. Generates docs/CLI_FLOW_TEST_RESULTS.md
# as it runs.
#
# Coverage is bounded by what the engine implements today: vault lifecycle
# (F-VL-1, F-VL-2, F-VL-3), file operations (F-FL-1, F-FL-2, F-FL-3, F-FL-4,
# F-FL-6), and state-boundary edge cases. Multi-device, sharing, snapshot
# replication, repair scheduling, and identity rotation are out of scope —
# the engine has skeletons but no CLI surface yet.
#
# Usage:
#     scripts/cli_flow_tests.sh
# Env:
#     PORT_TB / PORT_OS  — override default 9090 / 7878
#     KEEP=1             — keep the scratch dir for inspection

set -uo pipefail

PORT_TB="${PORT_TB:-9090}"
PORT_OS="${PORT_OS:-7878}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d -t openstorage-flowtest-XXXXXX)"
CLI="$ROOT/target/release/os"
ENGINE="$ROOT/target/release/openstorage"
REPORT="$ROOT/docs/CLI_FLOW_TEST_RESULTS.md"
mkdir -p "$ROOT/docs"

BLUE='\033[1;34m'; GREEN='\033[1;32m'; RED='\033[1;31m'; DIM='\033[2m'; END='\033[0m'

# ─── lifecycle ─────────────────────────────────────────────────────────────
TB_PID=""; OS_PID=""
cleanup() {
    set +e
    [[ -n "$OS_PID" ]] && kill "$OS_PID" 2>/dev/null
    [[ -n "$TB_PID" ]] && kill "$TB_PID" 2>/dev/null
    wait 2>/dev/null
    [[ -n "${OLD_STATE:-}" ]] && mv "$OLD_STATE" "$STATE_FILE" 2>/dev/null
    [[ "${KEEP:-0}" != "1" ]] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Move any existing CLI state aside.
STATE_DIR="$HOME/Library/Application Support/openstorage"
[[ -d "$HOME/.config/openstorage" ]] && STATE_DIR="$HOME/.config/openstorage"
STATE_FILE="$STATE_DIR/state.json"
if [[ -f "$STATE_FILE" ]]; then
    OLD_STATE="$STATE_FILE.bak.$$"
    mv "$STATE_FILE" "$OLD_STATE"
fi

# Pre-flight.
[[ -x "$CLI" ]]    || { echo "missing $CLI — build first";    exit 2; }
[[ -x "$ENGINE" ]] || { echo "missing $ENGINE — build first"; exit 2; }
pkill -f "testbench/server.py"        2>/dev/null
pkill -f "target/release/openstorage" 2>/dev/null
sleep 1

# ─── start backends ────────────────────────────────────────────────────────
echo -e "${BLUE}==> setup${END}"
cd "$ROOT/testbench"
if [[ ! -d .venv ]]; then
    python3 -m venv .venv >/dev/null
    .venv/bin/pip install -q -r requirements.txt
fi
TESTBENCH_DATA_DIR="$WORK_DIR/testbench-data" \
TESTBENCH_BIND="127.0.0.1:$PORT_TB" \
    .venv/bin/python server.py >"$WORK_DIR/testbench.log" 2>&1 &
TB_PID=$!
for i in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT_TB/v1/health" >/dev/null && break; sleep 0.5; done

OPENSTORAGE_BIND="127.0.0.1:$PORT_OS" \
OPENSTORAGE_DATA_DIR="$WORK_DIR/engine" \
OPENSTORAGE_MODE=dev TESTBENCH_URL="http://127.0.0.1:$PORT_TB" \
    "$ENGINE" >"$WORK_DIR/engine.log" 2>&1 &
OS_PID=$!
for i in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT_OS/v1/system/status" >/dev/null && break; sleep 0.5; done

export OPENSTORAGE_BASE="http://127.0.0.1:$PORT_OS"
echo -e "${GREEN}backends up${END} (testbench=$TB_PID engine=$OS_PID)"

# ─── report header ─────────────────────────────────────────────────────────
GIT_REV=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "no-git")
NOW=$(date "+%Y-%m-%d %H:%M:%S %Z")
TMP_REPORT="$WORK_DIR/report.md"
> "$TMP_REPORT"

# ─── test runner ───────────────────────────────────────────────────────────
TOTAL=0; PASS=0; FAIL=0
declare -a SUMMARY_ROWS=()

# tc_run TC-ID "description" "Flow ref" command_block
# command_block is a function that:
#   - sets RESULT="..." with the captured command output
#   - returns 0 for pass, non-zero for fail
#   - on fail, sets WHY="reason"
tc_run() {
    local id=$1 desc=$2 flow=$3 fn=$4
    TOTAL=$((TOTAL + 1))
    RESULT=""
    WHY=""
    local rc=0
    "$fn"; rc=$?
    local status icon
    if [[ $rc -eq 0 ]]; then
        PASS=$((PASS + 1)); status="PASS"; icon="✅"
        printf "  ${GREEN}✅ %-7s${END} %s\n" "$id" "$desc"
    else
        FAIL=$((FAIL + 1)); status="FAIL"; icon="❌"
        printf "  ${RED}❌ %-7s${END} %s ${DIM}(%s)${END}\n" "$id" "$desc" "$WHY"
    fi
    SUMMARY_ROWS+=("$icon|$id|$flow|$desc|$status")
    {
        echo
        echo "### $id — $desc"
        echo
        echo "- **Flow:** $flow"
        echo "- **Status:** $icon $status"
        if [[ -n "$WHY" ]]; then echo "- **Why:** $WHY"; fi
        echo
        echo "<details><summary>output</summary>"
        echo
        echo '```'
        printf '%s\n' "$RESULT"
        echo '```'
        echo
        echo "</details>"
    } >> "$TMP_REPORT"
}

# Helpers used inside test functions ----------------------------------------
ASSERT_LAST_OUT=""
run() {
    # Run a command, capture stdout+stderr, append to RESULT, set ASSERT_LAST_OUT.
    local out; local rc
    out=$("$@" 2>&1); rc=$?
    ASSERT_LAST_OUT="$out"
    RESULT+="$ $*"$'\n'"$out"$'\n'
    return $rc
}
run_status() {
    # Run a command, capture exit code, allow non-zero. Sets ASSERT_LAST_RC.
    local out; out=$("$@" 2>&1); ASSERT_LAST_RC=$?
    ASSERT_LAST_OUT="$out"
    RESULT+="$ $*"$'\n'"$out"$'\n(exit code: '"$ASSERT_LAST_RC"$')'$'\n'
}
fail() { WHY="$1"; return 1; }
have_substr() { echo "$ASSERT_LAST_OUT" | grep -qF "$1"; }
have_regex() { echo "$ASSERT_LAST_OUT" | grep -qE "$1"; }
file_size() { wc -c <"$1" | tr -d '[:space:]'; }
b3() {
    python3 - <<PY
import hashlib
h = hashlib.blake2b(digest_size=32)
with open("$1","rb") as f:
    while True:
        b = f.read(1024*1024)
        if not b: break
        h.update(b)
print(h.hexdigest())
PY
}
gen_file() {
    # gen_file <path> <size> [<pattern>]: pattern = random|zeros|repeat:<byte>
    local path=$1 size=$2 pattern=${3:-random}
    case $pattern in
        random) head -c "$size" /dev/urandom >"$path" ;;
        zeros)  head -c "$size" /dev/zero    >"$path" ;;
        repeat:*)
            local byte=${pattern#repeat:}
            python3 -c "
import sys
data = bytes([${byte}]) * ${size}
sys.stdout.buffer.write(data)
" >"$path" ;;
        *) echo "unknown pattern: $pattern" >&2; return 1 ;;
    esac
}

# ─── TEST CASES ════════════════════════════════════════════════════════════

tc_001() {
    run "$CLI" status || true
    have_substr '"state": "uncreated"' || { fail "expected uncreated state"; return 1; }
    have_substr "no saved vault"        || { fail "expected 'no saved vault' hint"; return 1; }
    return 0
}

tc_002() {
    OPENSTORAGE_PASSPHRASE='flow-tests' run "$CLI" init || { fail "init failed"; return 1; }
    have_regex 'vault [0-9a-f-]+ created' || { fail "missing 'vault X created'"; return 1; }
    [[ -f "$STATE_FILE" ]] || { fail "state.json not created"; return 1; }
    return 0
}

tc_003() {
    if [[ "$(uname)" == "Darwin" ]] || [[ "$(uname)" == "Linux" ]]; then
        local mode
        mode=$(stat -f '%Lp' "$STATE_FILE" 2>/dev/null || stat -c '%a' "$STATE_FILE" 2>/dev/null)
        RESULT+="state.json mode: $mode\n"
        [[ "$mode" == "600" ]] || { fail "expected mode 600, got $mode"; return 1; }
    fi
    return 0
}

tc_004() {
    run "$CLI" status || { fail "status failed"; return 1; }
    have_substr '"state": "unlocked"' || { fail "expected unlocked"; return 1; }
    return 0
}

tc_005() {
    run "$CLI" lock   || { fail "lock failed"; return 1; }
    have_substr 'locked' || { fail "missing locked acknowledgement"; return 1; }
    run "$CLI" status || { fail "status failed"; return 1; }
    have_substr '"state": "locked"' || { fail "state did not transition to locked"; return 1; }
    return 0
}

tc_006() {
    run "$CLI" unlock || { fail "unlock failed"; return 1; }
    have_substr 'unlocked' || { fail "missing unlocked acknowledgement"; return 1; }
    run "$CLI" status || { fail "status failed"; return 1; }
    have_substr '"state": "unlocked"' || { fail "state did not transition to unlocked"; return 1; }
    return 0
}

tc_007() {
    # Manually corrupt the saved passphrase, attempt unlock, then restore it.
    local original
    original=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['passphrase'])" "$STATE_FILE")
    python3 - <<PY
import json
p = "$STATE_FILE"
data = json.load(open(p))
data["passphrase"] = "WRONG-passphrase"
json.dump(data, open(p, "w"), indent=2)
PY
    run "$CLI" lock || true
    run_status "$CLI" unlock
    [[ $ASSERT_LAST_RC -ne 0 ]] || { restore_pass "$original"; fail "expected non-zero exit"; return 1; }
    have_substr "unlock failed" || { restore_pass "$original"; fail "missing 'unlock failed' message"; return 1; }
    restore_pass "$original"
    run "$CLI" unlock || { fail "could not restore unlocked state"; return 1; }
    return 0
}
restore_pass() {
    local p="$1"
    python3 - "$1" <<PY
import json, sys
state_path = "$STATE_FILE"
data = json.load(open(state_path))
data["passphrase"] = sys.argv[1]
json.dump(data, open(state_path, "w"), indent=2)
PY
}

# ─── file ops: empty / inline / boundary / chunked / large ────────────────

tc_010() {
    # Empty file
    local f="$WORK_DIR/empty.bin"; : >"$f"
    run "$CLI" upload "$f" --as /empty.bin || { fail "upload failed"; return 1; }
    have_regex 'uploaded 0 B|uploaded 0\.0 B' || { fail "expected zero-byte upload"; return 1; }
    local out="$WORK_DIR/empty.dl"
    run "$CLI" download empty.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(file_size "$out")" == "0" ]] || { fail "downloaded size != 0"; return 1; }
    return 0
}

tc_011() {
    # Tiny inline file
    local f="$WORK_DIR/tiny.txt"; printf 'hello CLI flow test\n' >"$f"
    run "$CLI" upload "$f" || { fail "upload failed"; return 1; }
    local src=$(b3 "$f")
    local out="$WORK_DIR/tiny.dl"
    run "$CLI" download tiny.txt --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$src" ]] || { fail "hash mismatch"; return 1; }
    return 0
}

tc_012() {
    # Inline-threshold boundary (exactly 16 KiB)
    local f="$WORK_DIR/boundary-16k.bin"
    gen_file "$f" 16384 random
    run "$CLI" upload "$f" --as /boundary-16k.bin || { fail "upload failed"; return 1; }
    local src=$(b3 "$f")
    local out="$WORK_DIR/boundary-16k.dl"
    run "$CLI" download boundary-16k.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$src" ]] || { fail "hash mismatch at 16 KiB boundary"; return 1; }
    return 0
}

tc_013() {
    # 16 KiB + 1 byte → forces chunked path
    local f="$WORK_DIR/just-over-16k.bin"
    gen_file "$f" $((16 * 1024 + 1)) random
    run "$CLI" upload "$f" --as /just-over-16k.bin || { fail "upload failed"; return 1; }
    local src=$(b3 "$f")
    local out="$WORK_DIR/just-over-16k.dl"
    run "$CLI" download just-over-16k.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$src" ]] || { fail "hash mismatch over 16 KiB"; return 1; }
    return 0
}

tc_014() {
    # Multi-chunk file (8 MiB → 2 chunks at 4 MiB)
    local f="$WORK_DIR/multi-chunk.bin"
    gen_file "$f" $((8 * 1024 * 1024)) random
    run "$CLI" upload "$f" --as /multi-chunk.bin || { fail "upload failed"; return 1; }
    local src=$(b3 "$f")
    local out="$WORK_DIR/multi-chunk.dl"
    run "$CLI" download multi-chunk.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$src" ]] || { fail "hash mismatch on 8 MiB"; return 1; }
    return 0
}

tc_015() {
    # 4 MiB exact (one chunk)
    local f="$WORK_DIR/exact-chunk.bin"
    gen_file "$f" $((4 * 1024 * 1024)) random
    run "$CLI" upload "$f" --as /exact-chunk.bin || { fail "upload failed"; return 1; }
    local src=$(b3 "$f")
    local out="$WORK_DIR/exact-chunk.dl"
    run "$CLI" download exact-chunk.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$src" ]] || { fail "hash mismatch on 4 MiB chunk-aligned"; return 1; }
    return 0
}

tc_016() {
    # Repeated upload to same name should preserve file_id
    local f1="$WORK_DIR/over1.bin"
    local f2="$WORK_DIR/over2.bin"
    gen_file "$f1" 32768 random
    gen_file "$f2" 32768 random
    run "$CLI" upload "$f1" --as /over.bin || { fail "first upload failed"; return 1; }
    run "$CLI" stat over.bin || { fail "stat after first upload failed"; return 1; }
    local id1=$(echo "$ASSERT_LAST_OUT" | awk '/file_id:/ {print $2}')
    run "$CLI" upload "$f2" --as /over.bin || { fail "second upload failed"; return 1; }
    run "$CLI" stat over.bin || { fail "stat after second upload failed"; return 1; }
    local id2=$(echo "$ASSERT_LAST_OUT" | awk '/file_id:/ {print $2}')
    [[ "$id1" == "$id2" ]] || { fail "file_id changed across overwrite ($id1 -> $id2)"; return 1; }
    # Content should match the second upload
    local out="$WORK_DIR/over.dl"
    run "$CLI" download over.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$(b3 "$f2")" ]] || { fail "overwrite did not replace content"; return 1; }
    return 0
}

tc_017() {
    run "$CLI" stat tiny.txt || { fail "stat failed"; return 1; }
    have_regex 'size:\s+[0-9]+ bytes' || { fail "missing size in stat output"; return 1; }
    have_regex 'file_id:' || { fail "missing file_id in stat output"; return 1; }
    return 0
}

tc_018() {
    run_status "$CLI" stat does-not-exist.bin
    [[ $ASSERT_LAST_RC -ne 0 ]] || { fail "expected non-zero exit"; return 1; }
    have_substr 'not found' || { fail "expected 'not found' message"; return 1; }
    return 0
}

tc_019() {
    run "$CLI" ls || { fail "ls failed"; return 1; }
    have_substr "/empty.bin"           || { fail "ls missing empty.bin"; return 1; }
    have_substr "/tiny.txt"            || { fail "ls missing tiny.txt"; return 1; }
    have_substr "/boundary-16k.bin"    || { fail "ls missing boundary file"; return 1; }
    have_substr "/just-over-16k.bin"   || { fail "ls missing chunked file"; return 1; }
    have_substr "/multi-chunk.bin"     || { fail "ls missing multi-chunk file"; return 1; }
    have_substr "/exact-chunk.bin"     || { fail "ls missing exact-chunk file"; return 1; }
    have_substr "/over.bin"            || { fail "ls missing overwritten file"; return 1; }
    return 0
}

tc_020() {
    run "$CLI" ls --prefix /nonexistent-prefix/ || { fail "ls failed"; return 1; }
    have_substr "no files under" || { fail "expected empty-listing message"; return 1; }
    return 0
}

tc_021() {
    # Upload two under a /nested/ prefix and check filtering works.
    local f="$WORK_DIR/nested.bin"; printf "nested file\n" >"$f"
    run "$CLI" upload "$f" --as /nested/a.txt
    run "$CLI" upload "$f" --as /nested/b.txt
    run "$CLI" upload "$f" --as /elsewhere.txt
    run "$CLI" ls --prefix /nested/
    have_substr "/nested/a.txt" || { fail "missing /nested/a.txt"; return 1; }
    have_substr "/nested/b.txt" || { fail "missing /nested/b.txt"; return 1; }
    echo "$ASSERT_LAST_OUT" | grep -q "/elsewhere.txt" && { fail "prefix did not filter"; return 1; }
    return 0
}

tc_022() {
    # delete + ensure download fails
    run "$CLI" rm tiny.txt || { fail "rm failed"; return 1; }
    have_substr 'deleted'  || { fail "missing 'deleted'"; return 1; }
    run_status "$CLI" download tiny.txt --out "$WORK_DIR/should-not-exist.bin"
    [[ $ASSERT_LAST_RC -ne 0 ]] || { fail "download succeeded after rm"; return 1; }
    have_substr 'not found' || { fail "missing 'not found' on deleted file"; return 1; }
    # ls should no longer show it
    run "$CLI" ls
    echo "$ASSERT_LAST_OUT" | grep -q "/tiny.txt" && { fail "ls still shows deleted file"; return 1; }
    return 0
}

tc_023() {
    # rm a non-existent file should error
    run_status "$CLI" rm not-here.bin
    [[ $ASSERT_LAST_RC -ne 0 ]] || { fail "rm of missing file did not error"; return 1; }
    have_substr 'not found' || { fail "missing 'not found'"; return 1; }
    return 0
}

# ─── content edge cases ────────────────────────────────────────────────────

tc_030() {
    # All zeros → exercise the all-same-byte path.
    local f="$WORK_DIR/zeros.bin"
    gen_file "$f" $((512 * 1024)) zeros
    run "$CLI" upload "$f" --as /zeros.bin || { fail "upload failed"; return 1; }
    local src=$(b3 "$f")
    local out="$WORK_DIR/zeros.dl"
    run "$CLI" download zeros.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$src" ]] || { fail "hash mismatch on zeros"; return 1; }
    return 0
}

tc_031() {
    # All same byte (was a chunk-key collision bug pre-fix).
    local f="$WORK_DIR/sevens.bin"
    gen_file "$f" $((512 * 1024)) repeat:7
    run "$CLI" upload "$f" --as /sevens.bin || { fail "upload failed"; return 1; }
    local src=$(b3 "$f")
    local out="$WORK_DIR/sevens.dl"
    run "$CLI" download sevens.bin --out "$out" || { fail "download failed"; return 1; }
    [[ "$(b3 "$out")" == "$src" ]] || { fail "hash mismatch on all-sevens"; return 1; }
    return 0
}

tc_032() {
    # Same content under different names — should upload independently
    local f="$WORK_DIR/dup.bin"
    gen_file "$f" 4096 random
    run "$CLI" upload "$f" --as /dup-a.bin
    run "$CLI" upload "$f" --as /dup-b.bin
    local src=$(b3 "$f")
    run "$CLI" download dup-a.bin --out "$WORK_DIR/dup-a.dl"
    run "$CLI" download dup-b.bin --out "$WORK_DIR/dup-b.dl"
    [[ "$(b3 "$WORK_DIR/dup-a.dl")" == "$src" ]] || { fail "dup-a hash mismatch"; return 1; }
    [[ "$(b3 "$WORK_DIR/dup-b.dl")" == "$src" ]] || { fail "dup-b hash mismatch"; return 1; }
    run "$CLI" stat dup-a.bin
    local id_a=$(echo "$ASSERT_LAST_OUT" | awk '/file_id:/ {print $2}')
    run "$CLI" stat dup-b.bin
    local id_b=$(echo "$ASSERT_LAST_OUT" | awk '/file_id:/ {print $2}')
    [[ "$id_a" != "$id_b" ]] || { fail "different paths share file_id"; return 1; }
    return 0
}

# ─── state-boundary / negative paths ───────────────────────────────────────

tc_040() {
    # Upload while the engine reports locked → expect 423 even though CLI
    # auto-unlocks. To exercise the boundary, hit the API directly.
    "$CLI" lock >/dev/null
    local vault_id; vault_id=$(python3 -c "import json;print(json.load(open('$STATE_FILE'))['vault_id'])")
    local code
    code=$(curl -s -o "$WORK_DIR/locked-write.out" -w '%{http_code}' \
        -T "$WORK_DIR/empty.bin" \
        "http://127.0.0.1:$PORT_OS/v1/vaults/$vault_id/files/locked-test.bin")
    RESULT+="HTTP $code body=$(cat "$WORK_DIR/locked-write.out" 2>/dev/null)"$'\n'
    "$CLI" unlock >/dev/null
    [[ "$code" == "423" ]] || { fail "expected 423, got $code"; return 1; }
    return 0
}

tc_041() {
    # Read while locked → 423 from API
    "$CLI" lock >/dev/null
    local vault_id; vault_id=$(python3 -c "import json;print(json.load(open('$STATE_FILE'))['vault_id'])")
    local code
    code=$(curl -s -o "$WORK_DIR/locked-read.out" -w '%{http_code}' \
        "http://127.0.0.1:$PORT_OS/v1/vaults/$vault_id/files/multi-chunk.bin")
    RESULT+="HTTP $code"$'\n'
    "$CLI" unlock >/dev/null
    [[ "$code" == "423" ]] || { fail "expected 423, got $code"; return 1; }
    return 0
}

tc_042() {
    # Download through the CLI while locked auto-unlocks.
    "$CLI" lock >/dev/null
    run "$CLI" download multi-chunk.bin --out "$WORK_DIR/auto-unlock.dl" || { fail "auto-unlock+download failed"; return 1; }
    [[ -f "$WORK_DIR/auto-unlock.dl" ]] || { fail "no file written"; return 1; }
    return 0
}

# ─── perf baselines (smoke) ────────────────────────────────────────────────

tc_050() {
    local f="$WORK_DIR/perf-64m.bin"
    gen_file "$f" $((64 * 1024 * 1024)) random
    local t0=$(python3 -c 'import time;print(time.time())')
    run "$CLI" upload "$f" --as /perf-64m.bin || { fail "upload failed"; return 1; }
    local t1=$(python3 -c 'import time;print(time.time())')
    local mbps=$(python3 -c "print(f'{64.0/(($t1)-($t0)):.1f}')")
    RESULT+="put throughput: $mbps MB/s"$'\n'
    have_regex 'uploaded 64\.0 MB' || { fail "expected 64 MB upload acknowledgement"; return 1; }
    return 0
}

tc_051() {
    local out="$WORK_DIR/perf-64m.dl"
    local t0=$(python3 -c 'import time;print(time.time())')
    run "$CLI" download perf-64m.bin --out "$out" || { fail "download failed"; return 1; }
    local t1=$(python3 -c 'import time;print(time.time())')
    local mbps=$(python3 -c "print(f'{64.0/(($t1)-($t0)):.1f}')")
    RESULT+="get throughput: $mbps MB/s"$'\n'
    [[ "$(file_size "$out")" == "$((64 * 1024 * 1024))" ]] || { fail "size mismatch on 64MB read"; return 1; }
    return 0
}

# ─── execute ───────────────────────────────────────────────────────────────
echo
echo -e "${BLUE}==> tests${END}"
tc_run TC-001 "status before init shows uncreated"          F-VL-1 tc_001
tc_run TC-002 "init creates vault and persists state.json"  F-VL-1 tc_002
tc_run TC-003 "state.json is mode 0600"                     F-VL-1 tc_003
tc_run TC-004 "status after init shows unlocked"            F-VL-1 tc_004
tc_run TC-005 "lock transitions to locked"                  F-VL-3 tc_005
tc_run TC-006 "unlock with saved passphrase succeeds"       F-VL-2 tc_006
tc_run TC-007 "unlock with wrong passphrase fails"          F-VL-2 tc_007

tc_run TC-010 "upload + download empty (0 byte) file"       F-FL-1+F-FL-2 tc_010
tc_run TC-011 "upload + download tiny inline file"          F-FL-1+F-FL-2 tc_011
tc_run TC-012 "exact 16 KiB inline-threshold boundary"      F-FL-1+F-FL-2 tc_012
tc_run TC-013 "16 KiB + 1 byte forces chunked path"         F-FL-1+F-FL-2 tc_013
tc_run TC-014 "8 MiB multi-chunk round-trip"                F-FL-1+F-FL-2 tc_014
tc_run TC-015 "4 MiB chunk-aligned round-trip"              F-FL-1+F-FL-2 tc_015
tc_run TC-016 "overwrite preserves file_id"                 F-FL-3 tc_016
tc_run TC-017 "stat returns size and file_id"               F-FL-6 tc_017
tc_run TC-018 "stat on missing file returns not_found"      F-FL-6 tc_018
tc_run TC-019 "ls shows all uploaded files"                 F-FL-2 tc_019
tc_run TC-020 "ls with empty prefix returns empty listing"  F-FL-2 tc_020
tc_run TC-021 "ls --prefix filters correctly"               F-FL-2 tc_021
tc_run TC-022 "rm + download afterwards returns not_found"  F-FL-4 tc_022
tc_run TC-023 "rm on missing file returns not_found"        F-FL-4 tc_023

tc_run TC-030 "all-zeros payload round-trips"               F-FL-1+F-FL-2 tc_030
tc_run TC-031 "all-same-byte payload round-trips (chunk-key collision regression)" F-FL-1+F-FL-2 tc_031
tc_run TC-032 "same content under two names yields distinct file_ids" F-FL-2 tc_032

tc_run TC-040 "PUT against locked vault returns HTTP 423"   "Vault×Op matrix" tc_040
tc_run TC-041 "GET against locked vault returns HTTP 423"   "Vault×Op matrix" tc_041
tc_run TC-042 "CLI download auto-unlocks when locked"       F-VL-2 tc_042

tc_run TC-050 "64 MiB upload throughput baseline"           Perf tc_050
tc_run TC-051 "64 MiB download throughput baseline"         Perf tc_051

# ─── write final report ────────────────────────────────────────────────────
{
    echo "# CLI Flow Test Results"
    echo
    echo "_Generated by \`scripts/cli_flow_tests.sh\` against a fresh engine + testbench._"
    echo
    echo "- Date: \`$NOW\`"
    echo "- Git: \`$GIT_REV\`"
    echo "- Engine: \`$ENGINE\`"
    echo "- CLI: \`$CLI\`"
    echo "- Testbench: Python (\`testbench/server.py\`) on port $PORT_TB"
    echo "- Total: **$TOTAL** · Passed: **$PASS** · Failed: **$FAIL**"
    echo
    echo "## Coverage scope"
    echo
    echo "Today's CLI surface only reaches a subset of the documented flows."
    echo "Multi-device coordination (F-MD-*), sharing (F-SH-*), repair / GC"
    echo "scheduling (F-HM-*), snapshot replication (F-SN-*), MK rotation"
    echo "(F-VL-5), and vault destruction (F-VL-4) are out of scope of this"
    echo "harness — the engine has skeletons but no CLI surface yet."
    echo
    echo "## Summary"
    echo
    echo "| | ID | Flow | Description | Status |"
    echo "|---|---|---|---|---|"
    for row in "${SUMMARY_ROWS[@]}"; do
        IFS='|' read -r icon id flow desc status <<< "$row"
        echo "| $icon | $id | $flow | $desc | $status |"
    done
    echo
    echo "## Detailed results"
    cat "$TMP_REPORT"
    echo
    echo "## Notes"
    echo
    echo "- TC-007 (wrong-passphrase unlock) corrupts the saved \`state.json\` mid-test and restores it before exit."
    echo "- TC-040 / TC-041 bypass the CLI's auto-unlock to exercise the API's locked-state error path directly with curl."
    echo "- All file-content tests use BLAKE2b-256 (Python \`hashlib.blake2b\`) for hashing; the CLI itself reports BLAKE3 hex."
} > "$REPORT"

echo
if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}all $TOTAL tests passed${END}"
    echo -e "${DIM}report: $REPORT${END}"
    exit 0
else
    echo -e "${RED}$FAIL of $TOTAL tests failed${END}"
    echo -e "${DIM}report: $REPORT${END}"
    exit 1
fi
