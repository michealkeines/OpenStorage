#!/bin/bash
# Layer-by-layer baseline gate for STRUCTURAL_REWORK.md.
#
# Runs each layer's baseline test individually so a regression in any
# layer is unambiguous. Final summary aggregates totals. Exits non-zero
# if any baseline fails.
#
# Usage: ./scripts/baseline_all_layers.sh
#
# Each layer has exactly one baseline file under cli/tests/. The CRDT
# proptests live in os-entities and run via the per-crate cargo test.
# Compatible with macOS /bin/bash 3.2 (no associative arrays).

set -o pipefail

cd "$(dirname "$0")/.."

# Parallel arrays: LABELS[i] / TESTS[i]. Each test entry is
# `<test-binary>::<test-fn>`.
LABELS=(
  "L0      "
  "L1      "
  "L2      "
  "L3a     "
  "L3b     "
  "L4a     "
  "L4b     "
  "L4c     "
)
TESTS=(
  "restart_survival::layer0_baseline_state_survives_restart"
  "supervisor_drives_workers::layer1_baseline_supervisor_detects_missing_shard_autonomously"
  "plugin_ban_recovery::layer2_baseline_discord_ban_survives_and_reads_continue"
  "weak_cas_safety::layer3_baseline_eventual_only_refused_for_snapshot"
  "weak_cas_safety::layer3_strongcas_provider_succeeds"
  "security_closure::layer4_baseline_identity_rotate_requires_lease"
  "security_closure::layer4_baseline_rotated_recovery_token_rejected"
  "security_closure::layer4_baseline_revoke_reencrypts_inline_payload"
)

OVERALL_OK=1
SUMMARY_LINES=()

for i in "${!TESTS[@]}"; do
  label="${LABELS[$i]}"
  test_id="${TESTS[$i]}"
  test_file="${test_id%%::*}"
  test_name="${test_id##*::}"
  printf "═══ %s %s ... " "$label" "$test_name"
  if cargo test --test "$test_file" "$test_name" --quiet 2>/dev/null \
      | grep -q "1 passed"; then
    echo "✅ PASS"
    SUMMARY_LINES+=("  $label PASS  $test_name")
  else
    echo "❌ FAIL"
    SUMMARY_LINES+=("  $label FAIL  $test_name")
    OVERALL_OK=0
  fi
done

# Layer 5 — CRDT proptests with elevated case count.
printf "═══ L5      crdt::proptests (1024 cases each) ... "
if PROPTEST_CASES=1024 cargo test -p os-entities --lib proptests --quiet 2>/dev/null \
    | grep -q "0 failed"; then
  echo "✅ PASS"
  SUMMARY_LINES+=("  L5       PASS  crdt::proptests")
else
  echo "❌ FAIL"
  SUMMARY_LINES+=("  L5       FAIL  crdt::proptests")
  OVERALL_OK=0
fi

# Full workspace as a sanity gate.
printf "═══ FW      cargo test --workspace ... "
WS_RESULT=$(cargo test --workspace 2>&1 | grep -E "^test result" \
  | awk '{p+=$4; f+=$6; i+=$8} END{printf "passed=%d failed=%d ignored=%d", p, f, i}')
WS_FAILED=$(echo "$WS_RESULT" | sed 's/.*failed=\([0-9]*\).*/\1/')
if [ "$WS_FAILED" = "0" ]; then
  echo "✅ PASS ($WS_RESULT)"
  SUMMARY_LINES+=("  FW       PASS  $WS_RESULT")
else
  echo "❌ FAIL ($WS_RESULT)"
  SUMMARY_LINES+=("  FW       FAIL  $WS_RESULT")
  OVERALL_OK=0
fi

echo
echo "── Summary ─────────────────────────────────────"
for line in "${SUMMARY_LINES[@]}"; do
  echo "$line"
done

if [ "$OVERALL_OK" = "1" ]; then
  echo
  echo "✅ All layer baselines green."
  exit 0
else
  echo
  echo "❌ At least one baseline failed. See output above."
  exit 1
fi
