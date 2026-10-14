#!/usr/bin/env bash
# Tests the sweep with a stub cargo, without nightly or cargo-fuzz.
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/fuzz"
cp "$(dirname "$0")/../run-all.sh" "$tmp/fuzz/run-all.sh"
export PATH="$tmp/bin:$PATH"
export FUZZ_TRIPLE=x86_64-unknown-linux-gnu
export CALLS="$tmp/calls"
export DISCOVERY="$tmp/discovery"
export REAL_SORT=$(command -v sort)
unset FUZZ_SHARD_INDEX FUZZ_SHARD_COUNT

cat > "$tmp/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2" == '+nightly fuzz' ]]
case "$3" in
  list)
    echo list >> "$DISCOVERY"
    case "$SCENARIO" in
      failed) exit 1 ;;
      partial) echo first; exit 1 ;;
      empty) exit 0 ;;
      whitespace) printf ' \t\n\n'; exit 0 ;;
      mixed|success|sort_failed) printf 'first\nsecond\nthird\n' ;;
      shards|shard_failures) cat "$TARGETS" ;;
      *) exit 2 ;;
    esac
    ;;
  run)
    printf '%s\n' "$*" >> "$CALLS"
    [[ "$SCENARIO" != mixed || "$8" == second ]]
    [[ "$SCENARIO" != shard_failures || "$8" == ninth ]]
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/cargo"

cat > "$tmp/bin/sort" <<'EOF'
#!/usr/bin/env bash
if [[ "$SCENARIO" == sort_failed ]]; then
  exit 1
fi
exec "$REAL_SORT" "$@"
EOF
chmod +x "$tmp/bin/sort"

fail() {
  echo "$SCENARIO: $*" >&2
  cat "$tmp/output" >&2
  exit 1
}

for SCENARIO in failed partial empty whitespace sort_failed mixed success; do
  export SCENARIO
  rm -rf "$tmp/fuzz/corpus"
  : > "$CALLS"
  status=0
  bash "$tmp/fuzz/run-all.sh" 7 -timeout=2 > "$tmp/output" 2>&1 || status=$?

  if [[ "$SCENARIO" == success ]]; then
    [[ "$status" == 0 ]] || fail "expected a successful sweep"
    grep -q 'every fuzz target in shard 0/1 ran for 7 s without a failure' "$tmp/output" \
      || fail "missing success report"
  else
    [[ "$status" != 0 ]] || fail "expected the sweep to fail"
    if grep -q 'without a failure' "$tmp/output"; then
      fail "reported success after failure"
    fi
  fi

  case "$SCENARIO" in
    failed|partial|empty|whitespace|sort_failed)
      [[ ! -s "$CALLS" ]] || fail "ran a target after invalid discovery"
      [[ ! -d "$tmp/fuzz/corpus" ]] || fail "created a corpus after invalid discovery"
      if [[ "$SCENARIO" == failed || "$SCENARIO" == partial ]]; then
        grep -q 'fuzz target discovery failed' "$tmp/output" || fail "missing discovery error"
      elif [[ "$SCENARIO" == sort_failed ]]; then
        grep -q 'fuzz target sorting failed' "$tmp/output" || fail "missing sorting error"
      else
        grep -q 'fuzz target discovery returned no targets' "$tmp/output" || fail "missing empty-list error"
      fi
      ;;
    mixed|success)
      : > "$tmp/expected"
      for t in first second third; do
        echo "+nightly fuzz run -O -a --target $FUZZ_TRIPLE $t fuzz/corpus/$t -- -max_total_time=7 -timeout=2" >> "$tmp/expected"
        [[ -d "$tmp/fuzz/corpus/$t" ]] || fail "missing corpus for $t"
      done
      diff -u "$tmp/expected" "$CALLS" || fail "did not run every target with the expected arguments"
      if [[ "$SCENARIO" == mixed ]]; then
        grep -q '^2 fuzz target(s) failed: first third$' "$tmp/output" || fail "incorrect failure summary"
      fi
      ;;
  esac
  echo "$SCENARIO: passed"
done

export SCENARIO=shards
export TARGETS="$tmp/targets"
printf '%s\n' third first ninth second sixth eighth fourth seventh fifth > "$TARGETS"
LC_ALL=C sort "$TARGETS" > "$tmp/sorted"
: > "$tmp/union"
for shard in 0 1 2 3; do
  export FUZZ_SHARD_INDEX=$shard FUZZ_SHARD_COUNT=4
  : > "$CALLS"
  bash "$tmp/fuzz/run-all.sh" 60 -timeout=20 -rss_limit_mb=4096 > "$tmp/output" 2>&1 \
    || fail "shard $shard failed"
  : > "$tmp/expected"
  while read -r t; do
    echo "+nightly fuzz run -O -a --target $FUZZ_TRIPLE $t fuzz/corpus/$t -- -max_total_time=60 -timeout=20 -rss_limit_mb=4096" >> "$tmp/expected"
  done < <(awk -v shard="$shard" '(NR - 1) % 4 == shard' "$tmp/sorted")
  diff -u "$tmp/expected" "$CALLS" || fail "incorrect selection or arguments for shard $shard"
  awk '{print $8}' "$CALLS" >> "$tmp/union"

  # Discovery order must not change which shard owns a target.
  LC_ALL=C sort -r "$TARGETS" > "$tmp/reversed"
  : > "$CALLS"
  TARGETS="$tmp/reversed" bash "$tmp/fuzz/run-all.sh" 60 -timeout=20 -rss_limit_mb=4096 > "$tmp/output" 2>&1 \
    || fail "reordered shard $shard failed"
  diff -u "$tmp/expected" "$CALLS" || fail "selection changed with discovery order"
done
LC_ALL=C sort "$tmp/union" > "$tmp/actual"
diff -u "$tmp/sorted" "$tmp/actual" || fail "shards did not cover every target exactly once"
echo "four-shard coverage and deterministic selection: passed"

# An empty shard is valid, unlike empty discovery.
: > "$CALLS"
FUZZ_SHARD_INDEX=9 FUZZ_SHARD_COUNT=10 bash "$tmp/fuzz/run-all.sh" > "$tmp/output" 2>&1 \
  || fail "empty shard failed"
[[ ! -s "$CALLS" ]] || fail "empty shard ran a target"
echo "empty shard: passed"

# Two failures in one shard must not prevent its third target from running.
export SCENARIO=shard_failures FUZZ_SHARD_INDEX=0
: > "$CALLS"
if bash "$tmp/fuzz/run-all.sh" > "$tmp/output" 2>&1; then
  fail "shard failures reported success"
fi
awk '{print $8}' "$CALLS" > "$tmp/actual"
printf '%s\n' eighth ninth third > "$tmp/expected"
diff -u "$tmp/expected" "$tmp/actual" || fail "failed shard stopped early or ran other targets"
grep -q '^2 fuzz target(s) failed: eighth third$' "$tmp/output" || fail "incorrect shard failure summary"
echo "shard failure aggregation: passed"

export SCENARIO=success
for pair in '0 0' '4 4' '5 4' '-1 4' '0 -1' 'x 4' '0 x' '1+1 4' '01 4' '0 04' \
    '18446744073709551616 4' '0 18446744073709551616'; do
  read -r FUZZ_SHARD_INDEX FUZZ_SHARD_COUNT <<< "$pair"
  : > "$CALLS"
  : > "$DISCOVERY"
  if bash "$tmp/fuzz/run-all.sh" > "$tmp/output" 2>&1; then
    fail "accepted invalid shard settings: $pair"
  fi
  grep -q '::error::FUZZ_SHARD_INDEX' "$tmp/output" || fail "missing shard validation error"
  [[ ! -s "$CALLS" && ! -s "$DISCOVERY" ]] || fail "called cargo with invalid shard settings"
done
for variable in FUZZ_SHARD_INDEX FUZZ_SHARD_COUNT; do
  if env FUZZ_SHARD_INDEX=0 FUZZ_SHARD_COUNT=4 "$variable=" bash "$tmp/fuzz/run-all.sh" > "$tmp/output" 2>&1; then
    fail "accepted empty $variable"
  fi
done
echo "invalid shard settings: passed"
