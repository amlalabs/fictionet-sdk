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

cat > "$tmp/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1 $2" == '+nightly fuzz' ]]
case "$3" in
  list)
    case "$SCENARIO" in
      failed) exit 1 ;;
      partial) echo first; exit 1 ;;
      empty) exit 0 ;;
      whitespace) printf ' \t\n\n'; exit 0 ;;
      mixed|success) printf 'first\nsecond\nthird\n' ;;
      *) exit 2 ;;
    esac
    ;;
  run)
    printf '%s\n' "$*" >> "$CALLS"
    [[ "$SCENARIO" != mixed || "$8" == second ]]
    ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/cargo"

fail() {
  echo "$SCENARIO: $*" >&2
  cat "$tmp/output" >&2
  exit 1
}

for SCENARIO in failed partial empty whitespace mixed success; do
  export SCENARIO
  rm -rf "$tmp/fuzz/corpus"
  : > "$CALLS"
  status=0
  bash "$tmp/fuzz/run-all.sh" 7 -timeout=2 > "$tmp/output" 2>&1 || status=$?

  if [[ "$SCENARIO" == success ]]; then
    [[ "$status" == 0 ]] || fail "expected a successful sweep"
    grep -q 'every fuzz target ran for 7 s without a failure' "$tmp/output" \
      || fail "missing success report"
  else
    [[ "$status" != 0 ]] || fail "expected the sweep to fail"
    if grep -q 'every fuzz target ran' "$tmp/output"; then
      fail "reported success after failure"
    fi
  fi

  case "$SCENARIO" in
    failed|partial|empty|whitespace)
      [[ ! -s "$CALLS" ]] || fail "ran a target after invalid discovery"
      [[ ! -d "$tmp/fuzz/corpus" ]] || fail "created a corpus after invalid discovery"
      if [[ "$SCENARIO" == failed || "$SCENARIO" == partial ]]; then
        grep -q 'fuzz target discovery failed' "$tmp/output" || fail "missing discovery error"
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
