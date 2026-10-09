# Shared assertions and cleanup for Docker tests.
failures=0

cleanup() { "${compose[@]}" down -v --remove-orphans --timeout 2 >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
agent() { "${compose[@]}" exec -T agent "$@"; }

# Runs a check: name, then the expected text (a grep -E pattern), then the
# command. The command's stdout and stderr are matched, as one line.
check() {
    local name="$1" want="$2"
    shift 2
    local out
    # Lines are joined with spaces, so a pattern can span them.
    out="$("$@" 2>&1 | tr '\n' ' ')" || true
    if grep -qE -- "$want" <<<"$out"; then pass "$name"; else fail "$name: wanted /$want/, got: $out"; fi
}

finish() {
    if [[ $failures == 0 ]]; then echo "ALL PASSED"; else echo "$failures FAILED"; exit 1; fi
}
