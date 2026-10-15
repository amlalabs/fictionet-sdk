# Shared assertions and cleanup for Docker tests.
failures=0
source "$(dirname "${BASH_SOURCE[0]}")/../common/assertions.sh"

cleanup() { "${compose[@]}" down -v --remove-orphans --timeout 2 >/dev/null 2>&1 || true; }
trap cleanup EXIT

agent() { "${compose[@]}" exec -T agent "$@"; }

finish() {
    if [[ $failures == 0 ]]; then echo "ALL PASSED"; else echo "$failures FAILED"; exit 1; fi
}
