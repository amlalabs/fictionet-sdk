#!/usr/bin/env bash
# Source in a guest, then call results_begin, results_run ID CMD..., results_end.
# Command output is streamed unchanged. The exit/timing lines remain readable by
# says/took; the === guest records are reserved for results.py. A command failure
# is recorded and execution continues, including under set -e. The host must
# validate every ID's expected status and the emulator's status with results.py.

results_begin() { printf '=== guest begin\n'; }
results_end() { printf '=== guest end\n'; }

results_run() {
    if [ "$#" -lt 2 ]; then
        echo 'results_run needs an ID and a command' >&2
        return 2
    fi
    local id="$1" status t0 t1 ms
    shift
    if [[ ! "$id" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]]; then
        echo "invalid guest result ID: $id" >&2
        return 2
    fi
    printf '$ %s\n' "$*"
    t0=$(date +%s%N) || return
    if "$@" 2>&1; then status=0; else status=$?; fi
    t1=$(date +%s%N) || return
    ms=$(((t1 - t0) / 1000000))
    # Start a fresh line even when the command's output has no final newline.
    printf '\n[exit %d]\n[took %d ms]\n=== guest result %s %d %d\n' \
        "$status" "$ms" "$id" "$status" "$ms"
}
