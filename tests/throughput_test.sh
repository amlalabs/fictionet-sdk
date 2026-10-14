#!/usr/bin/env bash
# Transfer-check fixtures; no Docker, Kubernetes, or network needed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
source "$here/throughput.sh"

case_name=setup
scratch="$(mktemp -d)"
# Keep fatal shell errors visible even while a case captures stderr.
exec 3>&2
trap 'status=$?; rm -rf "$scratch"; if (( status != 0 )); then echo "FAIL: $case_name (exit $status)" >&3; fi' EXIT

pass() { result=pass; message="$*"; }
fail() { result=fail; message="$*"; }
assert_equal() {
    if [[ $1 != "$2" ]]; then
        echo "FAIL: $case_name: $3: wanted '$2', got '$1'" >&2
        exit 1
    fi
}
expect_status() {
    local want="$1" status=0
    case_name="$2"
    shift 2
    "$@" 2>"$scratch/stderr" || status=$?
    assert_equal "$status" "$want" 'exit status'
    echo "PASS: $case_name"
}
assert_quiet() { assert_equal "$(cat "$scratch/stderr")" '' 'stderr'; }
rows() {
    local count="$1" size="$2" took="$3"
    for ((i=0; i<count; i++)); do echo "$size $took"; done
}
failed_transfer() { rows 10 16777216 0.1; return 28; }
spread_rows() { rows 31 16777216 2.0; rows 1 16777216 "$1"; }
expect() {
    local want="$1" name="$2"
    shift 2
    case_name="$name"
    result=unset
    check_downloads "$name" "$@"
    if [[ $result != "$want" ]]; then
        echo "FAIL: $name: wanted $want, got $result"
        exit 1
    fi
    echo "PASS: $name"
}

unset FICTIONET_PERF_CHECK
expect pass 'performance checks default off' 10 1 0 rows 10 16777216 1.2
FICTIONET_PERF_CHECK=0
expect pass 'slow complete downloads' 10 1 0 rows 10 16777216 1.2
expect pass 'slow complete Kubernetes downloads' 10 2 0 rows 10 16777216 2.2
expect pass 'uneven complete downloads' 32 0 0.8 spread_rows 3.0
expect fail 'short body' 10 1 0 rows 10 16777215 0.1
expect fail 'missing transfer' 10 1 0 rows 9 16777216 0.1
expect fail 'extra transfer' 10 1 0 rows 11 16777216 0.1
expect fail 'empty output' 10 1 0 true
expect fail 'malformed timing' 10 1 0 rows 10 16777216 invalid
expect fail 'curl deadline failure despite full byte counts' 10 1 0 failed_transfer

FICTIONET_PERF_CHECK=1
expect pass 'fast performance run' 10 1 0 rows 10 16777216 0.9
expect fail 'Docker performance threshold' 10 1 0 rows 10 16777216 1.0
expect pass 'Kubernetes performance run' 10 2 0 rows 10 16777216 1.9
expect fail 'Kubernetes performance threshold' 10 2 0 rows 10 16777216 2.0
expect pass 'uniformly slow parallel web run' 32 0 0.8 spread_rows 2.0
expect pass 'numeric spread threshold' 32 0 12 spread_rows 11.5
expect fail 'parallel web spread threshold' 32 0 0.8 spread_rows 2.8
expect fail 'performance mode still checks bytes' 10 1 0 rows 10 123 0.1

expect fail 'timing diagnostic includes limits' 10 1 0 rows 10 16777216 1.2
[[ $message == *'max=1 s, spread=0 s'* ]]

# Single transfers return a measurement only after a successful, complete body.
transfer() { printf '%s\n' "$1"; return "$2"; }
capture_transfer() { measurement="$(check_transfer "$@")"; }
for status in 0 22 28; do
    want=1
    [[ $status != 0 ]] || want=0
    expect_status "$want" "single download (curl status $status)" capture_transfer \
        16777216 transfer '16777216 1000000' "$status"
    if [[ $status == 0 ]]; then assert_equal "$measurement" 1000000 'speed'; fi
    expect_status "$want" "single upload (curl status $status)" capture_transfer \
        67108864 transfer $'67108864\n1.2' "$status"
    if [[ $status == 0 ]]; then assert_equal "$measurement" 1.2 'duration'; fi
done
expect_status 1 'single short body' capture_transfer 16777216 transfer '123 0.1' 0
expect_status 1 'single empty response' capture_transfer 16777216 true
expect_status 1 'single missing measurement' capture_transfer 16777216 transfer '16777216' 0
expect_status 1 'single malformed measurement' capture_transfer 16777216 transfer '16777216 invalid' 0
expect_status 1 'single extra transfer' capture_transfer 16777216 rows 2 16777216 0.1

FICTIONET_PERF_CHECK=0
expect_status 0 'slow recovery passes functionally' check_recovery 1 3
expect_status 1 'failed fresh transfer fails functionally' check_recovery failed 1
expect_status 1 'failed after transfer fails functionally' check_recovery 1 failed
FICTIONET_PERF_CHECK=1
expect_status 0 'fast recovery passes performance check' check_recovery 1 2
expect_status 1 'slow recovery fails performance threshold' check_recovery 1 3
expect_status 1 'recovery threshold is strict' check_recovery 1 2.1

# Hold until the parent sends a line; "exit" simulates an early exit after
# readiness without racing the readiness read against process reaping.
holder_command() {
    local release
    echo "$1"
    read -r release
    [[ $release == release ]] || return 1
    return "$2"
}
for line in 250 '256 1744'; do
    expect_status 0 "holder ready ($line)" start_holder counts holder_command "$line" 0
    assert_equal "$counts" "$line" 'readiness counts'
    assert_quiet
    expect_status 0 "holder released ($line)" release_holder
    assert_quiet
done
expect_status 1 'holder exits before readiness' start_holder counts false
assert_equal "$counts" '0 0' 'fallback counts'
assert_quiet
expect_status 1 'release holder that exited before readiness' release_holder
assert_quiet

# Exercise the already-reaped path deterministically, with both counts stale.
coproc holder { exit 1; }
holder_pid=$!
wait "$holder_pid" || true
unset holder
counts='256 1744'
expect_status 1 'read an already-reaped holder' read_holder counts
read -r served reset <<<"$counts"
assert_equal "$served" 0 'fallback served count'
assert_equal "$reset" 0 'fallback reset count'
assert_quiet
expect_status 1 'release an already-reaped holder' release_holder
assert_quiet

expect_status 0 'holder ready before early exit' start_holder counts holder_command '256 1744' 0
printf 'exit\n' >&"${holder[1]}"
wait "$holder_pid" || true
expect_status 1 'holder exits after readiness' release_holder
assert_quiet
expect_status 0 'holder ready before nonzero exit' start_holder counts holder_command '256 1744' 1
expect_status 1 'holder fails on release' release_holder
assert_quiet

# Execute the remote poll itself. Supply socket-table rows to real awk and
# advance the fixture on each sleep, so no network or wall-clock delay is needed.
drain_agent() (
    export DRAIN_SCENARIO="$1" DRAIN_ATTEMPT=0 DRAIN_LOG="$scratch/polls"
    shift
    : >"$DRAIN_LOG"
    awk() {
        [[ ${!#} == /proc/net/tcp ]] || return 2
        if [[ $DRAIN_SCENARIO == unreadable ]]; then
            echo 'cannot read socket table' >&2
            return 2
        fi
        local state=06
        local states=(01 04 05 08 09 06)
        case "$DRAIN_SCENARIO" in
            draining) state=${states[DRAIN_ATTEMPT]} ;;
            stalled) state=05 ;;
        esac
        # Ignore TIME_WAIT and connections to other addresses or ports.
        printf '%s\n' \
            'sl local_address rem_address st' \
            '0: 0100000A:1234 010012C6:0050 06' \
            '1: 0100000A:1235 020012C6:0050 01' \
            '2: 0100000A:1236 010012C6:0051 01' \
            "3: 0100000A:1237 010012C6:0050 $state" |
            command awk "${@:1:$#-1}"
    }
    sleep() {
        [[ $1 == 0.1 ]] || return 2
        DRAIN_ATTEMPT=$((DRAIN_ATTEMPT + 1))
        echo poll >>"$DRAIN_LOG"
    }
    export -f awk sleep
    "$@"
)
expect_status 0 'drained sockets ignore TIME_WAIT and other destinations' drain_connections drain_agent closed
assert_equal "$(wc -l <"$scratch/polls")" 0 'poll sleeps'
assert_quiet
expect_status 0 'wait for established and closing sockets to drain' drain_connections drain_agent draining
assert_equal "$(wc -l <"$scratch/polls")" 5 'poll sleeps'
assert_quiet
expect_status 1 'stalled close fails within the poll bound' drain_connections drain_agent stalled
assert_equal "$(wc -l <"$scratch/polls")" 100 'bounded poll sleeps'
assert_equal "$(cat "$scratch/stderr")" '1 connections to 198.18.0.1:80 did not close within 10 s' 'timeout diagnostic'
expect_status 1 'unreadable socket table fails' drain_connections drain_agent unreadable
assert_equal "$(wc -l <"$scratch/polls")" 0 'no retries for an unreadable table'
expect_status 1 'failed agent command fails the drain check' drain_connections false
