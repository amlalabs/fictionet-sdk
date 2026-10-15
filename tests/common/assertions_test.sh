#!/bin/sh
# Status and output fixtures; run under both bash and POSIX sh.
set -eu
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$here/assertions.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

assert_equal() {
    if [ "$1" != "$2" ]; then
        printf 'FAIL: %s: wanted <%s>, got <%s>\n' "$3" "$2" "$1" >&2
        cat "$scratch/output" >&2
        exit 1
    fi
}

expect_check() (
    expected=$1 case_name=$2
    shift 2
    failures=0
    unset passes
    "$@" >"$scratch/output"
    case "$expected" in
        pass)
            assert_equal "${passes:-0}" 1 "$case_name: passes"
            assert_equal "$failures" 0 "$case_name: failures"
            ;;
        fail)
            assert_equal "${passes:-0}" 0 "$case_name: passes"
            assert_equal "$failures" 1 "$case_name: failures"
            ;;
        *) printf 'invalid test expectation: %s\n' "$expected" >&2; exit 1 ;;
    esac
    printf 'PASS: %s\n' "$case_name"
)

expect_capture() (
    run_captured sh -c "$3" >"$scratch/output"
    assert_equal "$status" "$1" 'captured status'
    assert_equal "$out" "$2" 'captured output'
    if [ -s "$scratch/output" ]; then
        printf 'FAIL: capture printed output\n' >&2
        cat "$scratch/output" >&2
        exit 1
    fi
)

expect_capture 0 'a ' 'printf "a\n"'
expect_capture 0 'a' 'printf a'
expect_capture 7 'a  ' 'printf "a\n\n"; exit 7'
expect_capture 56 '' 'exit 56'
expect_capture 0 'stdout stderr ' 'printf "stdout\n"; printf "stderr\n" >&2'
expect_capture 7 '60 ' 'printf "60\n"; exit 7'
expect_capture 0 '-n \literal ' 'printf "%s\n" "-n \literal"'
printf 'PASS: capture preserves status, whitespace and stderr\n'

expect_check pass 'success and matching output' check_ok fixture '^hello $' \
    sh -c 'printf "hello\n"'
expect_check fail 'success with wrong output' check_ok fixture '^hello $' \
    sh -c 'printf "goodbye\n"'
for code in 7 56; do
    expect_check fail "expected body followed by exit $code" check_ok fixture \
        '^hello from https example.test 443' \
        sh -c 'printf "hello from https example.test 443 over HTTP/2.0\n"; exit "$1"' _ "$code"
done
expect_check fail 'failed pipeline with matching output' check_ok fixture '^hello $' \
    bash -o pipefail -c 'printf "hello\n"; false | cat'
# A wrapper owns its status; the helper cannot recover a status it discards.
expect_check pass 'wrapper explicitly returns success' check_ok fixture '^hello $' \
    sh -c 'printf "hello\n"; false || true'

expect_check fail 'success is not a refusal' check_fails fixture '^denied $' \
    sh -c 'printf "denied\n"'
for code in 1 6 7 9 28 56 60; do
    expect_check pass "refusal status $code" check_fails fixture '^denied $' \
        sh -c 'printf "denied\n" >&2; exit "$1"' _ "$code"
done
for code in 124 126 127 137 141 255; do
    expect_check fail "runner failure $code is not a refusal" check_fails fixture '^denied $' \
        sh -c 'printf "denied\n"; exit "$1"' _ "$code"
    expect_check fail "runner failure $code cannot be expected" check_fails_with fixture "$code" '' \
        sh -c 'exit "$1"' _ "$code"
done
expect_check fail 'refusal with wrong output' check_fails fixture 'certificate' \
    sh -c 'printf "no route\n"; exit 7'
expect_check pass 'exact refusal and matching output' check_fails_with fixture 60 '^certificate $' \
    sh -c 'printf "certificate\n" >&2; exit 60'
expect_check pass 'exact refusal without an output pattern' check_fails_with fixture 60 '' \
    sh -c 'exit 60'
expect_check fail 'wrong denial code' check_fails_with fixture 60 'certificate' \
    sh -c 'printf "certificate\n"; exit 7'
expect_check fail 'exact refusal with wrong reason' check_fails_with fixture 2 'Operation not permitted' \
    sh -c 'printf "Cannot find device\n"; exit 2'
expect_check fail 'success cannot be an expected refusal' check_fails_with fixture 0 '' \
    sh -c 'exit 0'
expect_check fail 'invalid output pattern' check_ok fixture '[' sh -c 'printf "hello\n"'

expect_check pass 'legacy check remains output-only' check fixture '^hello $' \
    sh -c 'printf "hello\n"; exit 7'
expect_check fail 'legacy check still rejects wrong output' check fixture '^hello $' \
    sh -c 'printf "goodbye\n"'

failures=0
unset passes
expect_checks 0
assert_equal "$failures" 0 'empty expected count'
pass 'count a pass' >"$scratch/output"
fail 'count a failure' >>"$scratch/output"
expect_checks 2
assert_equal "$passes" 1 'pass count'
assert_equal "$failures" 1 'failure count'
expect_checks 3 >"$scratch/output"
assert_equal "$failures" 2 'short check count fails'
assert_equal "$(cat "$scratch/output")" 'FAIL: wanted 3 checks, got 2' 'short count diagnostic'
expect_checks 2 >"$scratch/output"
assert_equal "$failures" 3 'extra check count fails'
expect_checks invalid >"$scratch/output"
assert_equal "$failures" 4 'invalid expected count fails'
printf 'PASS: expected counts include passes and failures\n'

# These calls must reach the final assertions under strict Bash settings.
bash -euo pipefail -c '
    . "$1"
    failures=0
    check_ok positive hello sh -c "echo hello; exit 7"
    check_fails refusal denied sh -c "echo denied; exit 7"
    check_fails timeout denied sh -c "echo denied; exit 124"
    check_fails_with exact 60 "" sh -c "exit 60"
    check_fails_with wrong 60 "" sh -c "exit 7"
    check_ok pipeline hello bash -o pipefail -c "echo hello; false | cat"
    [ "$failures" -eq 4 ]
    [ "$passes" -eq 2 ]
    expect_checks 6
    [ "$failures" -eq 4 ]
' _ "$here/assertions.sh" >"$scratch/output"
printf 'PASS: failed commands do not abort strict Bash callers\n'
