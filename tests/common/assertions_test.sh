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

connect_pattern="Couldn't connect|Connection timed out|Timeout was reached|Connection refused|Failed to connect"
connected_then_timeout() {
    printf 'curl: (28) Operation timed out after 5001 milliseconds with 0 bytes received\n' >&2
    return 28
}
expect_check fail 'connected_then_timeout' check_connect_fails fixture "$connect_pattern" \
    connected_then_timeout
for reason in 'Connection timed out after 5001 milliseconds' \
    'Failed to connect to 1.1.1.1 port 80: Timeout was reached'; do
    expect_check pass "$reason" check_connect_fails fixture "$connect_pattern" \
        sh -c 'printf "curl: (28) %s\n" "$1" >&2; exit 28' _ "$reason"
done
expect_check pass 'connection refusal' check_connect_fails fixture "$connect_pattern" \
    sh -c 'printf "%s\n" "$1" >&2; exit 7' _ "curl: (7) Couldn't connect to server"
expect_check fail 'denial text on stdout is not connection evidence' check_connect_fails fixture "$connect_pattern" \
    sh -c 'printf "Connection timed out\n"; exit 28'
expect_check fail 'successful connection with denial text' check_connect_fails fixture "$connect_pattern" \
    sh -c 'printf "Connection timed out\n" >&2'
expect_check fail 'ambiguous pre-connect and post-connect evidence' check_connect_fails fixture "$connect_pattern" \
    sh -c 'printf "Failed to connect: Operation timed out\n" >&2; exit 28'
expect_check fail 'bytes received rules out containment' check_connect_fails fixture "$connect_pattern" \
    sh -c 'printf "Connection timed out with 0 bytes received\n" >&2; exit 28'
for code in 124 126 127 137; do
    expect_check fail "runner failure $code is not containment" check_connect_fails fixture "$connect_pattern" \
        sh -c 'printf "Connection timed out\n" >&2; exit "$1"' _ "$code"
done

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

# Execute the actual harness calls with fake external commands. This catches a
# caller reverting to an output-only check or discarding a probe setup failure.
mkdir "$scratch/bin"
cat >"$scratch/bin/probe" <<'EOF'
#!/bin/sh
printf '%s' "$fixture_stdout"
printf '%s' "$fixture_stderr" >&2
exit "$fixture_status"
EOF
chmod +x "$scratch/bin/probe"
for tool in curl ip kubectl getent; do ln -s probe "$scratch/bin/$tool"; done

expect_harness() (
    expected=$1 harness=$2 label=$3
    fixture_status=$4 fixture_stdout=$5 fixture_stderr=$6
    export fixture_status fixture_stdout fixture_stderr
    awk -v label="$label" '
        /^check[_a-z]* "/ && index($0, "\"" label "\"") { found=1 }
        found { print; if ($0 !~ /\\$/) exit }
    ' "$here/../$harness" >"$scratch/check"
    if [ ! -s "$scratch/check" ]; then
        printf 'FAIL: missing harness check: %s\n' "$label" >&2
        exit 1
    fi
    PATH="$scratch/bin:$PATH" bash -euo pipefail -c '
        . "$1"
        failures=0
        passes=0
        agent() { "$@"; }
        ca=() bridge=fixture ns=fixture pod=fixture nopolicy_pod=fixture
        api=192.0.2.1 node_ip=192.0.2.2 gateway=192.0.2.3
        . "$2"
        case "$3" in
            pass) test "$passes" -eq 1 && test "$failures" -eq 0 ;;
            fail) test "$passes" -eq 0 && test "$failures" -eq 1 ;;
            *) exit 2 ;;
        esac
    ' _ "$here/assertions.sh" "$scratch/check" "$expected" >"$scratch/output" || {
        cat "$scratch/output" >&2
        exit 1
    }
    printf 'PASS: %s: %s (status %s)\n' "$harness" "$label" "$fixture_status"
)

for harness in docker/web/run.sh k8s/run.sh k8s/proxy.sh; do
    if [ "$harness" = docker/web/run.sh ]; then
        label='curl -L follows the redirect'
    else
        label='after the restart, https works again'
    fi
    expect_harness fail "$harness" "$label" 56 \
        'hello from https example.test 443 over HTTP/2.0' ''
done
expect_harness fail k8s/run.sh '1.1.1.1 is unreachable' 0 '' "Couldn't connect to server"
for label in 'and its first try at the API server is blocked' \
    '1.1.1.1 is unreachable around the proxy' \
    'the API server ($api) is unreachable around the proxy' \
    "the kubelet on the pod's node (\$node_ip) is unreachable" \
    "the kubelet at the pod's gateway (\$gateway) is unreachable"; do
    expect_harness fail k8s/proxy.sh "$label" 28 '' \
        'curl: (28) Operation timed out after 5001 milliseconds with 0 bytes received'
done
expect_harness pass k8s/proxy.sh '1.1.1.1 is unreachable around the proxy' 28 '' \
    'curl: (28) Connection timed out after 5001 milliseconds'
expect_harness pass k8s/proxy.sh '1.1.1.1 is unreachable around the proxy' 28 '' \
    'curl: (28) Failed to connect to 1.1.1.1 port 80: Timeout was reached'
expect_harness fail docker/proxy/run.sh \
    "the host has no IPv4 address on the sandbox's network (\$bridge)" 1 '' ''
expect_harness fail k8s/proxy.sh 'no container adds a capability or runs as root' 1 '' ''
expect_harness fail k8s/run.sh 'with attach stopped, tun0 is gone' 1 '' ''
expect_harness pass docker/proxy/run.sh \
    "the host has no IPv4 address on the sandbox's network (\$bridge)" 0 '' ''
expect_harness pass k8s/proxy.sh 'no container adds a capability or runs as root' 0 '{}' ''
expect_harness pass k8s/run.sh 'with attach stopped, tun0 is gone' 0 'lo UNKNOWN' ''

# Keep the migrated harnesses and new Docker/Kubernetes harnesses status-aware.
# The VM harness has its own migration (T11-37).
if matches=$(grep -RnE --include='*.sh' \
    '^[[:space:]]*check[[:space:]]*(\(|")|^[[:space:]]*[a-zA-Z_][a-zA-Z_0-9]*=.*2>&1.*\|[[:space:]]*tr.*\|\|[[:space:]]*true' \
    "$here" "$here/../docker" "$here/../k8s"); then
    printf 'FAIL: output-only shell assertions:\n%s\n' "$matches" >&2
    exit 1
else
    grep_status=$?
    if [ "$grep_status" -ne 1 ]; then exit "$grep_status"; fi
fi
printf 'PASS: Docker/Kubernetes harnesses have no legacy output-only captures or checks\n'
