# Shared assertions. The caller initializes failures and handles the result.
# Checks record passes/failures and return normally, including under set -e.
pass() { echo "PASS: $*"; passes=$((${passes:-0} + 1)); }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# Capture stdout, stderr and status before formatting. This prints nothing.
# The status suffix keeps command substitution from stripping output newlines.
run_captured() {
    out="$(
        if "$@" 2>&1; then
            printf '\n0'
        else
            printf '\n%d' "$?"
        fi
    )"
    status=${out##*'
'}
    out=${out%'
'*}
    out="$(printf '%s' "$out" | tr '\n' ' ')"
}

_check_output() {
    if printf '%s\n' "$out" | grep -E -- "$2" >/dev/null; then
        pass "$1"
    else
        fail "$1: wanted /$2/, got: $out"
    fi
}

_refusal_status() {
    case "$1" in 0|124|126|127) return 1 ;; esac
    [ "$1" -le 128 ]
}

# NAME, grep -E PATTERN, CMD...: require success before matching the output.
check_ok() {
    _assert_name=$1 _assert_want=$2
    shift 2
    run_captured "$@"
    if [ "$status" -eq 0 ]; then
        _check_output "$_assert_name" "$_assert_want"
    else
        fail "$_assert_name: wanted status 0, got $status: $out"
    fi
}

# NAME, PATTERN, CMD...: accept a refusal, but not a timeout, execution error
# (126/127), or signal (>128). The command must also print the expected text.
check_fails() {
    _assert_name=$1 _assert_want=$2
    shift 2
    run_captured "$@"
    if _refusal_status "$status"; then
        _check_output "$_assert_name" "$_assert_want"
    else
        fail "$_assert_name: wanted a refusal, got status $status: $out"
    fi
}

# NAME, STATUS, PATTERN, CMD...: require this exact refusal status. An empty
# pattern accepts any output. Timeouts, execution errors and signals still fail.
check_fails_with() {
    _assert_name=$1 _assert_status=$2 _assert_want=$3
    shift 3
    run_captured "$@"
    if _refusal_status "$status" && [ "$status" = "$_assert_status" ]; then
        _check_output "$_assert_name" "$_assert_want"
    else
        fail "$_assert_name: wanted refusal status $_assert_status, got $status: $out"
    fi
}

# Require exactly N recorded checks. This does not count itself as a pass.
expect_checks() {
    if [ "$((${passes:-0} + failures))" != "$1" ]; then
        fail "wanted $1 checks, got $((${passes:-0} + failures))"
    fi
}

# T11-32 replaces this legacy output-only check at its callers.
# Runs a check: name, then the expected text (a grep -E pattern), then the
# command. The command's stdout and stderr are matched, as one line.
check() {
    _legacy_name=$1 _legacy_want=$2
    shift 2
    # Lines are joined with spaces, so a pattern can span them.
    # Only the output is checked; the command's exit status is ignored.
    _legacy_out="$("$@" 2>&1 | tr '\n' ' ')" || true
    if printf '%s\n' "$_legacy_out" | grep -E -- "$_legacy_want" >/dev/null; then
        pass "$_legacy_name"
    else
        fail "$_legacy_name: wanted /$_legacy_want/, got: $_legacy_out"
    fi
}
