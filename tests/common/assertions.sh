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

_capture_stderr() { "$@" 2>"$_assert_stderr_file"; }

# NAME, PATTERN, CMD...: require a failed connection and its reason on stderr.
# A NetworkPolicy may drop SYNs. A timeout is evidence only before connecting;
# a stalled response (even with no bytes received) is not isolation evidence.
check_connect_fails() {
    _assert_name=$1 _assert_want=$2
    shift 2
    if ! _assert_stderr_file=$(mktemp); then
        fail "$_assert_name: could not create stderr capture"
        return
    fi
    run_captured _capture_stderr "$@"
    if ! _assert_stderr=$(cat "$_assert_stderr_file"); then
        fail "$_assert_name: could not read stderr capture"
        if ! rm -f "$_assert_stderr_file"; then fail "$_assert_name: could not remove stderr capture"; fi
        return
    fi
    if ! rm -f "$_assert_stderr_file"; then
        fail "$_assert_name: could not remove stderr capture"
        return
    fi
    if ! _refusal_status "$status"; then
        fail "$_assert_name: wanted a failed connection, got status $status: $out $_assert_stderr"
    elif printf '%s\n' "$_assert_stderr" | grep -E 'Operation timed out|bytes received' >/dev/null; then
        fail "$_assert_name: timeout after connecting: $_assert_stderr"
    elif printf '%s\n' "$_assert_stderr" | grep -E -- "$_assert_want" >/dev/null; then
        pass "$_assert_name"
    else
        fail "$_assert_name: wanted /$_assert_want/ on stderr, got status $status: $out $_assert_stderr"
    fi
}

# Require exactly N recorded checks. This does not count itself as a pass.
expect_checks() {
    if [ "$((${passes:-0} + failures))" != "$1" ]; then
        fail "wanted $1 checks, got $((${passes:-0} + failures))"
    fi
}

# The transfer helpers require Bash; the assertions above also work in sh.
[ -n "${BASH_VERSION:-}" ] || return 0

# Shared transfer checks for Docker and Kubernetes tests.
# Return a single transfer's measurement, or a diagnostic on failure.
# Upload responses may put the byte count and measurement on separate lines.
check_transfer() {
    local bytes="$1"
    shift
    local out size value extra
    if ! out="$("$@")"; then
        echo "transfer failed: $out"
        return 1
    fi
    if read -r size value extra <<<"${out//$'\n'/ }" && [[ $size == "$bytes" &&
        $value =~ ^[0-9]+([.][0-9]+)?$ && -z $extra ]]; then
        echo "$value"
    else
        echo "expected $bytes bytes and one measurement, got: $out"
        return 1
    fi
}

# Commands print one "bytes seconds" row per download and must fail on errors.
# Each download must be exactly `bytes` long.
check_downloads() {
    local name="$1" count="$2" bytes="$3"
    shift 3
    local out times
    if ! out="$("$@")"; then
        fail "$name: transfer failed: $out"
        return
    fi
    if ! awk -v count="$count" -v bytes="$bytes" '
        NF != 2 || $1 != bytes || $2 !~ /^[0-9]+([.][0-9]+)?$/ { bad = 1 }
        END { exit (bad || NR != count) }
    ' <<<"$out"; then
        fail "$name: expected $count complete downloads of $bytes bytes: $out"
        return
    fi
    read -r -a times <<<"$(awk '{print $2}' <<<"$out" | sort -n | tr '\n' ' ')"
    pass "$name (${times[0]} s to ${times[-1]} s)"
}

# The holder prints one readiness line and keeps its sockets until released.
# Save $! because Bash may unset holder_PID when it reaps an early exit.
start_holder() {
    local variable="$1"
    shift
    coproc holder { "$@"; }
    holder_pid=$!
    read_holder "$variable"
}

read_holder() {
    local -n readiness="$1"
    local fd=${holder[0]:-}
    readiness='0 0'
    if [[ -n $fd ]] && read -r -t 120 -u "$fd" readiness 2>/dev/null; then
        return 0
    fi
    readiness='0 0'
    return 1
}

release_holder() {
    local fd=${holder[1]:-} status=0
    # A closed pipe must not terminate the parent shell or print fd errors.
    if [[ -n $fd ]]; then
        { (printf 'release\n'); } 2>/dev/null >&"$fd" || status=1
    else
        status=1
    fi
    if [[ -n ${holder_pid:-} ]]; then
        wait "$holder_pid" || status=1
    else
        status=1
    fi
    return "$status"
}

# Run inside the agent after releasing a holder. FIN_WAIT and CLOSE_WAIT
# still count against the world's limit; give them 10 s to finish closing.
drain_connections() {
    "$@" bash -c '
        for ((i=0; i<100; i++)); do
            remaining=$(awk '\''$3 == "010012C6:0050" && $4 != "06" { n++ }
                END { print n+0 }'\'' /proc/net/tcp) || exit 1
            [[ $remaining == 0 ]] && exit 0
            sleep 0.1
        done
        echo "$remaining connections to 198.18.0.1:80 did not close within 10 s" >&2
        exit 1'
}
