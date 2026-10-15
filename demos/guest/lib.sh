# Helpers for the demo scripts, which run inside the VM as root.
# shellcheck shell=bash

set -euo pipefail
export PATH="/opt/fictionet/bin:$PATH"

# Reuse the harness's refusal classification. Its checks collect failures and
# flatten output; demos need to stop at the first failure and keep line breaks.
. "$(dirname "${BASH_SOURCE[0]}")/../../tests/common/assertions.sh"

if [[ -t 1 ]]; then
    bold=$'\e[1m' dim=$'\e[2m' reset=$'\e[0m'
else
    bold='' dim='' reset=''
fi

# A heading: what happens next, in plain words.
step() { printf '\n%s== %s%s\n' "$bold" "$*" "$reset"; }
# A line of explanation.
note() { printf '%s\n' "$*"; }

# show PROMPT COMMAND [RUNNER...]: prints the command after PROMPT, runs it
# with bash (inside RUNNER, such as `ip netns exec agent`), indents its
# output, and returns its exit status.
show() {
    local prompt="$1" cmd="$2"
    shift 2
    printf '%s%s%s %s\n' "$dim" "$prompt" "$reset" "$cmd"
    "$@" bash -eo pipefail -c "$cmd" 2>&1 | sed 's/^/    /'
    return "${PIPESTATUS[0]}"
}

# A command run in the VM itself, as root: setting up the demo. If it
# fails, the demo stops with an error.
vm() { show 'vm#' "$1" || { echo "demo: that command failed" >&2; exit 1; }; }

# A command run in the sandbox. AGENT is how to get into it.
AGENT=(ip netns exec agent)
agent() { show 'agent$' "$1" "${AGENT[@]}"; }

# Capture status and combined output before applying show's formatting. The
# callers keep out and status local. A suffix keeps trailing newlines.
_capture_agent() {
    printf '%sagent$%s %s\n' "$dim" "$reset" "$1"
    out="$(
        if "${AGENT[@]}" bash -eo pipefail -c "$1" 2>&1; then
            printf '\n0'
        else
            printf '\n%d' "$?"
        fi
    )"
    status=${out##*$'\n'}
    out=${out%$'\n'*}
}

_expect_pattern() {
    if [[ -n $1 ]] && printf '%s' "$out" | grep -E -- "$1" >/dev/null; then
        return 0
    fi
    echo "demo: wanted output matching /$1/" >&2
    return 1
}

# expect_fail STATUS [PATTERN] CMD: only this status and diagnostic prove the
# refusal. Status 124 (timeout), execution errors and signals cannot be expected.
expect_fail() {
    if [[ $# -ne 2 && $# -ne 3 ]]; then
        echo "demo: usage: expect_fail STATUS [PATTERN] CMD" >&2
        return 1
    fi
    local expected="$1" pattern='' cmd="${!#}" out status
    [[ $# -ne 3 ]] || pattern=$2
    _capture_agent "$cmd"
    printf '%s' "$out" | sed 's/^/    /'
    if ! _refusal_status "$status" || [[ $status != "$expected" ]]; then
        echo "demo: wanted refusal status $expected, got $status" >&2
        return 1
    fi
    [[ -z $pattern ]] || _expect_pattern "$pattern"
}

# expect_output CMD PATTERN...: the command must succeed and every pattern
# must match its unformatted output. Show matching lines on success and the
# whole capture on failure.
expect_output() {
    if [[ $# -lt 2 ]]; then
        echo "demo: usage: expect_output CMD PATTERN..." >&2
        return 1
    fi
    local cmd="$1" pattern out status
    local -a patterns=()
    shift
    _capture_agent "$cmd"
    if [[ $status -ne 0 ]]; then
        printf '%s' "$out" | sed 's/^/    /'
        echo "demo: wanted status 0, got $status" >&2
        return 1
    fi
    for pattern in "$@"; do
        if ! _expect_pattern "$pattern"; then
            printf '%s' "$out" | sed 's/^/    /'
            return 1
        fi
        patterns+=(-e "$pattern")
    done
    printf '%s' "$out" | grep -E "${patterns[@]}" | sed 's/^/    /'
}

# described WHAT COMMAND: like agent, for a command too long to read. It
# prints WHAT in place of the command.
described() {
    printf '%sagent$%s %s\n' "$dim" "$reset" "$1"
    "${AGENT[@]}" bash -eo pipefail -c "$2" 2>&1 | sed 's/^/    /'
}

# wait_for PATH SECONDS: waits until a file or socket exists.
wait_for() {
    local i
    for ((i = 0; i < $2 * 10; i++)); do
        [[ -e $1 ]] && return 0
        sleep 0.1
    done
    echo "timed out waiting for $1" >&2
    return 1
}

# stop_pid PID: stops a background process and waits for it.
stop_pid() {
    [[ -n $1 ]] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
