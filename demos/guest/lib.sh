# Helpers for the demo scripts, which run inside the VM as root.
# shellcheck shell=bash

set -euo pipefail
export PATH="/opt/fictionet/bin:$PATH"

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
    "$@" bash -o pipefail -c "$cmd" 2>&1 | sed 's/^/    /'
    return "${PIPESTATUS[0]}"
}

# A command run in the VM itself, as root: setting up the demo. If it
# fails, the demo stops with an error.
vm() { show 'vm#' "$1" || { echo "demo: that command failed" >&2; exit 1; }; }

# A command run in the sandbox. AGENT is how to get into it. Its failures
# are shown and the demo goes on: many of these commands are meant to fail.
AGENT=(ip netns exec agent)
agent() { show 'agent$' "$1" "${AGENT[@]}" || true; }

# described WHAT COMMAND: like agent, for a command too long to read. It
# prints WHAT in place of the command.
described() {
    printf '%sagent$%s %s\n' "$dim" "$reset" "$1"
    "${AGENT[@]}" bash -c "$2" 2>&1 | sed 's/^/    /' || true
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
