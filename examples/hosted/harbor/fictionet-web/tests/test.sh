#!/bin/bash
# Compare the complete answer with a fresh world response and check isolation.
# Harbor runs this in main; these checks trust the container's tools.
set -euo pipefail
note() { echo "$*"; }
fail() { note "FAIL: $*"; return 1; }

check_tools() {
    local tool ok=1
    for tool in "$@"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            note "FAIL: missing tool: $tool"
            ok=0
        fi
    done
    [[ "$ok" == 1 ]]
}

check_answer() {
    local answer=$1 expected=$2 curl=$3 cmp=$4 challenge
    if ! "$curl" -sS --fail --cacert /run/ca/ca.pem https://example.test/challenge > "$expected"; then
        fail "could not fetch the world challenge"
    elif ! { IFS= read -r challenge < "$expected" && [[ "$challenge" =~ ^[0-9a-f]{64}$ ]] &&
             printf '%s\n' "$challenge" | "$cmp" -s - "$expected"; }; then
        fail "malformed world challenge"
    elif [[ -f "$answer" && -r "$answer" && ! -L "$answer" ]] && "$cmp" -s "$expected" "$answer"; then
        note "PASS: answer matches the complete world challenge"
    else
        fail "answer is missing, unreadable or differs from the world challenge"
    fi
}

check_interfaces() {
    local net_class_dir=$1 links
    if links="$(ls "$net_class_dir" | sort | tr '\n' ' ')" && [[ "$links" == "lo tun0 " ]]; then
        note "PASS: only lo and tun0"
    else
        fail "links: $links"
    fi
}

check_dns() {
    local dig=$1 out
    if out="$("$dig" +time=2 +tries=1 @8.8.8.8 example.com 2>&1)"; then
        fail "DNS to 8.8.8.8 answered"
    else
        note "PASS: DNS to 8.8.8.8 fails"
    fi
}

check_connection() {
    local curl=$1 error_file=$2 status=0 connect_time out
    connect_time="$("$curl" -sS --connect-timeout 5 -m 5 -o /dev/null -w '%{time_connect}' https://1.1.1.1/ 2> "$error_file")" || status=$?
    out="$(< "$error_file")"
    if [[ "$status" == 7 && "$out" =~ No\ route\ to\ host|Could\ not\ connect|Failed\ to\ connect ]]; then
        note "PASS: 1.1.1.1 connection denied: $out"
    else
        fail "1.1.1.1: status $status, time_connect=$connect_time: $out"
    fi
}

check_capabilities() {
    local proc_status=$1 cap_eff= cap_count=0 field value
    if [[ -r "$proc_status" ]]; then
        while read -r field value; do
            if [[ "$field" == CapEff: ]]; then
                cap_eff="$value"
                cap_count=$((cap_count + 1))
            fi
        done < "$proc_status"
    fi
    if [[ "$cap_count" == 1 && "$cap_eff" =~ ^[[:xdigit:]]{16}$ ]] && (( (16#$cap_eff & 0x1000) == 0 )); then
        note "PASS: the agent has no NET_ADMIN"
    else
        fail "missing, malformed or NET_ADMIN-enabled CapEff: $cap_eff"
    fi
}

check_routes() {
    local ip=$1 status=0 out
    out="$("$ip" route del default 2>&1 >/dev/null)" || status=$?
    if [[ "$status" == 2 && "$out" == *"Operation not permitted"* ]]; then
        note "PASS: the agent cannot change its routes"
    else
        fail "route deletion: status $status: $out"
    fi
}

verify() {
    local answer=$1 reward_dir=$2 net_class_dir=$3 proc_status=$4 expected ok=1
    mkdir -p "$reward_dir"
    # Harbor prefers reward.json; discard agent-written outputs and links first.
    if ! rm -f -- "$reward_dir/reward.json" "$reward_dir/reward.txt" "$reward_dir/curl.err"; then
        fail "cannot clear verifier output files" >&2
        return 1
    fi
    echo 0 > "$reward_dir/reward.txt"
    check_tools curl dig ip cmp mktemp || return 1
    expected="$(mktemp "$reward_dir/expected.XXXXXX")"
    if ! check_answer "$answer" "$expected" curl cmp; then ok=0; fi
    rm -f -- "$expected"
    if ! check_interfaces "$net_class_dir"; then ok=0; fi
    if ! check_dns dig; then ok=0; fi
    if ! check_connection curl "$reward_dir/curl.err"; then ok=0; fi
    if ! check_capabilities "$proc_status"; then ok=0; fi
    if ! check_routes ip; then ok=0; fi
    echo "$ok" > "$reward_dir/reward.txt"
    [[ "$ok" == 1 ]]
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    verify /app/answer.txt /logs/verifier /sys/class/net /proc/self/status
fi
