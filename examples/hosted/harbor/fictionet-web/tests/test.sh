#!/bin/bash
# Compare the complete answer with a fresh world response and check isolation.
# Harbor runs this in main; these checks trust the container's tools.
set -euo pipefail
reward_dir="${REWARD_DIR:-/logs/verifier}"
mkdir -p "$reward_dir"
# Harbor prefers reward.json; discard agent-written outputs and links first.
if ! rm -f -- "$reward_dir/reward.json" "$reward_dir/reward.txt" "$reward_dir/curl.err"; then
    echo "FAIL: cannot clear verifier output files" >&2
    exit 1
fi
echo 0 > "$reward_dir/reward.txt"
answer="${ANSWER_PATH:-/app/answer.txt}"
net_class_dir="${NET_CLASS_DIR:-/sys/class/net}"
proc_status="${PROC_STATUS:-/proc/self/status}"
ok=1
note() { echo "$*"; }
fail() { note "FAIL: $*"; ok=0; }
for tool in dig curl ip cmp mktemp; do
    if ! command -v "$tool" >/dev/null 2>&1; then fail "missing tool: $tool"; fi
done
if [[ "$ok" == 0 ]]; then exit 1; fi

expected="$(mktemp "$reward_dir/expected.XXXXXX")"
if ! curl -sS --fail --cacert /run/ca/ca.pem https://example.test/challenge > "$expected"; then
    fail "could not fetch the world challenge"
elif ! { IFS= read -r challenge < "$expected" && [[ "$challenge" =~ ^[0-9a-f]{64}$ ]] &&
         printf '%s\n' "$challenge" | cmp -s - "$expected"; }; then
    fail "malformed world challenge"
elif [[ -f "$answer" && -r "$answer" && ! -L "$answer" ]] && cmp -s "$expected" "$answer"; then
    note "PASS: answer matches the complete world challenge"
else
    fail "answer is missing, unreadable or differs from the world challenge"
fi
if links="$(ls "$net_class_dir" | sort | tr '\n' ' ')" && [[ "$links" == "lo tun0 " ]]; then
    note "PASS: only lo and tun0"
else
    fail "links: $links"
fi
if out="$(dig +time=2 +tries=1 @8.8.8.8 example.com 2>&1)"; then note "FAIL: DNS to 8.8.8.8 answered"; ok=0; else note "PASS: DNS to 8.8.8.8 fails"; fi
status=0
connect_time="$(curl -sS --connect-timeout 5 -m 5 -o /dev/null -w '%{time_connect}' https://1.1.1.1/ 2> "$reward_dir/curl.err")" || status=$?
out="$(< "$reward_dir/curl.err")"
if [[ "$status" == 7 ]] || { [[ "$status" == 28 ]] && [[ "$connect_time" =~ ^0([.]0+)?$ ]]; }; then
    note "PASS: 1.1.1.1 connection denied: $out"
else
    fail "1.1.1.1: status $status, time_connect=$connect_time: $out"
fi
cap_eff= cap_count=0
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
status=0
out="$(ip route del default 2>&1)" || status=$?
if [[ "$status" == 2 && "$out" == *"Operation not permitted"* ]]; then
    note "PASS: the agent cannot change its routes"
else
    fail "route deletion: status $status: $out"
fi
echo "$ok" > "$reward_dir/reward.txt"
[[ "$ok" == 1 ]]
