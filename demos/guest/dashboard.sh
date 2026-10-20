#!/usr/bin/env bash
# The dashboard demo, run inside the VM by cargo xtask demo dashboard. The web world
# and its sandbox from cargo xtask demo web, with `fictionet dashboard` showing them
# live in your browser. `fictionet observe` reads the same API from a shell.
# Both commands connect to the world's private observation socket.
# needs: sdk
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/web_setup.sh"
host_port="${FICTIONET_DASHBOARD_PORT:-7878}"
seconds="${DASHBOARD_SECONDS:-}"

cleanup() {
    stop_pid "${traffic_pid:-}"
    stop_pid "${dash_pid:-}"
    cleanup_web
    rm -f /run/dashboard.log /run/traffic.log /run/watch.jsonl
}
trap cleanup EXIT
cleanup

step "Start the world, and attach a sandbox to it"
note "The same web_world example and network namespace as cargo xtask demo web."
start_web /run/fictionet/observation.sock
attach_web

step "Start the dashboard"
note "web_world serves its collector on the third path with fictionet_observe::serve."
note "fictionet dashboard connects through --observation unix:/run/fictionet/observation.sock."
note "In the VM it listens on port 7878, which cargo xtask vm forwards to"
note "127.0.0.1:$host_port on your machine, and nowhere else."
umask 077
token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" > /run/fictionet/dashboard-token
fictionet dashboard --token-file /run/fictionet/dashboard-token --observation unix:/run/fictionet/observation.sock --listen 0.0.0.0:7878 >/run/dashboard.log 2>&1 &
dash_pid=$!
for _ in $(seq 50); do grep -q serving /run/dashboard.log && break; sleep 0.1; done
sed 's/^/    /' /run/dashboard.log
vm "curl -sS -H 'Authorization: Bearer $token' -H 'Host: 127.0.0.1:$host_port' http://127.0.0.1:7878/ | grep -o '<title>[^<]*'"

step "Some traffic from the sandbox"
note "A loop in the sandbox looks up names and fetches pages every second, so the graph has"
note "something to show."
install -m 0644 /run/fictionet/ca.pem /run/agent-ca.pem
AGENT=(ip netns exec agent setpriv --reuid=agent --regid=agent --clear-groups
    --inh-caps=-all --bounding-set=-all --no-new-privs
    env -i PATH=/usr/bin:/bin HOME=/tmp)
agent 'dig +short example.test; curl -fsS --cacert /run/agent-ca.pem https://example.test/ >/dev/null; curl -fsS http://plain.test/ >/dev/null'
"${AGENT[@]}" bash -ec 'while :; do
    dig +short example.test nope.test >/dev/null
    curl -fsS --cacert /run/agent-ca.pem https://example.test/ >/dev/null
    curl -fsS http://plain.test/ >/dev/null
    sleep 1
done' >/run/traffic.log 2>&1 &
traffic_pid=$!
sleep 3
if ! kill -0 "$traffic_pid" 2>/dev/null; then
    echo "demo: sandbox traffic exited" >&2
    sed 's/^/    /' /run/traffic.log >&2
    exit 1
fi

step "The same API from a shell: fictionet observe"
vm "fictionet observe --observation unix:/run/fictionet/observation.sock world"
vm "fictionet observe --observation unix:/run/fictionet/observation.sock graph | jq -c '{tasks: [.nodes[] | select(.kind != \"sandbox\")] | length, sandboxes: [.nodes[] | select(.kind == \"sandbox\") | .name], links: (.edges | length)}'"
note "web_world installs a collector that retains events before clients connect."
note "watch 0 replays its retained events, then follows events as they arrive."
note "Retention is bounded. Here are the first four:"
vm "s=0
timeout 4 fictionet observe --observation unix:/run/fictionet/observation.sock watch 0 >/run/watch.jsonl || s=\$?
[[ \$s -eq 0 || \$s -eq 124 ]] || exit \"\$s\"
jq -es 'map(select(.event == \"event\" and .data.source == \"http\")) | length > 0' /run/watch.jsonl >/dev/null
jq -c 'select(.event == \"event\") | .data | {source, kind, summary}' /run/watch.jsonl | sed -n 1,4p"

step "Open the dashboard"
printf '\n    %shttp://127.0.0.1:%s/#token=%s%s\n\n' "$bold" "$host_port" "$token" "$reset"
if [[ -z $seconds && -t 0 ]]; then
    note "The sandbox keeps making requests while you look. Press Enter to stop."
    read -r _
else
    seconds="${seconds:-10}"
    note "Stopping in $seconds s (DASHBOARD_SECONDS sets how long)."
    sleep "$seconds"
fi

if ! kill -0 "$traffic_pid" 2>/dev/null; then
    echo "demo: sandbox traffic exited" >&2
    sed 's/^/    /' /run/traffic.log >&2
    exit 1
fi

step "Clean up"
note "Stopping the traffic, the dashboard, attach and the world."
