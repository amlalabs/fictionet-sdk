#!/usr/bin/env bash
# The dashboard demo, run inside the VM by demos/dashboard. The web world
# and its sandbox from demos/web, with `fictionet dashboard` showing them
# live in your browser, and `fictionet observe` reading the same API from
# a shell.
# needs: sdk
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/web_setup.sh"
host_port="${FICTIONET_DASHBOARD_PORT:-7878}"
seconds="${DASHBOARD_SECONDS:-}"

cleanup() {
    stop_pid "${traffic_pid:-}"
    stop_pid "${dash_pid:-}"
    cleanup_web
}
trap cleanup EXIT
cleanup

step "Start the world, and attach a sandbox to it"
note "The same web_world example and network namespace as demos/web."
start_web
attach_web

step "Start the dashboard"
note "fictionet dashboard connects to the world's socket as an observer: the world needs no"
note "flag of its own. In the VM it listens on port 7878, which vm/run forwards to"
note "127.0.0.1:$host_port on your machine, and nowhere else."
umask 077
token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" > /run/fictionet/dashboard-token
fictionet dashboard --token-file /run/fictionet/dashboard-token --world unix:/run/fictionet/world.sock --listen 0.0.0.0:7878 >/run/dashboard.log 2>&1 &
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
"${AGENT[@]}" bash -c 'while :; do
    dig +short example.test nope.test >/dev/null
    curl -sS --cacert /run/agent-ca.pem https://example.test/ >/dev/null
    curl -sS http://plain.test/ >/dev/null
    sleep 1
done' >/dev/null 2>&1 &
traffic_pid=$!
sleep 3

step "The same API from a shell: fictionet observe"
vm "fictionet observe --world unix:/run/fictionet/world.sock world"
vm "fictionet observe --world unix:/run/fictionet/world.sock graph | jq -c '{tasks: [.nodes[] | select(.kind != \"sandbox\")] | length, sandboxes: [.nodes[] | select(.kind == \"sandbox\") | .name], links: (.edges | length)}'"
note "The world keeps a log of events, such as web_world's dns.query and http.request, whether"
note "or not anyone watches. The watch request shows the latest, then each new one as it happens:"
vm "{ timeout 4 fictionet observe --world unix:/run/fictionet/world.sock watch || true; } | jq -c 'select(.event == \"event\") | .data | {source, kind, summary}' | sed -n 1,4p"

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

step "Clean up"
note "Stopping the traffic, the dashboard, attach and the world."
