#!/usr/bin/env bash
# The web demo, run inside the VM by cargo xtask demo web. A world of websites, and a
# sandbox that reaches it through a tun device, with ordinary tools. Then
# `fictionet observe` reads what the world saw from its observation socket.
# needs: sdk
. "$(dirname "$0")/lib.sh"
. "$(dirname "$0")/web_setup.sh"

cleanup() {
    cleanup_web
    rm -f /run/watch.jsonl
}
trap cleanup EXIT
cleanup

step "Start the world"
note "The world is the web_world example: an ordinary Rust program built on web::Sites."
note "It serves example.test over HTTPS with a CA it makes at start, plain.test over HTTP,"
note "and www.example.test, shared.test, v4only.test and v6only.test. Other names fail."
note "Its third path opens a private observation socket, for the last step."
start_web /run/fictionet/observation.sock

step "Make the sandbox and attach it"
note "The sandbox is a network namespace named agent. fictionet attach puts a tun device"
note "in it, gives it 10.0.0.2 with the world's gateway 10.0.0.1 as its default route and DNS"
note "server, and relays every packet to the world's socket."
attach_web
# The agent's commands run as the user agent, not as root: root in a
# network namespace could leave it. ping keeps its file capability.
install -m 0644 /run/fictionet/ca.pem /run/agent-ca.pem
AGENT=(ip netns exec agent setpriv --reuid=agent --regid=agent --clear-groups env -i PATH=/usr/bin:/bin HOME=/tmp)
note "The agent's commands run as an ordinary user, agent, inside the namespace."
note "Inside the sandbox, the tun device is the only way out:"
agent 'id; ip -br addr; ip route; cat /etc/resolv.conf'

step "DNS: the world decides what every name means"
agent 'dig +short example.test'
expect_output 'dig nope.test' 'status: NXDOMAIN' 'ANSWER: 0'

step "HTTPS, with the world's CA"
note "curl does its own TLS. The world's site answers with the name it was asked for and the"
note "HTTP version it spoke."
agent 'curl -fsS --cacert /run/agent-ca.pem https://example.test/'
agent 'curl -fsS --cacert /run/agent-ca.pem -o /dev/null -w "%{http_code} over HTTP/%{http_version}, certificate check %{ssl_verify_result} (0 means it passed)\n" https://www.example.test/'
note "Without the world's CA, curl refuses the certificate, as it would on the internet:"
expect_fail 60 'SSL certificate problem' 'curl -sS https://example.test/'
note "Plain HTTP: example.test redirects to https, and plain.test has no TLS at all."
agent 'curl -fsS -i http://example.test/ | head -2'
agent 'curl -fsS http://plain.test/'

step "ping, and an address with no machine"
agent 'ping -c 3 -W 2 10.0.0.1'
agent 'ping -c 2 -W 2 203.0.113.10'
note "The world answers an address it has no machine for with ICMP \"host unreachable\","
note "so a connection fails at once instead of hanging:"
expect_fail 1 'No route to host' 'time timeout 3 bash -c "exec 3<>/dev/tcp/192.0.2.1/80"'

step "An unknown host fails, and the real internet is not there"
expect_fail 6 'Could not resolve host' 'curl -sS --cacert /run/agent-ca.pem https://nope.test/'
expect_fail 6 'Could not resolve host' 'curl -sS -m 5 https://example.com/'
expect_fail 7 "Could(n't| not) connect" 'curl -sS -m 5 http://1.1.1.1/'
note "The VM itself has the internet (it pulled this demo's packages), but the sandbox only"
note "ever reaches the world."

step "What the world saw: fictionet observe"
note "web_world serves its collector on /run/fictionet/observation.sock with fictionet_observe."
note "fictionet observe reads it from a shell: the world, then its graph."
vm "fictionet observe --observation unix:/run/fictionet/observation.sock world"
vm "fictionet observe --observation unix:/run/fictionet/observation.sock graph | jq -c '{tasks: [.nodes[] | select(.kind != \"sandbox\")] | length, sandboxes: [.nodes[] | select(.kind == \"sandbox\") | .name], links: (.edges | length)}'"
note "The collector retains events before any client connects. watch 0 replays them, then"
note "follows new ones. The requests above are among them. Here are the first four:"
vm "s=0
timeout 4 fictionet observe --observation unix:/run/fictionet/observation.sock watch 0 >/run/watch.jsonl || s=\$?
[[ \$s -eq 0 || \$s -eq 124 ]] || exit \"\$s\"
jq -es 'map(select(.event == \"event\" and .data.source == \"http\")) | length > 0' /run/watch.jsonl >/dev/null
jq -c 'select(.event == \"event\") | .data | {source, kind, summary}' /run/watch.jsonl | sed -n 1,4p"

step "Clean up"
note "Stopping attach and the world, and deleting the namespace."
