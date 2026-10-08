#!/usr/bin/env bash
# The web demo, run inside the VM by demos/web. A world of websites, and a
# sandbox that reaches it through a tun device, with ordinary tools.
# needs: sdk
. "$(dirname "$0")/lib.sh"

cleanup() {
    stop_pid "${attach_pid:-}"
    stop_pid "${world_pid:-}"
    ip netns del agent 2>/dev/null || true
    rm -rf /etc/netns/agent /run/fictionet /run/attach.ready /run/agent-ca.pem
}
trap cleanup EXIT
cleanup

step "Start the world"
note "The world is the web_world example: an ordinary Rust program built on web::Sites."
note "It serves example.test over HTTPS with a CA it makes at start, plain.test over HTTP,"
note "and www.example.test, shared.test, v4only.test and v6only.test. Other names fail."
mkdir -p /run/fictionet
chmod 700 /run/fictionet
web_world /run/fictionet/world.sock /run/fictionet/ca.pem >/run/world.log 2>&1 &
world_pid=$!
wait_for /run/fictionet/world.sock 10
sed 's/^/    /' /run/world.log

step "Make the sandbox and attach it"
note "The sandbox is a network namespace named agent. fictionet attach puts a tun device"
note "in it, gives it 10.0.0.2 with the world's gateway 10.0.0.1 as its default route and DNS"
note "server, and relays every packet to the world's socket."
vm 'ip netns add agent && ip -n agent link set lo up'
# An ordinary user pings with ICMP datagram sockets, which the kernel
# allows only for the groups in ping_group_range. A new namespace allows
# none; Debian's own default allows all.
ip netns exec agent sysctl -q -w net.ipv4.ping_group_range="0 2147483647"
fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun \
    --netns /run/netns/agent --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 \
    --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6 --ready-file /run/attach.ready >/run/attach.log 2>&1 &
attach_pid=$!
wait_for /run/attach.ready 10
sed 's/^/    /' /run/attach.log
# The agent's commands run as the user agent, not as root: root in a
# network namespace could leave it. ping keeps its file capability.
id agent >/dev/null 2>&1 || useradd --uid 2000 --no-create-home --shell /bin/bash agent
install -m 0644 /run/fictionet/ca.pem /run/agent-ca.pem
AGENT=(ip netns exec agent setpriv --reuid=agent --regid=agent --clear-groups env -i PATH=/usr/bin:/bin HOME=/tmp)
note "The agent's commands run as an ordinary user, agent, inside the namespace."
note "Inside the sandbox, the tun device is the only way out:"
agent 'id; ip -br addr; ip route; cat /etc/resolv.conf'

step "DNS: the world decides what every name means"
agent 'dig +short example.test'
agent 'dig nope.test | grep -E "status|ANSWER:"'

step "HTTPS, with the world's CA"
note "curl does its own TLS. The world's site answers with the name it was asked for and the"
note "HTTP version it spoke."
agent 'curl -sS --cacert /run/agent-ca.pem https://example.test/'
agent 'curl -sS --cacert /run/agent-ca.pem -o /dev/null -w "%{http_code} over HTTP/%{http_version}, certificate check %{ssl_verify_result} (0 means it passed)\n" https://www.example.test/'
note "Without the world's CA, curl refuses the certificate, as it would on the internet:"
agent 'curl -sS https://example.test/ 2>&1 | head -1'
note "Plain HTTP: example.test redirects to https, and plain.test has no TLS at all."
agent 'curl -sS -i http://example.test/ | head -2'
agent 'curl -sS http://plain.test/'

step "ping, and an address with no machine"
agent 'ping -c 3 -W 2 10.0.0.1'
agent 'ping -c 2 -W 2 203.0.113.10'
note "The world answers an address it has no machine for with ICMP \"host unreachable\","
note "so a connection fails at once instead of hanging:"
agent 'time (exec 3<>/dev/tcp/192.0.2.1/80)'

step "An unknown host fails, and the real internet is not there"
agent 'curl -sS --cacert /run/agent-ca.pem https://nope.test/'
agent 'curl -sS -m 5 https://example.com/'
agent 'curl -sS -m 5 http://1.1.1.1/'
note "The VM itself has the internet (it pulled this demo's packages), but the sandbox only"
note "ever reaches the world."

step "Clean up"
note "Stopping attach and the world, and deleting the namespace."
