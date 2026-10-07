#!/usr/bin/env bash
# The proxy demo, run inside the VM by demos/proxy. A sandbox with no
# privileges and no tun device reaches the world through attach's HTTP
# proxy and SOCKS5 proxy.
# needs: sdk
. "$(dirname "$0")/lib.sh"

token="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
proxy="http://fictionet:$token@127.0.0.1:8080"
socks="socks5h://fictionet:$token@127.0.0.1:1080"

cleanup() {
    stop_pid "${http_pid:-}"
    stop_pid "${socks_pid:-}"
    stop_pid "${world_pid:-}"
    ip netns del agent 2>/dev/null || true
    rm -rf /run/fictionet /run/agent-ca.pem /run/proxy-token /run/attach-*.ready
}
trap cleanup EXIT
cleanup

step "Start the world"
note "The same web_world example as demos/web: example.test over HTTPS, plain.test over HTTP."
mkdir -p /run/fictionet
chmod 700 /run/fictionet
web_world /run/fictionet/world.sock /run/fictionet/ca.pem >/run/world.log 2>&1 &
world_pid=$!
wait_for /run/fictionet/world.sock 10
sed 's/^/    /' /run/world.log
install -m 0644 /run/fictionet/ca.pem /run/agent-ca.pem

step "Make a sandbox with no network at all"
note "The sandbox is a network namespace with only a loopback interface. Its commands run"
note "as the user agent, with no capabilities, so it cannot add a device or a route."
id agent >/dev/null 2>&1 || useradd --uid 2000 --no-create-home --shell /bin/bash agent
vm 'ip netns add agent && ip -n agent link set lo up'

step "Start two proxies inside the sandbox's namespace"
note "fictionet attach with --type http_proxy and --type socks5 makes no device. It listens"
note "on the sandbox's own 127.0.0.1 and turns each proxied connection into packets from the"
note "sandbox's address in the world. Clients must give a token as the proxy password."
printf '%s\n' "$token" >/run/proxy-token
chmod 600 /run/proxy-token
ip netns exec agent fictionet attach --world unix:/run/fictionet/world.sock --name agent-http \
    --type http_proxy --listen 127.0.0.1:8080 --token-file /run/proxy-token \
    --ip-addr 10.0.0.2 --dns 10.0.0.1 --ready-file /run/attach-http.ready >/run/attach-http.log 2>&1 &
http_pid=$!
ip netns exec agent fictionet attach --world unix:/run/fictionet/world.sock --name agent-socks \
    --type socks5 --listen 127.0.0.1:1080 --token-file /run/proxy-token \
    --ip-addr 10.0.0.3 --dns 10.0.0.1 --ready-file /run/attach-socks.ready >/run/attach-socks.log 2>&1 &
socks_pid=$!
wait_for /run/attach-http.ready 10
wait_for /run/attach-socks.ready 10
sed 's/^/    /' /run/attach-http.log /run/attach-socks.log

# From here on, every agent command runs as the user agent, in the
# namespace, with no capabilities, and with the usual proxy variables.
AGENT=(ip netns exec agent setpriv --reuid=agent --regid=agent --clear-groups
    --inh-caps=-all --bounding-set=-all --no-new-privs
    env -i PATH=/usr/bin:/bin HOME=/tmp
    "https_proxy=$proxy" "http_proxy=$proxy" "HTTPS_PROXY=$proxy" "HTTP_PROXY=$proxy"
    "SOCKS=$socks" CURL_CA_BUNDLE=/run/agent-ca.pem SSL_CERT_FILE=/run/agent-ca.pem)

step "Who the agent is, and what it has"
agent 'id; grep CapEff /proc/self/status; ip -br addr'
agent 'env | grep -E "^(https?_proxy|SOCKS)=" | sed "s/:[^:@]*@/:<token>@/"'

step "Through the HTTP proxy, by the proxy variables"
note "TLS is end to end: curl checks the site's certificate against the world's CA."
agent 'curl -sS https://example.test/'
agent 'curl -sS http://plain.test/'
agent 'python3 -c "import urllib.request; print(urllib.request.urlopen(\"https://example.test/\").read().decode().strip())"'

step "Through the SOCKS5 proxy"
agent 'curl -sS -x "$SOCKS" https://example.test/'

step "What does not work"
note "A wrong token is refused:"
agent 'curl -sS -x http://fictionet:wrong@127.0.0.1:8080 https://example.test/'
note "A name the world does not have gets 502, and attach says why:"
agent 'curl -sS -o /dev/null -D - http://nope.test/ | grep -iE "^HTTP|^x-fictionet"'
agent 'curl -sS -x "$SOCKS" https://nope.test/'
note "Around the proxy there is no network, and the world's socket is out of reach:"
agent 'curl -sS -m 5 --noproxy "*" http://1.1.1.1/'
agent 'ls /run/fictionet'

step "Clean up"
note "Stopping both proxies and the world, and deleting the namespace."
