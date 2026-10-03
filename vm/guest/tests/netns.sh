#!/usr/bin/env bash
# The `ip netns` test: the README's quick start, checked. Runs inside the VM
# as root (`vm/run test netns`), with the binaries from vm/guest/build.sh.
#
# A world (the web_world example) on a Unix socket, a network namespace
# named agent, and `fictionet attach --type tun --netns` putting tun0 in it.
# From inside the namespace it checks that:
#   1. tun0 is the only interface besides lo, the default route goes
#      through it, and /etc/netns/agent/resolv.conf names the world,
#   2. DNS answers the world's names, and NXDOMAIN for others,
#   3. HTTPS works with the world's CA, over HTTP/2, and fails without it,
#   4. port 80 redirects to https, and a plain HTTP site answers,
#   5. the gateway answers ping, and an address with no machine fails at
#      once with "no route to host",
#   6. nothing outside the world is reachable, though the VM has the internet,
#   7. when the world stops, attach exits and tun0 is gone.
set -euo pipefail
export PATH="/opt/fictionet/bin:$PATH"
failures=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
in_agent() { ip netns exec agent "$@"; }
ca=(--cacert /run/fictionet/ca.pem)

# Runs a check: name, then the expected text (a grep -E pattern), then the
# command. The command's stdout and stderr are matched, as one line.
check() {
    local name="$1" want="$2"
    shift 2
    local out
    out="$("$@" 2>&1 | tr '\n' ' ')" || true
    if grep -qE -- "$want" <<<"$out"; then pass "$name"; else fail "$name: wanted /$want/, got: $out"; fi
}

cleanup() {
    [[ -n ${attach_pid:-} ]] && { kill "$attach_pid" 2>/dev/null || true; }
    [[ -n ${world_pid:-} ]] && { kill "$world_pid" 2>/dev/null || true; }
    wait 2>/dev/null || true
    ip netns del agent 2>/dev/null || true
    rm -rf /etc/netns/agent /run/fictionet
}
trap cleanup EXIT
cleanup

mkdir -p /run/fictionet
web_world /run/fictionet/world.sock /run/fictionet/ca.pem >/run/fictionet/world.log 2>&1 &
world_pid=$!
for _ in $(seq 100); do [[ -S /run/fictionet/world.sock ]] && break; sleep 0.1; done
ip netns add agent
ip -n agent link set lo up
fictionet attach --world unix:/run/fictionet/world.sock --name agent --type tun --netns /run/netns/agent \
    --ip-addr 10.0.0.2/24 --gateway 10.0.0.1 --dns 10.0.0.1 --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6 \
    --ready-file /run/fictionet/attach.ready >/run/fictionet/attach.log 2>&1 &
attach_pid=$!
for _ in $(seq 100); do [[ -e /run/fictionet/attach.ready ]] && break; sleep 0.1; done
check "attach says it attached" 'agent attached as tun0' cat /run/fictionet/attach.log

# 1. The namespace.
check "the links are lo and tun0" '^lo +UNKNOWN .* tun0 +UNKNOWN +10\.0\.0\.2/24 +$' in_agent ip -br addr
check "the default route goes through tun0" '^default via 10\.0\.0\.1 dev tun0' in_agent ip route show default
check "resolv.conf names the world" ' nameserver 10\.0\.0\.1 $' cat /etc/netns/agent/resolv.conf

# 2. DNS.
check "dig A example.test" '^203\.0\.113\.10 $' in_agent dig +short example.test
check "dig nope.test is NXDOMAIN" 'status: NXDOMAIN' in_agent dig nope.test
check "dig +tcp plain.test" '^198\.18\.0\.1 $' in_agent dig +tcp +short plain.test

# 3. HTTPS.
check "https over HTTP/2" '^hello from https example.test 443 over HTTP/2.0 2 $' \
    in_agent curl -sS "${ca[@]}" -w '%{http_version}\n' https://example.test/
check "https without the world's CA fails" '\(60\)' in_agent curl -sS https://example.test/

# 4. Plain HTTP.
check "http redirects to https" '^301 https://example.test/ $' \
    in_agent curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' http://example.test/
check "a plain HTTP site" '^plain site http plain.test 80 $' in_agent curl -sS http://plain.test/

# 5. ICMP.
check "the gateway answers ping" ' 3 received' in_agent ping -c 3 -W 2 10.0.0.1
start=$(date +%s%N)
check "an address with no site is unreachable (ICMP host unreachable)" 'No route to host' \
    in_agent timeout 10 bash -c 'exec 3<>/dev/tcp/192.0.2.1/80'
ms=$(( ($(date +%s%N) - start) / 1000000 ))
if (( ms < 2000 )); then pass "it failed at once (${ms} ms)"; else fail "it took ${ms} ms"; fi

# 6. Nothing outside.
check "the VM itself has the internet" '^[0-9]{3} $' curl -sS -m 10 -o /dev/null -w '%{http_code}\n' https://deb.debian.org/
check "a real name does not resolve in the sandbox" 'Could not resolve host' in_agent curl -sS -m 5 https://example.com/
check "a real address is unreachable from the sandbox" 'No route to host|Failed to connect' in_agent curl -sS -m 5 http://1.1.1.1/
check "the VM's own DNS server is unreachable from the sandbox" 'no servers could be reached|unreachable' \
    in_agent dig +time=2 +tries=1 @10.0.2.3 deb.debian.org

# 7. The world stops.
kill "$world_pid"
wait "$world_pid" 2>/dev/null || true
world_pid=
for _ in $(seq 50); do kill -0 "$attach_pid" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$attach_pid" 2>/dev/null; then fail "attach is still running after the world stopped"; else
    wait "$attach_pid" && status=0 || status=$?
    attach_pid=
    check "when the world stops, attach exits 0" '^0 $' echo "$status"
fi
check "and tun0 is gone" '^0 $' in_agent sh -c 'ip -br link | grep -c tun0; true'
check "attach says why" 'world' tail -2 /run/fictionet/attach.log

echo
echo "--- attach log"
cat /run/fictionet/attach.log
if [[ $failures == 0 ]]; then echo "ALL PASSED"; else echo "$failures FAILED"; exit 1; fi
