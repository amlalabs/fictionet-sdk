#!/bin/sh
# Checks a running copy of this example from the machine that runs Docker:
# the world works for the agent, and nothing else is reachable from it.
# POSIX sh, since Docker-in-Docker images often have no bash.
#
#   docker compose up -d --build --wait && ./check.sh
#
# Prints PASS or FAIL per check, and exits 1 if any failed.
here="$(cd "$(dirname "$0")" && pwd)"
file="${COMPOSE_FILE:-$here/compose.yaml}"
failures=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
agent() { docker compose -f "$file" exec -T default "$@"; }

# check name pattern command...: the command's output, joined into one line,
# must match the grep -E pattern.
check() {
    name="$1" want="$2"
    shift 2
    out="$("$@" 2>&1 | tr '\n' ' ')"
    if printf '%s\n' "$out" | grep -qE -- "$want"; then pass "$name"; else fail "$name: wanted /$want/, got: $out"; fi
}

# The machine's own addresses, which the agent must not reach.
outer_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
outer_gw="$(ip -4 route show default 2>/dev/null | sed -n 's/^default via \([0-9.]*\).*/\1/p' | head -1)"
bridge_ip="$(ip -4 addr show docker0 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p')"
echo "outer address ${outer_ip:-?}, gateway ${outer_gw:-?}, docker0 ${bridge_ip:-?}"

# The world works.
check "the agent has only lo and tun0" '^lo tun0 $' agent sh -c 'ls /sys/class/net | sort'
check "tun0 has 10.0.0.2/24" 'inet 10\.0\.0\.2/24' agent ip -4 addr show tun0
check "the default route is tun0" '^default via 10\.0\.0\.1 dev tun0' agent ip route show default
check "resolv.conf points at the world" 'nameserver 10\.0\.0\.1' agent cat /etc/resolv.conf
check "the world's DNS answers" '^203\.0\.113\.10 $' agent dig +short example.test A
check "HTTPS with the world's CA" '^hello from https example.test 443 over HTTP/2.0 $' \
    agent curl -sS --cacert /run/ca/ca.pem https://example.test/
check "ping the gateway" ' 1 received' agent ping -c 1 -W 2 10.0.0.1

# The agent cannot change its network.
check "the agent has no NET_ADMIN" '^no NET_ADMIN $' \
    agent bash -c 'c=$(awk "/^CapEff/ {print \$2}" /proc/self/status); if (( 0x$c & 0x1000 )); then echo NET_ADMIN; else echo no NET_ADMIN; fi'
check "the agent cannot delete its route" 'Operation not permitted' agent ip route del default
check "the agent cannot add a link" 'Operation not permitted' agent ip link add x type dummy
check "the agent cannot see the world socket" 'No such file' agent ls /run/fictionet/world.sock

# Nothing outside the world answers.
check "DNS to 1.1.1.1 fails" 'timed out|no servers could be reached|connection refused|unreachable' \
    agent dig +time=2 +tries=1 @1.1.1.1 example.com
check "DNS to 8.8.8.8 fails" 'timed out|no servers could be reached|connection refused|unreachable' \
    agent dig +time=2 +tries=1 @8.8.8.8 example.com
check "HTTPS to 1.1.1.1 fails" 'No route to host|Could not connect|Failed to connect' \
    agent curl -sS -m 5 https://1.1.1.1/
check "a real name does not resolve" 'Could not resolve host' agent curl -sS -m 5 https://example.com/
check "the metadata address fails" 'No route to host|Could not connect|Failed to connect|timed out' \
    agent curl -sS -m 5 http://169.254.169.254/
for ip in $outer_ip $outer_gw $bridge_ip; do
    check "the sandbox's own network ($ip) fails" 'No route to host' \
        agent timeout 5 bash -c "exec 3<>/dev/tcp/$ip/22"
done

if [ "$failures" = 0 ]; then echo "ALL PASSED"; else echo "$failures FAILED"; exit 1; fi
