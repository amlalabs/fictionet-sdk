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
passes=0
pass() { echo "PASS: $*"; passes=$((passes + 1)); }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
agent() { docker compose -f "$file" exec -T default "$@"; }

# Keep this standalone: run_hosted.py uploads check.sh alone.
# The status suffix preserves output newlines before tr joins the lines.
run_captured() {
    out="$(
        if "$@" 2>&1; then
            printf '\n0'
        else
            printf '\n%d' "$?"
        fi
    )"
    status=${out##*'
'}
    out=${out%'
'*}
    out="$(printf '%s' "$out" | tr '\n' ' ')"
}

# NAME, grep -E PATTERN, CMD...: require success and matching output.
check_ok() {
    name="$1" want="$2"
    shift 2
    run_captured "$@"
    if [ "$status" -eq 0 ] && printf '%s\n' "$out" | grep -qE -- "$want"; then
        pass "$name"
    else
        fail "$name: wanted status 0 and /$want/, got status $status: $out"
    fi
}

_refusal_status() {
    case "$1" in 0|124|126|127) return 1 ;; esac
    [ "$1" -le 128 ]
}

# NAME, PATTERN, CMD...: accept a refusal, but not a timeout, execution error
# (126/127), or signal (>128). The command must also print the expected text.
check_fails() {
    name="$1" want="$2"
    shift 2
    run_captured "$@"
    if _refusal_status "$status" && printf '%s\n' "$out" | grep -qE -- "$want"; then
        pass "$name"
    else
        fail "$name: wanted a refusal and /$want/, got status $status: $out"
    fi
}

# The machine's own addresses, which the agent must not reach.
outer_ip= outer_gw= bridge_ip=
outer_reason='ip missing' gateway_reason='ip missing'
if command -v ip >/dev/null 2>&1; then
    outer_reason='no outer address' gateway_reason='no default route'
    if route="$(ip -4 route get 1.1.1.1)"; then
        outer_ip="$(printf '%s\n' "$route" | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
    else
        outer_reason="ip route get failed (status $?)"
    fi
    if route="$(ip -4 route show default)"; then
        outer_gw="$(printf '%s\n' "$route" | sed -n 's/^default via \([0-9.]*\).*/\1/p' | head -1)"
    else
        gateway_reason="ip route show failed (status $?)"
    fi
    if address="$(ip -4 addr show docker0)"; then
        bridge_ip="$(printf '%s\n' "$address" | sed -n 's/.*inet \([0-9.]*\).*/\1/p')"
    else
        echo "docker0 discovery failed (status $?); trying Docker's bridge gateway" >&2
    fi
fi
if [ -z "$bridge_ip" ]; then
    if gateway="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"; then
        bridge_ip="$gateway"
    else
        echo "Docker bridge discovery failed (status $?)" >&2
    fi
fi
echo "outer address ${outer_ip:-?}, gateway ${outer_gw:-?}, docker0 ${bridge_ip:-?}"

# The world works.
check_ok "the agent has only lo and tun0" '^lo tun0 $' agent sh -c 'ls /sys/class/net | sort'
check_ok "tun0 has 10.0.0.2/24" 'inet 10\.0\.0\.2/24' agent ip -4 addr show tun0
check_ok "the default route is tun0" '^default via 10\.0\.0\.1 dev tun0' agent ip route show default
check_ok "resolv.conf points at the world" 'nameserver 10\.0\.0\.1' agent cat /etc/resolv.conf
check_ok "the world's DNS answers" '^203\.0\.113\.10 $' agent dig +short example.test A
check_ok "HTTPS with the world's CA" '^hello from https example.test 443 over HTTP/2.0 $' \
    agent curl -sS --cacert /run/ca/ca.pem https://example.test/
check_ok "ping the gateway" ' 1 received' agent ping -c 1 -W 2 10.0.0.1

# The agent cannot change its network.
check_ok "the agent has no NET_ADMIN" '^no NET_ADMIN $' \
    agent bash -c 'c=$(awk "/^CapEff/ {print \$2}" /proc/self/status); if (( 0x$c & 0x1000 )); then echo NET_ADMIN; else echo no NET_ADMIN; fi'
check_fails "the agent cannot delete its route" 'Operation not permitted' agent ip route del default
check_fails "the agent cannot add a link" 'Operation not permitted' agent ip link add x type dummy
check_fails "the agent cannot see the world socket" 'No such file' agent ls /run/fictionet/world.sock

# Nothing outside the world answers.
check_fails "DNS to 1.1.1.1 fails" 'timed out|no servers could be reached|connection refused|unreachable' \
    agent dig +time=2 +tries=1 @1.1.1.1 example.com
check_fails "DNS to 8.8.8.8 fails" 'timed out|no servers could be reached|connection refused|unreachable' \
    agent dig +time=2 +tries=1 @8.8.8.8 example.com
check_fails "HTTPS to 1.1.1.1 fails" 'No route to host|Could not connect|Failed to connect' \
    agent curl -sS -m 5 https://1.1.1.1/
check_fails "a real name does not resolve" 'Could not resolve host' agent curl -sS -m 5 https://example.com/
check_fails "the metadata address fails" 'No route to host|Could not connect|Failed to connect|timed out' \
    agent curl -sS -m 5 http://169.254.169.254/
valid_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 { exit 1 }
        { for (i = 1; i <= NF; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1 }
        END { if (NR != 1) exit 1 }
    '
}
check_target() {
    if [ -z "$1" ]; then
        fail "the sandbox's own network (?) fails: $2"
    elif ! valid_ipv4 "$1"; then
        fail "the sandbox's own network (?) fails: invalid IPv4 target: $1"
    else
        check_fails "the sandbox's own network ($1) fails" 'No route to host' \
            agent timeout 5 bash -c "exec 3<>/dev/tcp/$1/22"
    fi
}
check_target "$outer_ip" "$outer_reason"
check_target "$outer_gw" "$gateway_reason"
check_target "$bridge_ip" 'no bridge address from docker0 or Docker bridge network'

if [ "$((passes + failures))" -ne 19 ]; then
    fail "wanted 19 checks, got $((passes + failures))"
fi

if [ "$failures" = 0 ]; then echo "ALL PASSED"; else echo "$failures FAILED"; exit 1; fi
