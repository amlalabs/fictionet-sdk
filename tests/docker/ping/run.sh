#!/usr/bin/env bash
# The ping test for `fictionet attach --type tun`, under Docker Compose.
#
#   tests/docker/ping/run.sh
#
# It checks that:
#   1. the sandbox can ping the world over IPv4 and IPv6,
#   2. the sandbox's resolv.conf lists the --dns server,
#   3. the sandbox cannot change its network (no NET_ADMIN),
#   4. a second attach with a taken name is refused (exit 3, with the reason),
#   5. SIGTERM and SIGKILL to attach both detach it in the world,
#   6. when the world goes away, attach removes its device and exits 0.
# Everything it starts is removed at the end.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose -f "$here/compose.yaml")
failures=0

cleanup() { "${compose[@]}" down -v --remove-orphans --timeout 2 >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# Waits up to 10 s for the world's log to contain a line.
world_says() {
    for _ in $(seq 50); do
        if "${compose[@]}" logs --no-log-prefix world 2>/dev/null | grep -q "$1"; then return 0; fi
        sleep 0.2
    done
    return 1
}

attach_flags=(--world unix:/run/fictionet/world.sock --type tun
    --no-ip-addr --no-gateway --no-dns
    --no-ip-addr-v6 --no-gateway-v6 --no-dns-v6)

cleanup
"${compose[@]}" build --quiet
"${compose[@]}" up -d --wait

# 1. Ping.
if "${compose[@]}" exec -T agent ping -c 3 -W 2 10.0.0.1; then pass "ping 10.0.0.1"; else fail "ping 10.0.0.1"; fi
if "${compose[@]}" exec -T agent ping -6 -c 3 -W 2 fd00::1; then pass "ping fd00::1"; else fail "ping fd00::1"; fi

# 2. DNS.
resolv="$("${compose[@]}" exec -T agent cat /etc/resolv.conf)"
if grep -qx "nameserver 10.0.0.1" <<<"$resolv"; then pass "agent resolv.conf lists 10.0.0.1"; else fail "agent resolv.conf: $resolv"; fi

# 3. No NET_ADMIN in the sandbox.
if out="$("${compose[@]}" exec -T agent ip addr add 10.0.0.9/24 dev tun0 2>&1)"; then
    fail "agent could run ip addr add"
elif grep -q "Operation not permitted" <<<"$out"; then
    pass "agent cannot run ip addr add ($out)"
else
    fail "ip addr add failed for another reason: $out"
fi

# 4. A taken name is refused.
set +e
out="$("${compose[@]}" run --rm --no-deps -T attach fictionet attach --name abc "${attach_flags[@]}" 2>&1)"
status=$?
set -e
if [[ $status == 3 ]] && grep -q "abc is already attached" <<<"$out"; then
    pass "taken name refused: $out"
else
    fail "taken name: status $status, $out"
fi

# 5a. SIGTERM detaches.
id="$("${compose[@]}" run -d --no-deps attach fictionet attach --name term "${attach_flags[@]}")"
if world_says "attached term"; then
    docker kill --signal TERM "$id" >/dev/null
    code="$(docker wait "$id")"
    if world_says "detached term"; then pass "SIGTERM: attach exited $code, the world saw the detach"; else fail "SIGTERM: no detach"; fi
else
    fail "second attach did not attach"
fi
docker rm -f "$id" >/dev/null 2>&1 || true

# 5b. SIGKILL detaches.
"${compose[@]}" kill -s SIGKILL attach >/dev/null 2>&1
if world_says "detached abc"; then pass "SIGKILL: the world saw abc detach"; else fail "SIGKILL: no detach"; fi

# 6. The world goes away: attach removes the device and exits 0.
"${compose[@]}" start attach >/dev/null
if world_says "attached abc mtu 1500.*" && [[ "$("${compose[@]}" logs --no-log-prefix world | grep -c '^attached abc')" == 2 ]]; then
    "${compose[@]}" kill -s SIGKILL world >/dev/null 2>&1
    code="$(docker wait "$("${compose[@]}" ps -aq attach)")"
    logs="$("${compose[@]}" logs --no-log-prefix attach)"
    if [[ $code == 0 ]] && grep -q "the world closed the connection; tun0 removed" <<<"$logs"; then
        pass "world gone: attach exited 0 and removed tun0"
    else
        fail "world gone: attach exited $code: $logs"
    fi
else
    fail "attach did not attach again after restart"
fi

echo
echo "--- world log"
"${compose[@]}" logs --no-log-prefix world
echo "--- attach log"
"${compose[@]}" logs --no-log-prefix attach

if [[ $failures == 0 ]]; then echo "ALL PASSED"; else echo "$failures FAILED"; exit 1; fi
