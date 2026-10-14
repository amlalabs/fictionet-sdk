#!/usr/bin/env bash
# The ping test for `fictionet attach --type tun`, under Docker Compose.
#
#   tests/docker/ping/run.sh
#   tests/docker/ping/run.sh --self-test  # Check restart polling without Docker.
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

# Waits up to 10 s for the world's log to contain a line.
world_says() {
    for _ in $(seq 50); do
        if "${compose[@]}" logs --no-log-prefix world 2>/dev/null | grep -q "$1"; then return 0; fi
        sleep 0.2
    done
    return 1
}

# Counts abc's attachments in the world's log.
attachment_count() {
    "${compose[@]}" logs --no-log-prefix world 2>/dev/null |
        awk '/^attached abc mtu 1500( |$)/ { n++ } END { print n+0 }'
}

# Waits up to 10 s for an attachment after the captured count.
world_attaches_again() {
    local count
    for _ in $(seq 50); do
        if count="$(attachment_count)" && (( count > $1 )); then return 0; fi
        sleep 0.2
    done
    return 1
}

# Checks the restart wait against stub logs, before any Docker command: an old
# attachment must not count, a new one must, and the wait gives up after 50 tries.
self_test() (
    self_test_fail() { echo "FAIL: restart polling self-test: $*" >&2; exit 1; }
    compose=(stub_logs)
    logs=''
    sleeps=0
    fresh_after=0
    stub_logs() { printf '%s\n' "$logs"; }
    sleep() {
        [[ $1 == 0.2 ]] || self_test_fail "expected a 0.2 s sleep, got $1"
        sleeps=$((sleeps + 1))
        if (( sleeps == fresh_after )); then
            logs+=$'\nattached abc mtu 1500'
        fi
    }

    [[ $(attachment_count) == 0 ]] || self_test_fail "empty logs must have no attachments"
    logs=$'attached abc mtu 1500\ndetached abc\nattached term mtu 1500'
    before="$(attachment_count)" || self_test_fail "could not read initial count"
    [[ $before == 1 ]] || self_test_fail "expected one abc attachment, got $before"
    if world_attaches_again "$before"; then
        self_test_fail "stale attachment satisfied restart polling"
    fi
    [[ $sleeps == 50 ]] || self_test_fail "stale logs must time out after 50 sleeps, got $sleeps"

    sleeps=0
    fresh_after=3
    world_attaches_again "$before" || self_test_fail "fresh attachment was not observed"
    [[ $sleeps == 3 && $(attachment_count) == 2 ]] || self_test_fail "expected two attachments after three sleeps"

    before="$(attachment_count)" || self_test_fail "could not read updated count"
    sleeps=0
    world_attaches_again "$before" || self_test_fail "next fresh attachment was not observed"
    [[ $sleeps == 3 && $(attachment_count) == 3 ]] || self_test_fail "expected three attachments after three sleeps"
    echo "PASS: restart polling rejects stale logs, waits for fresh logs, and is bounded"
)

self_test || exit 1
if [[ ${1:-} == --self-test ]]; then exit 0; fi

source "$here/../common.sh"

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

# 6. The world goes away: attach removes the device and exits 0. Count abc's
# attachments first, so the first attachment's line cannot pass for the restart.
if ! before="$(attachment_count)"; then
    fail "could not read attachment count before restart"
elif "${compose[@]}" start attach >/dev/null && world_attaches_again "$before"; then
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

finish
