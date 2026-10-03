#!/usr/bin/env bash
# The web test: `web::Sites` with a real sandbox, under Docker Compose.
#
#   tests/docker/web/run.sh
#
# The sandbox (curl and dig, attached with `fictionet attach --type tun`,
# with IPv4 and IPv6) checks that:
#   1. DNS answers A and AAAA for sites, NODATA for a family a site does
#      not have, NXDOMAIN for other names, over UDP and TCP,
#   2. HTTPS works with the world's CA, over HTTP/2 and HTTP/1.1, and the
#      handler sees the Target,
#   3. port 80 redirects a TLS site to https and serves a plain site,
#   4. a Host that is not the site gets 421, and an unknown TLS name is
#      rejected,
#   5. an address with no site fails at once with "no route to host",
#   6. a site keeps its state between requests,
#   7. web::proxy() reaches a real site on the world's network,
#   8. an agent that pushes hard does not break things: 300 HTTP/2 streams
#      at once, pings in fragments, 300 open connections (past 256 are
#      reset at once, and idle ones closed after 10 seconds), 32 large downloads
#      at once without stalls, and 250 idle connections that each
#      downloaded 1 MiB without the world keeping that memory, and 2,000
#      connections left in CLOSE_WAIT (256 served, the rest reset) without
#      slowing the machine,
#   9. a client that shuts down its side after its request still gets the
#      response,
#  10. IPv6: curl tries it first and falls back for an IPv4-only site, the
#      gateway answers ping -6, and an IPv6 address with no site fails at
#      once with "no route to host".
# Everything it starts is removed at the end.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose -f "$here/compose.yaml")
failures=0

cleanup() { "${compose[@]}" down -v --remove-orphans --timeout 2 >/dev/null 2>&1 || true; }
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
agent() { "${compose[@]}" exec -T agent "$@"; }
ca=(--cacert /run/ca/ca.pem)

# Runs a check: name, then the expected text (a grep -E pattern), then the
# command. The command's stdout and stderr are matched, as one line.
check() {
    local name="$1" want="$2"
    shift 2
    local out
    # Lines are joined with spaces, so a pattern can span them.
    out="$("$@" 2>&1 | tr '\n' ' ')" || true
    if grep -qE -- "$want" <<<"$out"; then pass "$name"; else fail "$name: wanted /$want/, got: $out"; fi
}

cleanup
"${compose[@]}" build --quiet
"${compose[@]}" up -d --wait

# 1. DNS.
check "dig A example.test (Site::at)" '^203\.0\.113\.10 $' agent dig +short example.test A
check "dig A example.test again, same answer" '^203\.0\.113\.10 $' agent dig +short example.test A
check "dig AAAA example.test (Site::at, IPv6)" '^2001:db8:113::10 $' agent dig +short example.test AAAA
check "dig nope.test is NXDOMAIN" 'status: NXDOMAIN' agent dig nope.test A
# plain.test is the first site with automatic addresses: the checks below
# connect to 198.18.0.1 by address.
check "dig +tcp plain.test (an address from 198.18.0.0/15)" '^198\.18\.0\.1 $' agent dig +tcp +short plain.test A
check "dig AAAA plain.test (an address from 2001:2::/48)" '^2001:2::1 $' agent dig +tcp +short plain.test AAAA
check "dig AAAA v4only.test is NODATA" 'status: NOERROR.*ANSWER: 0' agent dig v4only.test AAAA
check "dig A v6only.test is NODATA" 'status: NOERROR.*ANSWER: 0' agent dig v6only.test A
check "resolv.conf points at the gateway" 'nameserver 10\.0\.0\.1 nameserver 2001:db8::1' agent cat /etc/resolv.conf

# 2. HTTPS, HTTP/2 and HTTP/1.1.
check "https over HTTP/2" '^hello from https example.test 443 over HTTP/2.0 2 $' \
    agent curl -sS "${ca[@]}" -w '%{http_version}\n' https://example.test/
check "https over HTTP/1.1" '^hello from https example.test 443 over HTTP/1.1 1.1 $' \
    agent curl -sS "${ca[@]}" --http1.1 -w '%{http_version}\n' https://example.test/
check "https for the second name" '^hello from https www.example.test 443 over HTTP/2.0 $' \
    agent curl -sS "${ca[@]}" https://www.example.test/

# 3. Port 80.
check "http redirects to https" '^301 https://example.test/a\?b=c $' \
    agent curl -sS -o /dev/null -w '%{http_code} %{redirect_url}\n' 'http://example.test/a?b=c'
check "curl -L follows the redirect" '^hello from https example.test 443' \
    agent curl -sS "${ca[@]}" -L http://example.test/
check "a plain HTTP site" '^plain site http plain.test 80 $' agent curl -sS http://plain.test/x
check "a plain site sharing an address with TLS sites" '^plain site http shared.test 80 $' agent curl -sS http://shared.test/
check "HTTP/2 with prior knowledge on port 80" '^plain site http plain.test 80 2 $' \
    agent curl -sS --http2-prior-knowledge -w '%{http_version}\n' http://plain.test/

# 4. Wrong hosts.
check "a Host that is not this site gets 421" '^421 $' \
    agent curl -sS "${ca[@]}" -o /dev/null -w '%{http_code}\n' -H 'Host: plain.test' https://example.test/
check "TLS for a site without TLS at a TLS address is rejected" 'unrecognized name|unrecognised name|alert number 112' \
    agent curl -sS "${ca[@]}" https://shared.test/
check "port 443 is closed where no site has TLS" "Couldn't connect|Connection refused" \
    agent curl -sS "${ca[@]}" https://plain.test/

# 5. No site at an address: fails at once.
start=$(date +%s%N)
check "an address with no site is unreachable (ICMP host unreachable)" 'No route to host' \
    agent timeout 10 bash -c 'exec 3<>/dev/tcp/192.0.2.1/80'
ms=$(( ($(date +%s%N) - start) / 1000000 ))
if (( ms < 3000 )); then pass "it failed fast (${ms} ms, including docker exec)"; else fail "it took ${ms} ms"; fi

# 6. State.
a="$(agent curl -sS "${ca[@]}" https://example.test/count)"
b="$(agent curl -sS "${ca[@]}" https://www.example.test/count)"
if [[ $b == $((a + 1)) ]]; then pass "the site keeps its state ($a then $b)"; else fail "count went $a then $b"; fi

# Throughput: 16 MiB over HTTPS, HTTP/2 and HTTP/1.1.
for v in --http2 --http1.1; do
    out="$(agent curl -sS "${ca[@]}" $v -o /dev/null -w '%{size_download} %{speed_download}' https://example.test/big)"
    read -r size speed <<<"$out"
    if [[ $size == 16777216 ]]; then
        pass "16 MiB over $v at $((speed * 8 / 1000000)) Mbit/s"
    else
        fail "16 MiB over $v: $out"
    fi
done

# No stalls: a packet lost on a full socket buffer costs a 1 s retransmit.
# With small buffers about a third of these downloads stalled.
slow=0
for i in $(seq 10); do
    t="$(agent curl -sS "${ca[@]}" -o /dev/null -w '%{time_total}' https://example.test/big)"
    if [[ ${t%%.*} -ge 1 ]]; then slow=$((slow + 1)); fi
done
if [[ $slow == 0 ]]; then pass "10 downloads of 16 MiB, none stalled"; else fail "$slow of 10 downloads took over a second"; fi

# 7. The proxy.
check "web::proxy() reaches the real upstream" '^hello from the real upstream: GET /some/path\?q=1 HTTP/1.1 $' \
    agent curl -sS 'http://upstream/some/path?q=1'

# 8. Pushing hard.
check "300 requests at once over HTTP/2" '^300 $' \
    agent bash -c "curl -sS --no-progress-meter ${ca[*]} --http2 --parallel --parallel-max 100 -o /dev/null -w '%{http_code}\n' \
        \$(for i in \$(seq 300); do echo https://example.test/?\$i; done) | grep -c '^200\$'"
check "a 20,000-byte ping, in fragments both ways" ' 2 received' \
    agent ping -c 2 -W 2 -s 20000 10.0.0.1
# The world closes a connection that sends nothing for 10 s after it was
# accepted. The check waits until 8 s after the connections opened, when
# only the one that got an answer may be closed. Then it gives the others
# until 30 s to close, since a machine under heavy load can be seconds late.
check "300 open connections: 256 kept, the rest reset at once; idle ones closed after 10 s" \
    'opened 300 established 256 HTTP/1.1 200 OK closed-before-8s (1|not sampled in time) closed-by-30s 256 after (1[0-9]|2[0-9])\.[0-9] s' \
    agent bash -c '
        fds=()
        start=$(date +%s%N)
        for i in $(seq 300); do exec {fd}<>/dev/tcp/198.18.0.1/80 || break; fds+=("$fd"); done
        # Tenths of a second since the first connection.
        since() { echo $(( ($(date +%s%N) - start) / 100000000 )); }
        # Connections to port 80 (0050) by state: ESTABLISHED (01), and
        # CLOSE_WAIT (08) once the other side has closed. Reset ones are gone.
        count() { awk "\$3 ~ /:0050\$/ && \$4 == \"$1\"" /proc/net/tcp | wc -l; }
        closed() { count 08; }
        sleep 1
        echo "opened ${#fds[@]} established $(count 01)"
        printf "GET / HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n" >&"${fds[0]}"
        head -c 15 <&"${fds[0]}"; echo
        while (( $(since) < 80 )); do sleep 0.1; done
        c=$(closed) t=$(since)
        # A sample taken after 10 s says nothing about closing early.
        if (( t < 100 )); then echo "closed-before-8s $c"; else echo "closed-before-8s not sampled in time"; fi
        while (( $(closed) < 256 && $(since) < 300 )); do sleep 0.1; done
        t=$(since)
        echo "closed-by-30s $(closed) after $((t / 10)).$((t % 10)) s"'

# Many downloads at once. Each connection may have 256 KiB in flight, more
# in all than the socket buffer to attach holds. Packets that do not fit
# wait in the world; when they were dropped, most of these downloads
# stalled a second or more (smoltcp's minimum retransmission timeout).
out="$(agent bash -c "seq 32 | xargs -P 32 -I{} curl -sS ${ca[*]} -o /dev/null -w '%{time_total}\n' https://example.test/big" | sort -n | tr '\n' ' ')"
read -r -a times <<<"$out"
spread="$(awk -v a="${times[0]}" -v b="${times[-1]}" 'BEGIN { printf "%.2f", b - a }')"
if [[ ${#times[@]} == 32 ]] && awk -v s="$spread" 'BEGIN { exit !(s < 0.8) }'; then
    pass "32 downloads of 16 MiB at once, none stalled (${times[0]} s to ${times[-1]} s)"
else
    fail "32 downloads of 16 MiB at once: $out"
fi

# Memory: 250 connections that each downloaded 1 MiB and then sit idle.
world_pid="$(docker inspect -f '{{.State.Pid}}' "$("${compose[@]}" ps -q world)")"
rss() { awk '/^VmRSS:/ { print int($2 / 1024) }' "/proc/$world_pid/status"; }
before="$(rss)"
# The script says how many it opened, then holds them quiet for 10 s.
exec {pin}< <(agent python3 -c '
import socket, sys, time
socks = []
for i in range(250):
    s = socket.create_connection(("198.18.0.1", 80))
    s.sendall(b"GET /mb HTTP/1.1\r\nHost: plain.test\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += s.recv(65536)
    got = len(buf.split(b"\r\n\r\n", 1)[1])
    while got < 1 << 20:
        got += len(s.recv(1 << 20))
    socks.append(s)
print(len(socks), flush=True)
time.sleep(10)
')
read -r -t 120 -u "$pin" opened || opened=0
# The world gives a quiet connection's buffer pages back within 2 s.
sleep 4
held="$(rss)"
exec {pin}<&-
if [[ $opened == 250 ]] && (( held - before < 50 )); then
    pass "250 idle connections after 1 MiB each: world memory ${before} MB, then ${held} MB"
else
    fail "250 idle connections after 1 MiB each ($opened opened): world memory ${before} MB, then ${held} MB"
fi

# Connections the server closed but the client keeps open (CLOSE_WAIT)
# count against the 256 until they finish closing. Without that, a client
# could pile up thousands of closing sockets on a shared machine and slow
# it down for everyone, even after it let them go. While it holds them,
# its own next connection is reset too; once it lets them go, the machine
# is as fast as before.
# The script connects to 198.18.0.1 over IPv4. The limit is per machine,
# and the site's IPv6 address is another machine, so curl uses IPv4 too.
plain_big() { agent curl -sS -4 -o /dev/null -w '%{time_total}' http://plain.test/big; }
# The 250 connections above are held until their script ends.
sleep 8
fresh="$(plain_big)"
exec {pin}< <(agent python3 -c '
import resource, socket, time
resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
served, reset, socks = 0, 0, []
for i in range(2000):
    # A connection past the limit is reset right after the handshake. The
    # reset can arrive before connect() returns, and then connect() fails.
    try:
        s = socket.create_connection(("198.18.0.1", 80))
    except ConnectionResetError:
        reset += 1
        continue
    try:
        s.sendall(b"GET / HTTP/1.0\r\nHost: plain.test\r\n\r\n")
        data = b""
        while True:
            x = s.recv(65536)
            if not x:
                break
            data += x
        if data.startswith(b"HTTP/1.0 200"):
            served += 1
    except (ConnectionResetError, BrokenPipeError):
        reset += 1
    socks.append(s)
print(served, reset, flush=True)
time.sleep(5)
')
read -r -t 120 -u "$pin" served reset || served=0
held="$(agent curl -sS -4 -o /dev/null http://plain.test/big 2>&1 || true)"
exec {pin}<&-
# The script has ended and its sockets have closed.
sleep 6
after="$(plain_big)"
if [[ $served == 256 && $reset == 1744 && $held == *"reset by peer"* ]] && awk -v a="$after" -v f="$fresh" 'BEGIN { exit !(a < 2 * f + 0.1) }'; then
    pass "2,000 connections left in CLOSE_WAIT: 256 served, 1744 reset; 16 MiB took ${fresh} s before, ${after} s after"
else
    fail "2,000 connections left in CLOSE_WAIT: served ${served:-?} reset ${reset:-?}, while held: ${held}; 16 MiB took ${fresh} s before, ${after} s after"
fi

# 9. Half-close.
check "a client that half-closes after its request gets the response" '^200 OK 200 OK $' \
    agent python3 -c '
import socket
for req in [b"GET / HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
            b"GET / HTTP/1.0\r\nHost: plain.test\r\n\r\n"]:
    s = socket.create_connection(("198.18.0.1", 80), timeout=5)
    s.sendall(req)
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        x = s.recv(4096)
        if not x:
            break
        data += x
    print(data.split(b"\r\n")[0].split(b" ", 1)[1].decode())
'

# 10. IPv6.
check "curl tries IPv6 first (Happy Eyeballs)" '^hello from https example.test 443 over HTTP/2.0 2001:db8:113::10 $' \
    agent curl -sS "${ca[@]}" -w '%{remote_ip}\n' https://example.test/
check "curl -6 over HTTP/1.1" '^hello from https example.test 443 over HTTP/1.1 2001:db8:113::10 $' \
    agent curl -sS "${ca[@]}" -6 --http1.1 -w '%{remote_ip}\n' https://example.test/
check "curl -4 still works" '^hello from https example.test 443 over HTTP/2.0 203\.0\.113\.10 $' \
    agent curl -sS "${ca[@]}" -4 -w '%{remote_ip}\n' https://example.test/
check "an IPv4-only site is reached over IPv4" '^hello from https v4only.test 443 over HTTP/2.0 198\.18\.0\.[0-9]+ $' \
    agent curl -sS "${ca[@]}" -w '%{remote_ip}\n' https://v4only.test/
check "an IPv6-only site" '^hello from https v6only.test 443 over HTTP/2.0 2001:2::[0-9a-f]+ $' \
    agent curl -sS "${ca[@]}" -w '%{remote_ip}\n' https://v6only.test/
check "plain HTTP over IPv6" '^plain site http plain.test 80 2001:2::1 $' \
    agent curl -sS -w '%{remote_ip}\n' http://plain.test/
check "ping -6 the gateway" ' 1 received' agent ping -6 -c 1 -W 2 2001:db8::1
check "a 20,000-byte ping -6, in fragments both ways" ' 2 received' \
    agent ping -6 -c 2 -W 2 -s 20000 2001:db8::1
start=$(date +%s%N)
check "an IPv6 address with no site is unreachable (ICMPv6 address unreachable)" 'No route to host' \
    agent timeout 10 bash -c 'exec 3<>/dev/tcp/2001:db8:99::1/80'
ms=$(( ($(date +%s%N) - start) / 1000000 ))
if (( ms < 3000 )); then pass "it failed fast (${ms} ms, including docker exec)"; else fail "it took ${ms} ms"; fi
check "ping -6 an address with no site" 'Address unreachable' agent ping -6 -c 1 -W 2 2001:db8:99::1
out="$(agent curl -sS "${ca[@]}" -6 -o /dev/null -w '%{size_download} %{speed_download}' https://example.test/big)"
read -r size speed <<<"$out"
if [[ $size == 16777216 ]]; then pass "16 MiB over IPv6 at $((speed * 8 / 1000000)) Mbit/s"; else fail "16 MiB over IPv6: $out"; fi

echo
echo "--- world log"
"${compose[@]}" logs --no-log-prefix world
echo "--- upstream log"
"${compose[@]}" logs --no-log-prefix upstream

if [[ $failures == 0 ]]; then echo "ALL PASSED"; else echo "$failures FAILED"; exit 1; fi
