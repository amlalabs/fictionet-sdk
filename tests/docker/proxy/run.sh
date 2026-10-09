#!/usr/bin/env bash
# The proxy test: `fictionet attach --type http_proxy` and `--type
# socks5` with real clients, under Docker Compose.
#
#   tests/docker/proxy/run.sh
#
# The sandbox has no capabilities and one network, an internal one shared
# with the two attaches, so the proxies are its only way out. It checks
# that:
#   1. curl, wget, git, Python requests, Go and Node reach the world's
#      sites through the HTTP door, and curl, git, Python and Go through
#      the SOCKS5 door, with TLS end to end;
#   2. a missing or wrong token is refused by both doors;
#   3. names that do not exist, closed ports and addresses with no machine
#      get 502, or SOCKS replies 4 and 5, at once;
#   4. nothing outside the world is reachable: not through the proxies,
#      not around them, and not by DNS;
#   5. ten downloads of 16 MiB at once do not stall, through either door,
#      and 64 MiB uploads arrive whole;
#   6. 1,000 HTTPS requests, 200 at a time, all succeed;
#   7. when the world stops, attach exits and the proxies are gone.
# Everything it starts is removed at the end.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose -f "$here/compose.yaml")
# One token for this run. The sandbox gets it in its proxy URLs.
RELAY_TOKEN="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
export RELAY_TOKEN

source "$here/../common.sh"

cleanup
"${compose[@]}" build --quiet
"${compose[@]}" up -d --wait

# 1. Clients, through the HTTP door (HTTPS_PROXY and HTTP_PROXY are set).
check "curl https, HTTP/2" '^hello from https example.test 443 over HTTP/2.0 2 $' \
    agent curl -sS -w '%{http_version}\n' https://example.test/
check "curl http (a plain-HTTP proxy request)" '^plain site http plain.test 80 $' agent curl -sS http://plain.test/x
check "curl without the world's CA fails: TLS is end to end" '\(60\)' \
    agent env -u CURL_CA_BUNDLE -u SSL_CERT_FILE curl -sS https://example.test/
check "wget https" '^hello from https example.test 443 over HTTP/1.1 $' agent wget -q -O - --ca-certificate=/run/ca/ca.pem https://example.test/
check "wget http" '^plain site http plain.test 80 $' agent wget -q -O - http://plain.test/w
check "git over https reaches the site (which has no repository)" "repository 'https://example.test/repo.git/' not found" \
    agent git ls-remote https://example.test/repo.git
check "python requests https and http (Python 3.13)" \
    '^3\.13 hello from https example.test 443 over HTTP/1.1 plain site http plain.test 80 $' \
    agent python3 -c '
import platform, requests
print(".".join(platform.python_version_tuple()[:2]))
print(requests.get("https://example.test/").text.strip())
print(requests.get("http://plain.test/").text.strip())'
check "go net/http https and http" '^200 hello from https example.test 443 over HTTP/2.0 200 plain site http plain.test 80 $' \
    agent goclient https://example.test/ http://plain.test/
check "node fetch, with NODE_USE_ENV_PROXY=1" '^hello from https example.test 443 over HTTP/1.1 $' \
    agent node -e 'fetch("https://example.test/").then(r => r.text()).then(t => console.log(t.trim()))'
check "node fetch without NODE_USE_ENV_PROXY ignores the proxy, and fails" 'ENOTFOUND|EAI_AGAIN' \
    agent env -u NODE_USE_ENV_PROXY node -e 'fetch("https://example.test/").then(r => console.log(r.status)).catch(e => console.log(String(e.cause)))'

# The SOCKS5 door.
socks() { agent sh -c "$1"; }
check "curl https through socks5h" '^hello from https example.test 443 over HTTP/2.0 $' socks 'curl -sS -x "$SOCKS" https://example.test/'
check "curl http through socks5h (ALL_PROXY)" '^plain site http plain.test 80 $' \
    socks 'env -u http_proxy -u HTTP_PROXY ALL_PROXY="$SOCKS" curl -sS http://plain.test/s'
check "git over https through socks5h" "repository 'https://example.test/repo.git/' not found" \
    socks 'git -c http.proxy="$SOCKS" ls-remote https://example.test/repo.git'
check "python requests through socks5h" '^hello from https example.test 443 over HTTP/1.1 $' \
    socks 'python3 -c "import os, requests; print(requests.get(\"https://example.test/\", proxies={\"https\": os.environ[\"SOCKS\"]}).text.strip())"'
check "go net/http through socks5 (HTTPS_PROXY=socks5://)" '^200 hello from https example.test 443 over HTTP/2.0 $' \
    socks 'HTTPS_PROXY="socks5://${SOCKS#socks5h://}" goclient https://example.test/'

# 2. Tokens.
check "no token: 407" 'response 407' agent curl -sS -x http://attach-http:8080 https://example.test/
check "a wrong token: 407" 'response 407' agent curl -sS -x http://relay:wrong@attach-http:8080 https://example.test/
check "a wrong token, plain HTTP: 407" '^407 $' \
    agent curl -sS -o /dev/null -w '%{http_code}\n' -x http://relay:wrong@attach-http:8080 http://plain.test/
check "socks5 with a wrong token is rejected" 'rejected by the SOCKS5 server' \
    agent curl -sS -x socks5h://relay:wrong@attach-socks:1080 https://example.test/
check "socks5 with no login is refused" 'No authentication method was acceptable' \
    agent curl -sS -x socks5h://attach-socks:1080 https://example.test/

# 3. Failures.
check "no such name: 502" 'response 502' agent curl -sS https://nope.test/
check "the reason is in X-Proxy-Error" 'X-Proxy-Error: no such name in the world' \
    agent curl -sS -o /dev/null -D - -x "http://relay:$RELAY_TOKEN@attach-http:8080" http://nope.test/
check "a closed port: 502, connection refused" '< HTTP/1.1 502 Bad Gateway.*< X-Proxy-Error: connection refused' \
    agent curl -sS -v https://plain.test/
check "socks5: no such name is reply 4" 'connection to nope.test. \(4\)' socks 'curl -sS -x "$SOCKS" https://nope.test/'
check "socks5: a closed port is reply 5" 'connection to plain.test. \(5\)' socks 'curl -sS -x "$SOCKS" https://plain.test/'
start=$(date +%s%N)
check "an address with no machine: 502 host unreachable" 'response 502' agent curl -sS https://192.0.2.1/
ms=$(( ($(date +%s%N) - start) / 1000000 ))
if (( ms < 3000 )); then pass "it failed at once (${ms} ms, including docker exec)"; else fail "it took ${ms} ms"; fi

# 4. Nothing outside the world.
check "a real address through the proxy is just a world address: 502" 'response 502' agent curl -sS -m 10 https://1.1.1.1/
check "a real name through the proxy does not exist in the world: 502" 'response 502' agent curl -sS -m 10 https://example.com/
check "around the proxy, a real address is unreachable" "Network is unreachable|Couldn't connect" \
    agent curl -sS -m 5 --noproxy '*' http://1.1.1.1/
check "around the proxy, TCP to 1.1.1.1 fails" 'Network is unreachable' \
    agent python3 -c 'import socket; socket.create_connection(("1.1.1.1", 443), timeout=5)'
check "around the proxy, UDP DNS to 8.8.8.8 fails" 'Network is unreachable' \
    agent python3 -c 'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"x", ("8.8.8.8", 53))'
# The host has no IPv4 address on the sandbox's network, so the agent
# cannot reach services on the host. (The bridge's IPv6 link-local address
# is out of reach too: Docker turns IPv6 off in a container with no IPv6
# network.) The network's bridge on the host is br-<the first 12
# characters of its id>.
bridge="br-$(docker network inspect fictionet-proxy_sandbox -f '{{.Id}}' | cut -c1-12)"
check "the host has no IPv4 address on the sandbox's network ($bridge)" '^ok $' \
    sh -c "ip -o addr show dev $bridge | grep ' inet ' || echo ok"
check "the sandbox has no IPv6 address on its network" '^none $' \
    agent sh -c 'grep eth0 /proc/net/if_inet6 || echo none'
check "the sandbox resolves no real names" '^no address $' \
    agent sh -c 'getent hosts example.com || echo no address'
check "the sandbox has no ping and no raw sockets" 'Operation not permitted|PermissionError' \
    agent python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)'
check "the sandbox has no capabilities" '^CapEff:\s+0+ $' agent grep CapEff /proc/self/status
check "the sandbox cannot see the world socket" 'No such file or directory' agent ls /run/fictionet

# 5. Throughput, no stalls, uploads.
for door in http socks; do
    if [[ $door == http ]]; then x=(); else x=(-x "\$SOCKS"); fi
    out="$(socks "curl -sS ${x[*]} -o /dev/null -w '%{size_download} %{speed_download}' https://example.test/big")"
    read -r size speed <<<"$out"
    if [[ $size == 16777216 ]]; then pass "16 MiB through the $door door at $((speed * 8 / 1000000)) Mbit/s"; else fail "16 MiB through the $door door: $out"; fi
    # Ten at once. A packet lost on a full socket buffer costs a 1 s
    # retransmit; the prototype's lost wake-up stalled one for 45 s.
    out="$(socks "seq 10 | xargs -P 10 -I{} curl -sS ${x[*]} -o /dev/null -w '%{time_total}\n' https://example.test/big" | sort -n | tr '\n' ' ')"
    read -r -a times <<<"$out"
    if [[ ${#times[@]} == 10 ]] && awk -v t="${times[-1]}" 'BEGIN { exit !(t < 1) }'; then
        pass "10 downloads of 16 MiB at once through the $door door, none stalled (${times[0]} s to ${times[-1]} s)"
    else
        fail "10 downloads of 16 MiB at once through the $door door: $out"
    fi
    out="$(socks "head -c 67108864 /dev/zero | curl -sS ${x[*]} --data-binary @- -w '%{time_total}' https://example.test/upload" | tr '\n' ' ')"
    read -r got took <<<"$out"
    if [[ $got == 67108864 ]]; then pass "a 64 MiB upload through the $door door, in ${took} s"; else fail "a 64 MiB upload through the $door door: $out"; fi
done
check "a 64 MiB upload as a plain-HTTP request" '^67108864 $' \
    agent sh -c 'head -c 67108864 /dev/zero | curl -sS --data-binary @- http://plain.test/upload'

# 6. Many requests.
start=$(date +%s%N)
check "1,000 HTTPS requests, 200 at a time, all 200" '^1000 $' \
    agent sh -c "seq 1000 | xargs -P 200 -I{} curl -sS -o /dev/null -w '%{http_code}\n' 'https://example.test/?{}' | grep -c '^200\$'"
echo "    (took $(( ($(date +%s%N) - start) / 1000000 )) ms, including docker exec)"

echo
echo "--- attach-http log (last lines)"
"${compose[@]}" logs --no-log-prefix attach-http | tail -5
echo "--- attach-socks log (last lines)"
"${compose[@]}" logs --no-log-prefix attach-socks | tail -5
rss="$(docker exec "$("${compose[@]}" ps -q attach-http)" sh -c 'grep VmRSS /proc/1/status' | awk '{print int($2 / 1024)}')"
echo "attach-http memory after all of this: ${rss} MB"

# 7. The world stops: attach ends, and the proxies close.
"${compose[@]}" stop -t 2 world >/dev/null 2>&1
for _ in $(seq 50); do
    state="$("${compose[@]}" ps -a --format '{{.Service}} {{.State}} {{.ExitCode}}' | grep '^attach-http ' || true)"
    [[ $state == *exited* ]] && break
    sleep 0.2
done
check "when the world stops, attach exits 0" '^attach-http exited 0 $' echo "$state"
check "attach says why" 'the world closed the connection; the proxy is closed' "${compose[@]}" logs --no-log-prefix attach-http
check "and the sandbox has no way out at all" "Could not resolve proxy|Failed to connect|Couldn't connect" \
    agent curl -sS -m 5 https://example.test/

finish
