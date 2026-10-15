#!/usr/bin/env bash
# The Kubernetes test: charts/fictionet-sandbox on a kind cluster.
#
#   tests/k8s/run.sh
#   tests/k8s/run.sh --test-ordering  # timestamp fixtures only; no cluster needed
#
# Both modes run timestamp fixtures before any image build or cluster access.
#
# Needs docker, kind, kubectl and helm on PATH. It builds the attach,
# web_world and agent images, makes a kind cluster named
# fictionet-k8s-test (or uses it if it is already there), loads the
# images, installs the chart with examples/attach/k8s-tun.yaml, and checks from
# the agent's container that:
#   1. the agent runs as uid 1000, sees only its own processes, and has
#      the chart's default memory and CPU limits,
#   2. eth0 is down with no address, and the only default route is tun0's,
#   3. resolv.conf names only the world, and the world answers DNS,
#   4. HTTPS to the world's site works with the world's CA,
#   5. 1.1.1.1, the cluster's DNS and the API server are unreachable,
#   6. the agent cannot set eth0 up, and cannot see the world's socket,
#   7. the agent started no earlier than attach, and attach is ready,
#   8. when attach is stopped the agent has no network at all, and when
#      Kubernetes restarts it the network comes back,
#   9. with INSPECT=1, tests/k8s/inspect_eval.py passes through Inspect's
#      k8s sandbox (needs inspect-ai and inspect-k8s-sandbox).
# It removes the release at the end, and the cluster if it made it.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cluster=fictionet-k8s-test
release=fntest
pod="fictionet-sandbox-$release-default-0"
failures=0
source "$here/../common/assertions.sh"
made_cluster=0

cleanup() {
    helm uninstall "$release" --wait >/dev/null 2>&1 || true
    if [ "$made_cluster" = 1 ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
}

agent() { kubectl exec "$pod" -c default -- "$@"; }
ca=(--cacert /run/ca/ca.pem)

# Kubernetes start times have second granularity. Equality is valid coarse
# start-order evidence, but says nothing about when attach became ready.
starts_in_order() {
    local attach_started="$1" agent_started="$2"
    [[ -n "$attach_started" && -n "$agent_started" && ! "$agent_started" < "$attach_started" ]]
}

test_ordering_fixtures() {
    test_ordering() {
        local name="$1" want="$2" attach_started="$3" agent_started="$4" ordered=false
        if starts_in_order "$attach_started" "$agent_started"; then ordered=true; fi
        check_ok "$name" "^$want $" echo "$ordered"
    }
    test_ordering "equal start timestamps are accepted" true \
        2026-10-14T12:00:00Z 2026-10-14T12:00:00Z
    test_ordering "a later agent start is accepted" true \
        2026-10-14T12:00:00Z 2026-10-14T12:00:01Z
    test_ordering "a missing attach start is rejected" false \
        '' 2026-10-14T12:00:00Z
    test_ordering "a missing agent start is rejected" false \
        2026-10-14T12:00:00Z ''
    test_ordering "two missing starts are rejected" false '' ''
    test_ordering "reversed start timestamps are rejected" false \
        2026-10-14T12:00:01Z 2026-10-14T12:00:00Z
}

test_ordering_fixtures
if [ "${1:-}" = --test-ordering ]; then
    if [ "$failures" -gt 0 ]; then exit 1; fi
    exit 0
fi

trap cleanup EXIT

docker build -q -f "$root/deploy/Dockerfile" --target attach -t fictionet-attach:dev "$root" >/dev/null
docker build -q -f "$root/deploy/Dockerfile" --target web-world -t fictionet-web-world:dev "$root" >/dev/null
docker build -q -f "$root/deploy/Dockerfile" --target agent -t fictionet-agent:dev "$root" >/dev/null

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
    kind create cluster --name "$cluster" --wait 120s
    made_cluster=1
fi
kubectl config use-context "kind-$cluster" >/dev/null
kind load docker-image --name "$cluster" fictionet-attach:dev fictionet-web-world:dev fictionet-agent:dev >/dev/null
helm uninstall "$release" --wait >/dev/null 2>&1 || true
helm install "$release" "$root/charts/fictionet-sandbox" -f "$root/examples/attach/k8s-tun.yaml" --wait --timeout 180s >/dev/null

# 1. Who the agent is, and what it sees.
check_ok "the agent is uid 1000" '^uid=1000' agent id
check_ok "the agent's process 1 is its own command" '^sleep infinity +$' agent sh -c 'tr "\0" " " < /proc/1/cmdline'
check_ok "the agent sees no process of attach or the world" '^0 $' \
    agent bash -e -o pipefail -c 'cmdlines=$(cat /proc/[0-9]*/cmdline | tr "\0" " "); printf "%s\n" "$cmdlines" | awk "/fictione[t]|web_worl[d]/ { n++ } END { print n+0 }"'
check_ok "the agent's memory is limited to 2 GiB" '^2147483648 $' agent cat /sys/fs/cgroup/memory.max
check_ok "the agent's CPU is limited to 1" '^100000 100000 $' agent cat /sys/fs/cgroup/cpu.max
check_ok "with tun, there is no wait-blocked" '^world attach ?$' \
    kubectl get pod "$pod" -o jsonpath='{.spec.initContainers[*].name}'

# 2. Links and routes.
check_ok "eth0 is down" 'eth0@[^ ]+ +DOWN' agent ip -br link show eth0
check_ok "eth0 has no address" '^eth0@[^ ]+ +DOWN +$' agent ip -br addr show eth0
check_ok "the only default route is tun0's" '^default via 10\.0\.0\.1 dev tun0 proto static onlink +$' \
    agent sh -ec 'v4=$(ip route show table all); v6=$(ip -6 route show table all); printf "%s\n" "$v4" "$v6" | awk "/^default|dev eth0/"'

# 3. DNS.
check_ok "resolv.conf names only the world" '^nameserver 10\.0\.0\.1 options ndots:1 $' agent cat /etc/resolv.conf
check_ok "the world answers DNS" '^203\.0\.113\.10 $' agent dig +short example.test

# 4. HTTPS.
check_ok "https to the world's site" '^hello from https example.test 443 over HTTP/2.0 $' \
    agent curl -sS "${ca[@]}" https://example.test/

# 5. Nothing else.
check_fails "1.1.1.1 is unreachable" "Couldn't connect to server" agent curl -sS -m 5 http://1.1.1.1/
kube_dns="$(kubectl -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')"
check_fails "the cluster's DNS ($kube_dns) is unreachable" 'no servers could be reached' \
    agent dig +time=2 +tries=1 "@$kube_dns" kubernetes.default.svc.cluster.local
api="$(kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}')"
check_fails "the API server ($api) is unreachable" "Couldn't connect to server" agent curl -sS -m 5 -k "https://$api/version"

# 6. No way back.
check_fails "ip link set eth0 up is refused" 'Operation not permitted' agent ip link set eth0 up
check_fails "ip route add is refused" 'Operation not permitted' agent ip route add 1.1.1.1 dev eth0
check_fails "the world's socket is not in the agent's container" 'No such file or directory' agent ls /run/relay

# 7. Coarse start ordering and current readiness are separate checks.
attach_started="$(kubectl get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].state.running.startedAt}')"
agent_started="$(kubectl get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="default")].state.running.startedAt}')"
if starts_in_order "$attach_started" "$agent_started"; then
    pass "the agent started no earlier than attach"
else
    fail "start ordering: attach $attach_started, agent $agent_started"
fi
check_ok "attach is ready" '^true ?$' \
    kubectl get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].ready}'
check_ok "attach made /dev/net/tun and took eth0 down" 'eth0 is down.*made /dev/net/tun.*attached as tun0' \
    kubectl logs "$pod" -c attach

# 8. Attach stopped: no network. Restarted: the network is back.
node="$cluster-control-plane"
attach_id="$(docker exec "$node" crictl ps --name attach -q)"
docker exec "$node" crictl --timeout 30s stop -t 0 "$attach_id" >/dev/null
check_ok "with attach stopped, tun0 is gone" '^0 $' \
    agent sh -ec 'links=$(ip -br link); printf "%s\n" "$links" | awk "/tun0/ { n++ } END { print n+0 }"'
check_fails "with attach stopped, nothing answers" 'Could not resolve host' agent curl -sS -m 3 "${ca[@]}" https://example.test/
for _ in $(seq 1 60); do
    restarts="$(kubectl get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].restartCount}')"
    ready="$(kubectl get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].ready}')"
    if [ "$restarts" -ge 1 ] && [ "$ready" = true ]; then break; fi
    sleep 1
done
check_ok "attach restarted and is ready" '^1 true $' echo "$restarts $ready"
check_ok "after the restart, https works again" '^hello from https example.test 443' \
    agent curl -sS "${ca[@]}" https://example.test/

# 9. Inspect.
if [ "${INSPECT:-0}" = 1 ]; then
    check_ok "the Inspect eval passes" 'accuracy +1\.0' \
        sh -c "cd '$root' && inspect eval tests/k8s/inspect_eval.py --model mockllm/model --display plain \
            --log-dir target/inspect-logs"
fi

if [ "$failures" -gt 0 ]; then
    echo "$failures checks failed"
    exit 1
fi
echo "all checks passed"
