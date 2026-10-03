#!/usr/bin/env bash
# The Kubernetes test: charts/fictionet-sandbox on a kind cluster.
#
#   tests/k8s/run.sh
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
#   7. the agent started after attach was ready,
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
made_cluster=0

cleanup() {
    helm uninstall "$release" --wait >/dev/null 2>&1 || true
    if [ "$made_cluster" = 1 ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
agent() { kubectl exec "$pod" -c default -- "$@"; }
ca=(--cacert /run/ca/ca.pem)

# Runs a check: name, then the expected text (a grep -E pattern), then the
# command. The command's stdout and stderr are matched, as one line.
check() {
    local name="$1" want="$2"
    shift 2
    local out
    out="$("$@" 2>&1 | tr '\n' ' ')" || true
    if grep -qE -- "$want" <<<"$out"; then pass "$name"; else fail "$name: wanted /$want/, got: $out"; fi
}

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
check "the agent is uid 1000" '^uid=1000' agent id
check "the agent's process 1 is its own command" '^sleep infinity +$' agent sh -c 'tr "\0" " " < /proc/1/cmdline'
check "the agent sees no process of attach or the world" '^0 $' \
    agent sh -c 'cat /proc/[0-9]*/cmdline 2>/dev/null | tr "\0" " " | grep -c -E "fictione[t]|web_worl[d]"; true'
check "the agent's memory is limited to 2 GiB" '^2147483648 $' agent cat /sys/fs/cgroup/memory.max
check "the agent's CPU is limited to 1" '^100000 100000 $' agent cat /sys/fs/cgroup/cpu.max
check "with tun, there is no wait-blocked" '^world attach ?$' \
    kubectl get pod "$pod" -o jsonpath='{.spec.initContainers[*].name}'

# 2. Links and routes.
check "eth0 is down" 'eth0@[^ ]+ +DOWN' agent ip -br link show eth0
check "eth0 has no address" '^eth0@[^ ]+ +DOWN +$' agent ip -br addr show eth0
check "the only default route is tun0's" '^default via 10\.0\.0\.1 dev tun0 proto static onlink +$' \
    agent sh -c 'ip route show table all | grep -E "^default|dev eth0"; ip -6 route show table all | grep -E "^default|dev eth0"; true'

# 3. DNS.
check "resolv.conf names only the world" '^nameserver 10\.0\.0\.1 options ndots:1 $' agent cat /etc/resolv.conf
check "the world answers DNS" '^203\.0\.113\.10 $' agent dig +short example.test

# 4. HTTPS.
check "https to the world's site" '^hello from https example.test 443 over HTTP/2.0 $' \
    agent curl -sS "${ca[@]}" https://example.test/

# 5. Nothing else.
check "1.1.1.1 is unreachable" "Couldn't connect to server" agent curl -sS -m 5 http://1.1.1.1/
kube_dns="$(kubectl -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')"
check "the cluster's DNS ($kube_dns) is unreachable" 'no servers could be reached' \
    agent dig +time=2 +tries=1 "@$kube_dns" kubernetes.default.svc.cluster.local
api="$(kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}')"
check "the API server ($api) is unreachable" "Couldn't connect to server" agent curl -sS -m 5 -k "https://$api/version"

# 6. No way back.
check "ip link set eth0 up is refused" 'Operation not permitted' agent ip link set eth0 up
check "ip route add is refused" 'Operation not permitted' agent ip route add 1.1.1.1 dev eth0
check "the world's socket is not in the agent's container" 'No such file or directory' agent ls /run/fictionet

# 7. Order: the agent started after attach was ready.
attach_ready="$(kubectl get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].state.running.startedAt}')"
agent_started="$(kubectl get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="default")].state.running.startedAt}')"
check "the agent started after attach" 'after' \
    sh -c "[ \"$agent_started\" \> \"$attach_ready\" ] && echo after || echo 'attach $attach_ready, agent $agent_started'"
check "attach made /dev/net/tun and took eth0 down" 'eth0 is down.*made /dev/net/tun.*attached as tun0' \
    kubectl logs "$pod" -c attach

# 8. Attach stopped: no network. Restarted: the network is back.
node="$cluster-control-plane"
attach_id="$(docker exec "$node" crictl ps --name attach -q)"
docker exec "$node" crictl --timeout 30s stop -t 0 "$attach_id" >/dev/null
check "with attach stopped, tun0 is gone" '^0 $' agent sh -c 'ip -br link | grep -c tun0; true'
check "with attach stopped, nothing answers" 'Could not resolve host' agent curl -sS -m 3 "${ca[@]}" https://example.test/
for _ in $(seq 1 60); do
    restarts="$(kubectl get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].restartCount}')"
    ready="$(kubectl get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].ready}')"
    if [ "$restarts" -ge 1 ] && [ "$ready" = true ]; then break; fi
    sleep 1
done
check "attach restarted and is ready" '^1 true $' echo "$restarts $ready"
check "after the restart, https works again" '^hello from https example.test 443' \
    agent curl -sS "${ca[@]}" https://example.test/

# 9. Inspect.
if [ "${INSPECT:-0}" = 1 ]; then
    check "the Inspect eval passes" 'accuracy +1\.0' \
        sh -c "cd '$root' && inspect eval tests/k8s/inspect_eval.py --model mockllm/model --display plain \
            --log-dir target/inspect-logs"
fi

if [ "$failures" -gt 0 ]; then
    echo "$failures checks failed"
    exit 1
fi
echo "all checks passed"
