#!/usr/bin/env bash
# The Kubernetes proxy test: charts/fictionet-sandbox with attach.type
# http_proxy and socks5, on a kind cluster, in a namespace that enforces
# Pod Security "restricted".
#
#   tests/k8s/proxy.sh
#
# Needs docker, kind, kubectl and helm on PATH. It builds the attach,
# web_fixture and agent images, makes a kind cluster named
# fictionet-k8s-test (or uses it if it is already there), loads the
# images, and checks that:
#   1. the proxy release is admitted under "restricted" with no warning,
#      and its pods run with no capability and no root anywhere, while a
#      tun release in the same namespace is refused;
#   1a. the agent started only after wait-blocked saw the pod's direct
#      traffic blocked, and with no NetworkPolicy at all the agent does not
#      start until one is applied;
#   1b. the agent's container has its memory and CPU limits;
#   2. the agent reaches the world's sites through attach, by the proxy
#      variables the chart sets, through both doors;
#   3. the agent's eth0 is up, and still nothing else is reachable: not
#      the cluster's DNS, not the API server, not 1.1.1.1, not the kubelet
#      on the pod's own node, and names do not resolve in the pod;
#   4. a wrong token is refused, and nothing outside the world is
#      reachable through the proxy;
#   5. ten downloads of 16 MiB at once do not stall;
#   6. when attach is stopped the agent has no way out, and when
#      Kubernetes restarts it the proxy comes back.
# It removes the namespace at the end, and the cluster if it made it.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cluster=fictionet-k8s-test
ns=fictionet-restricted
release=fnproxy
pod="fictionet-sandbox-$release-default-0"
socks_pod="fictionet-sandbox-$release-socks-0"
failures=0
made_cluster=0

cleanup() {
    kubectl delete namespace "$ns" --wait=false >/dev/null 2>&1 || true
    if [ "$made_cluster" = 1 ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
agent() { kubectl -n "$ns" exec "$pod" -c default -- "$@"; }
socks_agent() { kubectl -n "$ns" exec "$socks_pod" -c socks -- "$@"; }

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
docker build -q -f "$root/tests/docker/web/Dockerfile" --target fixture -t fictionet-web-fixture:dev "$root" >/dev/null
docker build -q -f "$root/deploy/Dockerfile" --target agent -t fictionet-agent:dev "$root" >/dev/null

if ! kind get clusters 2>/dev/null | grep -qx "$cluster"; then
    kind create cluster --name "$cluster" --wait 120s
    made_cluster=1
fi
kubectl config use-context "kind-$cluster" >/dev/null
kind load docker-image --name "$cluster" fictionet-attach:dev fictionet-web-fixture:dev fictionet-agent:dev >/dev/null
kubectl delete namespace "$ns" --wait >/dev/null 2>&1 || true
kubectl create namespace "$ns" >/dev/null
kubectl label namespace "$ns" pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted >/dev/null

# 1. Pod Security.
out="$(helm install "$release" "$root/charts/fictionet-sandbox" -n "$ns" -f "$root/examples/attach/k8s-proxy.yaml" \
    --set serviceDefaults.world.image=fictionet-web-fixture:dev \
    --wait --timeout 180s 2>&1)" || fail "helm install: $out"
if grep -qi 'PodSecurity' <<<"$out"; then fail "Pod Security warnings: $out"; else pass "the proxy release is admitted under restricted, with no warning"; fi
check "both sandboxes run" '^Running Running ?$' \
    kubectl -n "$ns" get pod "$pod" "$socks_pod" -o jsonpath='{.items[*].status.phase}'
check "no container adds a capability or runs as root" '^$' \
    sh -c "kubectl -n $ns get pod $pod -o json | grep -E '\"add\"|\"runAsUser\": 0|\"privileged\": true' || true"
check "attach runs as the world's user, with no capabilities" '^uid=65532' \
    sh -c "kubectl -n $ns get pod $pod -o jsonpath='{.spec.initContainers[?(@.name==\"attach\")].securityContext.runAsUser}' | sed 's/^/uid=/'"
helm install fntun "$root/charts/fictionet-sandbox" -n "$ns" -f "$root/examples/attach/k8s-tun.yaml" >/dev/null 2>&1 || true
sleep 3
check "a tun release in the same namespace is refused" 'violates PodSecurity "restricted:latest".*NET_ADMIN' \
    kubectl -n "$ns" get events --field-selector reason=FailedCreate -o jsonpath='{.items[*].message}'
helm uninstall fntun -n "$ns" >/dev/null 2>&1 || true

# 1a. The agent waits for the NetworkPolicy.
check "wait-blocked exited 0 once the API server stopped answering" \
    'unreachable 3 times in a row' kubectl -n "$ns" logs "$pod" -c wait-blocked
blocked_at="$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="wait-blocked")].state.terminated.finishedAt}')"
agent_started="$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.containerStatuses[?(@.name=="default")].state.running.startedAt}')"
check "the agent started after wait-blocked exited" 'after' \
    sh -c "[ -n \"$blocked_at\" ] && [ ! \"$agent_started\" \< \"$blocked_at\" ] && echo after || echo 'wait-blocked $blocked_at, agent $agent_started'"
# A release with no NetworkPolicy: whatever the CNI does, the agent must
# not start. Then a deny-all policy is applied by hand, and it starts.
nopolicy_pod="fictionet-sandbox-fnnopolicy-default-0"
helm install fnnopolicy "$root/charts/fictionet-sandbox" -n "$ns" -f "$root/examples/attach/k8s-proxy.yaml" \
    --set serviceDefaults.world.image=fictionet-web-fixture:dev \
    --set networkPolicy.enabled=false >/dev/null
sleep 20
check "with no NetworkPolicy, wait-blocked is still waiting" 'still reachable; waiting' \
    kubectl -n "$ns" logs "$nopolicy_pod" -c wait-blocked
check "with no NetworkPolicy, the agent has not started" '^PodInitializing ?$' \
    kubectl -n "$ns" get pod "$nopolicy_pod" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}'
kubectl -n "$ns" apply -f - >/dev/null <<EOF_POLICY
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: fnnopolicy-deny-all
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: fnnopolicy
  policyTypes: [Ingress, Egress]
EOF_POLICY
kubectl -n "$ns" wait --for=condition=Ready "pod/$nopolicy_pod" --timeout 90s >/dev/null 2>&1 || true
check "once a deny-all policy is applied, the agent starts" '^true ?$' \
    kubectl -n "$ns" get pod "$nopolicy_pod" -o jsonpath='{.status.containerStatuses[0].ready}'
check "and its first try at the API server is blocked" "Couldn't connect|timed out|Failed to connect" \
    kubectl -n "$ns" exec "$nopolicy_pod" -c default -- curl -sS --noproxy '*' -m 5 -k "https://$(kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}')/version"
helm uninstall fnnopolicy -n "$ns" >/dev/null 2>&1 || true
kubectl -n "$ns" delete networkpolicy fnnopolicy-deny-all >/dev/null 2>&1 || true

# 1b. Resource limits.
check "the agent's memory is limited to 2 GiB" '^2147483648 $' agent cat /sys/fs/cgroup/memory.max
check "the agent's CPU is limited to 1" '^100000 100000 $' agent cat /sys/fs/cgroup/cpu.max

# 2. Through the proxies.
check "the agent is uid 1000 with no capabilities" '^uid=1000.* CapEff:\s+0+ $' \
    agent sh -c 'id; grep CapEff /proc/self/status'
check "the chart set the proxy variables" '^https_proxy=http://relay:\*\*\*@127\.0\.0\.1:8080 $' \
    agent sh -c 'echo "https_proxy=$https_proxy" | sed "s/:[^:@]*@/:***@/"'
check "https to the world's site through the HTTP door" '^hello from https example.test 443 over HTTP/2.0 $' \
    agent curl -sS https://example.test/
check "plain http through the HTTP door" '^plain site http plain.test 80 $' agent curl -sS http://plain.test/k
check "https through the SOCKS5 door (ALL_PROXY)" '^hello from https example.test 443 over HTTP/2.0 $' \
    socks_agent curl -sS https://example.test/

# 3. eth0 is up, and nothing else answers.
check "the agent's eth0 is up, with the pod's address" '^eth0@[^ ]+ +UP +[0-9.]+/' agent ip -br addr show eth0
check "names do not resolve in the pod" 'Could not resolve host' agent curl -sS --noproxy '*' -m 5 https://example.test/
check "1.1.1.1 is unreachable around the proxy" "Couldn't connect|timed out|Connection refused|Failed to connect" \
    agent curl -sS --noproxy '*' -m 5 http://1.1.1.1/
kube_dns="$(kubectl -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')"
check "the cluster's DNS ($kube_dns) is unreachable" 'no servers could be reached|timed out' \
    agent dig +time=2 +tries=1 "@$kube_dns" kubernetes.default.svc.cluster.local
api="$(kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}')"
check "the API server ($api) is unreachable around the proxy" "Couldn't connect|timed out|Failed to connect" \
    agent curl -sS --noproxy '*' -m 5 -k "https://$api/version"
node_ip="$(kubectl get node "$cluster-control-plane" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')"
check "the kubelet on the pod's node ($node_ip) is unreachable" "Couldn't connect|timed out|Failed to connect" \
    agent curl -sS --noproxy '*' -m 5 -k "https://$node_ip:10250/healthz"
gateway="$(agent ip -4 route show default | awk '{print $3}')"
check "the kubelet at the pod's gateway ($gateway) is unreachable" "Couldn't connect|timed out|Failed to connect" \
    agent curl -sS --noproxy '*' -m 5 -k "https://$gateway:10250/healthz"
check "the world's socket is not in the agent's container" 'No such file or directory' agent ls /run/relay

# 4. Tokens, and the world's edge.
check "a wrong token gets 407" 'response 407' agent curl -sS -x http://relay:wrong@127.0.0.1:8080 https://example.test/
check "the API server's address through the proxy is a world address with no machine: 502" 'response 502' \
    agent curl -sS -m 10 -k "https://$api/version"
check "a real name through the proxy does not exist in the world: 502" 'response 502' agent curl -sS -m 10 https://example.com/

# 5. No stalls.
out="$(agent sh -c "seq 10 | xargs -P 10 -I{} curl -sS -o /dev/null -w '%{time_total}\n' https://example.test/big" | sort -n | tr '\n' ' ')"
read -r -a times <<<"$out"
if [[ ${#times[@]} == 10 ]] && awk -v t="${times[-1]}" 'BEGIN { exit !(t < 2) }'; then
    pass "10 downloads of 16 MiB at once, none stalled (${times[0]} s to ${times[-1]} s)"
else
    fail "10 downloads of 16 MiB at once: $out"
fi
out="$(agent curl -sS -o /dev/null -w '%{size_download} %{speed_download}' https://example.test/big)"
read -r size speed <<<"$out"
if [[ $size == 16777216 ]]; then pass "16 MiB at $((speed * 8 / 1000000)) Mbit/s"; else fail "16 MiB: $out"; fi
check "attach logged the requests" 'CONNECT example.test:443 \(203\.0\.113\.10\) 200' kubectl -n "$ns" logs "$pod" -c attach

check "attach has not restarted under load" '^0 ?$' \
    kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].restartCount}'

# 6. Attach stopped: no way out. Restarted: the proxy is back.
node="$cluster-control-plane"
attach_id="$(docker exec "$node" crictl ps --name attach --label "io.kubernetes.pod.name=$pod" -q)"
docker exec "$node" crictl --timeout 30s stop -t 0 "$attach_id" >/dev/null
check "with attach stopped, nothing answers" 'Failed to connect|Connection refused' agent curl -sS -m 3 https://example.test/
for _ in $(seq 1 60); do
    restarts="$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].restartCount}')"
    ready="$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="attach")].ready}')"
    if [ "$restarts" -ge 1 ] && [ "$ready" = true ]; then break; fi
    sleep 1
done
check "attach restarted and is ready" '^1 true $' echo "$restarts $ready"
check "after the restart, https works again" '^hello from https example.test 443' agent curl -sS https://example.test/

helm uninstall "$release" -n "$ns" --wait >/dev/null 2>&1 || true
if [ "$failures" -gt 0 ]; then
    echo "$failures checks failed"
    exit 1
fi
echo "ALL PASSED"
