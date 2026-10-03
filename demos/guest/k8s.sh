#!/usr/bin/env bash
# The Kubernetes demo, run inside the VM by demos/k8s. A kind cluster, the
# Helm chart in charts/fictionet-sandbox, and an agent pod whose only
# network is the world.
# needs: sdk
. "$(dirname "$0")/lib.sh"
. /src/vm/versions.sh
cluster=fictionet-demo
release=demo
pod="fictionet-sandbox-$release-default-0"
export KUBECONFIG=/root/.kube/fictionet-demo

cleanup() {
    stop_pid "${kind_pid:-}"
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

step "Make a Kubernetes cluster with kind, and build the images meanwhile"
note "kind runs a whole cluster in one Docker container, inside this VM."
docker image inspect "$KIND_NODE_IMAGE" >/dev/null 2>&1 || docker pull -q "$KIND_NODE_IMAGE" >/dev/null
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 120s >/run/kind.log 2>&1 &
kind_pid=$!
note "The attach and world images come from deploy/Dockerfile. Its build stage is replaced"
note "by the static binaries just built (--build-context build=...), so nothing compiles"
note "twice. The agent image is the same file's agent target: Debian with curl, dig and ip."
vm 'docker build -q -f /src/deploy/Dockerfile --build-context build=/opt/fictionet/prebuilt --target attach -t fictionet-attach:dev /src'
vm 'docker build -q -f /src/deploy/Dockerfile --build-context build=/opt/fictionet/prebuilt --target web-world -t fictionet-web-world:dev /src'
vm 'docker build -q -f /src/deploy/Dockerfile --build-context build=/opt/fictionet/prebuilt --target agent -t fictionet-agent:dev /src'
wait "$kind_pid" || { cat /run/kind.log; exit 1; }
kind_pid=
sed 's/^/    /' /run/kind.log
vm "kind load docker-image --name $cluster fictionet-attach:dev fictionet-web-world:dev fictionet-agent:dev 2>&1 | { grep -v '^Image:' || true; }"

step "Install the chart"
note "examples/attach/k8s-tun.yaml runs the web_world example as the world and the Debian image as"
note "the agent, as uid 1000 with no capabilities. The world and attach run as native sidecars"
note "in the agent's pod; attach takes the pod's eth0 down and puts tun0 in its place."
vm "helm install $release /src/charts/fictionet-sandbox -f /src/examples/attach/k8s-tun.yaml --wait --timeout 180s | sed -n 1,6p"
vm "kubectl get pod $pod -o jsonpath='{range .spec.initContainers[*]}{.name}{\" (sidecar)\\n\"}{end}{range .spec.containers[*]}{.name}{\" (the agent)\\n\"}{end}'"
vm "kubectl logs $pod -c attach"

AGENT=(kubectl exec "$pod" -c default --)

step "Inside the agent's container"
agent 'id; ip -br addr; ip route; cat /etc/resolv.conf'
agent 'dig +short example.test'
agent 'curl -sS --cacert /run/ca/ca.pem https://example.test/'

step "The cluster is out of reach"
note "The agent cannot reach the internet, the cluster's DNS or the API server, and it cannot"
note "set eth0 up again: it has no capabilities."
kube_dns="$(kubectl -n kube-system get service kube-dns -o jsonpath='{.spec.clusterIP}')"
api="$(kubectl get service kubernetes -o jsonpath='{.spec.clusterIP}')"
agent 'curl -sS -m 5 http://1.1.1.1/'
agent "dig +time=2 +tries=1 @$kube_dns kubernetes.default.svc.cluster.local | tail -1"
agent "curl -sS -m 5 -k https://$api/version"
agent 'ip link set eth0 up'

step "Clean up"
note "Deleting the cluster."
