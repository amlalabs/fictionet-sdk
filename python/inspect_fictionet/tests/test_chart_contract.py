"""Compare Compose with Helm rendering of the chart shipped by the package."""

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from inspect_fictionet import Limits, chart_path, fictionet_sandbox


@pytest.fixture(scope="module")
def helm():
    if "CI" in os.environ:
        __import__("k8s_sandbox")
    else:
        pytest.importorskip("k8s_sandbox")
    executable = shutil.which("helm")
    if executable is None:
        assert "CI" not in os.environ, "helm is required in CI"
        pytest.skip("needs helm")
    return executable


@pytest.fixture
def configurations(tmp_path, helm):
    def generate(**kwargs):
        options = dict(world="world:contract", attach_image="attach:contract", cache_dir=tmp_path)
        options.update(kwargs)
        docker = fictionet_sandbox(**options)
        k8s = fictionet_sandbox(**options, backend="k8s")
        assert Path(k8s.config.chart) == chart_path()
        result = subprocess.run(
            [helm, "template", "contract", str(chart_path()), "--values", str(k8s.config.values)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        documents = list(yaml.safe_load_all(result.stdout))
        objects = {doc["kind"]: doc for doc in documents}
        assert len(objects) == len(documents)
        pod = objects["StatefulSet"]["spec"]["template"]["spec"]
        return yaml.safe_load(Path(docker.config).read_text()), pod, objects

    return generate


def environment(container):
    entries = container.get("env", [])
    assert len({entry["name"] for entry in entries}) == len(entries)
    return {entry["name"]: entry["value"] for entry in entries if "value" in entry}


@pytest.mark.parametrize("kind,port", [
    ("tun", None), ("http_proxy", None), ("http_proxy", 18080),
    ("socks5", None), ("socks5", 11080),
])
@pytest.mark.parametrize("ca", [None, "/opt/trust/ca.pem"])
def test_rendered_services(configurations, kind, port, ca):
    compose, pod, objects = configurations(
        attach=kind, proxy_port=port, world_ca=ca, name="contract-agent", world_wait=7,
        agent_image="agent:contract", agent_user="1000:1001", image_pull_policy="Never",
        world_args=["/run/relay/relay.sock", "argument with spaces"], world_env={"WORLD_MODE": "test"},
        agent_command=["sleep", "infinity"], agent_env={"AGENT_MODE": "test"},
    )
    services = compose["services"]
    world, attach = pod["initContainers"][:2]
    [agent] = pod["containers"]
    assert [world["name"], attach["name"], agent["name"]] == ["world", "attach", "default"]
    for container in (world, attach, agent):
        assert container["image"] == services[container["name"]]["image"]
        assert container["imagePullPolicy"] == "Never"
        assert "command" not in container  # Preserve the image's entrypoint.
    for container in (world, agent):
        assert container["args"] == services[container["name"]]["command"]
    assert environment(world) == services["world"]["environment"]
    assert services["default"]["user"] == "1000:1001"
    assert agent["securityContext"]["runAsUser"] == 1000
    assert agent["securityContext"]["runAsGroup"] == 1001
    assert agent["securityContext"]["capabilities"] == {"drop": ["ALL"]}

    # Native sidecars replace Compose dependencies; attach's probe gates the agent.
    assert world["restartPolicy"] == attach["restartPolicy"] == "Always"
    assert services["attach"]["depends_on"] == {"world": {"condition": "service_started"}}
    assert services["default"]["depends_on"] == {"attach": {"condition": "service_healthy"}}
    probe = services["attach"]["healthcheck"]["test"][1:]
    assert attach["startupProbe"]["exec"]["command"] == probe
    assert attach["readinessProbe"]["exec"]["command"] == probe
    assert attach["startupProbe"]["failureThreshold"] == services["attach"]["healthcheck"]["retries"] == 37
    assert pod["automountServiceAccountToken"] is False
    assert pod["shareProcessNamespace"] is False
    assert services["world"]["network_mode"] == services["attach"]["network_mode"] == "none"
    assert services["default"]["network_mode"] == "service:attach"
    policy = objects["NetworkPolicy"]["spec"]
    assert policy["policyTypes"] == ["Ingress", "Egress"]
    assert not policy.get("ingress") and not policy.get("egress")
    labels = objects["StatefulSet"]["spec"]["template"]["metadata"]["labels"]
    assert policy["podSelector"]["matchLabels"].items() <= labels.items()
    assert pod["dnsPolicy"] == "None"
    assert pod["dnsConfig"]["searches"] == []

    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["relay"]["emptyDir"] == {"medium": "Memory", "sizeLimit": "1Mi"}
    for container in (world, attach):
        assert {"name": "relay", "mountPath": "/run/relay"} in container["volumeMounts"]
    mounts = agent.get("volumeMounts", [])
    assert not {m["name"] for m in mounts} & {"relay", "token"}
    assert not any(m["source"] == "sock" for m in services["default"].get("volumes", []))
    if ca:
        assert volumes["shared-ca"]["emptyDir"] == {}
        assert {"name": "shared-ca", "mountPath": "/opt/trust"} in world["volumeMounts"]
        assert mounts == [{"name": "shared-ca", "mountPath": "/opt/trust", "readOnly": True}]
        assert services["world"]["volumes"][-1] == {
            "type": "volume", "source": "ca", "target": "/opt/trust",
        }
        assert services["default"]["volumes"] == [{
            "type": "volume", "source": "ca", "target": "/opt/trust", "read_only": True,
        }]
        for variable in ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"):
            assert environment(agent)[variable] == services["default"]["environment"][variable] == ca
    else:
        assert "shared-ca" not in volumes and "ca" not in compose["volumes"]
        assert not mounts and "volumes" not in services["default"]
    assert not any(m["name"] == "shared-ca" for m in attach["volumeMounts"])

    args = attach["args"]
    docker_args = services["attach"]["command"]
    assert args[:7] == docker_args[:7] == [
        "attach", "--world", "unix:/run/relay/relay.sock", "--name", "contract-agent", "--type", kind,
    ]
    if kind == "tun":
        # The chart sets DNS on the pod and takes the CNI interface down.
        extra = ["--mtu=1500", "--no-resolv-conf", "--down-link=eth0"]
        assert sorted(args) == sorted(docker_args + extra)
        assert pod["dnsConfig"]["nameservers"] == ["10.0.0.1"]
        assert len(pod["initContainers"]) == 2
        assert "Secret" not in objects and "token" not in volumes
        assert environment(agent) == services["default"]["environment"]
        assert set(attach["securityContext"]["capabilities"]["add"]) == set(services["attach"]["cap_add"]) | {"MKNOD"}
        assert services["attach"]["devices"] == ["/dev/net/tun"]
        assert services["default"]["cap_drop"] == ["NET_RAW"]
    else:
        assert args == docker_args
        port = port or (8080 if kind == "http_proxy" else 1080)
        assert f"--listen=127.0.0.1:{port}" in args
        assert "--ip-addr=10.0.0.2" in args
        assert "--token-file=/run/relay-token/token" in args
        assert not any(arg.startswith(("--gateway", "--no-", "--mtu")) for arg in args)
        assert pod["dnsConfig"]["nameservers"] == ["127.0.0.1"]
        assert [c["name"] for c in pod["initContainers"]] == ["world", "attach", "wait-blocked"]
        wait = pod["initContainers"][2]
        assert "restartPolicy" not in wait
        assert wait["args"] == ["wait-blocked", "--api-server", "--timeout", "120"]
        assert attach["securityContext"]["capabilities"] == {"drop": ["ALL"]}
        assert attach["securityContext"]["runAsUser"] == 65532
        assert services["attach"]["cap_add"] == ["DAC_OVERRIDE"]
        assert "devices" not in services["attach"]
        assert services["default"]["cap_drop"] == ["ALL"]

        # Kubernetes expands the Secret-backed variable before the proxy URLs.
        # Compose embeds its own token and also mounts the token file in the agent.
        secret = objects["Secret"]
        assert len(base64.b64decode(secret["data"]["token"], validate=True)) == 32
        assert agent["env"][0] == {
            "name": "RELAY_TOKEN",
            "valueFrom": {"secretKeyRef": {"name": secret["metadata"]["name"], "key": "token"}},
        }
        assert volumes["token"]["secret"] == {"secretName": secret["metadata"]["name"], "defaultMode": 0o444}
        assert {"name": "token", "mountPath": "/run/relay-token", "readOnly": True} in attach["volumeMounts"]
        token = compose["configs"]["relay-token"]["content"].strip()
        docker_env = services["default"]["environment"].copy()
        assert docker_env.pop("RELAY_TOKEN_FILE") == "/run/relay-token/token"
        assert environment(agent) == {k: v.replace(token, "$(RELAY_TOKEN)") for k, v in docker_env.items()}
        if kind == "http_proxy":
            variables = ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"]
        else:
            variables = ["ALL_PROXY", "all_proxy"]
        scheme = "http" if kind == "http_proxy" else "socks5h"
        for variable in variables:
            assert environment(agent)[variable] == f"{scheme}://relay:$(RELAY_TOKEN)@127.0.0.1:{port}"
        assert environment(agent)["NO_PROXY"] == environment(agent)["no_proxy"] == ""


@pytest.mark.parametrize("addresses,nameservers", [
    ({}, ["10.0.0.1"]),
    (dict(ip_addr="10.7.0.2/16", gateway="10.7.0.1", dns="10.7.0.53",
          ip_addr_v6="fd07::2/64", gateway_v6="fd07::1", dns_v6="fd07::53"), ["10.7.0.53", "fd07::53"]),
    (dict(ip_addr=None, gateway=None, dns=None, ip_addr_v6="fd07::2/64", dns_v6="fd07::53"), ["fd07::53"]),
])
def test_tun_addresses(configurations, addresses, nameservers):
    compose, pod, _ = configurations(**addresses, mtu=1400)
    args = pod["initContainers"][1]["args"]
    assert sorted(args) == sorted(compose["services"]["attach"]["command"] + ["--no-resolv-conf", "--down-link=eth0"])
    assert "--mtu=1400" in args
    assert pod["dnsConfig"]["nameservers"] == nameservers
    defaults = dict(ip_addr="10.0.0.2/24", gateway="10.0.0.1", dns="10.0.0.1",
                    ip_addr_v6=None, gateway_v6=None, dns_v6=None)
    for key, value in (defaults | addresses).items():
        flag = key.replace("_", "-")
        assert (f"--{flag}={value}" if value else f"--no-{flag}") in args


@pytest.mark.parametrize("options,expected", [
    ({}, [("2g", None, 1024, {"memory": "2Gi"}, {"memory": "64Mi"}),
          ("2g", 1.0, 1024, {"memory": "2Gi", "cpu": "1000m"}, {"memory": "256Mi", "cpu": "100m"})]),
    (dict(world_limits=Limits(memory="32m", cpus=0.25, pids=31),
          agent_limits=Limits(memory="128m", cpus=0.05, pids=63)),
     [("32m", 0.25, 31, {"memory": "32Mi", "cpu": "250m"}, {"memory": "32Mi"}),
      ("128m", 0.05, 63, {"memory": "128Mi", "cpu": "50m"}, {"memory": "128Mi", "cpu": "50m"})]),
    (dict(world_limits=Limits(), agent_limits=Limits()), [(None, None, None, {}, {}), (None, None, None, {}, {})]),
    (dict(world_limits=Limits(cpus=0.5), agent_limits=Limits(pids=17)),
     [(None, 0.5, None, {"cpu": "500m"}, {}), (None, None, 17, {}, {})]),
])
def test_rendered_limits(configurations, options, expected):
    compose, pod, _ = configurations(**options)
    world, attach = pod["initContainers"]
    [agent] = pod["containers"]
    for name, container, (memory, cpus, pids, limits, requests) in zip(
        ("world", "default", "attach"), (world, agent, attach),
        [*expected, ("512m", None, 256, {"memory": "512Mi"}, {"memory": "32Mi"})], strict=True,
    ):
        service = compose["services"][name]
        for key, value in (("mem_limit", memory), ("memswap_limit", memory), ("cpus", cpus), ("pids_limit", pids)):
            if value is None:
                assert key not in service
            else:
                assert service[key] == value
        # Kubernetes has requests but no per-container PID or swap limit.
        if limits:
            assert container["resources"] == {"limits": limits, "requests": requests}
        else:
            assert "resources" not in container  # Empty values must clear chart defaults.
        assert "pids_limit" not in container and "memswap_limit" not in container
