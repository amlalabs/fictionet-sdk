"""Unit tests for the compose file and the Helm values."""

import filecmp
import os
from pathlib import Path

import pytest
import yaml

from inspect_fictionet import (
    AGENT_LIMITS,
    ATTACH_IMAGE,
    WEB_WORLD_IMAGE,
    Build,
    CargoExample,
    Limits,
    chart_path,
    fictionet_sandbox,
)

REPO = Path(__file__).resolve().parents[3]
WEB = dict(world_args=["/run/fictionet/world.sock", "/run/ca/ca.pem"], world_ca="/run/ca/ca.pem")
BRANCH_ATTACH = "fictionet-attach:dev"


def compose(tmp_path, *args, **kwargs):
    spec = fictionet_sandbox(*args, cache_dir=tmp_path, **kwargs)
    assert spec.type == "docker"
    return yaml.safe_load(Path(spec.config).read_text())


def test_tun_services_and_order(tmp_path):
    c = compose(tmp_path, WEB_WORLD_IMAGE, **WEB)
    world, attach, agent = c["services"]["world"], c["services"]["attach"], c["services"]["default"]
    assert list(c["services"]) == ["world", "attach", "default"]

    # The world: no network, the socket volume and the CA volume.
    assert world["image"] == WEB_WORLD_IMAGE
    assert world["network_mode"] == "none"
    assert world["volumes"] == [
        {"type": "volume", "source": "sock", "target": "/run/fictionet"},
        {"type": "volume", "source": "ca", "target": "/run/ca"},
    ]
    assert world["command"] == WEB["world_args"]

    # Attach: after the world, waits for its socket, healthy once ready.
    assert attach["image"] == ATTACH_IMAGE
    assert attach["depends_on"] == {"world": {"condition": "service_started"}}
    assert attach["command"] == [
        "attach", "--world", "unix:/run/fictionet/world.sock", "--name", "agent", "--type", "tun",
        "--ip-addr=10.0.0.2/24", "--gateway=10.0.0.1", "--dns=10.0.0.1",
        "--no-ip-addr-v6", "--no-gateway-v6", "--no-dns-v6",
        "--ready-file=/run/fictionet/attach.ready", "--world-wait=60",
    ]  # fmt: skip
    assert attach["healthcheck"]["test"] == ["CMD", "/fictionet", "ready", "/run/fictionet/attach.ready"]
    assert attach["network_mode"] == "none"
    assert attach["devices"] == ["/dev/net/tun"]
    assert attach["cap_drop"] == ["ALL"]
    assert set(attach["cap_add"]) == {"NET_ADMIN", "DAC_OVERRIDE"}
    assert attach["volumes"] == [{"type": "volume", "source": "sock", "target": "/run/fictionet"}]

    # The agent: in attach's namespace, after attach is ready, CA read-only.
    assert agent["network_mode"] == "service:attach"
    assert agent["depends_on"] == {"attach": {"condition": "service_healthy"}}
    assert agent["volumes"] == [{"type": "volume", "source": "ca", "target": "/run/ca", "read_only": True}]
    assert agent["environment"]["SSL_CERT_FILE"] == "/run/ca/ca.pem"
    assert agent["environment"]["CURL_CA_BUNDLE"] == "/run/ca/ca.pem"
    assert "NET_ADMIN" not in agent.get("cap_add", [])
    assert agent["cap_drop"] == ["NET_RAW"]
    assert "configs" not in c


def test_agent_never_sees_the_socket(tmp_path):
    for attach in ("tun", "https_proxy", "socks5"):
        c = compose(tmp_path, WEB_WORLD_IMAGE, attach=attach, attach_image=BRANCH_ATTACH, **WEB)
        mounts = c["services"]["default"].get("volumes", [])
        assert not any(m["source"] == "sock" for m in mounts), attach


def test_world_healthcheck(tmp_path):
    c = compose(tmp_path, WEB_WORLD_IMAGE, world_healthcheck=["test", "-S", "/run/fictionet/world.sock"])
    assert c["services"]["world"]["healthcheck"]["test"] == ["CMD", "test", "-S", "/run/fictionet/world.sock"]
    assert c["services"]["attach"]["depends_on"]["world"]["condition"] == "service_healthy"


def test_addresses(tmp_path):
    c = compose(
        tmp_path, WEB_WORLD_IMAGE, name="sandbox1", ip_addr="10.1.0.5/16", gateway="10.1.0.1", dns="10.1.0.1",
        ip_addr_v6="fd00::2/64", gateway_v6="fd00::1", dns_v6=None, mtu=1400, world_wait=5,
    )  # fmt: skip
    args = c["services"]["attach"]["command"]
    assert args[args.index("--name") + 1] == "sandbox1"
    for flag in ("--ip-addr=10.1.0.5/16", "--ip-addr-v6=fd00::2/64", "--gateway-v6=fd00::1", "--no-dns-v6",
                 "--mtu=1400", "--world-wait=5"):  # fmt: skip
        assert flag in args
    assert c["services"]["attach"]["healthcheck"]["retries"] == 35


@pytest.mark.parametrize(
    ("kind", "port", "variables", "scheme"),
    [
        ("https_proxy", 8080, ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"], "http"),
        ("socks5", 1080, ["ALL_PROXY", "all_proxy"], "socks5h"),
    ],
)
def test_proxy(tmp_path, kind, port, variables, scheme):
    c = compose(tmp_path, WEB_WORLD_IMAGE, attach=kind, attach_image=BRANCH_ATTACH, agent_user="1000:1000", **WEB)
    attach, agent = c["services"]["attach"], c["services"]["default"]
    token = (tmp_path / "proxy-token").read_text().strip()
    assert len(token) == 32
    assert oct((tmp_path / "proxy-token").stat().st_mode & 0o777) == "0o600"
    assert c["configs"]["fictionet-token"]["content"].strip() == token

    args = attach["command"]
    assert f"--listen=127.0.0.1:{port}" in args
    assert "--token-file=/run/fictionet-token/token" in args
    assert "--ip-addr=10.0.0.2" in args  # no prefix
    assert not any(a.startswith(("--gateway", "--no-", "--mtu")) for a in args)
    assert "devices" not in attach
    assert attach["cap_add"] == ["DAC_OVERRIDE"]
    assert attach["configs"][0]["target"] == "/run/fictionet-token/token"

    # The agent: proxy variables with the token, the token file, no capabilities.
    for v in variables:
        assert agent["environment"][v] == f"{scheme}://fictionet:{token}@127.0.0.1:{port}"
    assert agent["environment"]["NO_PROXY"] == ""
    assert agent["environment"]["FICTIONET_TOKEN_FILE"] == "/run/fictionet-token/token"
    assert agent["configs"][0]["target"] == "/run/fictionet-token/token"
    assert agent["cap_drop"] == ["ALL"]
    assert agent["user"] == "1000:1000"
    assert agent["network_mode"] == "service:attach"


def test_same_config_same_file(tmp_path):
    a = fictionet_sandbox(WEB_WORLD_IMAGE, cache_dir=tmp_path, **WEB)
    b = fictionet_sandbox(WEB_WORLD_IMAGE, cache_dir=tmp_path, **WEB)
    c = fictionet_sandbox(WEB_WORLD_IMAGE, cache_dir=tmp_path, name="other", **WEB)
    assert a == b and a.config != c.config
    # Proxy specs reuse the token, so they are stable too.
    p1 = fictionet_sandbox(WEB_WORLD_IMAGE, attach="socks5", attach_image=BRANCH_ATTACH, cache_dir=tmp_path)
    p2 = fictionet_sandbox(WEB_WORLD_IMAGE, attach="socks5", attach_image=BRANCH_ATTACH, cache_dir=tmp_path)
    assert p1 == p2


def test_build_and_cargo_example(tmp_path):
    dockerfile = tmp_path / "agent.Dockerfile"
    dockerfile.write_text("FROM debian:bookworm-slim\n")
    c = compose(tmp_path, CargoExample("web_world", crate=REPO, features=["tokio"]),
                agent_image=Build(dockerfile, target="x", args={"A": "1"}))  # fmt: skip
    agent = c["services"]["default"]
    assert agent["build"] == {"context": str(tmp_path), "dockerfile": str(dockerfile), "target": "x", "args": {"A": "1"}}
    assert agent["image"].startswith("inspect-fictionet-agent:")
    world = c["services"]["world"]
    assert world["build"]["context"] == str(REPO)
    generated = Path(world["build"]["dockerfile"])
    text = generated.read_text()
    assert "cargo build --release --features tokio --example web_world" in text
    assert "target" in (generated.parent / "world.Dockerfile.dockerignore").read_text()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (dict(attach="tap"), "attach must be"),
        (dict(attach="socks5"), "has tun only"),
        (dict(attach="https_proxy", attach_image=BRANCH_ATTACH, ip_addr_v6="fd00::2/64"), "takes no ip_addr_v6"),
        (dict(attach="https_proxy", attach_image=BRANCH_ATTACH, ip_addr=None), "needs ip_addr and dns"),
        (dict(dns=None, dns_v6=None), "give dns or dns_v6"),
        (dict(world_ca="/run/fictionet/ca.pem"), "must not be /run/fictionet"),
        (dict(world_ca="//run/fictionet/ca.pem"), "must not be /run/fictionet"),
        (dict(world_ca="/var/../run/fictionet/ca.pem"), "must not be /run/fictionet"),
        (dict(world_ca="/run/./fictionet//x/ca.pem"), "must not be /run/fictionet"),
        (dict(world_ca="/run/ca.pem"), "must not be /run/fictionet"),
        (dict(world_ca="/run/fictionet-token/ca.pem"), "must not be /run/fictionet-token"),
        (dict(world_ca="/ca.pem"), "absolute path"),
        (dict(agent_limits=Limits(memory="lots")), "agent_limits: memory must be"),
        (dict(world_limits=Limits(memory="0")), "world_limits: memory must be"),
        (dict(agent_limits=Limits(cpus=0)), "cpus must be at least 0.001"),
        (dict(agent_limits=Limits(cpus=0.0001)), "cpus must be at least 0.001"),
        (dict(agent_limits=Limits(pids=0)), "pids must be at least 1"),
        (dict(world_ca="ca.pem"), "absolute path"),
        (dict(backend="vm"), "backend must be"),
    ],
)
def test_refuses(tmp_path, kwargs, message):
    with pytest.raises(ValueError, match=message):
        fictionet_sandbox(WEB_WORLD_IMAGE, cache_dir=tmp_path, **kwargs)


def test_missing_dockerfile(tmp_path):
    with pytest.raises(FileNotFoundError):
        fictionet_sandbox(WEB_WORLD_IMAGE, agent_image=Build(tmp_path / "nope"), cache_dir=tmp_path)


def test_k8s_values(tmp_path):
    pytest.importorskip("k8s_sandbox")
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", agent_image="agent:1", agent_user="1000:1000",
                             image_pull_policy="Never", cache_dir=tmp_path, **WEB)  # fmt: skip
    assert spec.type == "k8s"
    assert Path(spec.config.chart) == chart_path()
    v = yaml.safe_load(spec.config.values.read_text())
    assert v["attach"] == {
        "image": ATTACH_IMAGE, "type": "tun", "name": "agent", "worldWait": 60, "ipAddr": "10.0.0.2/24",
        "dns": "10.0.0.1", "gateway": "10.0.0.1", "ipAddrV6": "", "gatewayV6": "", "dnsV6": "",
        "imagePullPolicy": "Never",
    }  # fmt: skip
    svc = v["services"]["default"]
    assert svc["image"] == "agent:1"
    assert svc["args"] == ["tail", "-f", "/dev/null"] and "command" not in svc
    assert svc["world"] == {
        "image": WEB_WORLD_IMAGE, "resources": {"requests": {"memory": "64Mi"}, "limits": {"memory": "2Gi"}},
        "args": WEB["world_args"],
        "imagePullPolicy": "Never",
    }  # fmt: skip
    assert svc["shared"] == [{"name": "ca", "mountPath": "/run/ca"}]
    assert {"name": "SSL_CERT_FILE", "value": "/run/ca/ca.pem"} in svc["env"]
    assert svc["securityContext"]["runAsUser"] == 1000
    assert svc["resources"] == {
        "requests": {"memory": "256Mi", "cpu": "100m"}, "limits": {"memory": "2Gi", "cpu": "1000m"},
    }  # fmt: skip
    assert svc["world"]["resources"] == {"requests": {"memory": "64Mi"}, "limits": {"memory": "2Gi"}}


def test_k8s_refuses_builds(tmp_path):
    pytest.importorskip("k8s_sandbox")
    with pytest.raises(ValueError, match="images only"):
        fictionet_sandbox(CargoExample("web_world", crate=REPO), backend="k8s", cache_dir=tmp_path)


def test_k8s_proxy(tmp_path):
    pytest.importorskip("k8s_sandbox")
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", attach="socks5", attach_image=BRANCH_ATTACH,
                             proxy_port=1081, cache_dir=tmp_path)  # fmt: skip
    a = yaml.safe_load(spec.config.values.read_text())["attach"]
    assert a["type"] == "socks5" and a["port"] == 1081 and a["gateway"] == ""
    assert "ipAddrV6" not in a


@pytest.mark.skipif(not (REPO / "charts" / "fictionet-sandbox").is_dir(), reason="not in the repository")
def test_chart_copy_matches_the_repository():
    """The chart inside the package must be the repository's chart. After
    changing charts/fictionet-sandbox, copy it again:
    cp -r charts/fictionet-sandbox python/inspect_fictionet/src/inspect_fictionet/chart/"""
    ours, theirs = chart_path(), REPO / "charts" / "fictionet-sandbox"
    files = sorted(str(p.relative_to(theirs)) for p in theirs.rglob("*") if p.is_file())
    assert sorted(str(p.relative_to(ours)) for p in ours.rglob("*") if p.is_file()) == files
    match, mismatch, errors = filecmp.cmpfiles(theirs, ours, files, shallow=False)
    assert not mismatch and not errors, (mismatch, errors)


def test_cache_dir_default(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    spec = fictionet_sandbox(WEB_WORLD_IMAGE)
    assert Path(spec.config).is_relative_to(tmp_path / "inspect_fictionet")
    assert os.path.isfile(spec.config)


def test_k8s_values_merge(tmp_path):
    pytest.importorskip("k8s_sandbox")
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", cache_dir=tmp_path,
                             k8s_values={"attach": {"runAsUser": 0}, "networkPolicy": {"enabled": True},
                                         "services": {"default": {"world": {"securityContext": {}}}}})  # fmt: skip
    v = yaml.safe_load(spec.config.values.read_text())
    assert v["attach"]["runAsUser"] == 0 and v["attach"]["type"] == "tun"
    assert v["services"]["default"]["world"] == {
        "image": WEB_WORLD_IMAGE, "resources": {"requests": {"memory": "64Mi"}, "limits": {"memory": "2Gi"}},
        "securityContext": {},
    }  # fmt: skip
    assert v["networkPolicy"] == {"enabled": True}
    with pytest.raises(ValueError, match="k8s_values"):
        fictionet_sandbox(WEB_WORLD_IMAGE, k8s_values={"x": 1}, cache_dir=tmp_path)


def test_read_world_file_refuses_the_agents_sandbox(monkeypatch):
    import asyncio

    from inspect_fictionet import _world

    agent = object()
    monkeypatch.setattr(_world, "sandbox", lambda name=None: agent)
    with pytest.raises(RuntimeError, match="no sandbox named 'world'"):
        asyncio.run(_world.read_world_file("/log"))

    class World:
        async def read_file(self, path, text=True):
            return f"world:{path}"

    world = World()
    monkeypatch.setattr(_world, "sandbox", lambda name=None: world if name == "world" else agent)
    assert asyncio.run(_world.read_world_file("/log")) == "world:/log"


def test_default_limits(tmp_path):
    c = compose(tmp_path, WEB_WORLD_IMAGE)
    world, attach, agent = c["services"]["world"], c["services"]["attach"], c["services"]["default"]
    assert agent["mem_limit"] == agent["memswap_limit"] == "2g"
    assert (agent["cpus"], agent["pids_limit"]) == (1.0, 1024)
    assert (world["mem_limit"], world["memswap_limit"], world["pids_limit"]) == ("2g", "2g", 1024)
    assert "cpus" not in world
    # Inspect's own compose model reads the file too.
    from inspect_ai.util import parse_compose_yaml

    spec = fictionet_sandbox(WEB_WORLD_IMAGE, cache_dir=tmp_path)
    assert parse_compose_yaml(spec.config).services["default"].pids_limit == 1024
    assert (attach["mem_limit"], attach["pids_limit"]) == ("512m", 256)


def test_limits_are_configurable(tmp_path):
    c = compose(tmp_path, WEB_WORLD_IMAGE, agent_limits=Limits(memory="512m", pids=64), world_limits=Limits())
    agent, world = c["services"]["default"], c["services"]["world"]
    assert (agent["mem_limit"], agent["pids_limit"]) == ("512m", 64)
    assert "cpus" not in agent
    assert not {"mem_limit", "memswap_limit", "cpus", "pids_limit"} & world.keys()


def test_k8s_limits(tmp_path):
    pytest.importorskip("k8s_sandbox")
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", cache_dir=tmp_path,
                             agent_limits=Limits(memory="128m", cpus=0.05), world_limits=Limits())  # fmt: skip
    svc = yaml.safe_load(spec.config.values.read_text())["services"]["default"]
    # Requests are never more than the limits.
    assert svc["resources"] == {"requests": {"memory": "128Mi", "cpu": "50m"}, "limits": {"memory": "128Mi", "cpu": "50m"}}
    # An empty map: the chart then gives the world no limits at all.
    assert svc["world"]["resources"] == {}
    assert AGENT_LIMITS == Limits(memory="2g", cpus=1.0, pids=1024)


def test_ca_path_is_normalized(tmp_path):
    c = compose(tmp_path, WEB_WORLD_IMAGE, world_ca="//run//ca/./x/../ca.pem")
    assert c["services"]["world"]["volumes"][1]["target"] == "/run/ca"
    assert c["services"]["default"]["environment"]["SSL_CERT_FILE"] == "/run/ca/ca.pem"


def test_relative_cache_dir_gives_an_absolute_spec(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, cache_dir="cache")
    assert Path(spec.config).is_absolute()
    monkeypatch.chdir("/")
    assert Path(spec.config).is_file()


def test_concurrent_writes_of_the_same_file(tmp_path):
    """Threads that write the same new file at once each use their own
    temporary file, so none fails and every reader sees the whole file."""
    import threading

    from inspect_fictionet import _sandbox

    errors, paths = [], []
    barrier = threading.Barrier(16)

    def write():
        try:
            barrier.wait()
            paths.append(_sandbox._write_once(tmp_path, "x.yaml", "text\n" * 10000))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=write) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(set(paths)) == 1 and paths[0].read_text() == "text\n" * 10000
    assert [p.name for p in paths[0].parent.iterdir()] == ["x.yaml"]


def test_concurrent_token_creation(tmp_path):
    """Processes that make the token at once all get the same, complete one."""
    import multiprocessing

    from inspect_fictionet import _sandbox

    with multiprocessing.get_context("spawn").Pool(8) as pool:
        tokens = pool.map(_sandbox._proxy_token, [tmp_path] * 32)
    assert len(set(tokens)) == 1 and len(tokens[0]) == 32
    assert (tmp_path / "proxy-token").read_text() == tokens[0] + "\n"
    assert [p.name for p in tmp_path.iterdir()] == ["proxy-token"]


def test_a_token_file_without_a_token_is_an_error(tmp_path):
    from inspect_fictionet import _sandbox

    (tmp_path / "proxy-token").write_text("")
    with pytest.raises(RuntimeError, match="does not hold a proxy token"):
        _sandbox._proxy_token(tmp_path)
    (tmp_path / "proxy-token").unlink()
    token = _sandbox._proxy_token(tmp_path)
    assert _sandbox._proxy_token(tmp_path) == token
    assert oct((tmp_path / "proxy-token").stat().st_mode & 0o777) == "0o600"


def test_ca_dir_follows_posix_rules_on_any_host(monkeypatch):
    """The CA's directory is a path in a Linux container, so it is split
    with POSIX rules even where the host's own paths use backslashes."""
    import pathlib

    from inspect_fictionet import _sandbox

    monkeypatch.setattr(_sandbox, "Path", pathlib.PureWindowsPath)
    with pytest.raises(ValueError, match="must not be /run/fictionet"):
        fictionet_sandbox(WEB_WORLD_IMAGE, world_ca="/run/fictionet/ca.pem")


def test_k8s_tiny_cpu_limit(tmp_path):
    pytest.importorskip("k8s_sandbox")
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", cache_dir=tmp_path, agent_limits=Limits(cpus=0.0014))
    res = yaml.safe_load(spec.config.values.read_text())["services"]["default"]["resources"]
    assert res == {"requests": {"cpu": "1m"}, "limits": {"cpu": "1m"}}


@pytest.mark.skipif(
    os.environ.get("INSPECT_FICTIONET_DOCKER") != "1",
    reason="builds images with Docker; set INSPECT_FICTIONET_DOCKER=1",
)
def test_edited_source_is_rebuilt(tmp_path):
    """The image tag follows the build's configuration, not the source, so
    an edit leaves the compose file and the tag as they were. Inspect's
    docker sandbox runs `docker compose build` for each task anyway, and
    BuildKit's cache sees the changed file. This builds the way Inspect
    does, edits the source, builds again, and checks that the image changed."""
    import subprocess

    (tmp_path / "Dockerfile").write_text("FROM busybox:1.36\nCOPY msg.txt /msg.txt\n")
    (tmp_path / "msg.txt").write_text("one\n")
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, agent_image=Build(tmp_path / "Dockerfile"), cache_dir=tmp_path / "cache")
    image = yaml.safe_load(Path(spec.config).read_text())["services"]["default"]["image"]

    def build_and_read() -> str:
        subprocess.run(
            ["docker", "compose", "-p", "inspect-fictionet-rebuild-test", "-f", spec.config, "build", "default"],
            check=True,
            capture_output=True,
        )
        out = subprocess.run(["docker", "run", "--rm", image, "cat", "/msg.txt"], check=True, capture_output=True)
        return out.stdout.decode()

    try:
        assert build_and_read() == "one\n"
        (tmp_path / "msg.txt").write_text("two\n")
        assert fictionet_sandbox(
            WEB_WORLD_IMAGE, agent_image=Build(tmp_path / "Dockerfile"), cache_dir=tmp_path / "cache"
        ) == spec
        assert build_and_read() == "two\n"
    finally:
        subprocess.run(["docker", "rmi", "-f", image], capture_output=True)
