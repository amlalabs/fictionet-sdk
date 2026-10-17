"""Unit tests for the compose file and the Helm values."""

import os
import shutil
import subprocess
import zipfile
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
WEB = dict(world_args=["/run/relay/relay.sock", "/run/ca/ca.pem"], world_ca="/run/ca/ca.pem")
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
        {"type": "volume", "source": "sock", "target": "/run/relay"},
        {"type": "volume", "source": "ca", "target": "/run/ca"},
    ]
    assert world["command"] == WEB["world_args"]

    # Attach: after the world, waits for its socket, healthy once ready.
    assert attach["image"] == ATTACH_IMAGE
    assert attach["depends_on"] == {"world": {"condition": "service_started"}}
    assert attach["command"] == [
        "attach", "--world", "unix:/run/relay/relay.sock", "--name", "agent", "--type", "tun",
        "--ip-addr=10.0.0.2/24", "--gateway=10.0.0.1", "--dns=10.0.0.1",
        "--no-ip-addr-v6", "--no-gateway-v6", "--no-dns-v6",
        "--ready-file=/run/relay/attach.ready", "--world-wait=60",
    ]  # fmt: skip
    assert attach["healthcheck"]["test"] == ["CMD", "/fictionet", "ready", "/run/relay/attach.ready"]
    assert attach["network_mode"] == "none"
    assert attach["devices"] == ["/dev/net/tun"]
    assert attach["cap_drop"] == ["ALL"]
    assert set(attach["cap_add"]) == {"NET_ADMIN", "DAC_OVERRIDE"}
    assert attach["volumes"] == [{"type": "volume", "source": "sock", "target": "/run/relay"}]

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
    for attach in ("tun", "http_proxy", "socks5"):
        c = compose(tmp_path, WEB_WORLD_IMAGE, attach=attach, attach_image=BRANCH_ATTACH, **WEB)
        mounts = c["services"]["default"].get("volumes", [])
        assert not any(m["source"] == "sock" for m in mounts), attach


def test_world_healthcheck(tmp_path):
    c = compose(tmp_path, WEB_WORLD_IMAGE, world_healthcheck=["test", "-S", "/run/relay/relay.sock"])
    assert c["services"]["world"]["healthcheck"]["test"] == ["CMD", "test", "-S", "/run/relay/relay.sock"]
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
        ("http_proxy", 8080, ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"], "http"),
        ("socks5", 1080, ["ALL_PROXY", "all_proxy"], "socks5h"),
    ],
)
def test_proxy(tmp_path, kind, port, variables, scheme):
    c = compose(tmp_path, WEB_WORLD_IMAGE, attach=kind, attach_image=BRANCH_ATTACH, agent_user="1000:1000", **WEB)
    attach, agent = c["services"]["attach"], c["services"]["default"]
    token = (tmp_path / "proxy-token").read_text().strip()
    assert len(token) == 32
    assert oct((tmp_path / "proxy-token").stat().st_mode & 0o777) == "0o600"
    assert c["configs"]["relay-token"]["content"].strip() == token

    args = attach["command"]
    assert f"--listen=127.0.0.1:{port}" in args
    assert "--token-file=/run/relay-token/token" in args
    assert "--ip-addr=10.0.0.2" in args  # no prefix
    assert not any(a.startswith(("--gateway", "--no-", "--mtu")) for a in args)
    assert "devices" not in attach
    assert attach["cap_add"] == ["DAC_OVERRIDE"]
    assert attach["configs"][0]["target"] == "/run/relay-token/token"

    # The agent: proxy variables with the token, the token file, no capabilities.
    for v in variables:
        assert agent["environment"][v] == f"{scheme}://relay:{token}@127.0.0.1:{port}"
    assert agent["environment"]["NO_PROXY"] == ""
    assert agent["environment"]["RELAY_TOKEN_FILE"] == "/run/relay-token/token"
    assert agent["configs"][0]["target"] == "/run/relay-token/token"
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
    context = tmp_path / "agent"
    context.mkdir()
    dockerfile = context / "agent.Dockerfile"
    dockerfile.write_text("FROM debian:bookworm-slim\n")
    cache = tmp_path / "cache"
    c = compose(cache, CargoExample("web_world", crate=REPO, features=["tokio"]),
                agent_image=Build(dockerfile, target="x", args={"A": "1"}))  # fmt: skip
    agent = c["services"]["default"]
    agent_context = Path(agent["build"]["context"])
    assert agent_context.parent == cache / "context"
    assert not agent_context.is_symlink()
    assert (agent_context / "agent.Dockerfile").read_text() == dockerfile.read_text()
    assert agent["build"] == {"context": str(agent_context), "dockerfile": str(dockerfile), "target": "x", "args": {"A": "1"}}
    assert agent["image"].startswith("inspect-fictionet-agent:")
    world = c["services"]["world"]
    world_context = Path(world["build"]["context"])
    assert world_context.parent == cache / "context"
    assert (world_context / "Cargo.toml").read_bytes() == (REPO / "Cargo.toml").read_bytes()
    assert not (world_context / "target").exists()
    generated = Path(world["build"]["dockerfile"])
    text = generated.read_text()
    assert "cargo build --release --features tokio --example web_world" in text
    assert "target" in (generated.parent / "world.Dockerfile.dockerignore").read_text()


def test_ignored_file_does_not_change_context(tmp_path):
    crate = tmp_path / "crate"
    crate.mkdir()
    (crate / "Cargo.toml").write_text('[package]\nname = "snapshot"\nversion = "0.1.0"\n')
    # CargoExample uses its generated rules, not the crate's .dockerignore.
    (crate / ".dockerignore").write_text("*.rs\n")
    source = crate / "world.rs"
    source.write_text('fn main() { println!("one"); }\n')
    os.utime(source, (1_000_000_000, 1_000_000_000))
    before = source.stat()
    world = CargoExample("world", crate=crate)
    cache = tmp_path / "cache"
    (crate / "nested").mkdir()
    (crate / "nested/keep").write_text("included\n")
    spec = fictionet_sandbox(world, cache_dir=cache)
    service = yaml.safe_load(Path(spec.config).read_text())["services"]["world"]
    snapshot = Path(service["build"]["context"])
    assert snapshot.parent == cache / "context"
    for name in ("target/debug/data", ".git/objects/data", "nested/target/data"):
        path = crate / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("ignored\n")
    assert fictionet_sandbox(world, cache_dir=cache) == spec
    for name in ("target/debug/data", ".git/objects/data", "nested/target/data"):
        (crate / name).write_text("changed and still ignored\n")
    assert fictionet_sandbox(world, cache_dir=cache) == spec
    assert not (snapshot / "target").exists()
    assert not (snapshot / ".git").exists()
    assert not (snapshot / "nested/target").exists()
    assert (snapshot / ".dockerignore").read_bytes() == (crate / ".dockerignore").read_bytes()
    source.write_text('fn main() { println!("two"); }\n')
    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
    updated = fictionet_sandbox(world, cache_dir=cache)
    changed = yaml.safe_load(Path(updated.config).read_text())["services"]["world"]
    assert updated.config != spec.config
    assert changed["image"] == service["image"]
    assert changed["build"]["dockerfile"] == service["build"]["dockerfile"]
    assert changed["build"]["context"] != str(snapshot)
    assert (snapshot / "world.rs").read_text() == 'fn main() { println!("one"); }\n'
    assert (Path(changed["build"]["context"]) / "world.rs").read_bytes() == source.read_bytes()
    assert (source.stat().st_size, source.stat().st_mtime_ns) == (before.st_size, before.st_mtime_ns)


@pytest.mark.parametrize("cache_name", ["cache", "."])
def test_cache_inside_context_requires_ignore(tmp_path, cache_name):
    context = tmp_path / "source"
    context.mkdir()
    dockerfile = context / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
    cache = context / cache_name

    with pytest.raises(ValueError) as error:
        fictionet_sandbox(Build(dockerfile), cache_dir=cache)

    message = str(error.value)
    assert str(cache) in message
    assert str(context) in message
    assert "move cache_dir out of the context" in message
    assert "ignore rules" in message
    assert not (cache / "context").exists()


@pytest.mark.parametrize("rules", ["cache\n", "cache\n!keep\n"])
def test_ignored_cache_inside_context_is_stable(tmp_path, rules):
    context = tmp_path / "source"
    context.mkdir()
    dockerfile = context / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
    (context / ".dockerignore").write_text(rules)
    cache = context / "cache"
    world = Build(dockerfile)

    first = fictionet_sandbox(world, cache_dir=cache)
    service = yaml.safe_load(Path(first.config).read_text())["services"]["world"]
    snapshot = Path(service["build"]["context"])
    assert snapshot.parent == cache / "context"
    assert (snapshot / "Dockerfile").read_bytes() == dockerfile.read_bytes()
    assert (snapshot / ".dockerignore").read_text() == rules
    assert not (snapshot / "cache").exists()
    assert fictionet_sandbox(world, cache_dir=cache) == first
    assert list((cache / "context").iterdir()) == [snapshot]


def test_cache_ignore_exception_is_rejected(tmp_path):
    context = tmp_path / "source"
    context.mkdir()
    dockerfile = context / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
    (context / ".dockerignore").write_text("cache\n!cache/keep\n")
    cache = context / "cache"
    cache.mkdir()
    (cache / "keep").write_text("included by exception\n")

    with pytest.raises(ValueError, match="move cache_dir out of the context"):
        fictionet_sandbox(Build(dockerfile), cache_dir=cache)
    assert not (cache / "context").exists()


def test_context_preserves_permissions_and_symlinks(tmp_path):
    from inspect_fictionet._build import _snapshot_context

    context = tmp_path / "source"
    context.mkdir()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
    script = context / "script"
    script.write_text("#!/bin/sh\necho hello\n")
    script.chmod(0o755)
    (context / "link").symlink_to("script")
    (context / "broken").symlink_to("missing")
    (context / "directory-link").symlink_to("../outside", target_is_directory=True)
    (tmp_path / "outside").mkdir()
    cache = tmp_path / "cache"
    first = _snapshot_context(context, dockerfile, cache)
    assert (first / "script").stat().st_mode & 0o777 == 0o755
    assert (first / "script").stat().st_mtime_ns == script.stat().st_mtime_ns
    for name in ("link", "broken", "directory-link"):
        assert (first / name).is_symlink()
        assert os.readlink(first / name) == os.readlink(context / name)
    script.chmod(0o644)
    second = _snapshot_context(context, dockerfile, cache)
    assert second != first
    assert (second / "script").stat().st_mode & 0o777 == 0o644
    assert (second / "script").read_bytes() == (first / "script").read_bytes()
    (context / "broken").unlink()
    (context / "broken").symlink_to("another-missing-target")
    assert _snapshot_context(context, dockerfile, cache) != second


def test_concurrent_context_snapshots(tmp_path):
    import multiprocessing

    from inspect_fictionet._build import _snapshot_context

    context = tmp_path / "source"
    context.mkdir()
    dockerfile = context / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
    for i in range(16):
        (context / str(i)).write_bytes(bytes([i]) * 65536)
    cache = tmp_path / "cache"
    spawn = multiprocessing.get_context("spawn")
    barrier = spawn.Barrier(8)
    with spawn.Pool(8, initializer=barrier.wait) as pool:
        snapshots = pool.starmap(_snapshot_context, [(context, dockerfile, cache)] * 8)
    assert len(set(snapshots)) == 1
    snapshot = snapshots[0]
    assert list((cache / "context").iterdir()) == [snapshot]
    assert sorted(p.name for p in snapshot.iterdir()) == sorted(p.name for p in context.iterdir())
    for path in context.iterdir():
        assert (snapshot / path.name).read_bytes() == path.read_bytes()


@pytest.mark.parametrize("specific", [False, True])
def test_build_ignore_precedence(tmp_path, specific):
    from inspect_fictionet._build import _snapshot_context

    context = tmp_path / "source"
    context.mkdir()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\nCOPY . /\n")
    (context / ".dockerignore").write_text("root-rule\n.dockerignore\n")
    for name in ("root-rule", "specific-rule"):
        (context / name).write_text(name)
    if specific:
        dockerfile.with_name("Dockerfile.dockerignore").write_text("specific-rule\n")
    snapshot = _snapshot_context(context, dockerfile, tmp_path / "cache")
    assert (snapshot / "root-rule").exists() == specific
    assert (snapshot / "specific-rule").exists() != specific
    assert (snapshot / ".dockerignore").read_bytes() == (context / ".dockerignore").read_bytes()


@pytest.mark.parametrize("patterns,path,excluded", [
    ("*.rs", "src/lib.rs", False),
    ("*.rs", "lib.rs", True),
    ("**/*.rs", "src/deep/lib.rs", True),
    ("**/*.rs", "lib.rs", True),
    ("/src/", "src/deep/lib.rs", True),
    ("src", "nested/src/lib.rs", False),
    ("src/*", "src/deep/lib.rs", True),
    ("src\n!src/**/keep.rs", "src/deep/keep.rs", False),
    ("src\n!src/**/keep.rs\n**/keep.rs", "src/deep/keep.rs", True),
    ("**\n!src", "src/deep/keep.rs", False),
    ("file?.[a-c]", "file1.b", True),
    ("file?.[^a-c]", "file1.b", False),
    ("file?.[^a-c]", "file1.z", True),
    (r"literal\*", "literal*", True),
    (r"literal\*", "literalx", False),
    ("**suffix", "prefixsuffix", True),
    ("**suffix", "prefix\nsuffix", True),
    ("prefix/**", "prefix/file\nname", True),
    ("**", "file\nname", True),
    ("a**/b", "a/deep/b", True),
    ("a**/b", "axxb", False),
    ("\ufeff# comment\n.\n ./src/../keep/ \n", "keep/file", True),
    (" #literal", "#literal", True),
])
def test_dockerignore_patterns(patterns, path, excluded):
    from inspect_fictionet._build import _DockerIgnore

    assert _DockerIgnore(patterns).excludes(Path(path)) == excluded


@pytest.mark.parametrize("pattern", ["!", "[", "[]", "[a-]", "[z-a]", "trailing\\"])
def test_invalid_dockerignore_is_an_error(pattern):
    from inspect_fictionet._build import _DockerIgnore

    with pytest.raises(ValueError, match="invalid Docker ignore pattern"):
        _DockerIgnore(pattern)


@pytest.mark.skipif(
    os.environ.get("INSPECT_FICTIONET_DOCKER") != "1" and "CI" not in os.environ,
    reason="builds images with Docker; set INSPECT_FICTIONET_DOCKER=1",
)
@pytest.mark.parametrize("specific", [False, True])
def test_dockerignore_matches_docker(tmp_path, specific):
    from inspect_fictionet._build import _snapshot_context
    from inspect_fictionet._files import _short_key

    context = tmp_path / "source"
    context.mkdir()
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM busybox:1.36\nCOPY . /ctx\n")
    patterns = (
        "\ufeff# comment\n.\n*.log\n**/temp?\n/root-only/\nskip\n!skip/keep.txt\n"
        "!skip/reopened/\nskip/reopened/private\n**/cache\n!**/cache/keep.txt\n"
        "chars/file[0-2].txt\nchars/neg[^a-c].txt\nliteral\\*.txt\n"
    )
    (context / ".dockerignore").write_text("**" if specific else patterns)
    if specific:
        dockerfile.with_name("Dockerfile.dockerignore").write_text(patterns)
    for name in (
        "root.log", "nested/keep.log", "temp1", "deep/temp2/file", "root-only/file",
        "nested/root-only/keep", "skip/keep.txt", "skip/lost.txt", "skip/reopened/keep",
        "skip/reopened/private/file", "cache/lost", "deep/cache/keep.txt", "chars/file1.txt",
        "chars/file3.txt", "chars/nega.txt", "chars/negz.txt", "literal*.txt", "literalx.txt",
    ):
        path = context / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(name)
    (context / "empty").mkdir()
    (context / "link").symlink_to("nested/keep.log")
    snapshot = _snapshot_context(context, dockerfile, tmp_path / "cache")
    expected = sorted(p.relative_to(snapshot).as_posix() for p in snapshot.rglob("*"))
    images = []
    try:
        for i, directory in enumerate((context, snapshot)):
            image = f"inspect-fictionet-ignore-test:{_short_key(str(tmp_path))}-{i}"
            images.append(image)
            subprocess.run(["docker", "build", "-t", image, "-f", str(dockerfile), str(directory)], check=True)
            result = subprocess.run(
                ["docker", "run", "--rm", "--network=none", image, "find", "/ctx", "-mindepth", "1"],
                check=True, capture_output=True, text=True,
            )
            assert sorted(line.removeprefix("/ctx/") for line in result.stdout.splitlines()) == expected
    finally:
        for image in images:
            subprocess.run(["docker", "rmi", "-f", image], check=True, capture_output=True)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (dict(attach="tap"), "attach must be"),
        (dict(attach="socks5"), "has tun only"),
        (dict(attach="http_proxy", attach_image=BRANCH_ATTACH, ip_addr_v6="fd00::2/64"), "takes no ip_addr_v6"),
        (dict(attach="http_proxy", attach_image=BRANCH_ATTACH, ip_addr=None), "needs ip_addr and dns"),
        (dict(dns=None, dns_v6=None), "give dns or dns_v6"),
        (dict(world_ca="/run/relay/ca.pem"), "must not be /run/relay"),
        (dict(world_ca="//run/relay/ca.pem"), "must not be /run/relay"),
        (dict(world_ca="/var/../run/relay/ca.pem"), "must not be /run/relay"),
        (dict(world_ca="/run/./relay//x/ca.pem"), "must not be /run/relay"),
        (dict(world_ca="/run/ca.pem"), "must not be /run/relay"),
        (dict(world_ca="/run/relay-token/ca.pem"), "must not be /run/relay-token"),
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
    require_k8s()
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", agent_image="agent:1", agent_user="1000:1000",
                             image_pull_policy="Never", cache_dir=tmp_path, **WEB)  # fmt: skip
    assert spec.type == "k8s"
    assert Path(spec.config.chart) == chart_path()
    v = yaml.safe_load(spec.config.values.read_text())
    # The agent's hostname is its pod's name: agent-env-<release>-default-0.
    assert v["global"] == {"nameOverride": "agent-env"}
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
    require_k8s()
    with pytest.raises(ValueError, match="images only"):
        fictionet_sandbox(CargoExample("web_world", crate=REPO), backend="k8s", cache_dir=tmp_path)


def test_k8s_proxy(tmp_path):
    require_k8s()
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", attach="socks5", attach_image=BRANCH_ATTACH,
                             proxy_port=1081, cache_dir=tmp_path)  # fmt: skip
    a = yaml.safe_load(spec.config.values.read_text())["attach"]
    assert a["type"] == "socks5" and a["port"] == 1081 and a["gateway"] == ""
    assert "ipAddrV6" not in a


def test_the_wheel_holds_the_chart(tmp_path):
    """A wheel built from the sdist, as `uv build` makes it, holds every
    file of charts/fictionet-sandbox, unchanged."""
    if not (REPO / "charts" / "fictionet-sandbox").is_dir():
        assert "CI" not in os.environ, "repository chart is required in CI"
        pytest.skip("not in the repository")
    if shutil.which("uv") is None:
        assert "CI" not in os.environ, "uv is required in CI"
        pytest.skip("needs uv")
    package = Path(__file__).resolve().parents[1]
    subprocess.run(["uv", "build", "--quiet", "--out-dir", str(tmp_path), str(package)], check=True)
    [wheel] = tmp_path.glob("*.whl")
    chart = REPO / "charts" / "fictionet-sandbox"
    prefix = "inspect_fictionet/chart/fictionet-sandbox/"
    with zipfile.ZipFile(wheel) as z:
        got = {n[len(prefix) :]: z.read(n) for n in z.namelist() if n.startswith(prefix)}
    want = {str(p.relative_to(chart)): p.read_bytes() for p in chart.rglob("*") if p.is_file()}
    assert got == want


def test_cache_dir_default(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    spec = fictionet_sandbox(WEB_WORLD_IMAGE)
    assert Path(spec.config).is_relative_to(tmp_path / "inspect_fictionet")
    assert os.path.isfile(spec.config)


def test_k8s_values_merge(tmp_path):
    require_k8s()
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
    require_k8s()
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

    from inspect_fictionet import _files

    errors, paths = [], []
    barrier = threading.Barrier(16)

    def write():
        try:
            barrier.wait()
            paths.append(_files._write_once(tmp_path, "x.yaml", "text\n" * 10000))
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

    from inspect_fictionet import _files

    with multiprocessing.get_context("spawn").Pool(8) as pool:
        tokens = pool.map(_files._proxy_token, [tmp_path] * 32)
    assert len(set(tokens)) == 1 and len(tokens[0]) == 32
    assert (tmp_path / "proxy-token").read_text() == tokens[0] + "\n"
    assert [p.name for p in tmp_path.iterdir()] == ["proxy-token"]


def test_a_token_file_without_a_token_is_an_error(tmp_path):
    from inspect_fictionet import _files

    (tmp_path / "proxy-token").write_text("")
    with pytest.raises(RuntimeError, match="does not hold a proxy token"):
        _files._proxy_token(tmp_path)
    (tmp_path / "proxy-token").unlink()
    token = _files._proxy_token(tmp_path)
    assert _files._proxy_token(tmp_path) == token
    assert oct((tmp_path / "proxy-token").stat().st_mode & 0o777) == "0o600"


def test_ca_dir_follows_posix_rules_on_any_host(tmp_path):
    """The CA's directory is a path in a Linux container, so it is split
    with POSIX rules even where the host's own paths use backslashes."""
    c = compose(
        tmp_path,
        WEB_WORLD_IMAGE,
        world_args=["/run/relay/relay.sock", "/run/x\\y/z\\ca.pem"],
        world_ca="/run/x\\y/z\\ca.pem",
    )
    assert c["services"]["world"]["volumes"][1]["target"] == "/run/x\\y"
    assert c["services"]["default"]["volumes"] == [
        {"type": "volume", "source": "ca", "target": "/run/x\\y", "read_only": True}
    ]


def test_k8s_tiny_cpu_limit(tmp_path):
    require_k8s()
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, backend="k8s", cache_dir=tmp_path, agent_limits=Limits(cpus=0.0014))
    res = yaml.safe_load(spec.config.values.read_text())["services"]["default"]["resources"]
    assert res == {"requests": {"cpu": "1m"}, "limits": {"cpu": "1m"}}


@pytest.mark.skipif(
    os.environ.get("INSPECT_FICTIONET_DOCKER") != "1" and "CI" not in os.environ,
    reason="builds images with Docker; set INSPECT_FICTIONET_DOCKER=1",
)
def test_edited_source_is_rebuilt(tmp_path):
    """A same-size, same-mtime edit changes the snapshot and compose path.
    The image tag stays fixed, and Inspect's compose build gets new bytes."""
    context = tmp_path / "source"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM busybox:1.36\nCOPY msg.txt /msg.txt\n")
    source = context / "msg.txt"
    source.write_text("one\n")
    os.utime(source, (1_000_000_000, 1_000_000_000))
    spec = fictionet_sandbox(WEB_WORLD_IMAGE, agent_image=Build(context / "Dockerfile"), cache_dir=tmp_path / "cache")
    image = yaml.safe_load(Path(spec.config).read_text())["services"]["default"]["image"]
    image_ids = []

    def build_and_read() -> str:
        subprocess.run(
            ["docker", "compose", "-p", "inspect-fictionet-rebuild-test", "-f", spec.config, "build", "default"],
            check=True,
            capture_output=True,
        )
        inspected = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image], check=True, capture_output=True, text=True,
        )
        image_ids.append(inspected.stdout.strip())
        out = subprocess.run(["docker", "run", "--rm", image, "cat", "/msg.txt"], check=True, capture_output=True)
        return out.stdout.decode()

    try:
        assert build_and_read() == "one\n"
        source.write_text("two\n")
        os.utime(source, (1_000_000_000, 1_000_000_000))
        previous = spec
        spec = fictionet_sandbox(
            WEB_WORLD_IMAGE, agent_image=Build(context / "Dockerfile"), cache_dir=tmp_path / "cache"
        )
        service = yaml.safe_load(Path(spec.config).read_text())["services"]["default"]
        assert service["image"] == image
        assert build_and_read() == "two\n"
        assert spec.config != previous.config
        assert image_ids[0] != image_ids[1]
    finally:
        if image_ids:
            untagged = [image_id for image_id in dict.fromkeys(image_ids) if image_id != image_ids[-1]]
            subprocess.run(["docker", "rmi", "-f", image, *untagged], check=True, capture_output=True)


@pytest.mark.skipif(
    os.environ.get("INSPECT_FICTIONET_DOCKER") != "1" and "CI" not in os.environ,
    reason="builds images with Docker; set INSPECT_FICTIONET_DOCKER=1",
)
def test_cargo_example_image_is_rebuilt(tmp_path):
    """Run the generated scratch image before and after a source edit,
    reusing the image tag and Cargo target cache with a new snapshot."""
    crate = tmp_path / "crate"
    examples = crate / "examples"
    examples.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "cargo-image-test"\nversion = "0.1.0"\nedition = "2021"\n'
    )
    source = examples / "world.rs"

    def write_source(message):
        source.write_text(f'fn main() {{ println!("{message}"); }}\n')
        # A metadata-preserving edit must reach COPY and the warm Cargo build.
        os.utime(source, (1_000_000_000, 1_000_000_000))

    write_source("one")
    world = CargoExample("world", crate=crate)
    cache = tmp_path / "cache"
    spec = fictionet_sandbox(world, cache_dir=cache)
    image = yaml.safe_load(Path(spec.config).read_text())["services"]["world"]["image"]
    image_ids = []

    def build_and_run():
        subprocess.run(
            ["docker", "compose", "-p", "inspect-fictionet-cargo-test", "-f", spec.config, "build", "world"],
            check=True,
        )
        inspected = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}} {{.Config.User}}", image],
            check=True,
            capture_output=True,
            text=True,
        )
        image_id, user = inspected.stdout.strip().split()
        image_ids.append(image_id)
        assert user == "65532:65532"
        result = subprocess.run(
            ["docker", "run", "--rm", "--network=none", image],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    try:
        assert build_and_run() == "one\n"
        original_id = image_ids[-1]
        for name in ("target/ignored", ".git/ignored"):
            path = crate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("ignored by CargoExample\n")
        assert fictionet_sandbox(world, cache_dir=cache) == spec
        assert build_and_run() == "one\n"
        assert image_ids[-1] == original_id
        write_source("two")
        previous = spec
        spec = fictionet_sandbox(world, cache_dir=cache)
        service = yaml.safe_load(Path(spec.config).read_text())["services"]["world"]
        assert service["image"] == image
        assert build_and_run() == "two\n"
        assert spec.config != previous.config
        assert image_ids[-1] != original_id
    finally:
        if image_ids:
            # Earlier builds lose their tag on rebuild but still need removing.
            untagged = [image_id for image_id in dict.fromkeys(image_ids) if image_id != image_ids[-1]]
            subprocess.run(["docker", "rmi", "-f", image, *untagged], check=True, capture_output=True)


def require_k8s():
    if "CI" in os.environ:
        __import__("k8s_sandbox")
    else:
        pytest.importorskip("k8s_sandbox")


def test_missing_k8s_dependency_fails_in_ci(monkeypatch):
    import builtins

    original = builtins.__import__

    def missing(name, *args, **kwargs):
        if name == "k8s_sandbox":
            raise ModuleNotFoundError("No module named 'k8s_sandbox'")
        return original(name, *args, **kwargs)

    monkeypatch.setenv("CI", "")
    monkeypatch.setattr(builtins, "__import__", missing)
    with pytest.raises(ModuleNotFoundError, match="k8s_sandbox"):
        require_k8s()


@pytest.mark.parametrize("setting,value", [
    ("ip_addr_v6", "fd00::2/64"), ("gateway_v6", "fd00::1"), ("dns_v6", "fd00::1"),
])
def test_ipv6_enables_attach_sysctls(tmp_path, setting, value):
    c = compose(tmp_path, WEB_WORLD_IMAGE, **{setting: value})
    assert c["services"]["attach"]["sysctls"] == {
        "net.ipv6.conf.all.disable_ipv6": 0,
        "net.ipv6.conf.default.disable_ipv6": 0,
    }
    assert "sysctls" not in compose(tmp_path, WEB_WORLD_IMAGE)["services"]["attach"]
