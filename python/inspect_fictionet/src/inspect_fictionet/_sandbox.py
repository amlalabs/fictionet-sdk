"""Builds the sandbox spec: a compose file for Inspect's docker sandbox, or
Helm values for inspect_k8s_sandbox with the fictionet-sandbox chart."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from inspect_ai.util import SandboxEnvironmentSpec

from ._chart import chart_path
from ._config import (
    AGENT_LIMITS,
    ATTACH_IMAGE,
    ATTACH_LIMITS,
    WORLD_LIMITS,
    AttachType,
    Backend,
    Build,
    CargoExample,
    Limits,
    _Config,
    _READY_FILE,
    _SOCKET_DIR,
    _TOKEN_FILE,
    _container_path,
    _memory_bytes,
)


def fictionet_sandbox(
    world: str | Build | CargoExample,
    *,
    world_args: Sequence[str] = (),
    world_env: Mapping[str, str] | None = None,
    world_ca: str | None = None,
    world_healthcheck: Sequence[str] | None = None,
    agent_image: str | Build = "python:3.12-slim",
    agent_command: Sequence[str] = ("tail", "-f", "/dev/null"),
    agent_env: Mapping[str, str] | None = None,
    agent_user: str | None = None,
    agent_limits: Limits = AGENT_LIMITS,
    world_limits: Limits = WORLD_LIMITS,
    attach: AttachType = "tun",
    name: str = "agent",
    ip_addr: str | None = "10.0.0.2/24",
    gateway: str | None = "10.0.0.1",
    dns: str | None = "10.0.0.1",
    ip_addr_v6: str | None = None,
    gateway_v6: str | None = None,
    dns_v6: str | None = None,
    mtu: int | None = None,
    proxy_port: int | None = None,
    world_wait: int = 60,
    attach_image: str = ATTACH_IMAGE,
    backend: Backend = "docker",
    image_pull_policy: str | None = None,
    k8s_values: Mapping[str, Any] | None = None,
    cache_dir: str | os.PathLike[str] | None = None,
) -> SandboxEnvironmentSpec:
    """A sandbox for Inspect whose only network is a Fictionet world.

    Pass the result as a Task's `sandbox`. Three containers run per sample:
    the world, `fictionet attach`, and the agent, which Inspect knows as the
    `default` sandbox. The world and attach are the sandboxes `world` and
    `attach`, so a scorer can read the world's files with
    `sandbox("world").read_file(...)`.

    Args:
      world: The world: an image, a `Build`, or a `CargoExample`. It must
        listen on `/run/relay/relay.sock` (`WORLD_SOCKET`).
      world_args: The world's arguments (its image's CMD).
      world_env: The world's environment.
      world_ca: Where the world writes its CA certificate, such as
        `/run/ca/ca.pem`. Its directory is shared, read-only, with the
        agent at the same path, and the agent's SSL_CERT_FILE,
        CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS and
        GIT_SSL_CAINFO point at it.
      world_healthcheck: A command that exits 0 once the world is up. It
        runs in the world's container, so the image must have it. Without
        one, attach waits for the world's socket (`world_wait`).
      agent_image: The agent's image, or a `Build`.
      agent_command: The agent's command. It must keep running.
      agent_env: More environment for the agent.
      agent_user: The user the agent runs as, such as `"1000:1000"`.
      agent_limits: The agent's memory, CPU and process limits. Default:
        `AGENT_LIMITS`, 2 GiB, 1 CPU and 1024 processes.
      world_limits: The world's limits. Default: `WORLD_LIMITS`, 2 GiB and
        1024 processes. Attach always gets `ATTACH_LIMITS`.
      attach: `"tun"`, `"http_proxy"` or `"socks5"`. With tun the agent's
        only interface is tun0. With a proxy type the agent has only
        loopback, where attach listens, and gets the proxy variables.
      name: The name attach gives the world for this sandbox.
      ip_addr, gateway, dns, ip_addr_v6, gateway_v6, dns_v6: The sandbox's
        addresses. None turns a setting off. The proxy types use ip_addr
        (without its prefix) and dns only.
      mtu: tun0's MTU. Default: attach's, 1500.
      proxy_port: The proxy's port on 127.0.0.1. Default: 8080 for
        http_proxy, 1080 for socks5.
      world_wait: Seconds attach waits for the world's socket.
      attach_image: The attach image. It must have the binary at
        `/fictionet`.
      backend: `"docker"` for Inspect's docker sandbox, `"k8s"` for
        inspect_k8s_sandbox with the fictionet-sandbox chart.
      image_pull_policy: k8s only: the pods' imagePullPolicy, such as
        `"Never"` for images loaded into kind.
      k8s_values: k8s only: more values for the fictionet-sandbox chart,
        merged key by key over the ones this function writes, such as
        `{"attach": {"runAsUser": 1000}}` or
        `{"services": {"default": {"world": {"securityContext":
        {"readOnlyRootFilesystem": False}}}}}`.
      cache_dir: Where the generated files go. Default: the user's cache
        directory, `inspect_fictionet/` in it.
    """
    cfg = _Config(
        world=world,
        world_args=list(world_args),
        world_env=dict(world_env or {}),
        world_ca=_container_path(world_ca) if world_ca is not None else None,
        world_healthcheck=list(world_healthcheck) if world_healthcheck else None,
        agent_image=agent_image,
        agent_command=list(agent_command),
        agent_env=dict(agent_env or {}),
        agent_user=agent_user,
        agent_limits=agent_limits,
        world_limits=world_limits,
        attach=attach,
        name=name,
        ip_addr=ip_addr,
        gateway=gateway,
        dns=dns,
        ip_addr_v6=ip_addr_v6,
        gateway_v6=gateway_v6,
        dns_v6=dns_v6,
        mtu=mtu,
        proxy_port=proxy_port,
        world_wait=world_wait,
        attach_image=attach_image,
        image_pull_policy=image_pull_policy,
        k8s_values=dict(k8s_values or {}),
    )
    cfg.check()
    # Absolute, so the spec names the same file from whatever directory
    # Inspect later runs in.
    cache = (Path(cache_dir).expanduser() if cache_dir is not None else _default_cache_dir()).resolve()
    if backend == "docker":
        if k8s_values:
            raise ValueError("k8s_values is for backend='k8s' only")
        _quiet_working_dir_warnings()
        return SandboxEnvironmentSpec("docker", str(write_compose(cfg, cache)))
    if backend == "k8s":
        return _k8s_spec(cfg, cache)
    raise ValueError(f"backend must be 'docker' or 'k8s', not {backend!r}")


# Docker


def compose_config(cfg: _Config, cache: Path, token: str | None = None) -> dict[str, Any]:
    """The compose file, as a dict. Builds of a `CargoExample` are written
    into `cache`."""
    world: dict[str, Any] = {**_image_or_build(cfg.world, "world", cache)}
    if cfg.world_args:
        world["command"] = cfg.world_args
    if cfg.world_env:
        world["environment"] = cfg.world_env
    # The world has no network: its only way in is the socket.
    world["network_mode"] = "none"
    world["volumes"] = [_volume("sock", _SOCKET_DIR)]
    if cfg.ca_dir:
        world["volumes"].append(_volume("ca", cfg.ca_dir))
    world |= _compose_limits(cfg.world_limits)
    if cfg.world_healthcheck:
        world["healthcheck"] = {
            "test": ["CMD", *cfg.world_healthcheck],
            "interval": "1s",
            "timeout": "2s",
            "retries": cfg.world_wait,
        }

    attach: dict[str, Any] = {
        "image": cfg.attach_image,
        "entrypoint": ["/fictionet"],
        "command": cfg.attach_args(),
        # The agent joins this network namespace. It starts with only lo.
        "network_mode": "none",
        "volumes": [_volume("sock", _SOCKET_DIR)],
        "depends_on": {"world": {"condition": "service_healthy" if cfg.world_healthcheck else "service_started"}},
        "healthcheck": {
            "test": ["CMD", "/fictionet", "ready", _READY_FILE],
            "interval": "1s",
            "timeout": "2s",
            # Attach writes the ready file within world_wait seconds, or exits.
            "retries": cfg.world_wait + 30,
        },
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        **_compose_limits(ATTACH_LIMITS),
    }
    if cfg.ip_addr_v6 or cfg.gateway_v6 or cfg.dns_v6:
        attach["sysctls"] = {
            "net.ipv6.conf.all.disable_ipv6": 0,
            "net.ipv6.conf.default.disable_ipv6": 0,
        }
    if cfg.proxy:
        # No device and no NET_ADMIN. DAC_OVERRIDE lets root connect to a
        # socket that the world's user owns.
        attach["cap_add"] = ["DAC_OVERRIDE"]
        attach["configs"] = [{"source": "relay-token", "target": _TOKEN_FILE, "mode": 0o444}]
    else:
        attach["cap_add"] = ["NET_ADMIN", "DAC_OVERRIDE"]
        attach["devices"] = ["/dev/net/tun"]

    agent: dict[str, Any] = {**_image_or_build(cfg.agent_image, "agent", cache)}
    agent["command"] = cfg.agent_command
    agent["init"] = True
    agent["network_mode"] = "service:attach"
    agent["depends_on"] = {"attach": {"condition": "service_healthy"}}
    env = cfg.ca_env()
    if cfg.proxy:
        assert token is not None
        env |= cfg.proxy_env(token)
        env["RELAY_TOKEN_FILE"] = _TOKEN_FILE
        agent["configs"] = [{"source": "relay-token", "target": _TOKEN_FILE, "mode": 0o444}]
        # Nothing to configure in the network: no capabilities at all.
        agent["cap_drop"] = ["ALL"]
    else:
        # No raw sockets. The agent never has NET_ADMIN, so it cannot change tun0.
        agent["cap_drop"] = ["NET_RAW"]
    agent["security_opt"] = ["no-new-privileges:true"]
    env |= cfg.agent_env
    if env:
        agent["environment"] = env
    if cfg.ca_dir:
        agent["volumes"] = [_volume("ca", cfg.ca_dir, read_only=True)]
    if cfg.agent_user:
        agent["user"] = cfg.agent_user
    agent |= _compose_limits(cfg.agent_limits)

    # tmpfs, writable by any user: the world may run as any uid, and the
    # images on scratch have no directory there to take an owner from.
    def tmpfs() -> dict[str, Any]:
        return {"driver_opts": {"type": "tmpfs", "device": "tmpfs", "o": "mode=1777"}}

    out: dict[str, Any] = {
        "services": {"world": world, "attach": attach, "default": agent},
        "volumes": {"sock": tmpfs()} | ({"ca": tmpfs()} if cfg.ca_dir else {}),
    }
    if cfg.proxy:
        out["configs"] = {"relay-token": {"content": token + "\n"}}
    return out


def write_compose(cfg: _Config, cache: Path) -> Path:
    """Writes the compose file into `cache` and returns its path. The same
    configuration gives the same path."""
    token = _proxy_token(cache) if cfg.proxy else None
    text = _HEADER + yaml.safe_dump(compose_config(cfg, cache, token), sort_keys=False, width=1000)
    # A proxy type's compose file holds the token: readable by its owner only.
    return _write_once(cache / "compose", "compose.yaml", text, 0o600 if cfg.proxy else 0o644)


def _volume(source: str, target: str, read_only: bool = False) -> dict[str, Any]:
    # The long syntax: a target path is taken as it is, with no ':' to split on.
    return {"type": "volume", "source": source, "target": target, **({"read_only": True} if read_only else {})}


def _compose_limits(limits: Limits) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if limits.memory is not None:
        # memswap_limit is memory and swap together: no swap beyond the limit.
        out["mem_limit"] = out["memswap_limit"] = _docker_size(_memory_bytes(limits.memory, "memory"))
    if limits.cpus is not None:
        out["cpus"] = limits.cpus
    if limits.pids is not None:
        out["pids_limit"] = limits.pids
    return out


def _k8s_resources(limits: Limits, memory_request: int, cpu_request: float | None = None) -> dict[str, Any]:
    """Kubernetes resources: the limits, and requests (what the scheduler
    goes by) of at most `memory_request` bytes and `cpu_request` CPUs, so
    many sandboxes fit on a node."""
    out: dict[str, Any] = {}
    requests: dict[str, Any] = {}
    if limits.memory is not None:
        memory = _memory_bytes(limits.memory, "memory")
        out["memory"] = _k8s_quantity(memory)
        requests["memory"] = _k8s_quantity(min(memory, memory_request))
    if limits.cpus is not None:
        millicores = max(1, round(limits.cpus * 1000))
        out["cpu"] = f"{millicores}m"
        if cpu_request is not None:
            requests["cpu"] = f"{min(millicores, round(cpu_request * 1000))}m"
    return {"requests": requests, "limits": out} if out else {}


def _docker_size(n: int) -> str:
    # A string, as Inspect's compose model wants: "2g", "512m" or bytes.
    for suffix, size in (("g", 1 << 30), ("m", 1 << 20), ("k", 1 << 10)):
        if n % size == 0:
            return f"{n // size}{suffix}"
    return f"{n}b"


def _k8s_quantity(n: int) -> str:
    for suffix, size in (("Gi", 1 << 30), ("Mi", 1 << 20), ("Ki", 1 << 10)):
        if n % size == 0:
            return f"{n // size}{suffix}"
    return str(n)


_HEADER = """\
# Generated by inspect_fictionet. Edits are overwritten.
#
#   world   - the world, with no network. Its only way in is the socket in
#             the `sock` volume, which only attach also mounts.
#   attach  - fictionet attach. With tun it makes tun0 in its own network
#             namespace. With a proxy type it listens on 127.0.0.1 there.
#   default - the agent, in attach's network namespace. Inspect runs its
#             tools here.
"""


def _image_or_build(image: str | Build | CargoExample, role: str, cache: Path) -> dict[str, Any]:
    if isinstance(image, str):
        return {"image": image}
    if isinstance(image, CargoExample):
        image = _cargo_build(image, cache)
    dockerfile = Path(image.dockerfile).resolve()
    if not dockerfile.is_file():
        raise FileNotFoundError(f"{role}: no Dockerfile at {dockerfile}")
    context = Path(image.context).resolve() if image.context is not None else dockerfile.parent
    build: dict[str, Any] = {"context": str(context), "dockerfile": str(dockerfile)}
    if image.target:
        build["target"] = image.target
    if image.args:
        build["args"] = dict(image.args)
    # A fixed tag, so all samples share one image instead of one per project.
    tag = f"inspect-fictionet-{role}:{_short_key(repr(sorted(build.items())))}"
    return {"build": build, "image": tag}


_CARGO_DOCKERFILE = """\
# syntax=docker/dockerfile:1
# Generated by inspect_fictionet: the cargo example {name}, static, on scratch.
FROM {rust_image} AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \\
    --mount=type=cache,target=/src/target,id=inspect-fictionet-{key} \\
    find . -name '*.rs' -exec touch {{}} + \\
    && cargo build --release {cargo_args} --example {name} \\
    && cp target/release/examples/{name} /world

FROM scratch
COPY --from=build /world /world
USER 65532:65532
ENTRYPOINT ["/world"]
"""

_CARGO_DOCKERIGNORE = "target\n**/target\n.git\n.venv\n**/.venv\nnode_modules\n"


def _cargo_build(example: CargoExample, cache: Path) -> Build:
    crate = Path(example.crate).resolve()
    if not (crate / "Cargo.toml").is_file():
        raise FileNotFoundError(f"world: no Cargo.toml in {crate}")
    cargo_args = []
    if example.package:
        cargo_args += ["-p", example.package]
    if example.features:
        cargo_args += ["--features", ",".join(example.features)]
    key = _short_key(f"{crate}|{example.name}|{example.package}")
    text = _CARGO_DOCKERFILE.format(
        name=example.name, rust_image=example.rust_image, key=key, cargo_args=" ".join(cargo_args)
    )
    dockerfile = _write_once(cache / "build", "world.Dockerfile", text)
    # BuildKit reads <Dockerfile>.dockerignore next to the Dockerfile.
    ignore = dockerfile.parent / "world.Dockerfile.dockerignore"
    if not ignore.is_file() or ignore.read_text() != _CARGO_DOCKERIGNORE:
        _write_atomic(ignore, _CARGO_DOCKERIGNORE)
    return Build(dockerfile=dockerfile, context=crate)


class _NoShellFilter(logging.Filter):
    """Drops Inspect's warning that it could not run `pwd` in the world's or
    attach's container. Both images have no shell, so the warning comes
    twice per sample and means nothing."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return not any(
            message.startswith(f"Failed to get working directory for docker container '{s}'")
            for s in ("world", "attach")
        )


def _quiet_working_dir_warnings() -> None:
    logger = logging.getLogger("inspect_ai.util._sandbox.docker.docker")
    if not any(isinstance(f, _NoShellFilter) for f in logger.filters):
        logger.addFilter(_NoShellFilter())


# Kubernetes


def k8s_values(cfg: _Config) -> dict[str, Any]:
    """Values for the fictionet-sandbox chart."""
    if isinstance(cfg.world, (Build, CargoExample)) or isinstance(cfg.agent_image, Build):
        raise ValueError(
            "backend='k8s' takes images only: build the world and the agent, push them where the "
            "cluster pulls from, and pass their names"
        )
    if cfg.world_healthcheck:
        raise ValueError("backend='k8s' takes no world_healthcheck: attach waits for the socket")
    attach: dict[str, Any] = {
        "image": cfg.attach_image,
        "type": cfg.attach,
        "name": cfg.name,
        "worldWait": cfg.world_wait,
        "ipAddr": cfg.ip_addr or "",
        "dns": cfg.dns or "",
    }
    if cfg.proxy:
        attach["gateway"] = ""
        if cfg.proxy_port:
            attach["port"] = cfg.proxy_port
    else:
        attach |= {
            "gateway": cfg.gateway or "",
            "ipAddrV6": cfg.ip_addr_v6 or "",
            "gatewayV6": cfg.gateway_v6 or "",
            "dnsV6": cfg.dns_v6 or "",
        }
        if cfg.mtu is not None:
            attach["mtu"] = cfg.mtu
    # Given whole: the chart takes a service's resources in place of its
    # defaults, so a limit left out here is not limited.
    world: dict[str, Any] = {"image": cfg.world, "resources": _k8s_resources(cfg.world_limits, 64 << 20)}
    if cfg.world_args:
        world["args"] = cfg.world_args
    if cfg.world_env:
        world["env"] = [{"name": k, "value": v} for k, v in cfg.world_env.items()]
    # args, not command: like Compose's command, it keeps the image's entrypoint.
    service: dict[str, Any] = {
        "image": cfg.agent_image,
        "args": cfg.agent_command,
        "resources": _k8s_resources(cfg.agent_limits, 256 << 20, 0.1),
        "world": world,
    }
    env = cfg.ca_env() | cfg.agent_env
    if env:
        service["env"] = [{"name": k, "value": v} for k, v in env.items()]
    if cfg.ca_dir:
        service["shared"] = [{"name": "ca", "mountPath": cfg.ca_dir}]
    if cfg.agent_user:
        user, _, group = cfg.agent_user.partition(":")
        if not user.isdigit() or (group and not group.isdigit()):
            raise ValueError("backend='k8s' takes agent_user as a uid or uid:gid, such as '1000:1000'")
        service["securityContext"] = {
            "runAsNonRoot": user != "0",
            "runAsUser": int(user),
            **({"runAsGroup": int(group)} if group else {}),
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"},
        }
    if cfg.image_pull_policy:
        attach["imagePullPolicy"] = cfg.image_pull_policy
        world["imagePullPolicy"] = cfg.image_pull_policy
        service["imagePullPolicy"] = cfg.image_pull_policy
    # The pod's name is the agent's hostname. Named as Inspect's own
    # agent-env chart names its pods, it says nothing about the harness.
    base = {"global": {"nameOverride": "agent-env"}, "attach": attach, "services": {"default": service}}
    return _merge(base, cfg.k8s_values)


def _merge(base: dict[str, Any], extra: Mapping[str, Any]) -> dict[str, Any]:
    """Merges `extra` into `base`, key by key. Lists and other values replace."""
    out = dict(base)
    for key, value in extra.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def _k8s_spec(cfg: _Config, cache: Path) -> SandboxEnvironmentSpec:
    try:
        from k8s_sandbox import K8sSandboxEnvironmentConfig
    except ImportError as e:
        raise ImportError(
            "backend='k8s' needs inspect-k8s-sandbox: pip install 'inspect-fictionet[k8s]'"
        ) from e
    text = _HEADER_K8S + yaml.safe_dump(k8s_values(cfg), sort_keys=False, width=1000)
    values = _write_once(cache / "k8s", "values.yaml", text)
    return SandboxEnvironmentSpec(
        "k8s", K8sSandboxEnvironmentConfig(chart=str(chart_path()), values=values)
    )


_HEADER_K8S = "# Generated by inspect_fictionet: values for the fictionet-sandbox chart.\n"


# Files


def _default_cache_dir() -> Path:
    from platformdirs import user_cache_dir

    return Path(user_cache_dir("inspect_fictionet"))


def _short_key(text: str) -> str:
    # A cache key, so that different configurations get different files.
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _write_once(directory: Path, filename: str, text: str, mode: int = 0o644) -> Path:
    """Writes `text` to `directory/<key>/filename`, where the key follows
    from the text, and returns the path. Rewrites it only if it differs."""
    path = directory / _short_key(text) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file() or path.read_text() != text:
        _write_atomic(path, text, mode)
    return path


def _write_atomic(path: Path, text: str, mode: int = 0o644) -> None:
    """Writes `text` to a temporary file next to `path`, then renames it
    over `path`. A reader sees the old file or the new one, never part of
    one, and writers in other threads or processes each use their own
    temporary file."""
    tmp = _write_temp(path, text, mode)
    try:
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _write_temp(path: Path, text: str, mode: int) -> Path:
    """Writes `text` to a new temporary file in `path`'s directory, flushed
    to disk, and returns its path."""
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
    except BaseException:
        os.unlink(name)
        raise
    return Path(name)


def _valid_token(text: str) -> bool:
    return len(text) == 32 and all(c in "0123456789abcdef" for c in text)


def _proxy_token(cache: Path) -> str:
    """The proxy token: made once per cache directory, then reused, so the
    compose file stays the same across runs.

    The token is written in full to a temporary file first, then linked to
    `proxy-token`. The link fails if the file is already there, so the
    first process to publish its token wins, and every process reads a
    complete token. A file that does not hold a token (left by an older
    version, or edited by hand) is an error: replacing it here could race
    with another process doing the same, and give the two different
    tokens."""
    path = cache / "proxy-token"
    cache.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        tmp = _write_temp(path, secrets.token_hex(16) + "\n", 0o600)
        try:
            os.link(tmp, path)
        except FileExistsError:  # another process published its token first
            pass
        finally:
            tmp.unlink()
    token = path.read_text().strip()
    if not _valid_token(token):
        raise RuntimeError(f"{path} does not hold a proxy token (32 hex digits); remove it and run again")
    return token
