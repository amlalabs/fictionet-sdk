"""The docker backend: the compose file for Inspect's docker sandbox, its
resource limits, and the filter for Inspect's working-directory warning."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from ._build import _image_or_build
from ._config import (
    ATTACH_LIMITS,
    Limits,
    _Config,
    _READY_FILE,
    _SOCKET_DIR,
    _TOKEN_FILE,
    _memory_bytes,
)
from ._files import _proxy_token, _write_once


def compose_config(cfg: _Config, cache: Path, token: str | None = None) -> dict[str, Any]:
    """The compose file, as a dict. Builds of a `CargoExample` are written
    into `cache`."""
    world: dict[str, Any] = {**_image_or_build(cfg.world, "world", cache)}
    if cfg.world_args:
        world["command"] = cfg.world_args
    if cfg.world_env:
        world["environment"] = cfg.world_env
    world["network_mode"] = cfg.world_network
    world["volumes"] = [_volume("sock", _SOCKET_DIR)]
    world["volumes"].extend(
        {"type": "bind", "source": source, "target": target}
        for source, target in cfg.world_mounts.items()
    )
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
    if cfg.hostname:
        attach["hostname"] = cfg.hostname
    if cfg.disable_ipv6:
        attach["sysctls"] = {f"net.ipv6.conf.{name}.disable_ipv6": 1 for name in ("all", "default", "lo")}
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


def _docker_size(n: int) -> str:
    # A string, as Inspect's compose model wants: "2g", "512m" or bytes.
    for suffix, size in (("g", 1 << 30), ("m", 1 << 20), ("k", 1 << 10)):
        if n % size == 0:
            return f"{n // size}{suffix}"
    return f"{n}b"


_HEADER = """\
# Generated by inspect_fictionet. Edits are overwritten.
#
#   world   - the world. Agent traffic enters through the socket in
#             the `sock` volume, which only attach also mounts.
#   attach  - fictionet attach. With tun it makes tun0 in its own network
#             namespace. With a proxy type it listens on 127.0.0.1 there.
#   default - the agent, in attach's network namespace. Inspect runs its
#             tools here.
"""


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
