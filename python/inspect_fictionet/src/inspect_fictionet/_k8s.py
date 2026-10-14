"""The k8s backend: values for the fictionet-sandbox chart, Kubernetes
resources, and the spec for inspect_k8s_sandbox."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from inspect_ai.util import SandboxEnvironmentSpec

from ._chart import chart_path
from ._config import Build, CargoExample, Limits, _Config, _memory_bytes
from ._files import _write_once


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


def _k8s_quantity(n: int) -> str:
    for suffix, size in (("Gi", 1 << 30), ("Mi", 1 << 20), ("Ki", 1 << 10)):
        if n % size == 0:
            return f"{n // size}{suffix}"
    return str(n)


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
