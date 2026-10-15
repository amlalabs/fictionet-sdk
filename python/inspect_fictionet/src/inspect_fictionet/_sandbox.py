"""The sandbox factory: builds the validated configuration and hands it to
the docker or k8s backend."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from inspect_ai.util import SandboxEnvironmentSpec

from ._config import (
    AGENT_LIMITS,
    ATTACH_IMAGE,
    WORLD_LIMITS,
    AttachType,
    Backend,
    Build,
    CargoExample,
    Limits,
    _Config,
    _container_path,
)
from ._docker import _quiet_working_dir_warnings, write_compose
from ._files import _default_cache_dir
from ._k8s import _k8s_spec


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
      cache_dir: Where generated files and build context snapshots go.
        Default: the user's cache directory, `inspect_fictionet/` in it.
        Snapshots accumulate; remove them only when no builds or saved
        compose files need them. A cache inside a build context is an error
        unless the effective ignore rules exclude it and everything under it.
        Move cache_dir out of the context, or add it to those rules.
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
