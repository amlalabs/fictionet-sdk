"""The sandbox's configuration: its types, defaults and validation."""

from __future__ import annotations

import ipaddress
import os
import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

#: The `fictionet attach` image. It holds the static binary at `/fictionet`.
ATTACH_IMAGE = "ghcr.io/amlalabs/fictionet-attach:4903de4"

#: The `web_world` example as an image: a small world of websites.
WEB_WORLD_IMAGE = "ghcr.io/amlalabs/fictionet-web-world:4903de4"

#: Where the world must listen. The directory is shared with attach only.
#: On Kubernetes the agent shares the pod's network namespace, so it can
#: list the world's socket in /proc/net/unix. The path names nothing.
WORLD_SOCKET = "/run/relay/relay.sock"

AttachType = Literal["tun", "http_proxy", "socks5"]
Backend = Literal["docker", "k8s"]

_SOCKET_DIR = "/run/relay"
_READY_FILE = "/run/relay/attach.ready"
_TOKEN_DIR = "/run/relay-token"
_TOKEN_FILE = f"{_TOKEN_DIR}/token"
_PROXY_USER = "relay"

# Variables that point common clients at one CA file.
_CA_ENV = ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO")


@dataclass(frozen=True)
class Build:
    """An image built from a Dockerfile, for the world or the agent.

    Relative paths are taken from the current directory when
    `fictionet_sandbox` runs. In a task file, pass absolute ones, such as
    `Path(__file__).parent / "agent.Dockerfile"`.

    Each call snapshots the context's contents under Docker's ignore rules.
    Source edits change the snapshot and compose paths, but keep the image tag.
    """

    dockerfile: str | os.PathLike[str]
    """The Dockerfile."""
    context: str | os.PathLike[str] | None = None
    """The build context. Default: the Dockerfile's directory."""
    target: str | None = None
    """The stage to build, for a multi-stage Dockerfile."""
    args: Mapping[str, str] = field(default_factory=dict)
    """Build arguments."""


@dataclass(frozen=True)
class Limits:
    """Resource limits for one container. None leaves that resource
    unlimited.

    On Docker all three apply. On Kubernetes, `memory` and `cpus` become
    the container's `resources.limits`, with smaller requests, and `pids`
    is ignored: Kubernetes has no per-container process limit, so the
    kubelet's `podPidsLimit` sets one for the whole pod.
    """

    memory: str | None = None
    """Memory, with its swap, as a number and a unit: `"512m"` or `"2g"`
    (MiB and GiB). A plain number is bytes."""
    cpus: float | None = None
    """CPUs, such as `1.0` or `0.5`."""
    pids: int | None = None
    """Processes and threads."""


#: The agent's default limits: as much memory and CPU as Inspect's own
#: Kubernetes chart gives a sandbox, and enough processes for builds and
#: test runs, but not for a fork bomb.
AGENT_LIMITS = Limits(memory="2g", cpus=1.0, pids=1024)

#: The world's default limits. The world is trusted, but the agent's
#: traffic drives how much it allocates.
WORLD_LIMITS = Limits(memory="2g", pids=1024)

#: Attach's limits. A few connections' buffers and a handful of threads.
ATTACH_LIMITS = Limits(memory="512m", pids=256)


@dataclass(frozen=True)
class CargoExample:
    """A world built from a cargo example in a user crate.

    The image is generated: the example is built with musl on
    `rust_image`, statically, and copied alone onto `scratch`, where it
    runs as uid 65532. The crate's `target/` and `.git/` are left out of
    the build context by generated ignore rules, which take precedence over
    the crate's `.dockerignore`. Each call snapshots the included contents.
    """

    name: str
    """The example's name, as in `cargo build --example <name>`."""
    crate: str | os.PathLike[str] = "."
    """The crate's directory (the one with Cargo.toml)."""
    features: Sequence[str] = ()
    """Cargo features to turn on."""
    package: str | None = None
    """The package, in a workspace (`cargo build -p`)."""
    rust_image: str = "rust:1.99-alpine"
    """The image the example is built in."""


@dataclass
class _Config:
    world: str | Build | CargoExample
    world_args: list[str]
    world_env: dict[str, str]
    world_ca: str | None
    world_healthcheck: list[str] | None
    agent_image: str | Build
    agent_command: list[str]
    agent_env: dict[str, str]
    agent_user: str | None
    agent_limits: Limits
    world_limits: Limits
    attach: str
    name: str
    ip_addr: str | None
    gateway: str | None
    dns: str | None
    ip_addr_v6: str | None
    gateway_v6: str | None
    dns_v6: str | None
    mtu: int | None
    proxy_port: int | None
    world_wait: int
    attach_image: str
    image_pull_policy: str | None
    k8s_values: dict[str, Any]

    world_network: str = "none"
    world_mounts: dict[str, str] = field(default_factory=dict)
    hostname: str | None = None
    disable_ipv6: bool = False

    @property
    def proxy(self) -> bool:
        return self.attach != "tun"

    @property
    def port(self) -> int:
        if self.proxy_port:
            return self.proxy_port
        return 1080 if self.attach == "socks5" else 8080

    @property
    def ca_dir(self) -> str | None:
        # A path in a Linux container: POSIX rules, whatever the host.
        return posixpath.dirname(self.world_ca) if self.world_ca else None

    def check(self) -> None:
        if self.world_network not in ("none", "bridge"):
            raise ValueError("world_network must be 'none' or 'bridge'")
        if self.disable_ipv6 and (self.ip_addr_v6 or self.gateway_v6 or self.dns_v6):
            raise ValueError("disable_ipv6 conflicts with IPv6 addresses")
        for source, target in self.world_mounts.items():
            if not os.path.isabs(source) or not target.startswith("/"):
                raise ValueError("world_mounts needs absolute host and container paths")
            if any(_overlaps(target, taken) for taken in (_SOCKET_DIR, _TOKEN_DIR, self.ca_dir) if taken):
                raise ValueError("world_mounts must not overlap the socket, token or CA directories")
        if self.attach not in ("tun", "http_proxy", "socks5"):
            raise ValueError(f"attach must be 'tun', 'http_proxy' or 'socks5', not {self.attach!r}")
        if not 1 <= len(self.name.encode()) <= 255:
            raise ValueError("name must be 1 to 255 bytes")
        if not self.dns and not self.dns_v6:
            raise ValueError("give dns or dns_v6: the agent's only DNS server is the world's")
        if self.world_wait < 1:
            raise ValueError("world_wait must be at least 1 second")
        if self.world_ca is not None:
            # world_ca is already in normal form (_container_path).
            if not self.world_ca.startswith("/") or self.ca_dir in ("/", "") or self.world_ca == "/":
                raise ValueError(f"world_ca must be an absolute path to a file in a directory, not {self.world_ca!r}")
            for taken in (_SOCKET_DIR, _TOKEN_DIR):
                if _overlaps(self.ca_dir, taken):
                    raise ValueError(
                        f"world_ca's directory, {self.ca_dir}, must not be {taken}, or be in it or hold it: "
                        "the sandbox mounts it there"
                    )
        for who, limits in (("agent_limits", self.agent_limits), ("world_limits", self.world_limits)):
            if not isinstance(limits, Limits):
                raise TypeError(f"{who} must be a Limits")
            if limits.memory is not None:
                _memory_bytes(limits.memory, who)
            if limits.cpus is not None and not limits.cpus >= 0.001:
                raise ValueError(f"{who}.cpus must be at least 0.001 (one millicore)")
            if limits.pids is not None and limits.pids < 1:
                raise ValueError(f"{who}.pids must be at least 1")
        if self.proxy:
            if self.attach_image == ATTACH_IMAGE:
                raise ValueError(
                    f"attach={self.attach!r} needs an attach image built from this repository "
                    f"(deploy/Dockerfile, target attach): {ATTACH_IMAGE} has tun only. "
                    "Pass it as attach_image."
                )
            if not self.ip_addr or not self.dns:
                raise ValueError(f"attach={self.attach!r} needs ip_addr and dns")
            ipaddress.ip_interface(self.ip_addr)  # fails on a bad address
            for setting in ("ip_addr_v6", "gateway_v6", "dns_v6", "mtu"):
                if getattr(self, setting) is not None:
                    raise ValueError(f"attach={self.attach!r} takes no {setting}: attach makes the packets itself")
        if self.proxy_port is not None and not 1 <= self.proxy_port <= 65535:
            raise ValueError("proxy_port must be 1 to 65535")
        if not self.agent_command:
            raise ValueError("agent_command must not be empty")

    def attach_args(self) -> list[str]:
        """The arguments of `fictionet attach`."""
        args = ["attach", "--world", f"unix:{WORLD_SOCKET}", "--name", self.name, "--type", self.attach]
        if self.proxy:
            assert self.ip_addr and self.dns
            args += [
                f"--listen=127.0.0.1:{self.port}",
                f"--token-file={_TOKEN_FILE}",
                f"--ip-addr={self.ip_addr.split('/')[0]}",
                f"--dns={self.dns}",
            ]
        else:
            for flag, value in (
                ("ip-addr", self.ip_addr),
                ("gateway", self.gateway),
                ("dns", self.dns),
                ("ip-addr-v6", self.ip_addr_v6),
                ("gateway-v6", self.gateway_v6),
                ("dns-v6", self.dns_v6),
            ):
                args.append(f"--{flag}={value}" if value else f"--no-{flag}")
            if self.mtu is not None:
                args.append(f"--mtu={self.mtu}")
        args += [f"--ready-file={_READY_FILE}", f"--world-wait={self.world_wait}"]
        return args

    def proxy_env(self, token: str) -> dict[str, str]:
        """The agent's proxy variables, with the token in the URL."""
        if self.attach == "http_proxy":
            url = f"http://{_PROXY_USER}:{token}@127.0.0.1:{self.port}"
            env = {k: url for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")}
            env["NODE_USE_ENV_PROXY"] = "1"
        else:
            url = f"socks5h://{_PROXY_USER}:{token}@127.0.0.1:{self.port}"
            env = {k: url for k in ("ALL_PROXY", "all_proxy")}
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""
        return env

    def ca_env(self) -> dict[str, str]:
        return {k: self.world_ca for k in _CA_ENV} if self.world_ca else {}


_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}


def _memory_bytes(memory: str, who: str) -> int:
    """`"2g"` as bytes. Units k, m and g are KiB, MiB and GiB, as in Docker."""
    m = re.fullmatch(r"([0-9]+)([kmg]?)b?", str(memory).strip().lower())
    if not m or int(m[1]) == 0:
        raise ValueError(
            f"{who}: memory must be a number with an optional unit k, m or g, such as '2g', not {memory!r}"
        )
    return int(m[1]) * _UNITS[m[2]]


def _container_path(path: str) -> str:
    """A path inside a container in normal form: `..` and `.` resolved,
    and repeated slashes, leading ones too, made one. Docker and Kubernetes
    mount at the normal form, so checks must look at it."""
    if not path.startswith("/"):
        return path
    return "/" + posixpath.normpath(path).lstrip("/")


def _overlaps(a: str, b: str) -> bool:
    """Whether one of two normal directory paths is the other or holds it."""
    return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")
