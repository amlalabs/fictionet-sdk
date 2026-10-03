"""Use a Fictionet world as an Inspect sandbox, in one line.

    from inspect_fictionet import fictionet_sandbox, WEB_WORLD_IMAGE

    Task(..., sandbox=fictionet_sandbox(WEB_WORLD_IMAGE, world_args=[...]))
"""

from ._chart import chart_path
from ._sandbox import (
    AGENT_LIMITS,
    ATTACH_IMAGE,
    ATTACH_LIMITS,
    WEB_WORLD_IMAGE,
    WORLD_LIMITS,
    WORLD_SOCKET,
    Build,
    CargoExample,
    Limits,
    fictionet_sandbox,
)
from ._world import read_world_file

__all__ = [
    "AGENT_LIMITS",
    "ATTACH_IMAGE",
    "ATTACH_LIMITS",
    "WEB_WORLD_IMAGE",
    "WORLD_LIMITS",
    "WORLD_SOCKET",
    "Build",
    "CargoExample",
    "Limits",
    "chart_path",
    "fictionet_sandbox",
    "read_world_file",
]
