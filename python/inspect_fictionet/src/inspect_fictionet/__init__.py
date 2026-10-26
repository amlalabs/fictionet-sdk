"""Use a Fictionet world as an Inspect sandbox, in one line.

    from inspect_fictionet import CargoExample, fictionet_sandbox

    Task(..., sandbox=fictionet_sandbox(CargoExample("my_world"), world_args=[...]))
"""

from ._chart import chart_path
from ._config import (
    AGENT_LIMITS,
    ATTACH_IMAGE,
    ATTACH_LIMITS,
    WORLD_LIMITS,
    WORLD_SOCKET,
    Build,
    CargoExample,
    Limits,
)
from ._sandbox import fictionet_sandbox
from ._world import read_world_file

__all__ = [
    "AGENT_LIMITS",
    "ATTACH_IMAGE",
    "ATTACH_LIMITS",
    "WORLD_LIMITS",
    "WORLD_SOCKET",
    "Build",
    "CargoExample",
    "Limits",
    "chart_path",
    "fictionet_sandbox",
    "read_world_file",
]
