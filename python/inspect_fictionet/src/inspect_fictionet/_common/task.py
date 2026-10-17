"""What every world's task shares: reading the world's private state and log.

The world shows the agent nothing it could score with. The eval reads two
files from the world's container, which the agent cannot reach: ``state.json``
(what the world serves this run) and ``log.jsonl`` (one line per request,
lookup or handshake). Both are read with ``read_file``, never through command
output, which Inspect cuts to its last 10 MiB without an error.
"""

from __future__ import annotations

import json
from typing import Any

from inspect_ai.util import sandbox

from inspect_fictionet._world import read_world_file

from .finalize import finalize_world
from .logs import read_log

WORLD = "world"
STATE = "/var/lib/fictionet/state.json"
LOG = "/var/lib/fictionet/log.jsonl"


async def world_state() -> dict[str, Any]:
    """The world's ``state.json``."""
    return json.loads(await read_world_file(STATE))


async def world_log(offset: int = 0, *, finalize: bool = True) -> list[dict[str, Any]]:
    """The world's log lines from line ``offset`` on, after finalization.

    Finalization stops the world's exchanges and drains its log writer; a
    snapshot taken without it does not prove the writer has drained. Set
    ``finalize=False`` only for the preflight read, which notes where the log
    stands before the agent starts. Missing bytes, an incomplete last line or a
    lost line prevent scoring.
    """
    world = sandbox(WORLD)
    if finalize:
        await finalize_world(world, sandbox(), LOG)
    return await read_log(world, LOG, offset, read_file=read_world_file)
