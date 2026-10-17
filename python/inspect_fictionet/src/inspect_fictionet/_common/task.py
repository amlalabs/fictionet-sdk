"""What every world's task shares: reading the world's private state and
log, the preflight check before the agent starts, and task arguments.

The world shows the agent nothing it could score with. The eval reads two
files from the world's container, which the agent cannot reach: ``state.json``
(what the world serves this run) and ``log.jsonl`` (one line per request,
lookup or handshake). Both are read with ``read_file``, never through command
output, which Inspect cuts to its last 10 MiB without an error.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from inspect_ai.log import transcript
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import sandbox, store

from inspect_fictionet._world import read_world_file

from . import commands
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


def status_probe(url: str) -> list[str]:
    """Curl ``url`` directly, printing the HTTP status and the TLS verification result."""
    return [*commands.CURL_DIRECT, "-sS", "-o", "/dev/null", "-w",
            "%{http_code} verify=%{ssl_verify_result}", url]


@solver
def preflight(keys: Sequence[str], url: str) -> Solver:
    """Check the world before the agent starts, and note where its log stands.

    The world's state must match the sample's metadata on ``keys`` (this
    catches a sample whose metadata did not reach Compose). The agent's
    environment has no proxy variable, and curl, ignoring its configuration
    and proxies, completes a 200 response from ``url`` over trusted TLS. The
    scorer then reads only the log lines that come after these checks.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        del generate
        world = await world_state()
        for key in keys:
            if world[key] != state.metadata[key]:
                msg = f"the world runs {key} {world[key]!r}, the sample wants {state.metadata[key]!r}"
                raise RuntimeError(msg)
        execute = sandbox().exec
        commands.require_no_proxy(await commands.run_async(["env"], runner=execute))
        result = await commands.run_async(status_probe(url), runner=execute)
        if not commands.succeeded(result, stdout="200 verify=0"):
            msg = f"the agent cannot reach the world (rc={result.rc}): {result.stdout} {result.stderr}"
            raise RuntimeError(msg)
        store().set("log_offset", len(await world_log(finalize=False)))
        transcript().info({"world": world, "status": result.stdout.strip()}, source="fictionet")
        return state

    return solve


def split(value: str | Sequence[str], options: Sequence[str], what: str) -> list[str]:
    """The names in a task argument (``-T variants=legitimate,hijack``), as a
    comma-separated string or a list: nonempty, distinct, and each one of ``options``."""
    items = [item.strip() for item in (value.split(",") if isinstance(value, str) else value)]
    if not items or any(item not in options for item in items):
        msg = f"{what}s must be a nonempty list drawn from {list(options)}, not {items}"
        raise ValueError(msg)
    if len(items) != len(set(items)):
        msg = f"{what}s must not repeat: {items}"
        raise ValueError(msg)
    return items
