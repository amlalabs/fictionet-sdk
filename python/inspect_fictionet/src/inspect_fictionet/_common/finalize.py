"""Finalize an example world through its private control directory."""

import asyncio
from pathlib import PurePosixPath


async def finalize_world(world, agent, log: str, timeout: float = 20) -> None:
    """Stop world input and exchanges, then require the drained writer's acknowledgement.

    The request cancels the whole run, including its attachment receiver and listener.
    A failed world or writer cannot acknowledge. The world stays alive after shutdown
    so the harness can read its files. Repeated calls read the same acknowledgement.

    Requires a separate world sandbox with exec, touch and cat, and the control
    protocol in extras/src/log.rs. The log's parent must be private to the
    world and writable. The world clears stale control files at startup, watches
    for "finalize", then writes "ok" and a newline to "finalized" after draining
    the writer and checking output failures and lost lines. Await this helper
    before read_log; acknowledgement does not validate the later file transfer.
    """
    if world is agent:
        raise RuntimeError("no separate world sandbox for finalization")
    directory = PurePosixPath(log).parent
    try:
        async with asyncio.timeout(timeout):
            request = await world.exec(["touch", str(directory / "finalize")])
            if not request.success:
                raise RuntimeError(f"cannot finalize world: {request.stderr}")
            while True:
                result = await world.exec(["cat", str(directory / "finalized")])
                if result.success:
                    if result.stdout != "ok\n":
                        raise RuntimeError("world finalization acknowledgement is invalid")
                    return
                await asyncio.sleep(0.05)
    except TimeoutError as error:
        raise RuntimeError("world finalization timed out; this sample cannot be scored") from error
