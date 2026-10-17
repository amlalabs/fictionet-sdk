"""Compose private world file access without depending on an eval framework."""

import json

from .finalize import finalize_world
from .logs import read_log


class WorldFiles:
    """Use injected sandbox handles and an optional checked file reader.

    The world supplies exec and, unless read_file is given, read_file. State-only
    access through a checked reader needs no sandbox handles. The caller owns
    sandbox selection, domain parsing and error conversion. Log operations for
    the same path must be serialized, as they share a snapshot file.
    """

    def __init__(self, world=None, agent=None, *, state: str, log: str,
                 read_file=None, state_error: str = "cannot read world state"):
        self.world = world
        self.agent = agent
        self.state_path = state
        self.log_path = log
        self.read_file = read_file
        self.state_error = state_error

    async def state(self) -> dict:
        """Parse state through the checked reader, or through world exec."""
        if self.read_file is not None:
            data = await self.read_file(self.state_path)
        else:
            result = await self.world.exec(["cat", self.state_path])
            if not result.success:
                raise RuntimeError(f"{self.state_error}: {result.stderr}")
            data = result.stdout
        return json.loads(data)

    async def _snapshot(self, *, finalize: bool, raw: bool, offset: int = 0):
        if finalize:
            await finalize_world(self.world, self.agent, self.log_path)
        return await read_log(self.world, self.log_path, offset, raw=raw, read_file=self.read_file)

    async def finalized_snapshot(self) -> bytes:
        """Finalize and check the complete transfer, leaving domain parsing to the caller.

        The caller must check for lost lines before scoring. Byte offsets, if
        needed, apply to these bytes only after the complete transfer is checked.
        """
        return await self._snapshot(finalize=True, raw=True)

    async def log_lines(self, offset: int = 0, *, finalize: bool = True) -> list[dict]:
        """Check every entry for loss, then apply a line offset.

        Set finalize=False only for preflight reads. A complete live snapshot
        does not prove that the writer has drained.
        """
        return await self._snapshot(finalize=finalize, raw=False, offset=offset)
