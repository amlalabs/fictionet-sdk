"""Finalized Border logs apply byte offsets after checking the whole transfer."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from border_eval import world


@pytest.mark.parametrize("offset_kind", ["start", "episode", "end", "past_end"])
def test_finalized_byte_offsets(offset_kind, monkeypatch):
    preflight = '{"type":"http","path":"/é"}\n'.encode()
    episode = b'{"type":"dns"}\n'
    data = preflight + episode
    offset = {"start": 0, "episode": len(preflight), "end": len(data), "past_end": len(data) + 1}[offset_kind]
    private = SimpleNamespace(exec=AsyncMock(side_effect=lambda command: SimpleNamespace(
        success=True, stdout=str(len(data)) if command[0] == "sh" else "ok\n")),
                              read_file=AsyncMock(return_value=data))
    monkeypatch.setattr(world, "sandbox", lambda name=None: private if name else object())
    if offset_kind == "past_end":
        with pytest.raises(RuntimeError, match="offset"):
            asyncio.run(world.world_log(offset))
    else:
        expected = [] if offset_kind == "end" else [{"type": "dns"}]
        if offset_kind == "start":
            expected.insert(0, {"type": "http", "path": "/é"})
        assert asyncio.run(world.world_log(offset)) == expected
