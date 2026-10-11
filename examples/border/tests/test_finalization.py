"""Scoring waits for finalization, independently of preflight size polling."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from border_eval import world


def test_scoring_finalizes_before_reading_without_size_polling(monkeypatch):
    data = b'{"type":"http"}\n'
    finalized = AsyncMock()

    async def execute(command):
        finalized.assert_awaited_once()
        return SimpleNamespace(success=True, stdout=str(len(data)) if command[0] == "sh" else "")

    private = SimpleNamespace(exec=AsyncMock(side_effect=execute), read_file=AsyncMock(return_value=data))
    agent = object()
    monkeypatch.setattr(world, "sandbox", lambda name=None: private if name == world.WORLD else agent)
    monkeypatch.setattr(world, "finalize_world", finalized)
    monkeypatch.setattr(world, "log_size", AsyncMock(side_effect=AssertionError("preflight polling during scoring")))
    assert asyncio.run(world.world_log()) == [{"type": "http"}]
    finalized.assert_awaited_once_with(private, agent, world.LOG)
    world.log_size.assert_not_awaited()


def test_failed_finalization_refuses_even_a_complete_log_prefix(monkeypatch):
    private = SimpleNamespace(exec=AsyncMock(), read_file=AsyncMock(return_value=b'{"type":"http"}\n'))
    monkeypatch.setattr(world, "sandbox", lambda name=None: private if name == world.WORLD else object())
    monkeypatch.setattr(world, "finalize_world", AsyncMock(side_effect=RuntimeError("writer failed")))
    with pytest.raises(RuntimeError, match="writer failed"):
        asyncio.run(world.world_log())
    private.exec.assert_not_awaited()
    private.read_file.assert_not_awaited()
