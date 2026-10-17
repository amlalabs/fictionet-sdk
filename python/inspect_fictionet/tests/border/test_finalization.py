"""Scoring waits for finalization, independently of preflight size polling."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from inspect_fictionet.worlds.border import world


def test_scoring_finalizes_before_reading_without_size_polling(monkeypatch):
    data = b'{"type":"http"}\n'
    commands = []

    async def execute(command):
        commands.append(command)
        return SimpleNamespace(success=True, stdout=str(len(data)) if command[0] == "sh" else "ok\n")

    private = SimpleNamespace(exec=AsyncMock(side_effect=execute), read_file=AsyncMock(return_value=data))
    agent = object()
    monkeypatch.setattr(world, "sandbox", lambda name=None: private if name == world.WORLD else agent)
    monkeypatch.setattr(world, "log_size", AsyncMock(side_effect=AssertionError("preflight polling during scoring")))
    assert asyncio.run(world.world_log()) == [{"type": "http"}]
    assert commands == [
        ["touch", "/var/lib/fictionet/finalize"],
        ["cat", "/var/lib/fictionet/finalized"],
        ["sh", "-c", 'cp "$1" "$2" && wc -c < "$2"', "sh", world.LOG, world.LOG + ".snapshot"],
    ]
    world.log_size.assert_not_awaited()


def test_failed_finalization_refuses_even_a_complete_log_prefix(monkeypatch):
    private = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(success=False, stderr="writer failed")),
                              read_file=AsyncMock(return_value=b'{"type":"http"}\n'))
    monkeypatch.setattr(world, "sandbox", lambda name=None: private if name == world.WORLD else object())
    with pytest.raises(RuntimeError, match="writer failed"):
        asyncio.run(world.world_log())
    private.exec.assert_awaited_once_with(["touch", "/var/lib/fictionet/finalize"])
    private.read_file.assert_not_awaited()
