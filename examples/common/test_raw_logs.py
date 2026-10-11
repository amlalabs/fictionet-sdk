"""Raw log reads keep bytes intact and reject incomplete transfers."""

import runpy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

read_log = runpy.run_path(str(Path(__file__).with_name("logs.py")))["read_log"]


class RawLogs(unittest.IsolatedAsyncioTestCase):
    async def test_raw_read_preserves_utf8_and_uses_private_accessor(self):
        data = '{"path":"/é"}\n{"type":"http"}\n'.encode()
        world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
            success=True, stdout=str(len(data)))), read_file=AsyncMock())
        reader = AsyncMock(return_value=data)
        self.assertEqual(await read_log(world, "/log", raw=True, read_file=reader), data)
        reader.assert_awaited_once_with("/log", text=False)
        world.read_file.assert_not_awaited()

    async def test_raw_read_rejects_truncation_growth_partial_lines_and_text(self):
        for want, data in [(6, b'{}\n'), (0, b'{}\n'), (2, b'{}'), (3, '{}\n')]:
            with self.subTest(want=want, data=data):
                world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
                    success=True, stdout=str(want))), read_file=AsyncMock(return_value=data))
                with self.assertRaisesRegex(RuntimeError, "cannot be scored"):
                    await read_log(world, "/log", raw=True)
