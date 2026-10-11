"""Raw log reads keep bytes intact and reject incomplete transfers."""

import runpy
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

read_log = runpy.run_path(str(Path(__file__).with_name("logs.py")))["read_log"]


class RawLogs(unittest.IsolatedAsyncioTestCase):
    async def test_live_log_growth_after_count_reads_complete_snapshot(self):
        data = b'{"type":"http"}\n'
        for private_accessor in [False, True]:
            with self.subTest(private_accessor=private_accessor), TemporaryDirectory() as directory:
                log = Path(directory) / "world log.jsonl"
                log.write_bytes(data)

                async def execute(command):
                    result = subprocess.run(command, capture_output=True, text=True, check=False)
                    with log.open("ab") as live:
                        live.write(b'{"type":"dns"}\n')
                    return SimpleNamespace(success=result.returncode == 0,
                                           stdout=result.stdout, stderr=result.stderr)

                async def read_file(path, *, text):
                    self.assertFalse(text)
                    return Path(path).read_bytes()

                reader = AsyncMock(side_effect=read_file)
                world = SimpleNamespace(exec=execute, read_file=AsyncMock(side_effect=read_file))
                self.assertEqual(await read_log(
                    world, str(log), read_file=reader if private_accessor else None,
                ), [{"type": "http"}])
                self.assertEqual(log.read_bytes(), data + b'{"type":"dns"}\n')
                accessor = reader if private_accessor else world.read_file
                accessor.assert_awaited_once_with(str(log) + ".snapshot", text=False)
                if private_accessor:
                    world.read_file.assert_not_awaited()

    async def test_raw_read_preserves_utf8_and_uses_private_accessor(self):
        data = '{"path":"/é"}\n{"type":"http"}\n'.encode()
        world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
            success=True, stdout=str(len(data)))), read_file=AsyncMock())
        reader = AsyncMock(return_value=data)
        self.assertEqual(await read_log(world, "/log", raw=True, read_file=reader), data)
        reader.assert_awaited_once_with("/log.snapshot", text=False)
        world.read_file.assert_not_awaited()

    async def test_raw_read_rejects_truncation_growth_partial_lines_and_text(self):
        for want, data in [(6, b'{}\n'), (0, b'{}\n'), (2, b'{}'), (3, '{}\n')]:
            with self.subTest(want=want, data=data):
                world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
                    success=True, stdout=str(want))), read_file=AsyncMock(return_value=data))
                with self.assertRaisesRegex(RuntimeError, "cannot be scored"):
                    await read_log(world, "/log", raw=True)
