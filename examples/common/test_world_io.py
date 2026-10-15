"""Contracts for the injected private world file adapter."""

import json
import runpy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

WorldFiles = runpy.run_path(str(Path(__file__).with_name("world_io.py")))["WorldFiles"]


class WorldIO(unittest.IsolatedAsyncioTestCase):
    def files(self, data=b'{}\n', *, read_file=None, returned=None, want=None):
        self.commands = []

        async def execute(command):
            self.commands.append(command)
            if command[0] == "sh":
                return SimpleNamespace(success=True, stdout=str(len(data) if want is None else want))
            return SimpleNamespace(success=True, stdout="ok\n")

        async def read(path, *, text):
            self.assertEqual(len(self.commands), 3)
            self.assertEqual(self.commands[:2], [
                ["touch", "/private/finalize"], ["cat", "/private/finalized"],
            ])
            self.assertEqual(path, "/private/log.jsonl.snapshot")
            self.assertFalse(text)
            return data if returned is None else returned

        self.world = SimpleNamespace(exec=AsyncMock(side_effect=execute), read_file=AsyncMock(side_effect=read))
        return WorldFiles(self.world, object(), state="/private/state.json", log="/private/log.jsonl",
                          read_file=read_file)

    async def test_state_uses_exec_and_preserves_errors(self):
        for message in ["cannot read world state", "cannot read the world's state"]:
            with self.subTest(message=message):
                world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
                    success=True, stdout='{"seed":"one"}')))
                files = WorldFiles(world, state="/state", log="/log", state_error=message)
                self.assertEqual(await files.state(), {"seed": "one"})
                world.exec.assert_awaited_once_with(["cat", "/state"])
                world.exec.return_value = SimpleNamespace(success=False, stderr="denied")
                with self.assertRaises(RuntimeError) as raised:
                    await files.state()
                self.assertEqual(str(raised.exception), message + ": denied")
                world.exec.return_value = SimpleNamespace(success=True, stdout="not json")
                with self.assertRaises(json.JSONDecodeError):
                    await files.state()

    async def test_checked_state_reader_needs_no_sandbox_exec(self):
        reader = AsyncMock(return_value='{"seed":"two"}')
        files = WorldFiles(state="/state", log="/log", read_file=reader)
        self.assertEqual(await files.state(), {"seed": "two"})
        reader.assert_awaited_once_with("/state")
        error = RuntimeError("untrusted sandbox")
        reader.side_effect = error
        with self.assertRaises(RuntimeError) as raised:
            await files.state()
        self.assertIs(raised.exception, error)

    async def test_finalized_snapshot_preserves_bytes_for_domain_parser(self):
        data = '{"type":"lost","path":"/é"}\n'.encode()
        self.assertEqual(await self.files(data).finalized_snapshot(), data)
        self.world.read_file.assert_awaited_once_with("/private/log.jsonl.snapshot", text=False)

    async def test_checked_reader_overrides_world_reader(self):
        reader = AsyncMock(return_value=b'{}\n')
        files = self.files(read_file=reader)
        self.assertEqual(await files.finalized_snapshot(), b'{}\n')
        reader.assert_awaited_once_with("/private/log.jsonl.snapshot", text=False)
        self.world.read_file.assert_not_awaited()
        self.assertEqual([command[0] for command in self.commands], ["touch", "cat", "sh"])

    async def test_line_offsets_follow_loss_check(self):
        data = '{"path":"/é"}\n\n{"type":"http"}\n'.encode()
        for offset, expected in [(0, [{"path": "/é"}, {"type": "http"}]), (1, [{"type": "http"}]), (2, [])]:
            with self.subTest(offset=offset):
                self.assertEqual(await self.files(data).log_lines(offset), expected)
        with self.assertRaisesRegex(RuntimeError, "lost log lines"):
            await self.files(b'{"type":"lost"}\n{}\n').log_lines(1)

    async def test_preflight_only_reads_snapshot(self):
        reader = AsyncMock(return_value=b'{}\n')
        files = self.files(read_file=reader)
        self.assertEqual(await files.log_lines(finalize=False), [{}])
        self.assertEqual([command[0] for command in self.commands], ["sh"])
        reader.assert_awaited_once_with("/private/log.jsonl.snapshot", text=False)

    async def test_both_operations_reject_incomplete_transfers(self):
        for method in ["finalized_snapshot", "log_lines"]:
            for data, want in [(b'{}\n', 6), (b'{}\n', 0), (b'{}', 2), ('{}\n', 3)]:
                with self.subTest(method=method, data=data, want=want):
                    files = self.files(returned=data, want=want)
                    with self.assertRaisesRegex(RuntimeError, "cannot be scored"):
                        await getattr(files, method)()

    async def test_finalization_failure_prevents_snapshot(self):
        for method in ["finalized_snapshot", "log_lines"]:
            for alias in [False, True]:
                with self.subTest(method=method, alias=alias):
                    world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
                        success=False, stderr="writer failed")), read_file=AsyncMock())
                    files = WorldFiles(world, world if alias else object(), state="/state", log="/log")
                    with self.assertRaisesRegex(RuntimeError, "separate" if alias else "writer failed"):
                        await getattr(files, method)()
                    if alias:
                        world.exec.assert_not_awaited()
                    else:
                        world.exec.assert_awaited_once_with(["touch", "/finalize"])
                    world.read_file.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
