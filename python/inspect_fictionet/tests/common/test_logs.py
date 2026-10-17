"""World logs must remain complete when command output is capped."""

from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from inspect_fictionet._common.finalize import finalize_world as finalize
from inspect_fictionet._common.logs import parse_log, read_log


class ReadLog(unittest.IsolatedAsyncioTestCase):
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

    async def test_private_accessor_preserves_utf8_and_overrides_the_world_reader(self):
        data = '{"type":"http","path":"/é"}\n'.encode()
        world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
            success=True, stdout=str(len(data)))), read_file=AsyncMock())
        reader = AsyncMock(return_value=data)
        self.assertEqual(await read_log(world, "/log", read_file=reader), [{"type": "http", "path": "/é"}])
        reader.assert_awaited_once_with("/log.snapshot", text=False)
        world.read_file.assert_not_awaited()

    async def test_truncation_growth_partial_lines_and_text_are_rejected(self):
        for want, data in [(6, b'{"type":"a"}\n'), (0, b'{"type":"a"}\n'), (12, b'{"type":"a"}'), (13, '{"type":"a"}\n')]:
            with self.subTest(want=want, data=data):
                world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
                    success=True, stdout=str(want))), read_file=AsyncMock(return_value=data))
                with self.assertRaisesRegex(RuntimeError, "cannot be scored"):
                    await read_log(world, "/log")


class ParseLog(unittest.TestCase):
    def test_malformed_untyped_and_lost_lines_are_rejected(self):
        for text in ['{', '[]', 'null', '{}', '\n', '{"type":1}', '{"type":"lost","count":1}\n']:
            with self.subTest(text=text), self.assertRaisesRegex(RuntimeError, "cannot be scored"):
                parse_log(text)

    def test_typed_lines_parse_in_order(self):
        self.assertEqual(parse_log(''), [])
        self.assertEqual(parse_log('{"type":"dns","path":"/é"}\n{"type":"http"}\n'),
                         [{"type": "dns", "path": "/é"}, {"type": "http"}])


class Finalization(unittest.IsolatedAsyncioTestCase):
    async def test_request_precedes_acknowledgement(self):
        world = SimpleNamespace(exec=AsyncMock(side_effect=[
            SimpleNamespace(success=True),
            SimpleNamespace(success=False),
            SimpleNamespace(success=True, stdout="ok\n"),
        ]))
        await finalize(world, object(), "/state/log.jsonl")
        self.assertEqual([c.args[0] for c in world.exec.await_args_list], [
            ["touch", "/state/finalize"], ["cat", "/state/finalized"], ["cat", "/state/finalized"],
        ])

    async def test_dead_writer_or_world_cannot_acknowledge(self):
        world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(success=False, stderr="stopped")))
        with self.assertRaisesRegex(RuntimeError, "stopped"):
            await finalize(world, object(), "/state/log.jsonl")
        world.exec = AsyncMock(side_effect=lambda cmd: SimpleNamespace(success=cmd[0] == "touch"))
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            await finalize(world, object(), "/state/log.jsonl", timeout=0.01)

    async def test_agent_alias_is_refused(self):
        agent = object()
        with self.assertRaisesRegex(RuntimeError, "separate"):
            await finalize(agent, agent, "/state/log.jsonl")


if __name__ == "__main__":
    unittest.main()
