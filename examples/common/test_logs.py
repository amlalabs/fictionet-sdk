"""World logs must remain complete when command output is capped."""
import importlib.util
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


class Logs(unittest.IsolatedAsyncioTestCase):
    def modules(self):
        root = Path(__file__).resolve().parents[1]
        util = ModuleType("inspect_ai.util")
        util.sandbox = lambda name: None
        with patch.dict("sys.modules", {"inspect_ai": ModuleType("inspect_ai"), "inspect_ai.util": util}):
            for example, package in [("fakewiki", "fakewiki_eval"), ("adaptive-web", "adaptive_web_eval")]:
                spec = importlib.util.spec_from_file_location(package, root / example / "src" / package / "world.py")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                yield module

    async def read(self, module, data, *, returned=None, success=True, offset=0):
        async def execute(command):
            if not success or command[0] == "cat":
                return SimpleNamespace(success=success, stdout=data[-10 * 1024**2:].decode(), stderr="read failed")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            return SimpleNamespace(success=result.returncode == 0, stdout=result.stdout, stderr=result.stderr)

        async def read_file(path, *, text):
            self.assertFalse(text)
            return Path(path).read_bytes() if returned is None else returned

        sandbox = SimpleNamespace(exec=execute, read_file=read_file)
        with TemporaryDirectory() as directory:
            log = Path(directory) / "log.jsonl"
            log.write_bytes(data)
            with patch.object(module, "LOG", str(log)), patch.object(module, "sandbox", return_value=sandbox):
                return await module.world_log(offset, finalize=False)

    async def test_failed_finalization_prevents_log_snapshot(self):
        from unittest.mock import AsyncMock
        for module in self.modules():
            world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(
                success=False, stderr="writer failed")), read_file=AsyncMock())
            with patch.object(module, "sandbox", side_effect=lambda name=None: world if name else object()):
                with self.assertRaisesRegex(RuntimeError, "writer failed"):
                    await module.world_log()
            world.exec.assert_awaited_once_with(["touch", "/var/lib/fictionet/finalize"])
            world.read_file.assert_not_awaited()

    async def test_loss_before_offset_is_rejected(self):
        for module in self.modules():
            with self.subTest(module=module.__name__):
                with self.assertRaisesRegex(RuntimeError, "lost log lines"):
                    await self.read(
                        module, b'{"type":"lost","count":3}\n{"type":"http"}\n', offset=1
                    )
                self.assertEqual(
                    await self.read(module, b'{"type":"dns"}\n{"type":"http"}\n', offset=1),
                    [{"type": "http"}],
                )

    async def test_large_log_keeps_early_lines_and_line_offsets(self):
        first = {"type": "http", "path": "/é"}
        data = (json.dumps(first, ensure_ascii=False) + "\n").encode() + b'{"pad":"' + b'x' * (10 * 1024**2 - 11) + b'"}\n'
        for module in self.modules():
            with self.subTest(module=module.__name__):
                entries = await self.read(module, data)
                self.assertEqual(entries[0], first)
                self.assertEqual(len(entries), 2)
                self.assertEqual(await self.read(module, b'{}\n{"n":2}\n', offset=1), [{"n": 2}])

    async def test_lost_marker_before_output_limit_is_rejected(self):
        data = b'{"type":"lost"}\n' + b'{"pad":"' + b'x' * (10 * 1024**2 - 11) + b'"}\n'
        for module in self.modules():
            with self.subTest(module=module.__name__), self.assertRaisesRegex(RuntimeError, "lost log lines"):
                await self.read(module, data)

    async def test_incomplete_reads_are_rejected(self):
        for module in self.modules():
            for data, returned in [(b'{}\n{}\n', b'{}\n'), (b'{}', b'{}')]:
                with self.subTest(module=module.__name__, data=data), self.assertRaisesRegex(RuntimeError, "cannot be scored"):
                    await self.read(module, data, returned=returned)

    async def test_incomplete_snapshot_cannot_pass(self):
        for module in self.modules():
            for data, offset in [(b'', 1), (b'{}\n', 2)]:
                with self.subTest(module=module.__name__, data=data, offset=offset):
                    with self.assertRaisesRegex(RuntimeError, "invalid offset.*cannot be scored"):
                        await self.read(module, data, offset=offset)

    async def test_line_offset_must_be_a_nonnegative_integer(self):
        for module in self.modules():
            for offset in [-1, True, 1.0, "1", None]:
                with self.subTest(module=module.__name__, offset=offset):
                    with self.assertRaisesRegex(RuntimeError, "invalid offset"):
                        await self.read(module, b'{}\n', offset=offset)
            self.assertEqual(await self.read(module, b'{}\n', offset=1), [])

    async def test_empty_log_and_read_failure(self):
        for module in self.modules():
            with self.subTest(module=module.__name__):
                self.assertEqual(await self.read(module, b''), [])
                with self.assertRaisesRegex(RuntimeError, "read failed"):
                    await self.read(module, b'', success=False)




class Finalization(unittest.IsolatedAsyncioTestCase):
    async def test_request_precedes_acknowledgement(self):
        import runpy
        from unittest.mock import AsyncMock
        finalize = runpy.run_path(str(Path(__file__).with_name("finalize.py")))["finalize_world"]
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
        import runpy
        from unittest.mock import AsyncMock
        finalize = runpy.run_path(str(Path(__file__).with_name("finalize.py")))["finalize_world"]
        world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(success=False, stderr="stopped")))
        with self.assertRaisesRegex(RuntimeError, "stopped"):
            await finalize(world, object(), "/state/log.jsonl")
        world.exec = AsyncMock(side_effect=lambda cmd: SimpleNamespace(success=cmd[0] == "touch"))
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            await finalize(world, object(), "/state/log.jsonl", timeout=0.01)

    async def test_agent_alias_is_refused(self):
        import runpy
        finalize = runpy.run_path(str(Path(__file__).with_name("finalize.py")))["finalize_world"]
        agent = object()
        with self.assertRaisesRegex(RuntimeError, "separate"):
            await finalize(agent, agent, "/state/log.jsonl")


if __name__ == "__main__":
    unittest.main()
