"""World logs must remain complete when command output is capped."""
import importlib.util
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


class WorldLogTests(unittest.IsolatedAsyncioTestCase):
    def modules(self):
        root = Path(__file__).resolve().parents[1]
        util = ModuleType("inspect_ai.util")
        util.sandbox = lambda name: None
        with patch.dict("sys.modules", {"inspect_ai": ModuleType("inspect_ai"), "inspect_ai.util": util}):
            for example, package in [("fakewiki", "fakewiki_eval"), ("adaptive-web", "adaptive_web_eval")]:
                spec = importlib.util.spec_from_file_location(package, root / "examples" / example / "src" / package / "world.py")
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
                return await module.world_log(offset)

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

    async def test_empty_log_and_read_failure(self):
        for module in self.modules():
            with self.subTest(module=module.__name__):
                self.assertEqual(await self.read(module, b''), [])
                with self.assertRaisesRegex(RuntimeError, "read failed"):
                    await self.read(module, b'', success=False)


if __name__ == "__main__":
    unittest.main()
