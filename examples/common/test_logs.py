"""The example graders reject incomplete logs, including before an offset."""
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


class Logs(unittest.IsolatedAsyncioTestCase):
    async def test_loss_before_offset_is_rejected(self):
        for folder, package in [("fakewiki", "fakewiki_eval"), ("adaptive-web", "adaptive_web_eval")]:
            with self.subTest(world=folder):
                utility = types.ModuleType("inspect_ai.util")
                utility.sandbox = lambda _: client
                client = types.SimpleNamespace(exec=AsyncMock(return_value=types.SimpleNamespace(
                    success=True, stdout='{"type":"lost","count":3}\n{"type":"http"}\n'
                )))
                path = Path(__file__).resolve().parents[1] / folder / "src" / package / "world.py"
                spec = importlib.util.spec_from_file_location("world_under_test", path)
                module = importlib.util.module_from_spec(spec)
                with patch.dict(sys.modules, {"inspect_ai.util": utility}):
                    spec.loader.exec_module(module)
                with self.assertRaisesRegex(RuntimeError, "lost log lines"):
                    await module.world_log(offset=1)
                client.exec.return_value.stdout = '{"type":"dns"}\n{"type":"http"}\n'
                self.assertEqual(await module.world_log(offset=1), [{"type": "http"}])


if __name__ == "__main__":
    unittest.main()
