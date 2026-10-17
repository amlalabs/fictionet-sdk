"""Every world reads its private state and log the same checked way."""

import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from inspect_fictionet._common import task


def observation(rc=0, out="", err=""):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class WorldState(unittest.IsolatedAsyncioTestCase):
    async def test_state_comes_through_the_checked_reader(self):
        reader = AsyncMock(return_value='{"seed":"two"}')
        with patch.object(task, "read_world_file", reader):
            self.assertEqual(await task.world_state(), {"seed": "two"})
        reader.assert_awaited_once_with(task.STATE)
        error = RuntimeError("untrusted sandbox")
        with patch.object(task, "read_world_file", AsyncMock(side_effect=error)):
            with self.assertRaises(RuntimeError) as raised:
                await task.world_state()
        self.assertIs(raised.exception, error)
        with patch.object(task, "read_world_file", AsyncMock(return_value="not json")):
            with self.assertRaises(json.JSONDecodeError):
                await task.world_state()


class WorldLog(unittest.IsolatedAsyncioTestCase):
    """Snapshots run the real cp and wc against a log in a temporary directory."""

    async def read(self, data, *, finalize=False, offset=0, returned=None, success=True):
        self.commands = []

        async def execute(command):
            self.commands.append(command)
            if not success:
                return SimpleNamespace(success=False, stdout="", stderr="read failed")
            if command[0] in ("touch", "cat"):
                return SimpleNamespace(success=True, stdout="ok\n")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            return SimpleNamespace(success=result.returncode == 0, stdout=result.stdout, stderr=result.stderr)

        async def read_file(path, *, text=True):
            self.assertFalse(text)
            return Path(path).read_bytes() if returned is None else returned

        world = SimpleNamespace(exec=AsyncMock(side_effect=execute))
        self.reader = AsyncMock(side_effect=read_file)
        with TemporaryDirectory() as directory:
            self.log = str(Path(directory) / "log.jsonl")
            Path(self.log).write_bytes(data)
            with patch.object(task, "LOG", self.log), \
                 patch.object(task, "sandbox", lambda name=None: world if name else object()), \
                 patch.object(task, "read_world_file", self.reader):
                return await task.world_log(offset, finalize=finalize)

    async def test_scoring_finalizes_then_snapshots(self):
        self.assertEqual(await self.read(b'{"type":"http"}\n', finalize=True), [{"type": "http"}])
        directory = str(Path(self.log).parent)
        self.assertEqual(self.commands, [
            ["touch", directory + "/finalize"],
            ["cat", directory + "/finalized"],
            ["sh", "-c", 'cp "$1" "$2" && wc -c < "$2"', "sh", self.log, self.log + ".snapshot"],
        ])
        self.reader.assert_awaited_once_with(self.log + ".snapshot", text=False)

    async def test_preflight_only_snapshots(self):
        self.assertEqual(await self.read(b'{"type":"http"}\n'), [{"type": "http"}])
        self.assertEqual([command[0] for command in self.commands], ["sh"])

    async def test_failed_finalization_prevents_the_snapshot(self):
        world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(success=False, stderr="writer failed")))
        reader = AsyncMock()
        with patch.object(task, "sandbox", lambda name=None: world if name else object()), \
             patch.object(task, "read_world_file", reader):
            with self.assertRaisesRegex(RuntimeError, "writer failed"):
                await task.world_log()
        world.exec.assert_awaited_once_with(["touch", "/var/lib/fictionet/finalize"])
        reader.assert_not_awaited()

    async def test_the_agents_sandbox_cannot_stand_in_for_the_world(self):
        agent = SimpleNamespace(exec=AsyncMock())
        with patch.object(task, "sandbox", lambda name=None: agent):
            with self.assertRaisesRegex(RuntimeError, "separate"):
                await task.world_log()
        agent.exec.assert_not_awaited()

    async def test_loss_before_offset_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "lost 3 log lines"):
            await self.read(b'{"type":"lost","count":3}\n{"type":"http"}\n', offset=1)
        self.assertEqual(await self.read(b'{"type":"dns"}\n{"type":"http"}\n', offset=1), [{"type": "http"}])

    async def test_large_log_keeps_early_lines_and_line_offsets(self):
        first = {"type": "http", "path": "/é"}
        data = (json.dumps(first, ensure_ascii=False) + "\n").encode() + b'{"type":"pad","x":"' + b'x' * (10 * 1024**2) + b'"}\n'
        entries = await self.read(data)
        self.assertEqual(entries[0], first)
        self.assertEqual(len(entries), 2)
        self.assertEqual(await self.read(b'{"type":"a"}\n{"type":"b"}\n', offset=1), [{"type": "b"}])

    async def test_lost_marker_before_output_limit_is_rejected(self):
        data = b'{"type":"lost"}\n' + b'{"type":"pad","x":"' + b'x' * (10 * 1024**2) + b'"}\n'
        with self.assertRaisesRegex(RuntimeError, "lost"):
            await self.read(data)

    async def test_incomplete_reads_are_rejected(self):
        for data, returned in [(b'{"type":"a"}\n{"type":"b"}\n', b'{"type":"a"}\n'), (b'{"type":"a"}', b'{"type":"a"}')]:
            with self.subTest(data=data), self.assertRaisesRegex(RuntimeError, "cannot be scored"):
                await self.read(data, returned=returned)

    async def test_offsets_past_the_end_cannot_pass(self):
        for data, offset in [(b'', 1), (b'{"type":"a"}\n', 2)]:
            with self.subTest(data=data, offset=offset):
                with self.assertRaisesRegex(RuntimeError, "invalid offset.*cannot be scored"):
                    await self.read(data, offset=offset)

    async def test_line_offset_must_be_a_nonnegative_integer(self):
        for offset in [-1, True, 1.0, "1", None]:
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(RuntimeError, "invalid offset"):
                    await self.read(b'{"type":"a"}\n', offset=offset)
        self.assertEqual(await self.read(b'{"type":"a"}\n', offset=1), [])

    async def test_empty_log_and_read_failure(self):
        self.assertEqual(await self.read(b''), [])
        with self.assertRaisesRegex(RuntimeError, "read failed"):
            await self.read(b'', success=False)


class Preflight(unittest.IsolatedAsyncioTestCase):
    STATUS = ["curl", "-q", "--noproxy", "*", "-sS", "-o", "/dev/null", "-w",
              "%{http_code} verify=%{ssl_verify_result}", "https://status.example/"]

    def setUp(self):
        self.replies = {"env": observation(out="PATH=/usr/bin\nNAME=proxy text\n"), "status": observation(out="200 verify=0")}
        self.world = {"variant": "control", "task": "read", "hosts": ["a.example"]}
        self.state = SimpleNamespace(metadata={"variant": "control", "task": "read"})
        self.calls, self.stored = [], {}
        self.log = AsyncMock(return_value=[{"type": "dns"}] * 3)
        self.info = Mock()

    async def run_preflight(self, keys=("variant", "task")):
        async def execute(argv, **kwargs):
            self.calls.append(argv)
            return self.replies["env" if argv == ["env"] else "status"]

        with patch.object(task, "sandbox", lambda name=None: SimpleNamespace(exec=execute)), \
             patch.object(task, "world_state", AsyncMock(return_value=self.world)), \
             patch.object(task, "world_log", self.log), \
             patch.object(task, "store", lambda: SimpleNamespace(set=self.stored.__setitem__)), \
             patch.object(task, "transcript", lambda: SimpleNamespace(info=self.info)):
            return await task.preflight(keys, "https://status.example/")(self.state, None)

    async def test_direct_200_records_the_log_offset(self):
        self.assertIs(await self.run_preflight(), self.state)
        self.assertEqual(self.calls, [["env"], self.STATUS])
        self.assertEqual(self.stored, {"log_offset": 3})
        self.log.assert_awaited_once_with(finalize=False)
        self.info.assert_called_once_with({"world": self.world, "status": "200 verify=0"}, source="fictionet")

    async def test_the_world_must_run_the_sample(self):
        for key in ("variant", "task"):
            with self.subTest(key=key):
                self.world[key] = "other"
                with self.assertRaisesRegex(RuntimeError, f"the world runs {key} 'other'"):
                    await self.run_preflight()
                self.world[key] = self.state.metadata[key]
        self.assertEqual(self.calls, [])
        self.world["variant"] = "other"
        self.assertIs(await self.run_preflight(keys=("task",)), self.state)

    async def test_failed_status_transfer(self):
        for rc, out in [(28, "200"), (28, "200 verify=0"), (18, "200 verify=0"), (0, "200 verify=60"), (0, "500 verify=0")]:
            with self.subTest(rc=rc, out=out):
                self.replies["status"] = observation(rc, out, "curl failed")
                with self.assertRaisesRegex(RuntimeError, "the agent cannot reach the world"):
                    await self.run_preflight()
        self.log.assert_not_awaited()

    async def test_proxy_variables(self):
        for name in ("http_proxy", "HTTPS_PROXY", "NO_PROXY", "SomeProxySetting"):
            with self.subTest(name=name):
                self.replies["env"] = observation(out=f"PATH=/usr/bin\n{name}=http://proxy:8080\n")
                with self.assertRaisesRegex(RuntimeError, name):
                    await self.run_preflight()
                self.assertEqual(self.calls, [["env"]])
                self.calls.clear()
        self.log.assert_not_awaited()

    async def test_env_failure(self):
        for rc, out in [(1, ""), (127, ""), (0, "(no proxy variables)"), (0, "PATH=/usr/bin\nPATH=/bin\n")]:
            with self.subTest(rc=rc, out=out):
                self.replies["env"] = observation(rc, out, "env failed")
                with self.assertRaisesRegex(RuntimeError, "env observation"):
                    await self.run_preflight()
                self.assertEqual(self.calls, [["env"]])
                self.calls.clear()
        self.log.assert_not_awaited()


class Split(unittest.TestCase):
    def test_names_are_trimmed_and_checked(self):
        self.assertEqual(task.split(" a, b ", ("a", "b", "c"), "variant"), ["a", "b"])
        self.assertEqual(task.split(["b"], ("a", "b"), "variant"), ["b"])

    def test_empty_unknown_and_repeated_names_are_rejected(self):
        for value in ["", "a,", "unknown", "a,a", [], ["missing", ""]]:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "variants"):
                task.split(value, ("a", "b"), "variant")


if __name__ == "__main__":
    unittest.main()
