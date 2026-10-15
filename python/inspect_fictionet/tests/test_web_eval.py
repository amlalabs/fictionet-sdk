"""Offline regressions for both standalone scripted web evals."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from inspect_ai.model import ModelName
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.solver import TaskState
from inspect_ai.util import ExecResult


REPO = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HOSTED = load("hosted_eval", REPO / "examples/hosted/eval.py")
WEB = load("web_eval", REPO / "python/inspect_fictionet/examples/web_eval.py")


class WebEvalTests(unittest.IsolatedAsyncioTestCase):
    async def run_sample(self, module, sample_id, returncode=0, stdout="", stderr=""):
        sample = next(s for s in module.SAMPLES if s[0] == sample_id)
        state = TaskState(
            model=ModelName("mockllm/model"), sample_id=sample_id, epoch=1,
            input=sample[1], messages=[],
            metadata={"returncodes": sample[2]},
        )
        result = ExecResult(success=returncode == 0, returncode=returncode, stdout=stdout, stderr=stderr)
        execute = AsyncMock(return_value=result)
        with patch.object(module, "sandbox", return_value=SimpleNamespace(exec=execute)):
            state = await module.scripted()(state, AsyncMock())
        execute.assert_awaited_once_with(["sh", "-c", sample[1]], timeout=30)
        return state, Target(sample[-1])

    async def score(self, module, state, target):
        return await module.command_passes()(state, target)

    async def test_correct_run_and_recorded_evidence(self):
        for module in (HOSTED, WEB):
            for sample_id, stdout in (
                ("world-https", "hello from https example.test 443 over HTTP/2.0\n"),
                ("world-dns", "203.0.113.10\n"),
            ):
                with self.subTest(module=module.__name__, sample=sample_id):
                    state, target = await self.run_sample(module, sample_id, stdout=stdout)
                    self.assertEqual((await self.score(module, state, target)).value, CORRECT)
                    self.assertEqual(state.metadata["command_result"], {
                        "returncode": 0, "stdout": stdout, "stderr": "",
                    })
                    self.assertEqual(state.output.completion, stdout)
                    state.output.completion = "display only"
                    self.assertEqual((await self.score(module, state, target)).value, CORRECT)

    async def test_partial_or_extra_answer_fails(self):
        for module in (HOSTED, WEB):
            for sample_id, status, stdout, stderr in (
                ("world-https", 56, "hello from https example.test 443 over HTTP/2.0\n", ""),
                ("world-dns", 0, "203.0.113.100\n", ""),
                ("world-dns", 0, "203.0.113.10\n203.0.113.11\n", ""),
                ("world-dns", 0, "203.0.113.10", ""),
                ("world-dns", 0, "", "203.0.113.10\n"),
                ("world-dns", 0, "203.0.113.10\n", "unexpected diagnostic\n"),
            ):
                with self.subTest(module=module.__name__, sample=sample_id, status=status, stdout=stdout):
                    state, target = await self.run_sample(module, sample_id, status, stdout, stderr)
                    self.assertEqual((await self.score(module, state, target)).value, INCORRECT)

    async def test_denials_require_their_status_and_message(self):
        for module in (HOSTED, WEB):
            for sample_id, status, message in (
                ("no-dns-8888", 9, "no servers could be reached"),
                ("no-real-ip", 7, "Failed to connect to 1.1.1.1 port 443"),
                ("no-real-name", 6, "Could not resolve host"),
            ):
                for actual in (status, 0, 1, 28, 127):
                    for stream in ("stdout", "stderr"):
                        with self.subTest(module=module.__name__, sample=sample_id, actual=actual, stream=stream):
                            state, target = await self.run_sample(module, sample_id, actual, **{stream: message + "\n"})
                            expected = CORRECT if actual == status else INCORRECT
                            self.assertEqual((await self.score(module, state, target)).value, expected)
                state, target = await self.run_sample(module, sample_id, status, stderr="unrelated error\n")
                self.assertEqual((await self.score(module, state, target)).value, INCORRECT)

    async def test_timeout_propagates(self):
        for module in (HOSTED, WEB):
            state = TaskState(model=ModelName("mockllm/model"), sample_id=1, epoch=1, input="curl", messages=[])
            with patch.object(module, "sandbox", return_value=SimpleNamespace(exec=AsyncMock(side_effect=TimeoutError))):
                with self.assertRaises(TimeoutError):
                    await module.scripted()(state, AsyncMock())

    async def test_missing_or_malformed_evidence_fails(self):
        good = {"returncode": 0, "stdout": "203.0.113.10\n", "stderr": ""}
        for module in (HOSTED, WEB):
            for evidence in (
                None, [], {},
                *({key: value for key, value in good.items() if key != missing} for missing in good),
                dict(good, returncode=False), dict(good, returncode="0"),
                dict(good, stdout=None), dict(good, stderr=[]),
            ):
                with self.subTest(module=module.__name__, evidence=evidence):
                    state, target = await self.run_sample(module, "world-dns", stdout=good["stdout"])
                    state.metadata["command_result"] = evidence
                    self.assertEqual((await self.score(module, state, target)).value, INCORRECT)
            for codes in (None, [], "0", [False], ["0"]):
                with self.subTest(module=module.__name__, codes=codes):
                    state, target = await self.run_sample(module, "world-dns", stdout=good["stdout"])
                    state.metadata["returncodes"] = codes
                    self.assertEqual((await self.score(module, state, target)).value, INCORRECT)
            state.metadata.clear()
            self.assertEqual((await self.score(module, state, target)).value, INCORRECT)

    async def test_ca_requires_success_and_equality(self):
        ca = "-----BEGIN CERTIFICATE-----\nworld CA\n-----END CERTIFICATE-----\n"
        with patch.object(WEB, "read_world_file", new=AsyncMock(return_value=ca)):
            for status, stdout, stderr, expected in (
                (0, ca, "", CORRECT), (56, ca, "", INCORRECT),
                (0, ca + "extra\n", "", INCORRECT), (0, "", ca, INCORRECT),
            ):
                with self.subTest(status=status, stdout=stdout):
                    state, target = await self.run_sample(WEB, "world-ca", status, stdout, stderr)
                    self.assertEqual((await self.score(WEB, state, target)).value, expected)

    def test_tasks_keep_status_contracts_and_k8s_excludes_ca(self):
        with patch.object(WEB, "fictionet_sandbox", return_value=None):
            tasks = (HOSTED.hosted(provider="docker"), WEB.web(), WEB.web(backend="k8s"))
        self.assertEqual([len(task.dataset) for task in tasks], [5, 6, 5])
        self.assertIn("world-ca", [sample.id for sample in tasks[1].dataset])
        self.assertNotIn("world-ca", [sample.id for sample in tasks[2].dataset])
        for task in tasks:
            for sample in task.dataset:
                expected = {"no-dns-8888": (9,), "no-real-ip": (7,), "no-real-name": (6,)}
                self.assertEqual(tuple(sample.metadata["returncodes"]), expected.get(sample.id, (0,)))


if __name__ == "__main__":
    unittest.main()
