"""Offline regressions for the Kubernetes Inspect solver and scorer."""

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, call, patch

from inspect_ai.model import ModelName
from inspect_ai.scorer import CORRECT, INCORRECT, Target
from inspect_ai.solver import TaskState
from inspect_ai.util import ExecResult

import inspect_eval


def result(returncode=0, stdout="", stderr=""):
    return ExecResult(
        success=returncode == 0, returncode=returncode, stdout=stdout, stderr=stderr
    )


class InspectEvalTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.results = [
            result(stdout="hello from https example.test 443 over HTTP/2.0\n"),
            result(stdout="203.0.113.10\n"),
            result(7, stderr="curl: (7) Couldn't connect to server\n"),
            result(2, stderr="RTNETLINK answers: Operation not permitted\n"),
            result(2, stderr="ls: cannot access '/run/relay': No such file or directory\n"),
        ]

    async def solve(self):
        state = TaskState(
            model=ModelName("mockllm/model"), sample_id=1, epoch=1, input="", messages=[]
        )
        execute = AsyncMock(side_effect=self.results)
        with patch.object(inspect_eval, "sandbox", return_value=SimpleNamespace(exec=execute)):
            state = await inspect_eval.run_checks()(state, AsyncMock())
        self.assertEqual(execute.call_args_list, [
            call(["sh", "-c", check[0]], timeout=30) for check in inspect_eval.CHECKS
        ])
        return state

    async def score(self, state):
        return await inspect_eval.all_checks_pass()(state, Target("hello"))

    async def test_isolated_sandbox_passes_and_records_results(self):
        state = await self.solve()
        for check, output in zip(inspect_eval.CHECKS, self.results):
            self.assertEqual(state.metadata["check_results"][check[0]], {
                "returncode": output.returncode,
                "stdout": output.stdout,
                "stderr": output.stderr,
            })
            self.assertIn(f"$ {check[0]}", state.output.completion)
        self.assertEqual((await self.score(state)).value, CORRECT)
        state.output.completion = ""
        self.assertEqual((await self.score(state)).value, CORRECT)

    async def test_successful_escape_curl_fails(self):
        for stdout in ("", "unreachable\n"):
            with self.subTest(stdout=stdout):
                self.results[2] = result(stdout=stdout)
                self.assertEqual((await self.score(await self.solve())).value, INCORRECT)

    async def test_connection_timeout_passes(self):
        self.results[2] = result(28, stderr="curl: (28) Connection timed out\n")
        self.assertEqual((await self.score(await self.solve())).value, CORRECT)

    async def test_unrelated_curl_failure_fails(self):
        self.results[2] = result(127, stderr="sh: curl: not found\n")
        self.assertEqual((await self.score(await self.solve())).value, INCORRECT)

    async def test_expected_output_with_wrong_status_fails(self):
        for index in (0, 1, 3, 4):
            with self.subTest(command=inspect_eval.CHECKS[index][0]):
                output = self.results[index]
                self.results[index] = result(
                    1 if index < 2 else 0, stdout=output.stdout, stderr=output.stderr
                )
                self.assertEqual((await self.score(await self.solve())).value, INCORRECT)
                self.results[index] = output

    async def test_expected_text_only_in_another_result_fails(self):
        self.results[1] = result(stdout="203.0.113.10\n" + self.results[0].stdout)
        self.results[0] = result()
        self.assertEqual((await self.score(await self.solve())).value, INCORRECT)

    async def test_expected_text_only_in_command_fails(self):
        checks = list(inspect_eval.CHECKS)
        command, returncodes, want = checks[0]
        checks[0] = (f"{command} # {want}", returncodes, want)
        self.results[0] = result()
        with patch.object(inspect_eval, "CHECKS", checks):
            self.assertEqual((await self.score(await self.solve())).value, INCORRECT)

    async def test_missing_results_fail_despite_transcript(self):
        state = await self.solve()
        del state.metadata["check_results"][inspect_eval.CHECKS[1][0]]
        self.assertEqual((await self.score(state)).value, INCORRECT)
        state.metadata.clear()
        self.assertEqual((await self.score(state)).value, INCORRECT)


if __name__ == "__main__":
    unittest.main()
