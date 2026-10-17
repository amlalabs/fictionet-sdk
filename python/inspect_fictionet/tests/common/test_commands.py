"""Offline command outcomes must distinguish denial from failed observation."""

from types import SimpleNamespace
from dataclasses import FrozenInstanceError
import subprocess
import sys
import unittest
from unittest.mock import AsyncMock, Mock


from inspect_fictionet._common import commands
Result = commands.Result
Outcome = commands.Outcome


class Commands(unittest.TestCase):
    def test_result_is_immutable(self):
        argv = ["env"]
        result = Result(argv, 0, "A=B\n", "")
        argv.append("extra")
        self.assertEqual(result.argv, ("env",))
        with self.assertRaises(FrozenInstanceError):
            result.rc = 1

    def test_expected_prefix_then_nonzero(self):
        result = Result(("curl",), 56, "hello from https example.test\n", "recv failed")
        self.assertFalse(commands.succeeded(result, stdout=result.stdout))
        self.assertEqual(commands.classify_curl(result), Outcome.CONNECTED_THEN_FAILED)
        self.assertFalse(commands.succeeded(Result(("dig",), 0, "203.0.113.100\n", ""),
                                            stdout="203.0.113.10\n"))
        self.assertTrue(commands.succeeded(Result(("dig",), 0, "203.0.113.10\n", ""),
                                           stdout="203.0.113.10\n"))

    def test_partial_http_200(self):
        for stdout in ("200 10.0.0.5 0", "200 verify=0", "200 1.2.3.4 verify=0", "404"):
            with self.subTest(stdout=stdout):
                result = Result(("curl",), 18, stdout, "transfer closed with bytes remaining")
                self.assertFalse(commands.succeeded(result, stdout=stdout))
                self.assertEqual(commands.classify_curl(result), Outcome.CONNECTED_THEN_FAILED)
                complete = Result(result.argv, 0, stdout, "")
                self.assertTrue(commands.succeeded(complete, stdout=stdout))
                self.assertEqual(commands.classify_curl(complete), Outcome.SUCCESS)

    def test_missing_tool_and_invalid_observations(self):
        classifiers = (commands.classify, commands.classify_curl, commands.classify_dig,
                       commands.classify_getent, commands.classify_connect, commands.classify_ip_add)
        for rc, stdout, stderr in (
            (127, "", "tool not found"), (126, "", "Permission denied"),
            (-15, "CONNECTED\n", "terminated"), (7, "", ""), (2, "", ""),
            (28, " \n", "\t"), (None, "200", ""), ("0", "200", ""),
            (False, "200", ""), (0, None, ""), (0, "", b""),
        ):
            for classify in classifiers:
                with self.subTest(rc=rc, classify=classify.__name__):
                    result = Result(("probe",), rc, stdout, stderr)
                    self.assertEqual(classify(result), Outcome.INVALID_OBSERVATION)
                    self.assertFalse(commands.succeeded(result))

    def test_pre_connect_timeout(self):
        self.assertEqual(commands.CURL_CONNECT_WRITE_OUT,
                         "%{remote_ip}\t%{num_connects}\t%{time_connect}\n")
        for stderr in (
            "curl: (28) Connection timed out after 2001 milliseconds",
            "curl: (28) Connection timed out after 2000 milliseconds",
        ):
            with self.subTest(stderr=stderr):
                result = Result(("curl",), 28, "\t0\t0.000000\n", stderr)
                self.assertEqual(commands.classify_curl(result), Outcome.EXPECTED_FAILURE)

    def test_timeout_without_connection_write_out_is_invalid(self):
        for stderr in (
            "curl: (28) Connection timed out after 2000 milliseconds",
            "curl: (28) Failed to connect to 1.1.1.1 port 443: Timeout was reached",
        ):
            with self.subTest(stderr=stderr):
                self.assertEqual(commands.classify_curl(Result(("curl",), 28, "", stderr)),
                                 Outcome.INVALID_OBSERVATION)

    def test_tls_handshake_timeout_is_connected(self):
        for stdout, stderr in (
            ("127.0.0.1\t1\t0.000000\n", "curl: (28) Connection timed out after 2000 milliseconds"),
            ("\t1\t0.000000\n", "curl: (28) Connection timed out after 2003 milliseconds"),
        ):
            with self.subTest(stdout=stdout, stderr=stderr):
                self.assertEqual(commands.classify_curl(Result(("curl",), 28, stdout, stderr)),
                                 Outcome.CONNECTED_THEN_FAILED)

    def test_reachable_timeout(self):
        for stdout, stderr in (
            ("", "curl: (28) Operation timed out after 5001 milliseconds with 0 bytes received"),
            ("\t0\t0.000000\n", "curl: (28) Operation timed out after 2001 milliseconds with 0 bytes received"),
            ("127.0.0.1\t1\t0.000178\n", "curl: (28) Operation timed out after 2001 milliseconds with 0 bytes received"),
            ("1.1.1.1\t0\t0.000000\n", "curl: (28) Connection timed out after 2000 milliseconds"),
            ("\t0\t0.001234\n", "curl: (28) Connection timed out after 2000 milliseconds"),
        ):
            with self.subTest(stdout=stdout, stderr=stderr):
                self.assertEqual(commands.classify_curl(Result(("curl",), 28, stdout, stderr)),
                                 Outcome.CONNECTED_THEN_FAILED)

    def test_curl_denial_and_tls_failure_are_different(self):
        for rc in (6, 7):
            self.assertEqual(commands.classify_curl(Result(("curl",), rc, "", "connect failed")),
                             Outcome.EXPECTED_FAILURE)
        for rc in (18, 35, 52, 56, 60):
            result = Result(("curl", "https://1.1.1.1/"), rc, "", "TLS or transfer failure")
            self.assertEqual(commands.classify_curl(result), Outcome.CONNECTED_THEN_FAILED)
            self.assertNotEqual(commands.classify_curl(result), Outcome.EXPECTED_FAILURE)
        for rc, stdout, stderr in (
            (77, "", "CA bundle missing"), (28, "", "Timeout was reached"),
            (28, "200", "Connection timed out"),
            (28, "\t0\tNaN\n", "Connection timed out"),
            (28, "\t0\t-1.000000\n", "Connection timed out"),
            (28, "\t0\t0.000000\nextra", "Connection timed out"),
            (28, "\t0.000000\n", "curl: (28) Connection timed out after 2000 milliseconds"),
            (28, "\t0\t0.000000", "curl: (28) Connection timed out after 2000 milliseconds"),
            (28, "\t-1\t0.000000\n", "curl: (28) Connection timed out after 2000 milliseconds"),
            (28, "\tNaN\t0.000000\n", "curl: (28) Connection timed out after 2000 milliseconds"),
            (28, "\t0\t0.000000\textra\n", "curl: (28) Connection timed out after 2000 milliseconds"),
        ):
            with self.subTest(rc=rc, stdout=stdout):
                self.assertEqual(commands.classify_curl(Result(("curl",), rc, stdout, stderr)),
                                 Outcome.INVALID_OBSERVATION)

    def test_command_specific_denials(self):
        cases = (
            (commands.classify_dig, 9, ";; no servers could be reached\n", "", Outcome.EXPECTED_FAILURE),
            (commands.classify_dig, 9, "", "bad option", Outcome.INVALID_OBSERVATION),
            (commands.classify_dig, 9, "no servers could be ", "reached", Outcome.INVALID_OBSERVATION),
            (commands.classify_dig, 1, "no servers could be reached", "", Outcome.INVALID_OBSERVATION),
            (commands.classify_dig, 0, "answer", "", Outcome.SUCCESS),
            (commands.classify_ip_add, 2, "", "RTNETLINK answers: Operation not permitted", Outcome.EXPECTED_FAILURE),
            (commands.classify_ip_add, 2, "", "RTNETLINK answers: No such process", Outcome.INVALID_OBSERVATION),
            (commands.classify_ip_add, 1, "", "Operation not permitted", Outcome.INVALID_OBSERVATION),
            (commands.classify_ip_add, 0, "", "", Outcome.SUCCESS),
        )
        for classify, rc, stdout, stderr, outcome in cases:
            with self.subTest(classify=classify.__name__, rc=rc, stderr=stderr):
                self.assertEqual(classify(Result(("probe",), rc, stdout, stderr)), outcome)

    def test_getent_lookup_outcomes(self):
        for program in ("getent", "/usr/bin/getent"):
            with self.subTest(program=program):
                result = Result((program, "hosts", "example.com"), 2, "", "")
                self.assertEqual(commands.classify_getent(result), Outcome.EXPECTED_FAILURE)
                for classify in (commands.classify, commands.classify_curl, commands.classify_dig,
                                 commands.classify_connect, commands.classify_ip_add):
                    self.assertEqual(classify(result), Outcome.INVALID_OBSERVATION)
        for argv in (("probe",), ("probe", "hosts", "example.com"),
                     ("getent",), ("getent", "hosts"), ()):
            with self.subTest(argv=argv):
                self.assertEqual(commands.classify_getent(Result(argv, 2, "", "")),
                                 Outcome.INVALID_OBSERVATION)
        for rc, stdout, stderr, want in (
            (0, "203.0.113.10 example.test\n", "", Outcome.SUCCESS),
            (2, "203.0.113.10 example.test\n", "", Outcome.INVALID_OBSERVATION),
            (2, " \n", "", Outcome.INVALID_OBSERVATION),
            (1, "", "Unknown database: nosuchdb\n", Outcome.INVALID_OBSERVATION),
            (127, "", "getent: command not found", Outcome.INVALID_OBSERVATION),
            (126, "", "", Outcome.INVALID_OBSERVATION),
            (-15, "", "", Outcome.INVALID_OBSERVATION),
            (2.0, "", "", Outcome.INVALID_OBSERVATION),
            (2, None, "", Outcome.INVALID_OBSERVATION),
            (2, "", None, Outcome.INVALID_OBSERVATION),
            (2, "", b"", Outcome.INVALID_OBSERVATION),
        ):
            with self.subTest(rc=rc, stdout=stdout, stderr=stderr):
                result = Result(("getent", "hosts", "example.test", "example.com"), rc, stdout, stderr)
                self.assertEqual(commands.classify_getent(result), want)
        self.assertEqual(commands.classify_getent(Result(("getent", "hosts", None), 2, "", "")),
                         Outcome.INVALID_OBSERVATION)

    def test_python_connect_requires_phase_evidence(self):
        for error in ("OSError: [Errno 113] No route to host", "TimeoutError: timed out"):
            traceback = "Traceback (most recent call last):\n  socket.create_connection(...)\n" + error
            self.assertEqual(commands.classify_connect(Result(("python3",), 1, "", traceback)),
                             Outcome.EXPECTED_FAILURE)
        for rc, stdout, stderr, want in (
            (0, "CONNECTED\n", "", Outcome.SUCCESS),
            (1, "CONNECTED\n", "later failure", Outcome.CONNECTED_THEN_FAILED),
            (0, "", "", Outcome.INVALID_OBSERVATION),
            (1, "NOT CONNECTED\n", "NameError: socket", Outcome.INVALID_OBSERVATION),
            (1, "", "TimeoutError: timed out", Outcome.INVALID_OBSERVATION),
            (1, "", "Traceback (most recent call last):\nNameError: OSError", Outcome.INVALID_OBSERVATION),
        ):
            with self.subTest(rc=rc, stdout=stdout, stderr=stderr):
                self.assertEqual(commands.classify_connect(Result(("python3",), rc, stdout, stderr)), want)

    def test_private_path_errors_are_not_absence(self):
        argv = ("ls", "-ld", "/run/relay")
        for rc, stdout, stderr in (
            (2, "", "ls: cannot access '/run/relay': Permission denied"),
            (127, "", "ls: No such file or directory"),
            (2, "drwxr-xr-x /run/relay\n", "No such file or directory"),
            (2, "", "No such file or directory\nPermission denied"),
            (2, "", ""), (0, "", "No such file or directory"),
        ):
            with self.subTest(rc=rc, stdout=stdout, stderr=stderr):
                self.assertFalse(commands.path_absent(Result(argv, rc, stdout, stderr)))
        combined = Result(("ls", "-ld", "/missing", "/run/relay"), 2, "",
                          "ls: cannot access '/missing': No such file or directory")
        self.assertFalse(commands.path_absent(combined))

    def test_proxy_environment(self):
        clean = Result(("env",), 0, "PATH=/usr/bin\nNAME=proxy text\nVALUE=a=b\n", "")
        self.assertEqual(commands.read_env(clean)["VALUE"], "a=b")
        commands.require_no_proxy(clean)
        for name in ("http_proxy", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "custom_PrOxY"):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, name):
                commands.require_no_proxy(Result(("env",), 0, clean.stdout + name + "=\n", ""))
        self.assertEqual(commands.classify(Result(("env",), 1, "", "env failed")),
                         Outcome.INVALID_OBSERVATION)
        for result in (
            Result(("env",), 1, "PATH=/usr/bin\n", "env failed"),
            Result(("env",), 127, "", "env not found"),
            Result(("env",), 0, "not an environment\n", ""),
            Result(("env",), 0, "=empty name\n", ""),
            Result(("env",), 0, "A=one\nA=two\n", ""),
        ):
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                commands.require_no_proxy(result)

    def test_sync_runner_preserves_status_and_output(self):
        argv = ["curl", "https://example.test/"]
        runner = Mock(return_value=SimpleNamespace(returncode=18, stdout="200", stderr="partial"))
        self.assertEqual(commands.run(argv, runner=runner, timeout=3),
                         Result(tuple(argv), 18, "200", "partial"))
        runner.assert_called_once_with(argv, capture_output=True, text=True, check=False, timeout=3)
        result = commands.run([sys.executable, "-c", "import sys; print('200'); sys.stderr.write('partial'); sys.exit(18)"])
        self.assertEqual((result.rc, result.stdout, result.stderr), (18, "200\n", "partial"))
        self.assertFalse(commands.succeeded(result))

    def test_runner_exceptions_propagate(self):
        for error in (FileNotFoundError("missing tool"), TimeoutError("timeout"),
                      subprocess.TimeoutExpired("curl", 3), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                commands.run(["curl"], runner=Mock(side_effect=error))

    def test_direct_curl_prefix(self):
        self.assertEqual(commands.CURL_DIRECT, ("curl", "-q", "--noproxy", "*"))


class AsyncCommands(unittest.IsolatedAsyncioTestCase):
    async def test_async_runner_preserves_status_and_output(self):
        runner = AsyncMock(return_value=SimpleNamespace(success=True, returncode=28, stdout="200", stderr="timeout"))
        result = await commands.run_async(["curl"], runner=runner, timeout=3)
        self.assertEqual(result, Result(("curl",), 28, "200", "timeout"))
        self.assertFalse(commands.succeeded(result, stdout="200"))
        runner.assert_awaited_once_with(["curl"], timeout=3)
        for error in (TimeoutError("timeout"), FileNotFoundError("curl"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                await commands.run_async(["curl"], runner=AsyncMock(side_effect=error))

    async def test_mixed_visible_paths(self):
        paths = ("/var/lib/fictionet", "/run/relay")
        missing = SimpleNamespace(returncode=2, stdout="",
                                  stderr="ls: cannot access '/var/lib/fictionet': No such file or directory\n")
        visible = SimpleNamespace(returncode=0, stdout="drwxr-xr-x 2 root root 40 /run/relay\n", stderr="")
        runner = AsyncMock(side_effect=[missing, visible])
        results = await commands.inspect_paths(paths, runner=runner)
        self.assertEqual([c.args[0] for c in runner.await_args_list],
                         [["ls", "-ld", path] for path in paths])
        self.assertEqual([commands.path_absent(r) for r in results], [True, False])
        self.assertEqual(results[1].stdout, visible.stdout)
        runner = AsyncMock(side_effect=[missing, SimpleNamespace(
            returncode=2, stdout="", stderr="ls: cannot access '/run/relay': No such file or directory\n")])
        self.assertTrue(all(commands.path_absent(r) for r in await commands.inspect_paths(paths, runner=runner)))
        with self.assertRaises(ValueError):
            await commands.inspect_paths([], runner=runner)


if __name__ == "__main__":
    unittest.main()
