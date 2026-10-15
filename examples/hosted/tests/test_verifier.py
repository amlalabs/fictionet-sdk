"""Exercise Harbor's verifier with isolated paths and command fixtures."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


TASK = Path(__file__).resolve().parents[1] / "harbor" / "fictionet-web"
VERIFIER = TASK / "tests" / "test.sh"
FETCH = ("-sS", "--fail", "--cacert", "/run/ca/ca.pem", "https://example.test/challenge")
PROBE = ("-sS", "--connect-timeout", "5", "-m", "5", "-o", "/dev/null",
         "-w", "%{time_connect}", "https://1.1.1.1/")
ROUTE = ("route", "del", "default")
NONCE = "b76adf8402e5c391" * 4 + "\n"


class VerifierTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for command in ("mkdir", "rm", "dirname", "ls", "sort", "tr", "cmp", "mktemp", "cat", "grep"):
            executable = shutil.which(command)
            self.assertIsNotNone(executable, f"test prerequisite missing: {command}")
            (self.bin / command).symlink_to(executable)
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash, "test prerequisite missing: bash")
        self.answer = self.root / "answer.txt"
        self.answer.write_text(NONCE)
        self.reward_dir = self.root / "verifier"
        self.reward_dir.mkdir()
        # A stale or agent-written reward must not survive a failed check.
        (self.reward_dir / "reward.txt").write_text("1\n")
        self.links = self.root / "net"
        self.links.mkdir()
        for link in ("lo", "tun0"):
            (self.links / link).mkdir()
        self.status = self.root / "status"
        self.status.write_text("Name:\tbash\nCapEff:\t00000000a80425fb\n")
        self.calls = self.root / "calls.jsonl"
        self.env = {
            **os.environ, "PATH": str(self.bin), "ANSWER_PATH": str(self.answer),
            "REWARD_DIR": str(self.reward_dir), "NET_CLASS_DIR": str(self.links),
            "PROC_STATUS": str(self.status),
        }
        self.responses = {
            "curl": {FETCH: (NONCE, "", 0), PROBE: ("0.000000", "Failed to connect\n", 7)},
            "dig": {("+time=2", "+tries=1", "@8.8.8.8", "example.com"):
                    ("", "no servers could be reached\n", 9)},
            "ip": {ROUTE: ("", "RTNETLINK answers: Operation not permitted\n", 2)},
        }

    def run_script(self, script):
        for command, responses in self.responses.items():
            stub = self.bin / command
            if responses is None:
                if stub.exists():
                    stub.unlink()
                continue
            stub.write_text(
                f"#!{sys.executable}\nimport json, sys\nresponses = {responses!r}\n"
                f"with open({str(self.calls)!r}, 'a') as log:\n"
                f"    log.write(json.dumps([{command!r}, *sys.argv[1:]]) + '\\n')\n"
                "stdout, stderr, status = responses[tuple(sys.argv[1:])]\n"
                "sys.stdout.write(stdout)\nsys.stderr.write(stderr)\nsys.exit(status)\n"
            )
            stub.chmod(0o755)
        return subprocess.run(
            [self.bash, str(script)], env=self.env,
            capture_output=True, text=True, check=False,
        )

    def assert_reward(self, reward, reason):
        result = self.run_script(VERIFIER)
        output = result.stdout + result.stderr
        reward_file = self.reward_dir / "reward.txt"
        self.assertFalse(reward_file.is_symlink(), output)
        self.assertTrue(reward_file.is_file(), output)
        self.assertEqual(reward_file.read_text(), f"{reward}\n", output)
        self.assertEqual(result.returncode, 0 if reward else 1, output)
        self.assertIn(reason, output)
        if reward:
            self.assertNotIn("FAIL:", output)

    def test_agent_written_reward_json_removed(self):
        for reward in (0, 1):
            with self.subTest(reward=reward):
                self.answer.write_text(NONCE if reward else "forged\n")
                reward_json = self.reward_dir / "reward.json"
                reward_json.write_text('{"reward": 1.0}\n')
                self.assert_reward(reward, "PASS: answer" if reward else "FAIL: answer")
                self.assertFalse(reward_json.exists())

    def test_reward_json_link_removed_without_changing_target(self):
        target = self.root / "agent-reward.json"
        target.write_text('{"reward": 1.0}\n')
        reward_json = self.reward_dir / "reward.json"
        reward_json.symlink_to(target)
        self.answer.unlink()
        self.assert_reward(0, "FAIL: answer")
        self.assertFalse(reward_json.is_symlink())
        self.assertFalse(reward_json.exists())
        self.assertEqual(target.read_text(), '{"reward": 1.0}\n')

    def test_reward_txt_link_replaced_without_changing_target(self):
        target = self.root / "agent-reward.txt"
        target.write_text("1\n")
        for reward in (0, 1):
            with self.subTest(reward=reward):
                self.answer.write_text(NONCE if reward else "forged\n")
                reward_file = self.reward_dir / "reward.txt"
                reward_file.unlink()
                reward_file.symlink_to(target)
                self.assert_reward(reward, "PASS: answer" if reward else "FAIL: answer")
                self.assertEqual(target.read_text(), "1\n")

    def test_curl_error_link_replaced_without_changing_target(self):
        target = self.root / "agent-curl.err"
        target.write_text("agent data\n")
        error_file = self.reward_dir / "curl.err"
        error_file.symlink_to(target)
        self.assert_reward(1, "PASS: answer")
        self.assertEqual(target.read_text(), "agent data\n")
        self.assertFalse(error_file.is_symlink())
        self.assertTrue(error_file.is_file())
        self.assertEqual(error_file.read_text(), "Failed to connect\n")

    def test_output_cleanup_failure_stops_verification(self):
        (self.reward_dir / "curl.err").mkdir()
        (self.reward_dir / "reward.json").write_text('{"reward": 1.0}\n')
        result = self.run_script(VERIFIER)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("FAIL: cannot clear verifier output files", result.stdout + result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertFalse((self.reward_dir / "reward.json").exists())
        self.assertFalse((self.reward_dir / "reward.txt").exists())

    def test_forged_known_greeting(self):
        self.answer.write_text("hello from https example.test 443 over HTTP/2.0\n")
        self.assert_reward(0, "FAIL: answer")

    def test_forged_public_prefix(self):
        self.answer.write_text("hello from https example.test 443\n")
        self.assert_reward(0, "FAIL: answer")

    def test_real_fetch_rewarded(self):
        self.answer.unlink()
        result = self.run_script(TASK / "solution" / "solve.sh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.answer.read_text(), NONCE)
        self.assert_reward(1, "PASS: answer matches the complete world challenge")
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(calls.count(["curl", *FETCH]), 2)

    def test_missing_answer_rejected(self):
        self.answer.unlink()
        self.assert_reward(0, "FAIL: answer")

    def test_copied_other_run_answer(self):
        self.answer.write_text("9c18e7ab3fd56024" * 4 + "\n")
        self.assert_reward(0, "FAIL: answer")

    def test_complete_response_required(self):
        for answer in ("", NONCE[:-1], NONCE[:32], NONCE + "\n", NONCE + "extra\n"):
            with self.subTest(answer=answer):
                self.answer.write_text(answer)
                self.assert_reward(0, "FAIL: answer")

    def test_forged_agent_log(self):
        self.answer.unlink()
        (self.reward_dir / "agent.log").write_text("PASS: answer from the world\n")
        (self.reward_dir / "expected.txt").write_text(NONCE)
        self.assert_reward(0, "FAIL: answer")

    def test_answer_link_to_verifier_evidence_rejected(self):
        self.answer.unlink()
        evidence = self.reward_dir / "expected.txt"
        evidence.write_text(NONCE)
        self.answer.symlink_to(evidence)
        self.assert_reward(0, "FAIL: answer")

    def test_evidence_link_cannot_overwrite_answer(self):
        self.answer.write_text("hello from https example.test 443\n")
        (self.reward_dir / "expected.txt").symlink_to(self.answer)
        self.assert_reward(0, "FAIL: answer")

    def test_world_fetch_failure(self):
        # Even a complete-looking body with a failed fetch is not evidence.
        self.responses["curl"][FETCH] = NONCE, "transfer failed\n", 18
        self.assert_reward(0, "FAIL: could not fetch the world challenge")

    def test_malformed_world_challenge(self):
        for response in ("", "not a nonce\n", NONCE[:-1], NONCE + "\n"):
            with self.subTest(response=response):
                self.responses["curl"][FETCH] = response, "", 0
                self.answer.write_text(response)
                self.assert_reward(0, "FAIL: malformed world challenge")

    def test_curl_tls_failure_not_isolation(self):
        self.responses["curl"][PROBE] = "0.010000", "SSL certificate problem\n", 60
        self.assert_reward(0, "FAIL: 1.1.1.1: status 60, time_connect=0.010000: SSL certificate problem")

    def test_curl_other_failures_not_isolation(self):
        for status in (0, 6, 35, 77, 127):
            with self.subTest(status=status):
                self.responses["curl"][PROBE] = "0.000000", "probe output\n", status
                self.assert_reward(0, f"FAIL: 1.1.1.1: status {status}")

    def test_connect_timeout_is_isolation(self):
        self.responses["curl"][PROBE] = "0.000000", "Connection timed out\n", 28
        self.assert_reward(1, "PASS: 1.1.1.1 connection denied")

    def test_timeout_requires_zero_connect_time(self):
        for timing in ("0.001000", "", "bad", "0.000000\n0.010000"):
            with self.subTest(timing=timing):
                self.responses["curl"][PROBE] = timing, "Operation timed out\n", 28
                self.assert_reward(0, "FAIL: 1.1.1.1: status 28")

    def test_ip_no_such_process_rejected(self):
        self.responses["ip"][ROUTE] = "", "RTNETLINK answers: No such process\n", 2
        self.assert_reward(0, "FAIL: route deletion: status 2: RTNETLINK answers: No such process")

    def test_ip_requires_denial_status(self):
        for status in (0, 124, 126, 127, 137):
            with self.subTest(status=status):
                self.responses["ip"][ROUTE] = "", "Operation not permitted\n", status
                self.assert_reward(0, f"FAIL: route deletion: status {status}")

    def test_net_admin_rejected(self):
        self.status.write_text("CapEff:\t00000000a80435fb\n")
        self.assert_reward(0, "FAIL: missing, malformed or NET_ADMIN-enabled CapEff")

    def test_missing_or_malformed_capabilities(self):
        for status in ("", "CapEff: unknown\n", "CapEff: 0\n", "CapEff: 0000000000000000\n" * 2):
            with self.subTest(status=status):
                self.status.write_text(status)
                self.assert_reward(0, "FAIL: missing, malformed or NET_ADMIN-enabled CapEff")
        self.status.unlink()
        self.assert_reward(0, "FAIL: missing, malformed or NET_ADMIN-enabled CapEff")

    def test_missing_tool_rejected(self):
        for tool in ("curl", "dig", "ip", "cmp", "mktemp"):
            with self.subTest(tool=tool):
                responses = self.responses.get(tool)
                self.responses[tool] = None
                self.assert_reward(0, f"FAIL: missing tool: {tool}")
                if responses is None:
                    (self.bin / tool).symlink_to(shutil.which(tool))
                    del self.responses[tool]
                else:
                    self.responses[tool] = responses

    def test_extra_interface_rejected(self):
        (self.links / "eth0").mkdir()
        self.assert_reward(0, "FAIL: links:")

    def test_external_dns_answer_rejected(self):
        key = next(iter(self.responses["dig"]))
        self.responses["dig"][key] = "example.com. 300 IN A 93.184.215.14\n", "", 0
        self.assert_reward(0, "FAIL: DNS to 8.8.8.8 answered")


if __name__ == "__main__":
    unittest.main()
