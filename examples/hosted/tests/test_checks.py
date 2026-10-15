"""Run the standalone hosted check with deterministic command fixtures."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


CHECK = Path(__file__).resolve().parents[1] / "check.sh"
HTTPS = ("curl", "-sS", "--cacert", "/run/ca/ca.pem", "https://example.test/")
METADATA = ("curl", "-sS", "-m", "5", "http://169.254.169.254/")
BRIDGE = ("network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.ip = {
            ("-4", "route", "get", "1.1.1.1"): ("1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.2\n", "", 0),
            ("-4", "route", "show", "default"): ("default via 192.0.2.1 dev eth0\n", "", 0),
            ("-4", "addr", "show", "docker0"): ("    inet 172.17.0.1/16 scope global docker0\n", "", 0),
        }
        self.docker = {
            BRIDGE: ("172.17.0.1\n", "", 0),
            ("sh", "-c", "ls /sys/class/net | sort"): ("lo\ntun0\n", "", 0),
            ("ip", "-4", "addr", "show", "tun0"): ("inet 10.0.0.2/24\n", "", 0),
            ("ip", "route", "show", "default"): ("default via 10.0.0.1 dev tun0\n", "", 0),
            ("cat", "/etc/resolv.conf"): ("nameserver 10.0.0.1\n", "", 0),
            ("dig", "+short", "example.test", "A"): ("203.0.113.10\n", "", 0),
            HTTPS: ("hello from https example.test 443 over HTTP/2.0\n", "", 0),
            ("ping", "-c", "1", "-W", "2", "10.0.0.1"): ("1 packets transmitted, 1 received\n", "", 0),
            ("bash", "-c", 'c=$(awk "/^CapEff/ {print \\$2}" /proc/self/status); if (( 0x$c & 0x1000 )); then echo NET_ADMIN; else echo no NET_ADMIN; fi'): ("no NET_ADMIN\n", "", 0),
            ("ip", "route", "del", "default"): ("", "Operation not permitted\n", 2),
            ("ip", "link", "add", "x", "type", "dummy"): ("", "Operation not permitted\n", 2),
            ("ls", "/run/fictionet/world.sock"): ("", "No such file\n", 2),
            ("curl", "-sS", "-m", "5", "https://1.1.1.1/"): ("", "Failed to connect\n", 7),
            ("curl", "-sS", "-m", "5", "https://example.com/"): ("", "Could not resolve host\n", 6),
            METADATA: ("", "No route to host\n", 7),
        }
        for address in ("1.1.1.1", "8.8.8.8"):
            self.docker[("dig", "+time=2", "+tries=1", f"@{address}", "example.com")] = (
                "no servers could be reached\n", "", 9
            )
        for address in ("192.0.2.2", "192.0.2.1", "172.17.0.1"):
            self.docker[("timeout", "5", "bash", "-c", f"exec 3<>/dev/tcp/{address}/22")] = (
                "", "No route to host\n", 1
            )

    def run_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # An isolated PATH also lets the missing-ip case stay independent
            # of the host's installed tools.
            for command in ("dirname", "sed", "head", "tr", "grep", "awk"):
                (root / command).symlink_to(shutil.which(command))
            for command, responses in (("ip", self.ip), ("docker", self.docker)):
                if responses is None:
                    continue
                stub = root / command
                stub.write_text(
                    f"#!{sys.executable}\nimport sys\nresponses = {responses!r}\n"
                    "key = tuple(sys.argv[1:])\n"
                    "if key[:1] == ('compose',):\n"
                    "    assert key[1] == '-f' and key[3:6] == ('exec', '-T', 'default')\n"
                    "    key = key[6:]\n"
                    "stdout, stderr, status = responses[key]\n"
                    "sys.stdout.write(stdout)\nsys.stderr.write(stderr)\nsys.exit(status)\n"
                )
                stub.chmod(0o755)
            return subprocess.run(
                [shutil.which("sh"), str(CHECK)],
                env={**os.environ, "PATH": directory},
                capture_output=True, text=True, check=False,
            )

    def assert_failed(self, result, reason):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("ALL PASSED", result.stdout)
        self.assertIn(reason, result.stdout)
        self.assertEqual(sum(line.startswith(("PASS:", "FAIL:")) for line in result.stdout.splitlines()), 19)

    def test_all_good(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("PASS:"), 19)
        self.assertIn("ALL PASSED", result.stdout)

    def test_expected_prefix_exit_7(self):
        for status in (7, 56):
            with self.subTest(status=status):
                stdout, stderr, _ = self.docker[HTTPS]
                self.docker[HTTPS] = stdout, stderr, status
                self.assert_failed(self.run_check(), "FAIL: HTTPS with the world's CA")

    def test_reachable_metadata(self):
        self.docker[METADATA] = "", "No route to host\n", 0
        self.assert_failed(self.run_check(), "FAIL: the metadata address fails")

    def test_metadata_requires_refusal_status(self):
        for status in (124, 126, 127, 137):
            with self.subTest(status=status):
                self.docker[METADATA] = "", "No route to host\n", status
                result = self.run_check()
                self.assert_failed(result, "FAIL: the metadata address fails")
                self.assertIn(f"got status {status}:", result.stdout)

    def test_empty_route_discovery(self):
        self.ip = {command: ("", "", 0) for command in self.ip}
        self.assert_failed(self.run_check(), "no default route")

    def test_failed_ip(self):
        self.ip = {command: (stdout, "ip failed\n", 7) for command, (stdout, _, _) in self.ip.items()}
        self.assert_failed(self.run_check(), "ip route")

    def test_missing_ip(self):
        self.ip = None
        self.assert_failed(self.run_check(), "ip missing")

    def test_bridge_fallback(self):
        self.ip[("-4", "addr", "show", "docker0")] = "", "no docker0\n", 1
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("PASS:"), 19)
        self.assertIn("PASS: the sandbox's own network (172.17.0.1) fails", result.stdout)

    def test_missing_bridge(self):
        self.ip[("-4", "addr", "show", "docker0")] = "", "", 0
        for output in (("", "", 0), ("172.17.0.1\n", "inspect failed\n", 1)):
            with self.subTest(output=output):
                self.docker[BRIDGE] = output
                self.assert_failed(self.run_check(), "no bridge")

    def test_invalid_bridge(self):
        self.ip[("-4", "addr", "show", "docker0")] = "", "", 0
        for address in ("<no value>", "999.17.0.1", "172.17.0.1\n172.18.0.1"):
            with self.subTest(address=address):
                self.docker[BRIDGE] = address + "\n", "", 0
                self.assert_failed(self.run_check(), "invalid IPv4 target")


if __name__ == "__main__":
    unittest.main()
