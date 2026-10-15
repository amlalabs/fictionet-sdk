"""Check the namespace demo's launch and resolver configuration."""

from pathlib import Path
import re
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Launchers(unittest.TestCase):
    def test_required_fetches_fail_on_http_errors(self):
        required = {
            "proxy": ["https://example.test/", "http://plain.test/", '-x "$SOCKS" https://example.test/'],
            "k8s": ["--cacert /run/ca/ca.pem https://example.test/"],
            "border": ["-b /tmp/jar $bank/balance"],
            "dashboard": ["--cacert /run/agent-ca.pem https://example.test/", "http://plain.test/"],
        }
        for demo, fetches in required.items():
            lines = (ROOT / f"demos/guest/{demo}.sh").read_text().splitlines()
            for fetch in fetches:
                with self.subTest(demo=demo, fetch=fetch):
                    commands = [shlex.split(shlex.split(line)[1]) for line in lines
                                if line.startswith("agent ") and fetch in line and "curl " in line]
                    self.assertTrue(commands)
                    for command in commands:
                        self.assertTrue(any(arg == "--fail" or
                                            (arg.startswith("-") and not arg.startswith("--") and "f" in arg[1:])
                                            for arg in command[1:]), command)

    def test_dashboard_drops_privileges_and_uses_public_ca(self):
        script = (ROOT / "demos/guest/dashboard.sh").read_text()
        prefix = re.search(r"^AGENT=\(.*?\)$", script, re.M | re.S)
        self.assertIsNotNone(prefix)
        result = subprocess.run(
            ["bash", "-c", prefix.group() + '\nprintf "%s\\n" "${AGENT[@]}"'],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.splitlines(), [
            "ip", "netns", "exec", "agent", "setpriv", "--reuid=agent", "--regid=agent",
            "--clear-groups", "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs",
            "env", "-i", "PATH=/usr/bin:/bin", "HOME=/tmp",
        ])
        self.assertIn('"${AGENT[@]}" bash -ec', script)
        loop = script.split('"${AGENT[@]}" bash -ec \'', 1)[1].split("done'", 1)[0]
        curls = [line for line in loop.splitlines() if 'curl ' in line]
        self.assertEqual(len(curls), 2)
        for line in curls:
            self.assertIn('-fsS', shlex.split(line))
        self.assertIn('install -m 0644 /run/fictionet/ca.pem /run/agent-ca.pem', script)
        self.assertIn('--cacert /run/agent-ca.pem', script)
        self.assertIn('timeout 4 fictionet observe --world unix:/run/fictionet/world.sock watch 0', script)

    def test_provision_disables_shared_resolver_and_replaces_symlink(self):
        script = (ROOT / "vm/guest/provision.sh").read_text()
        commands = [shlex.split(line) for line in script.splitlines() if line.startswith(("systemctl mask --now systemd-resolved", "rm -f /etc/resolv.conf", "printf 'nameserver"))]
        mask = commands.index(["systemctl", "mask", "--now", "systemd-resolved"])
        unlink = commands.index(["rm", "-f", "/etc/resolv.conf"])
        write = commands.index(["printf", "nameserver 10.0.2.3\\n", ">", "/etc/resolv.conf"])
        self.assertLess(mask, unlink)
        self.assertLess(unlink, write)


if __name__ == "__main__":
    unittest.main()
