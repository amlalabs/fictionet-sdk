"""Check the namespace demo's launch and resolver configuration."""

from pathlib import Path
import re
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Launchers(unittest.TestCase):
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
        self.assertIn('"${AGENT[@]}" bash -c', script)
        self.assertIn('install -m 0644 /run/fictionet/ca.pem /run/agent-ca.pem', script)
        self.assertIn('--cacert /run/agent-ca.pem', script)

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
