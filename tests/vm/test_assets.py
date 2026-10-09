"""Each independently pinned VM asset changes the cached ISO path."""
from pathlib import Path
import subprocess
import unittest


class AssetsTests(unittest.TestCase):
    def test_cache_key_tracks_each_pin(self):
        script = Path(__file__).with_name("nested.sh").read_text()
        assignment = next(line for line in script.splitlines() if line.startswith("assets_iso="))

        def path(**pins):
            values = dict(vmdir="/tmp/vm", release="debian", fc_version="fc", ch_version="ch", kernel="kernel") | pins
            return subprocess.check_output(
                ["bash", "-c", assignment + '\nprintf "%s" "$assets_iso"'], env=values, text=True
            )

        original = path()
        for pin in ["release", "fc_version", "ch_version", "kernel"]:
            with self.subTest(pin=pin):
                self.assertNotEqual(path(**{pin: "changed"}), original)


if __name__ == "__main__":
    unittest.main()
