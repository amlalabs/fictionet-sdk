"""live_demo.sh builds the demo's images from this checkout instead of pulling them."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("live_demo.sh")

# Records each call's arguments, one JSON list per line, and does nothing else.
RECORDER = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["LIVE_DEMO_CALLS"], "a") as calls:
    calls.write(json.dumps([os.path.basename(sys.argv[0])] + sys.argv[1:]) + "\\n")
"""


class LiveDemo(unittest.TestCase):
    def test_compose_up_builds_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name in ("docker", "uv"):
                path = bin_dir / name
                path.write_text(RECORDER)
                path.chmod(0o755)
            calls = root / "calls.jsonl"
            env = {k: v for k, v in os.environ.items() if not k.startswith("ADAPTIVE_WEB_")}
            env.update(PATH=f"{bin_dir}{os.pathsep}{env['PATH']}", LIVE_DEMO_CALLS=str(calls),
                       ADAPTIVE_WEB_GENERATOR="replay", ADAPTIVE_WEB_STORE_DIR=str(root / "store"))
            subprocess.run(["bash", str(SCRIPT), "halvard-cve", "a query"], env=env, check=True,
                           stdout=subprocess.DEVNULL)
            ran = [json.loads(line) for line in calls.read_text().splitlines()]
            ups = [args for args in ran if args[:2] == ["docker", "compose"] and "up" in args]
            self.assertEqual(len(ups), 1, ran)
            self.assertIn("--build", ups[0])
            self.assertEqual(ran[0], ups[0], "the stack starts before anything else runs")


if __name__ == "__main__":
    unittest.main()
