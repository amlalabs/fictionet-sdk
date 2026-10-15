"""Offline fixtures for the VM result protocol and emulator completion checks."""

from pathlib import Path
import runpy
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


HERE = Path(__file__).resolve().parent
results = runpy.run_path(str(HERE / "results.py"))
REQUIRED = {"dns": 0, "https": 0, "nxdomain": 6, "unreachable": 7}
# The commands, outputs and diagnostic lines follow run.sh and l2-check.sh.
COMPLETE = """=== guest begin
network online 2.3 s after the kernel started
$ dig +short example.test
203.0.113.10
[exit 0]
=== guest result dns 0 12
$ curl -sS --cacert /root/ca.pem https://example.test/
hello from https example.test 443
[exit 0]
=== guest result https 0 20
$ curl -sS --max-time 10 http://nowhere.test/
curl: (6) Could not resolve host: nowhere.test
[exit 6]
[took 4 ms]
=== guest result nxdomain 6 4
$ curl -sS --max-time 10 http://192.0.2.1/
curl: (7) Failed to connect to 192.0.2.1 port 80
[exit 7]
[took 5 ms]
=== guest result unreachable 7 5
=== guest end
"""


class Results(unittest.TestCase):
    def check(self, transcript=COMPLETE, status=0):
        return results["validate"](transcript, status, REQUIRED)

    def test_complete(self):
        self.assertEqual(self.check(), [])
        self.assertEqual(self.check(COMPLETE.replace("\n", "\r\n")), [])

    def test_missing_exit(self):
        text = COMPLETE.replace("=== guest result https 0 20\n", "")
        self.assertEqual(self.check(text), ["missing guest result: https"])

    def test_duplicate_id(self):
        text = COMPLETE.replace("=== guest result https 0 20\n",
                                "=== guest result https 0 20\n" * 2)
        self.assertEqual(self.check(text), ["duplicate guest ID: https"])

    def test_truncated_boot(self):
        for text in ("", COMPLETE[:COMPLETE.index("$ curl")], COMPLETE[:-1]):
            with self.subTest(text=text):
                self.assertIn("missing guest end", self.check(text))

    def test_successful_prefix_nonzero(self):
        text = COMPLETE.replace("hello from https example.test 443\n[exit 0]",
                                "hello from https example.test 443\n[exit 56]")
        text = text.replace("=== guest result https 0 20", "=== guest result https 56 20")
        self.assertEqual(self.check(text), ["https: expected status 0, got 56"])

    def test_absent_guest_end(self):
        self.assertEqual(self.check(COMPLETE.replace("=== guest end\n", "")),
                         ["missing guest end"])

    def test_emulator_crash(self):
        for status in (1, 124, 137):
            with self.subTest(status=status):
                reason = "timed out" if status == 124 else "failed"
                self.assertEqual(self.check(status=status),
                                 [f"emulator {reason} with status {status}"])

    def test_expected_failure_requires_exact_status(self):
        for status in (0, 7, 28, 124, 127, 137):
            with self.subTest(status=status):
                text = COMPLETE.replace("=== guest result nxdomain 6 4",
                                        f"=== guest result nxdomain {status} 4")
                self.assertEqual(self.check(text),
                                 [f"nxdomain: expected status 6, got {status}"])

    def test_undeclared_id(self):
        text = COMPLETE.replace("=== guest end", "=== guest result extra 0 1\n=== guest end")
        self.assertEqual(self.check(text), ["undeclared guest ID: extra"])

    def test_missing_begin(self):
        self.assertIn("missing guest begin", self.check(COMPLETE.replace("=== guest begin\n", "")))

    def test_duplicate_and_out_of_order_records(self):
        for text in (COMPLETE * 2, "=== guest begin\n" + COMPLETE,
                     COMPLETE + "=== guest end\n", "=== guest end\n" + COMPLETE):
            with self.subTest(text=text):
                self.assertTrue(self.check(text))
        record = "=== guest result https 0 20\n"
        rest = COMPLETE.replace(record, "")
        for text in (record + rest, rest + record):
            with self.subTest(text=text):
                self.assertTrue(any("result https outside guest begin/end" in e for e in self.check(text)))

    def test_malformed_records(self):
        for record in ("=== guest result https", "=== guest result https 0",
                       "=== guest result https 256 1", "=== guest result https -1 1",
                       "=== guest result https 0 -1", "=== guest result https 0 NaN",
                       "=== guest result https 0 1 extra", "=== guest result bad/id 0 1",
                       "=== guest finished", "=== guest end extra"):
            with self.subTest(record=record):
                text = COMPLETE.replace("=== guest end", record + "\n=== guest end")
                self.assertTrue(any("malformed guest record" in e for e in self.check(text)))

    def test_legacy_diagnostics_do_not_replace_results(self):
        text = "\n".join(line for line in COMPLETE.split("\n")
                         if not line.startswith("=== guest result"))
        self.assertEqual(self.check(text), [f"missing guest result: {name}" for name in REQUIRED])

    def test_requirements(self):
        self.assertEqual(results["requirements"](["https=0", "nxdomain=6"]),
                         {"https": 0, "nxdomain": 6})
        for values in ([], ["https"], ["https=*"], ["https=-1"], ["https=256"],
                       ["=0"], ["bad/id=0"], ["https=0", "https=0"], ["https=0", "https=6"]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                results["requirements"](values)
        self.assertIn("no required guest IDs declared", results["validate"](COMPLETE, 0, {}))

    def test_producer_round_trip(self):
        script = r'''
source "$1"
results_begin
results_run https bash -c 'printf "hello from https example.test 443\n"; printf "stderr without newline" >&2; exit "$1"' guest "$2"
results_run nxdomain bash -c 'printf "Could not resolve host: nowhere.test\n" >&2; exit 6'
results_run unreachable bash -c 'printf "Failed to connect to 192.0.2.1\n" >&2; exit 7'
results_end
'''
        expected = {"https": 0, "nxdomain": 6, "unreachable": 7}
        for status in (0, 56):
            with self.subTest(status=status):
                run = subprocess.run(["bash", "-euo", "pipefail", "-c", script, "guest",
                                      str(HERE / "results.sh"), str(status)],
                                     capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stderr, "")
                self.assertIn(f"hello from https example.test 443\nstderr without newline\n[exit {status}]",
                              run.stdout)
                self.assertRegex(run.stdout, rf"\[took [0-9]+ ms\]\n=== guest result https {status} [0-9]+\n")
                errors = [] if status == 0 else ["https: expected status 0, got 56"]
                self.assertEqual(results["validate"](run.stdout, 0, expected), errors)

    def test_cli_standalone(self):
        with TemporaryDirectory() as directory:
            script = Path(directory) / "results.py"
            shutil.copyfile(HERE / "results.py", script)
            transcript = Path(directory) / "guest.txt"
            transcript.write_text(COMPLETE, encoding="utf-8")
            command = [sys.executable, "-I", str(script)]
            inventory = [arg for name, status in REQUIRED.items()
                         for arg in ("--require", f"{name}={status}")]
            for status, text, messages in (
                (0, COMPLETE, []),
                (124, COMPLETE.replace("=== guest end\n", ""),
                 ["FAIL: emulator timed out with status 124", "FAIL: missing guest end"]),
            ):
                with self.subTest(status=status):
                    transcript.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
                    run = subprocess.run(command + ["--status", str(status)] + inventory + [str(transcript)],
                                         cwd=directory, capture_output=True, text=True)
                    self.assertEqual(run.returncode, 1 if messages else 0, run.stderr)
                    self.assertEqual(run.stderr.splitlines(), messages)
            transcript.write_text(COMPLETE, encoding="utf-8")
            for args in ([], ["--status", "0"], ["--status", "invalid"] + inventory,
                         ["--status", "256"] + inventory,
                         ["--status", "124", "--status", "0"] + inventory,
                         ["--status", "0", "--status", "0"] + inventory,
                         ["--status", "0", "--require", "https=0", "--require", "https=6"]):
                with self.subTest(args=args):
                    run = subprocess.run(command + args + [str(transcript)], cwd=directory,
                                         capture_output=True, text=True)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertTrue(run.stderr)
            transcript.unlink()
            run = subprocess.run(command + ["--status", "0"] + inventory + [str(transcript)],
                                 cwd=directory, capture_output=True, text=True)
            self.assertEqual(run.returncode, 1)
            self.assertIn("No such file", run.stderr)


class EmulatorEnded(unittest.TestCase):
    def check(self, transcript, status):
        script = r'''
source "$1"
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
results_emulator_ended fixture "$2" "$3" "$4" "$5"
echo "checks continued"
if [ "$failures" -gt 0 ]; then exit 1; fi
'''
        with TemporaryDirectory() as directory:
            out = Path(directory) / "guest.txt"
            out.write_bytes(transcript.encode("utf-8"))
            vmm_log = Path(directory) / "vmm.log"
            vmm_log.write_text("emulator diagnostic\n", encoding="utf-8")
            console = Path(directory) / "console.log"
            console.write_text("console diagnostic\n", encoding="utf-8")
            run = subprocess.run(["bash", "-euo", "pipefail", "-c", script, "host",
                                  str(HERE / "results.sh"), str(status), str(out),
                                  str(vmm_log), str(console)], capture_output=True, text=True)
        self.assertEqual(run.stderr, "")
        self.assertIn("checks continued\n", run.stdout)
        return run

    def test_complete(self):
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=newline):
                run = self.check(newline.join(("=== guest begin", "[exit 0]",
                                               "=== guest end", "")), 0)
                self.assertEqual(run.returncode, 0)
                self.assertEqual(run.stdout, "checks continued\n")

    def test_failed_emulator_with_complete_output(self):
        for status in (1, 124):
            with self.subTest(status=status):
                run = self.check("=== guest begin\n[exit 0]\n=== guest end\n", status)
                self.assertEqual(run.returncode, 1)
                self.assertIn(f"FAIL: fixture: emulator exited with status {status}\n", run.stdout)
                self.assertNotIn("missing === guest end", run.stdout)
                self.assertIn("emulator diagnostic\n", run.stdout)
                self.assertIn("console diagnostic\n", run.stdout)

    def test_missing_end(self):
        for end in ("", "prefix === guest end\n", "=== guest end extra\n"):
            with self.subTest(end=end):
                run = self.check("=== guest begin\n[exit 0]\n" + end, 0)
                self.assertEqual(run.returncode, 1)
                self.assertIn("FAIL: fixture: missing === guest end\n", run.stdout)
                self.assertIn("emulator diagnostic\n", run.stdout)
                self.assertIn("console diagnostic\n", run.stdout)

    def test_failed_emulator_and_missing_end(self):
        run = self.check("", 124)
        self.assertEqual(run.returncode, 1)
        self.assertIn("FAIL: fixture: emulator exited with status 124\n", run.stdout)
        self.assertIn("FAIL: fixture: missing === guest end\n", run.stdout)
        self.assertEqual(run.stdout.count("emulator diagnostic\n"), 1)
        self.assertEqual(run.stdout.count("console diagnostic\n"), 1)


if __name__ == "__main__":
    unittest.main()
