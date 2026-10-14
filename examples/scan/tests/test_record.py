import asyncio
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch


spec = importlib.util.spec_from_file_location("record", Path(__file__).parents[1] / "record.py")
record = importlib.util.module_from_spec(spec)
spec.loader.exec_module(record)

DISCOVERY = "".join(
    f"Nmap scan report for 10.0.0.{host}\nHost is up (0.004s latency).\n"
    for host in (10, 11, 12, 13, 50)
)
SERVICES = """PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.7 (protocol 2.0)
80/tcp open  http    nginx 1.26.3
"""
SUMMARY = "Nmap done: 256 IP addresses (5 hosts up) scanned in 36.36 seconds\n"
PORT_SCAN = DISCOVERY + SERVICES + SUMMARY


class ScanTests(unittest.TestCase):
    def test_complete_scans(self):
        record.validate_scan(DISCOVERY + SUMMARY)
        record.validate_scan(PORT_SCAN, services=True)

    def test_missing_host_even_with_success_summary(self):
        for host in (10, 11, 12, 13, 50):
            for services in (False, True):
                with self.subTest(host=host, services=services):
                    output = PORT_SCAN.replace(
                        f"Nmap scan report for 10.0.0.{host}\nHost is up (0.004s latency).\n", ""
                    )
                    with self.assertRaisesRegex(ValueError, "Expected hosts"):
                        record.validate_scan(output, services=services)

    def test_empty_scan(self):
        with self.assertRaisesRegex(ValueError, "Expected hosts"):
            record.validate_scan("")

    def test_host_must_be_up(self):
        with self.assertRaisesRegex(ValueError, "Expected hosts"):
            record.validate_scan(PORT_SCAN.replace("Host is up", "Host seems down", 1))

    def test_wrong_host_with_same_count(self):
        with self.assertRaisesRegex(ValueError, "Expected hosts"):
            record.validate_scan(PORT_SCAN.replace("10.0.0.13", "10.0.0.99"))

    def test_service_must_be_identified_and_open_on_expected_port(self):
        for old, new, product in [
            ("OpenSSH 9.7 (protocol 2.0)", "", "OpenSSH"),
            ("nginx 1.26.3", "Apache httpd", "nginx"),
            ("22/tcp open", "22/tcp filtered", "OpenSSH"),
            ("80/tcp open", "80/tcp closed", "nginx"),
            ("80/tcp open", "80/tcp open|filtered", "nginx"),
            ("22/tcp", "222/tcp", "OpenSSH"),
            ("80/tcp", "8080/tcp", "nginx"),
        ]:
            with self.subTest(old=old, new=new):
                with self.assertRaisesRegex(ValueError, product):
                    record.validate_scan(PORT_SCAN.replace(old, new), services=True)

    def test_services_on_another_host_do_not_count(self):
        output = DISCOVERY.replace(
            "Nmap scan report for 10.0.0.50", SERVICES + "\nNmap scan report for 10.0.0.50"
        ) + SUMMARY
        with self.assertRaisesRegex(ValueError, "OpenSSH"):
            record.validate_scan(output, services=True)


class CommandTests(unittest.IsolatedAsyncioTestCase):
    async def run_command(self, output, status, out):
        proc = AsyncMock()
        proc.stdout = asyncio.StreamReader()
        proc.stdout.feed_data(output.encode())
        proc.stdout.feed_eof()
        proc.wait.return_value = status
        page = AsyncMock()
        with patch.object(record.asyncio, "create_subprocess_exec", return_value=proc) as spawn:
            try:
                return await record.run_command(page, record.DISCOVERY, ["docker", "compose"], out)
            finally:
                spawn.assert_awaited_once_with(
                    "docker", "compose", "exec", "-T", "scanner", *record.DISCOVERY,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                )
                proc.wait.assert_awaited_once()
                self.assertEqual(
                    [call.args[1] for call in page.evaluate.await_args_list],
                    output.splitlines(keepends=True),
                )

    async def test_failed_command_preserves_output_and_previous_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / "nmap.txt").write_text("previous scan\n")
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                await self.run_command("partial output\nscanner failed\n", 2, out)
            self.assertEqual(raised.exception.returncode, 2)
            self.assertEqual(raised.exception.output, "partial output\nscanner failed\n")
            self.assertEqual(
                (out / "nmap.txt").read_text(),
                "previous scan\n$ nmap -sn -n 10.0.0.0/24\npartial output\nscanner failed\n\n",
            )

    async def test_success_returns_and_saves_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            output = await self.run_command(DISCOVERY + SUMMARY, 0, out)
            self.assertEqual(output, DISCOVERY + SUMMARY)
            self.assertEqual(
                (out / "nmap.txt").read_text(), "$ nmap -sn -n 10.0.0.0/24\n" + output + "\n"
            )


if __name__ == "__main__":
    unittest.main()
