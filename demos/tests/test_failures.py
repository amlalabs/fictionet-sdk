"""Launcher failures must stop the demo and retain diagnostics."""

import os
from pathlib import Path
import runpy
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class Failures(unittest.TestCase):
    def shell(self, command):
        return subprocess.run(
            ['bash', '-c', f'. "{ROOT}/demos/guest/lib.sh"; AGENT=(); {command}'],
            capture_output=True, text=True,
        )

    def test_required_agent_failure_stops_script(self):
        result = self.shell("agent 'exit 7'; echo continued")
        self.assertEqual(result.returncode, 7)
        self.assertNotIn('continued', result.stdout)

    def test_required_command_sequence_stops_at_first_failure(self):
        result = self.shell("agent 'false; true'; echo continued")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('continued', result.stdout)

    def test_described_pipeline_failure_stops_script(self):
        result = self.shell("described fetch 'exit 7 | cat'; echo continued")
        self.assertEqual(result.returncode, 7)
        self.assertNotIn('continued', result.stdout)

    def test_expected_failure_continues(self):
        result = self.shell("expect_fail 'exit 7'; echo continued")
        self.assertEqual(result.returncode, 0)
        self.assertIn('continued', result.stdout)

    def test_unexpected_success_stops_script(self):
        result = self.shell("expect_fail 'true'; echo continued")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected the command to fail', result.stderr)
        self.assertNotIn('continued', result.stdout)

    def test_border_start_failure_keeps_diagnostics(self):
        script = (ROOT / 'demos/guest/border.sh').read_text()
        start = re.search(r'^start\(\) \{.*?^}', script, re.M | re.S).group()
        result = subprocess.run(['bash', '-e', '-c',
                                 "compose=(bash -c 'echo border-start-failed >&2; exit 17' --)\n"
                                 + start + '\nstart legitimate'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 17)
        self.assertIn('border-start-failed', result.stderr)

    def test_border_empty_log_fails(self):
        script = (ROOT / 'demos/guest/border.sh').read_text()
        pipeline = script.split('world_log | ', 1)[1].split('\n\nstep', 1)[0]
        result = subprocess.run(['bash', '-o', 'pipefail', '-c', pipeline],
                                input='', capture_output=True, text=True)
        self.assertEqual(result.returncode, 4)

    def test_hosted_start_failure_skips_checks_and_cleans_up(self):
        module = runpy.run_path(str(ROOT / 'examples/hosted/run_hosted.py'))
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            return (23, 'startup failed') if ' up ' in command else (0, '')

        with self.assertRaises(SystemExit) as error:
            module['up_and_check'](run, 'cd /example &&', '')
        self.assertEqual(error.exception.code, 23)
        self.assertFalse(any('check.sh' in command for command in commands))
        self.assertIn(' down ', commands[-1])
        self.assertNotIn('|', commands[0])

    def test_hosted_check_failure_survives_cleanup(self):
        module = runpy.run_path(str(ROOT / 'examples/hosted/run_hosted.py'))
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            return (19, 'check failed') if 'check.sh' in command else (0, '')

        with self.assertRaises(SystemExit) as error:
            module['up_and_check'](run, '', '')
        self.assertEqual(error.exception.code, 19)
        self.assertIn(' down ', commands[-1])

    def test_hosted_readme_keeps_directory_and_check_status(self):
        readme = (ROOT / 'examples/hosted/README.md').read_text()
        recipe = readme.split('# Local Docker\n', 1)[1].split('# Daytona', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosted = root / 'examples/hosted'
            hosted.mkdir(parents=True)
            check = hosted / 'check.sh'
            check.write_text('#!/bin/sh\nexit 29\n')
            check.chmod(0o755)
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\nexit 0\n')
            docker.chmod(0o755)
            env = dict(os.environ, PATH=f'{root}:' + os.environ['PATH'])
            result = subprocess.run(['sh', '-c', recipe + '\nstatus=$?; pwd; exit "$status"'],
                                    cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 29)
            self.assertEqual(result.stdout.strip(), str(root))

    def test_adaptive_start_failure_keeps_output_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            docker = Path(directory) / 'docker'
            calls = Path(directory) / 'calls'
            docker.write_text('#!/bin/sh\necho "$*" >> "$CALLS"\ncase "$*" in *" up "*) echo startup-failed >&2; exit 17;; esac\n')
            docker.chmod(0o755)
            env = dict(os.environ, PATH=f'{directory}:' + os.environ['PATH'], CALLS=str(calls),
                       ADAPTIVE_WEB_GENERATOR='stub', ADAPTIVE_WEB_STORE_DIR=directory)
            result = subprocess.run(['bash', str(ROOT / 'examples/adaptive-web/scripts/live_demo.sh'),
                                     'halvard-cve', 'query'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 17)
            self.assertIn('startup-failed', result.stderr)
            self.assertIn(' down ', calls.read_text())

    def adaptive_client(self, response):
        script = (ROOT / 'examples/adaptive-web/scripts/live_demo.sh').read_text()
        client = script.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        with patch('sys.argv', ['-', 'query']), patch('subprocess.run', return_value=response):
            exec(compile(client, 'live_demo client', 'exec'), {})

    def test_adaptive_curl_failure_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'curl failed'):
            self.adaptive_client(subprocess.CompletedProcess([], 7, '\n000 0.1', 'connection failed'))

    def test_adaptive_empty_results_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'expected 10'):
            self.adaptive_client(subprocess.CompletedProcess([], 0, '<html></html>\n200 0.1', ''))

    def test_adaptive_pages_are_fetched_after_ten_results(self):
        body = ''.join(f'<div class="yuRUbf"><a href="https://example.test/{i}"><h3>Page {i}</h3>'
                       '<div class="VwiC3b">Snippet</div>' for i in range(10))
        script = (ROOT / 'examples/adaptive-web/scripts/live_demo.sh').read_text()
        client = script.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        search = subprocess.CompletedProcess([], 0, body + '\n200 0.1', '')
        page = subprocess.CompletedProcess([], 0, '<html>Page</html>\n200 0.1', '')
        with patch('sys.argv', ['-', 'query']), patch('subprocess.run', side_effect=[search, page, page, page]) as run:
            exec(compile(client, 'live_demo client', 'exec'), {})
        self.assertEqual(run.call_count, 4)
        self.assertEqual(run.call_args_list[-1].args[0][-1], 'https://example.test/2')
        self.assertIn('-f', run.call_args.args[0])

    def test_adaptive_defaults_come_from_selected_seed(self):
        script = (ROOT / 'examples/adaptive-web/scripts/live_demo.sh').read_text()
        code = script.split("<<'PYSEED'\n", 1)[1].split('\nPYSEED', 1)[0]
        result = subprocess.run(['python3', '-c', code, 'corvane-acquisition'],
                                cwd=ROOT / 'examples/adaptive-web', capture_output=True, text=True, check=True)
        self.assertIn('Corvane', result.stdout)
        self.assertNotIn('Halvard', result.stdout)


if __name__ == '__main__':
    unittest.main()
