"""Launcher failures must stop the demo and retain diagnostics."""

import os
from pathlib import Path
import runpy
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]

CA = """-----BEGIN CERTIFICATE-----
MIIBfjCCASOgAwIBAgIUXTPmZFNqiy55DXYFjxBijg9nCEUwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJZGVtby10ZXN0MB4XDTI2MTAxNDIxNTQzOFoXDTM2MTAxMTIx
NTQzOFowFDESMBAGA1UEAwwJZGVtby10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEYY/pl05nVwgSouSZvxW77WNZsUfDQPRd1BxsLXcVu1+CC6yKGLOX+6Q5
5eu8/f8gqR14h5oczaYg+quLPby+hKNTMFEwHQYDVR0OBBYEFJrdgO5hl7N9gEan
woJ0kXhVbzYXMB8GA1UdIwQYMBaAFJrdgO5hl7N9gEanwoJ0kXhVbzYXMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAL/BgLw5XnZiWGTwW3CixmGZ
kmu8qO18sMF8hhCoPU5bAiEAmxKwDG8vcmMhgNqbgxdaXe3y+MNXYmEa6F5jMiT/
lXc=
-----END CERTIFICATE-----
"""


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
        result = self.shell("expect_fail 7 'exit 7'; echo continued")
        self.assertEqual(result.returncode, 0)
        self.assertIn('continued', result.stdout)

    def test_unexpected_success_stops_script(self):
        result = self.shell("expect_fail 7 'true'; echo continued")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('wanted refusal status 7, got 0', result.stderr)
        self.assertNotIn('continued', result.stdout)

    def refusal(self, status, command, pattern=''):
        return self.shell(shlex.join(['expect_fail', str(status), pattern, command])
                          + '; echo continued')

    def assert_stopped(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn('continued', result.stdout)

    def test_missing_binary_is_not_refusal(self):
        result = self.shell("AGENT=(bash -c 'echo runner-missing >&2; exit 127' --); "
                            "expect_fail 60 'certificate' 'exit 60'; echo continued")
        self.assert_stopped(result)
        self.assertIn('got 127', result.stderr)
        self.assertIn('    runner-missing', result.stdout)

    def test_unrelated_exit_7(self):
        result = self.refusal(60, 'echo certificate >&2; exit 7', 'certificate')
        self.assert_stopped(result)
        self.assertIn('wanted refusal status 60, got 7', result.stderr)

    def test_wrong_reason_is_not_refusal(self):
        result = self.refusal(2, 'echo Cannot find device >&2; exit 2',
                              'Operation not permitted')
        self.assert_stopped(result)
        self.assertIn('Operation not permitted', result.stderr)
        self.assertIn('    Cannot find device', result.stdout)

    def test_demo_refusals_follow_world_semantics(self):
        # curl.se/docs/manpage.html#exit-codes. tests/k8s/run.sh also checks
        # Could not resolve host, Couldn't connect, no servers could be reached
        # and Operation not permitted. tests/docker/proxy/run.sh checks response
        # 407, connection to nope.test. (4), and Network is unreachable|Couldn't
        # connect. No route to host is in tests/docker/web/run.sh and
        # vm/guest/tests/netns.sh. Only tool docs supply curl 60 with SSL
        # certificate problem and GNU ls 2 with Permission denied when another user
        # lists a mode-0700 directory. web_world.rs declares
        # NXDOMAIN for other names. The raw TCP connect receives ICMP host
        # unreachable; dig cannot reach cluster DNS; the agent lacks NET_ADMIN.
        cases = {
            'web': [(60, 'SSL certificate problem'), (1, 'No route to host'),
                    (6, 'Could not resolve host'), (6, 'Could not resolve host'),
                    (7, "Couldn't connect to server")],
            'border': [(60, 'SSL certificate problem')],
            'k8s': [(7, "Couldn't connect to server"), (9, 'no servers could be reached'),
                    (7, "Couldn't connect to server"), (2, 'Operation not permitted')],
            'proxy': [(56, 'CONNECT tunnel failed, response 407'),
                      (97, "Can't complete SOCKS5 connection to nope.test. (4)"),
                      (7, 'Network is unreachable'), (2, 'Permission denied')],
        }
        for demo, refusals in cases.items():
            lines = (ROOT / f'demos/guest/{demo}.sh').read_text().splitlines()
            lines = [line for line in lines if line.startswith('expect_fail ')]
            self.assertEqual(len(lines), len(refusals), demo)
            for line, (status, diagnostic) in zip(lines, refusals):
                with self.subTest(demo=demo, command=line):
                    # Exercise the actual call, including its patterns. No world
                    # or tool is run; the runner supplies the protocol evidence.
                    prefix = 'bank=https://bank.test; kube_dns=10.96.0.10; api=10.96.0.1; '
                    for actual, output in ((status, diagnostic), (7, 'unrelated failure'),
                                           (status, 'unrelated failure'), (127, diagnostic)):
                        runner = f'printf "%s\\n" {shlex.quote(output)} >&2; exit {actual}'
                        result = self.shell(prefix + f'AGENT=(bash -c {shlex.quote(runner)} --); '
                                            + line + '; echo continued')
                        if actual == status and output == diagnostic:
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertIn('continued', result.stdout)
                        else:
                            self.assert_stopped(result)

    def test_immediate_refusal_has_a_deadline(self):
        script = (ROOT / 'demos/guest/web.sh').read_text()
        line = next(line for line in script.splitlines() if '/dev/tcp/' in line)
        command = shlex.split(shlex.split(line)[-1])
        self.assertEqual(command[:4], ['time', 'timeout', '3', 'bash'])
        self.assertEqual(command[4:], ['-c', 'exec 3<>/dev/tcp/192.0.2.1/80'])

    def test_runner_death_is_not_host_unreachable(self):
        result = self.shell("AGENT=(bash -c 'echo runner-died >&2; exit 1' --); "
                            "expect_fail 1 'No route to host' 'exit 1'; echo continued")
        self.assert_stopped(result)
        self.assertIn('    runner-died', result.stdout)

    def test_timeouts_execution_errors_and_signals_cannot_be_expected(self):
        for status in (0, 124, 126, 127, 129, 137, 141, 255):
            with self.subTest(status=status):
                result = self.refusal(status, f'echo denied >&2; exit {status}', 'denied')
                self.assert_stopped(result)
                self.assertIn(f'got {status}', result.stderr)

    def test_timeout_is_not_host_unreachable(self):
        result = self.refusal(1, 'echo No route to host >&2; exit 124', 'No route to host')
        self.assert_stopped(result)
        self.assertIn('got 124', result.stderr)

    def test_refusal_matches_raw_combined_output(self):
        result = self.refusal(60, "printf 'stdout\\n'; printf 'certificate\\n' >&2; exit 60",
                              '^certificate$')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('    stdout\n    certificate\ncontinued\n', result.stdout)

    def test_formatter_cannot_supply_the_refusal_status(self):
        command = '(seq 1 100000; exit 60)'
        result = self.refusal(60, command + ' | head -1')
        self.assert_stopped(result)
        self.assertIn('got 141', result.stderr)
        result = self.refusal(60, command, '^100000$')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('    1\n    2\n', result.stdout)
        self.assertIn('    100000\ncontinued\n', result.stdout)

    def proxy_response(self, response, status=0):
        script = (ROOT / 'demos/guest/proxy.sh').read_text()
        command = next(line for line in script.splitlines() if 'http://nope.test/' in line)
        return self.shell(f'curl() {{ printf %s {shlex.quote(response)}; return {status}; }}; '
                          f'export -f curl; {command}; echo continued')

    def test_HTTP_200_not_502(self):
        result = self.proxy_response('HTTP/1.1 200 OK\r\n'
                                     'X-Proxy-Error: no such name in the world\r\n')
        self.assert_stopped(result)

    def test_missing_proxy_marker(self):
        self.assert_stopped(self.proxy_response('HTTP/1.1 502 Bad Gateway\r\n'))

    def test_proxy_requires_the_exact_explanation(self):
        for response in ('X-Proxy-Error: no such name in the world\r\n',
                         'HTTP/1.1 502 Bad Gateway\r\nX-Proxy-Error: connection refused\r\n',
                         'prefix HTTP/1.1 502 Bad Gateway\r\n'
                         'X-Proxy-Error: no such name in the world\r\n',
                         'HTTP/1.1 502 Bad Gateway\r\nprefix '
                         'X-Proxy-Error: no such name in the world\r\n',
                         'HTTP/1.1 502 Bad Gateway\r\n'
                         'X-Proxy-Error: no such name in the worldly\r\n'):
            with self.subTest(response=response):
                self.assert_stopped(self.proxy_response(response))

    def test_proxy_status_and_explanation_continue(self):
        response = ('HTTP/1.1 502 Bad Gateway\r\n'
                    'X-Proxy-Error: no such name in the world\r\n\r\n')
        result = self.proxy_response(response)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('continued', result.stdout)
        self.assert_stopped(self.proxy_response(response, status=7))

    def test_output_requires_patterns_and_success(self):
        for command in ("expect_output 'true'", "expect_output 'echo hello' ''",
                        "expect_output 'echo hello' '['",
                        "expect_output 'echo hello' '^goodbye$'",
                        "expect_output 'echo hello; exit 7' '^hello$'"):
            with self.subTest(command=command):
                self.assert_stopped(self.shell(command + '; echo continued'))

    def test_output_success_displays_only_matching_lines(self):
        result = self.shell(
            "emit() { printf 'before\\nfirst\\nboth\\n'; "
            "printf 'second\\nafter\\n' >&2; }; export -f emit; "
            "expect_output emit '^second$|^both$' '^first$|^both$'; echo continued")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'agent$ emit\n    first\n    both\n    second\ncontinued\n')
        self.assertEqual(result.stderr, '')

    def test_output_failed_command_displays_whole_capture(self):
        result = self.shell(
            "emit() { printf 'before\\nfirst\\n'; "
            "printf 'second\\nafter\\n' >&2; return 7; }; export -f emit; "
            "expect_output emit '^first$' '^second$'; echo continued")
        self.assert_stopped(result)
        self.assertEqual(result.stdout, 'agent$ emit\n    before\n    first\n    second\n    after\n')
        self.assertIn('wanted status 0, got 7', result.stderr)

    def test_output_missing_pattern_displays_whole_capture_and_stops(self):
        for patterns in (['^missing$'], ['^first$', '^missing$']):
            with self.subTest(patterns=patterns):
                result = self.shell(
                    "emit() { printf 'before\\nfirst\\n'; "
                    "printf 'after\\n' >&2; }; export -f emit; "
                    + shlex.join(['expect_output', 'emit', *patterns]) + '; echo continued')
                self.assert_stopped(result)
                self.assertEqual(result.stdout, 'agent$ emit\n    before\n    first\n    after\n')
                self.assertIn('wanted output matching /^missing$/', result.stderr)

    def test_demo_checks_do_not_gate_on_display_filters(self):
        for path in sorted((ROOT / 'demos/guest').glob('*.sh')):
            if path.name == 'lib.sh':
                continue
            for line in path.read_text().splitlines():
                with self.subTest(path=path.name, line=line):
                    self.assertNotRegex(line, r'^\s*show\s')
                    self.assertNotRegex(line, r'^\s*agent\s.*\|\s*grep\b')
                    if re.match(r'^\s*expect_\w+\s', line):
                        args = shlex.split(line)
                        self.assertIn(args[0], ('expect_fail', 'expect_output'))
                        if args[0] == 'expect_fail':
                            self.assertEqual(len(args), 4)
                            self.assertTrue(args[1].isdigit())
                            self.assertTrue(args[2])
                            self.assertNotRegex(args[3], r'\|\s*(head|tail|grep)\b')

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

    def dashboard_watch(self, output, status):
        script = (ROOT / 'demos/guest/dashboard.sh').read_text()
        section = script.split('step "The same API from a shell: fictionet observe"', 1)[1]
        section = section.split('\nstep ', 1)[0]
        command = section[section.rindex('\nvm "') + 1:].strip()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fictionet = root / 'fictionet'
            fictionet.write_text(f'#!/bin/sh\nprintf "%s" {shlex.quote(output)}\nexit {status}\n')
            fictionet.chmod(0o755)
            command = command.replace('/run/', f'{root}/')
            # lib.sh prepends its own bin directory; put the stub first after sourcing it.
            return self.shell(f'export PATH={shlex.quote(directory)}:$PATH; '
                              + command + '\necho continued')

    def test_dashboard_observer_start_failure(self):
        self.assert_stopped(self.dashboard_watch('', 1))

    def test_dashboard_empty_capture(self):
        for status in (0, 124):
            with self.subTest(status=status):
                self.assert_stopped(self.dashboard_watch('', status))

    def test_dashboard_missing_required_event(self):
        event = '{"event":"event","data":{"source":"dns","kind":"query","summary":"example.test"}}\n'
        self.assert_stopped(self.dashboard_watch(event, 124))

    def test_dashboard_http_capture_accepts_completion_and_deadline(self):
        event = '{"event":"event","data":{"source":"http","kind":"request","summary":"GET /"}}\n'
        for status in (0, 124):
            with self.subTest(status=status):
                result = self.dashboard_watch(event, status)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('    {"source":"http","kind":"request","summary":"GET /"}', result.stdout)
                self.assertIn('continued', result.stdout)
        self.assert_stopped(self.dashboard_watch(event, 1))

    def test_dashboard_malformed_capture(self):
        event = '{"event":"event","data":{"source":"http","kind":"request","summary":"GET /"}}\n'
        self.assert_stopped(self.dashboard_watch(event + '{truncated', 124))

    def test_dashboard_background_job_failure(self):
        script = (ROOT / 'demos/guest/dashboard.sh').read_text()
        start = script.index('"${AGENT[@]}" bash -')
        command = script[start:script.index('\ntraffic_pid=$!', start)]
        self.assertTrue(command.endswith(' &'))
        command = command.removesuffix(' &')
        for failed_fetch in ('https://example.test/', 'http://plain.test/'):
            with self.subTest(failed_fetch=failed_fetch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                stubs = {
                    'dig': 'exit 0',
                    'curl': f'case "$*" in *{failed_fetch}*) echo traffic-failed >&2; exit 7;; esac',
                    # Stop an unchecked loop without waiting or spinning forever.
                    'sleep': 'echo unexpected-sleep >&2; kill -TERM "$PPID"',
                }
                for name, body in stubs.items():
                    stub = root / name
                    stub.write_text('#!/bin/sh\n' + body + '\n')
                    stub.chmod(0o755)
                result = self.shell(f'export PATH={shlex.quote(directory)}:$PATH; '
                                    + command.replace('/run/', f'{root}/') + '\necho continued')
                self.assertEqual(result.returncode, 7, result.stderr)
                self.assertNotIn('continued', result.stdout)
                log = (root / 'traffic.log').read_text()
                self.assertIn('traffic-failed', log)
                self.assertNotIn('unexpected-sleep', log)

    def test_dashboard_checks_traffic_after_start_and_before_cleanup(self):
        script = (ROOT / 'demos/guest/dashboard.sh').read_text()
        checks = list(re.finditer(r'^if ! kill -0 "\$traffic_pid".*?^fi$', script, re.M | re.S))
        self.assertEqual(len(checks), 2)
        self.assertLess(script.index('sleep 3\n'), checks[0].start())
        self.assertLess(checks[0].end(), script.index('step "The same API'))
        self.assertLess(script.index('sleep "$seconds"\nfi'), checks[1].start())
        self.assertLess(checks[1].end(), script.index('step "Clean up"'))
        for check in checks:
            with self.subTest(check=check.start()), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'traffic.log').write_text('traffic-failed\n')
                command = check.group().replace('/run/', f'{root}/')
                result = self.shell("bash -c 'exit 7' & traffic_pid=$!; "
                                    'status=0; wait "$traffic_pid" || status=$?; [[ $status -eq 7 ]];\n'
                                    + command + '\necho continued')
                self.assert_stopped(result)
                self.assertIn('traffic-failed', result.stderr)
                result = self.shell('traffic_pid=$$;\n' + command + '\necho continued')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('continued', result.stdout)

    def web_start(self, scenario):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'complete.pem').write_text(CA)
            for name in ('ticks', 'acks'):
                os.mkfifo(root / name)
            # Each readiness sleep advances the fake world by one step.
            # The handshake makes partial publication independent of timing.
            (root / 'world.py').write_text('''
from pathlib import Path
import socket
import sys

sock = socket.socket(socket.AF_UNIX)
sock.bind(sys.argv[1])
ca = Path(sys.argv[2])
scenario = sys.argv[3]
print('fake world startup', flush=True)
with open('ticks') as ticks, open('acks', 'w') as acks:
    for step, _ in enumerate(ticks, 1):
        if scenario == 'exit':
            sys.exit(17)
        if scenario in ('partial', 'unfinished'):
            ca.write_text(Path('complete.pem').read_text()[:100])
        if scenario == 'invalid':
            ca.write_text('-----BEGIN CERTIFICATE-----\\ninvalid\\n-----END CERTIFICATE-----\\n')
        if step >= 2 and scenario in ('delayed', 'partial'):
            ca.write_text(Path('complete.pem').read_text())
        acks.write('done\\n')
        acks.flush()
''')
            script = (ROOT / 'demos/guest/web_setup.sh').read_text().replace('/run/', f'{root}/')
            command = f'''
. {shlex.quote(str(ROOT / 'demos/guest/lib.sh'))}
{script}
exec 3<>ticks 4<>acks
polls=0
web_world() {{ exec python3 world.py "$@" {shlex.quote(scenario)}; }}
sleep() {{
    polls=$((polls + 1))
    printf 'tick\\n' >&3
    if [[ {shlex.quote(scenario)} == exit ]]; then
        wait "$world_pid" || true
    else
        read -r -u 4
    fi
}}
trap 'stop_pid "${{world_pid:-}}"; echo "polls=$polls"' EXIT
start_web
echo ready
cmp fictionet/ca.pem complete.pem
'''
            return subprocess.run(['bash', '-c', command], cwd=root,
                                  capture_output=True, text=True, timeout=15)

    def test_web_waits_for_complete_ca(self):
        for scenario in ('delayed', 'partial'):
            with self.subTest(scenario=scenario):
                result = self.web_start(scenario)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('ready', result.stdout)
                self.assertIn('polls=2', result.stdout)

    def test_web_ca_timeout_keeps_diagnostics(self):
        for scenario in ('missing', 'unfinished', 'invalid'):
            with self.subTest(scenario=scenario):
                result = self.web_start(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('ready', result.stdout)
                self.assertIn('timed out', result.stderr)
                self.assertIn('ca.pem', result.stderr)
                self.assertIn('fake world startup', result.stderr)
                self.assertIn('polls=100', result.stdout)

    def test_web_exit_before_ca_keeps_diagnostics(self):
        result = self.web_start('exit')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('ready', result.stdout)
        self.assertIn('exited before', result.stderr)
        self.assertIn('fake world startup', result.stderr)
        self.assertIn('polls=1', result.stdout)

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

    def test_local_hosted_recipe_keeps_directory_and_check_status(self):
        guide = (ROOT / 'docs/guide/attaching.rs').read_text()
        section = guide.split('//! ## Run it locally first\n', 1)[1].split('//! ## ', 1)[0]
        block = section.split('//! ```sh\n', 1)[1].split('//! ```', 1)[0]
        lines = [line.removeprefix('//! ') for line in block.splitlines()]
        recipe = '\n'.join(lines[lines.index('('):lines.index(')') + 1])
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
