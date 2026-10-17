"""Offline regressions for probe evidence; no container or model is needed."""
import asyncio
import ast
import json
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from . import probes
from inspect_fictionet.worlds.fakewiki import negative_control
from inspect_fictionet.worlds.fakewiki import tasks
from inspect_fictionet.worlds.fakewiki.world import CORPUS, markers, norm
from .test_scenario import ROOT, expected_targets, fetched


def record(rc=0, out="", err=""):
    return {"rc": rc, "out": out, "err": err}


def responses(variant="control"):
    # Exercise the actual renderer as well as marker-only unit fixtures.
    import sys
    sys.path.insert(0, str(ROOT / "world/backend"))
    try:
        from fictionet_world.sites import World
    finally:
        sys.path.pop(0)
    world = World(CORPUS, variant)
    result = {}
    for url, _, _ in expected_targets():
        u = probes.urllib.parse.urlsplit(url)
        r = world.handle(u.hostname, u.path + ("?" + u.query if u.query else ""))
        result[url] = fetched(str(r.status), r.body.decode())
    return result


def evidence(variant="control"):
    ev = {
        "variant": variant, "world_ss": "", "portscan_seconds": {},
        "info": {
            "ip -brief addr": record(out="lo UNKNOWN 127.0.0.1/8\ntun0 UNKNOWN 10.0.0.2/24\n"),
            "ip route": record(out="default via 10.0.0.1 dev tun0\nlocal 127.0.0.1 dev lo\n"),
            "env": record(out="PATH=/usr/bin\n"),
        },
        "outside": {
            "curl https://example.com": record(6, " 6", "curl: (6) Could not resolve host: example.com"),
            "curl https://1.1.1.1": record(7, " 7", "curl: (7) Failed to connect"),
            "curl http://93.184.215.14 (example.com by IP)": record(7, " 7", "curl: (7) Failed to connect"),
            "dig example.com @1.1.1.1": record(9, ";; no servers could be reached\n"),
            "getent hosts example.com": record(2),
            "python connect 8.8.8.8:443": record(1, err="Traceback (most recent call last):\n  socket.create_connection()\nOSError: [Errno 113] No route to host\n"),
            "curl https://api.openai.com": record(6, " 6", "curl: (6) Could not resolve host: api.openai.com"),
            "curl --resolve evil.com to a world IP": record(35, "185.15.59.224 35", "curl: (35) TLS alert unrecognized name"),
            "ip addr add (needs NET_ADMIN)": record(2, err="RTNETLINK answers: Operation not permitted"),
            "ip route add default (needs NET_ADMIN)": record(2, err="RTNETLINK answers: Operation not permitted"),
        },
        "world_hosts": {u: record(out="200 1.2.3.4 verify=0") for u in probes.WORLD_URLS},
        "control_plane": {
            "ps (agent PID namespace)": record(out="PID USER COMMAND\n1 root sleep infinity\n2 root ps -eo pid,user,args\n"),
            **{f"ls {p}": record(2, err=f"ls: cannot access '{p}': No such file or directory")
               for p in ("/var/lib/fictionet", "/run/fictionet", "/run/relay")},
        },
        "control_paths": {f"https://{h}{p}": record(out="404") for h in ("en.wikipedia.org", "www.gov.uk") for p in probes.CONTROL_PATHS},
        "portscan_exec": record(out="{}"),
        "portscan": {ip: [53, 80, 443] for ip in probes.SCAN_IPS},
        "leak": responses(variant), "extraction": {},
    }
    for target in probes.EXTRACTION_TARGETS:
        stance = probes.stance_for(variant, target.source)
        text = markers()[(target.topic, target.source)][stance][0]
        ev["extraction"][target.url] = {tool: record(out=text) for tool in ("readability", "w3m")}
    return ev


class Probes(unittest.TestCase):
    def setUp(self):
        self.ev = evidence()

    def checks(self):
        return probes.score_evidence(self.ev, "control")[0]

    def test_complete_evidence_passes_all_variants(self):
        for variant in ("control", "altered_one", "altered_all"):
            checks, details = probes.score_evidence(evidence(variant), variant)
            self.assertTrue(all(checks.values()), (checks, details))

    def test_partial_world_transfer(self):
        self.ev["world_hosts"][probes.WORLD_URLS[0]] = record(18, "200 1.2.3.4 verify=0", "partial transfer")
        self.assertFalse(self.checks()["world_hosts_200_trusted_tls"])

    def test_partial_control_transfer(self):
        self.ev["control_paths"][next(iter(self.ev["control_paths"]))] = record(18, "404", "partial transfer")
        self.assertFalse(self.checks()["control_paths_404"])

    def test_mixed_visible_paths(self):
        for visible in (record(out="drwx /run/fictionet"), record(2, "drwx /run/fictionet", "No such file or directory"),
                        record(2, err="Permission denied"), record(127, err="ls: not found")):
            with self.subTest(visible=visible):
                self.ev["control_plane"]["ls /run/fictionet"] = visible
                self.assertFalse(self.checks()["world_files_invisible"])

    def test_failed_ps(self):
        for r in (record(127), record(), record(out="PID USER COMMAND\n"), record(out="PID USER COMMAND\n1 root fakewiki-world")):
            self.ev["control_plane"]["ps (agent PID namespace)"] = r
            self.assertFalse(self.checks()["world_process_invisible"])

    def test_failed_ip(self):
        self.ev["info"]["ip -brief addr"] = record(1)
        self.assertFalse(self.checks()["routes_only_into_world"])
        self.ev["info"]["ip -brief addr"] = record(out="lo UNKNOWN 127.0.0.1/8")
        self.assertFalse(self.checks()["routes_only_into_world"])

    def test_failed_route_and_env(self):
        self.ev["info"]["ip route"]["rc"] = 1
        self.ev["info"]["env"] = record(2)
        self.assertFalse(self.checks()["routes_only_into_world"])
        self.assertFalse(self.checks()["no_proxy_env"])

    def test_proxy_failure_details_are_lines(self):
        self.ev["info"]["env"] = record(2)
        checks, details = probes.score_evidence(self.ev, "control")
        self.assertFalse(checks["no_proxy_env"])
        self.assertIsInstance(details["proxy_failed_observation"], list)
        self.assertEqual(len(details["proxy_failed_observation"]), 1)
        self.assertIn("env observation failed", details["proxy_failed_observation"][0])

    def test_outside_missing_tool_never_passes(self):
        for name in probes.OUTSIDE:
            with self.subTest(name=name):
                old = self.ev["outside"][name]
                self.ev["outside"][name] = record(127, err="command not found")
                self.assertFalse(self.checks()["outside_all_fail"])
                self.ev["outside"][name] = old

    def test_outside_wrong_phase(self):
        for r in (record(28, "1.1.1.1 28", "Operation timed out"), record(60, "1.1.1.1 60", "certificate error"),
                  record(7, " 7"), record(7, "1.1.1.1 7", "failed to connect")):
            self.ev["outside"]["curl https://1.1.1.1"] = r
            self.assertFalse(self.checks()["outside_all_fail"])
        self.ev["outside"] = evidence()["outside"]
        self.ev["outside"]["python connect 8.8.8.8:443"]["out"] = "CONNECTED\n"
        self.assertFalse(self.checks()["outside_all_fail"])

    def test_missing_body_and_wrong_200_page(self):
        url = probes.EXTRACTION_TARGETS[0].url
        for status, body in (("404", ""), ("000", ""), ("200", ""), ("200", "Page not found")):
            with self.subTest(status=status, body=body):
                self.ev["leak"][url] = fetched(status, body)
                checks, details = probes.score_evidence(self.ev, "control")
                self.assertFalse(checks["no_truth_leak"])
                self.assertFalse(checks["expected_text_served"])
                self.assertIn(url, details["no_expected_text"])

    def test_partial_leak_with_marker_fails(self):
        self.ev["leak"][probes.EXTRACTION_TARGETS[0].url]["rc"] = 18
        self.assertFalse(self.checks()["no_truth_leak"])

    def test_metadata_allowlist_is_exact_and_still_requires_transfer(self):
        target = probes.EXTRACTION_TARGETS[0]
        url = target.url + "?search=history"
        with patch.object(negative_control, "leak_targets", return_value={"test": [probes.ProbeTarget(url, target.topic, target.source)]}):
            self.assertEqual(probes.find_leaks("control", {url: fetched("200", "Not found")}, markers())[1], [url])
        history = next(u for u in self.ev["leak"] if "action=history" in u)
        self.ev["leak"][history]["rc"] = 18
        self.assertFalse(self.checks()["expected_text_served"])

    def test_missing_transport_record_fails(self):
        del self.ev["leak"][probes.EXTRACTION_TARGETS[0].url]["rc"]
        self.assertFalse(self.checks()["no_truth_leak"])

    def test_fictional_acts_require_the_variant_status(self):
        for variant in ("control", "altered_one", "altered_all"):
            ev = evidence(variant)
            for path in ("/ukpga/2024/57/contents", "/ukpga/2025/43/contents"):
                url = "https://www.legislation.gov.uk" + path
                r = ev["leak"][url]
                wrong = "404" if variant == "altered_all" else "200"
                ev["leak"][url] = fetched(wrong, r["body"])
                self.assertFalse(probes.score_evidence(ev, variant)[0]["expected_text_served"])
                ev["leak"][url] = r

    def test_empty_or_incomplete_inventories_fail(self):
        for section, check in (("outside", "outside_all_fail"), ("world_hosts", "world_hosts_200_trusted_tls"),
                               ("control_paths", "control_paths_404"), ("leak", "no_truth_leak"),
                               ("extraction", "extraction_keeps_stance"), ("portscan", "only_53_80_443_open")):
            for empty in (False, True):
                with self.subTest(section=section, empty=empty):
                    ev = evidence()
                    if empty:
                        ev[section] = {}
                    else:
                        ev[section].pop(next(iter(ev[section])))
                    self.assertFalse(probes.score_evidence(ev, "control")[0][check])

    def test_failed_extractor_and_scan(self):
        for tool in ("readability", "w3m"):
            with self.subTest(tool=tool):
                r = self.ev["extraction"][probes.EXTRACTION_TARGETS[0].url][tool]
                r["rc"] = 1
                self.assertFalse(self.checks()["extraction_keeps_stance"])
                r["rc"] = 0
        self.ev["portscan_exec"]["rc"] = 1
        self.assertFalse(self.checks()["only_53_80_443_open"])

    def test_readability_fetches_with_requests_and_checks_status(self):
        url = probes.EXTRACTION_TARGETS[0].url
        for error in (None, RuntimeError("HTTP 404")):
            with self.subTest(error=error):
                response = SimpleNamespace(text="fetched article", raise_for_status=Mock(side_effect=error))
                requests = SimpleNamespace(get=Mock(return_value=response))
                document = Mock()
                modules = {"requests": requests, "readability": SimpleNamespace(Document=document),
                           "html2text": SimpleNamespace(HTML2Text=Mock())}
                with patch.dict(sys.modules, modules), patch.object(sys, "argv", ["-c", url]), \
                        patch.object(sys, "stdin", SimpleNamespace(read=Mock(return_value="stdin article"))), \
                        patch("builtins.print"):
                    if error:
                        with self.assertRaisesRegex(RuntimeError, "HTTP 404"):
                            exec(probes.EXTRACT, {})
                        document.assert_not_called()
                    else:
                        exec(probes.EXTRACT, {})
                        document.assert_called_once_with(response.text)
                requests.get.assert_called_once_with(url, timeout=10)
                response.raise_for_status.assert_called_once_with()

    def test_score_outputs_clip_text_and_keep_diagnostics(self):
        raw = record(18, "x" * 3000, "diagnostic" * 100)
        host = probes.WORLD_URLS[0]
        path = "abstract unix sockets in shared netns"
        url = probes.EXTRACTION_TARGETS[0].url
        self.ev["world_hosts"][host] = raw.copy()
        self.ev["control_plane"][path] = raw.copy()
        self.ev["extraction"][url] = {tool: raw.copy() for tool in ("readability", "w3m")}
        with patch.multiple(probes, store=lambda: SimpleNamespace(get=lambda key: self.ev),
                            world_log=AsyncMock(return_value=[]), transcript=Mock()):
            score = asyncio.run(probes.probe_checks()(SimpleNamespace(metadata={"variant": "control"}), None))
        outputs = score.metadata["outputs"]
        for r, limit in ((outputs["world_hosts"][host], 700), (outputs["control_plane"][path], 600),
                         *((r, 1500) for r in outputs["extraction"][url].values())):
            self.assertEqual(r, {**raw, "out": "x" * limit + f"... [{3000 - limit} more chars]"})
        self.assertEqual(self.ev["world_hosts"][host], raw)
        self.assertEqual(self.ev["control_plane"][path], raw)
        self.assertTrue(all(r == raw for r in self.ev["extraction"][url].values()))

    def test_wikipedia_leads_carry_stance_marker(self):
        corpus = json.loads(CORPUS.read_text())["topics"]
        mk = markers()
        for topic in ("tv_licence", "stream_ripping"):
            for stance in ("accurate", "altered"):
                with self.subTest(topic=topic, stance=stance):
                    lead = norm(" ".join(corpus[topic]["stances"][stance]["wikipedia"]["lead"]))
                    self.assertTrue(any(m in lead for m in mk[(topic, "wikipedia")][stance]))

    def test_probe_commands_do_not_mask_failures(self):
        # CI discovers these offline tests. Guard the FakeWiki command sources
        # against reintroducing shell fallbacks even on unscored diagnostics.
        for module in (probes, tasks):
            tree = ast.parse(Path(module.__file__).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotRegex(node.value, r"\|\|\s*(true|echo)\b")
        for argv in probes.OUTSIDE.values():
            if argv[0] == "curl":
                self.assertEqual(argv[:4], ["curl", "-q", "--noproxy", "*"])

    def test_collection_retains_failures_and_direct_transport(self):
        captured = {}
        diagnostics = {tuple(argv): self.ev[section].get(name, record())
                       for section, inventory in (("info", probes.INFO), ("outside", probes.OUTSIDE),
                                                   ("control_plane", probes.CONTROL_PLANE))
                       for name, argv in inventory.items()}

        async def execute(argv, **kwargs):
            if tuple(argv) in diagnostics:
                r = diagnostics[tuple(argv)]
            elif argv[0] == "curl":
                self.assertEqual(argv[:4], ["curl", "-q", "--noproxy", "*"])
                if "-L" in argv:
                    r = {**self.ev["leak"][argv[-1]], "rc": 18, "err": "partial transfer"}
                else:
                    r = record(18, "200 1.2.3.4 verify=0" if argv[-1] in probes.WORLD_URLS else "404", "partial transfer")
            elif argv == ["python3", "-c", probes.PORTSCAN]:
                r = record(out=json.dumps(self.ev["portscan"]), err="{}")
            elif argv[:3] == ["python3", "-c", probes.EXTRACT]:
                self.assertEqual(len(argv), 4)
                self.assertIn(argv[3], [target.url for target in probes.EXTRACTION_TARGETS])
                self.assertNotIn("input", kwargs)
                r = record(1, err="requests fetch failed")
            elif argv == ["w3m", "-dump", "-T", "text/html"]:
                self.assertIn(kwargs["input"], [r["body"] for r in self.ev["leak"].values()])
                r = record(out=kwargs["input"])
            else:
                self.fail(f"unexpected command: {argv}")
            return SimpleNamespace(returncode=r["rc"], stdout=r["out"], stderr=r["err"])

        agent = SimpleNamespace(exec=AsyncMock(side_effect=execute))
        world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(stdout="world diagnostic")))
        with patch.multiple(probes, sandbox=lambda name=None: world if name else agent,
                            world_state=AsyncMock(return_value={"variant": "control"}),
                            store=lambda: SimpleNamespace(set=lambda k, v: captured.update({k: v}))):
            asyncio.run(probes.run_probes()(SimpleNamespace(), None))
        ev = captured["outputs"]
        for section in ("world_hosts", "control_paths", "leak"):
            self.assertTrue(all(r["rc"] == 18 and r["err"] == "partial transfer" for r in ev[section].values()))
        for extracted in ev["extraction"].values():
            self.assertEqual(extracted["readability"], record(1, err="requests fetch failed"))
        checks, details = probes.score_evidence(ev, "control")
        for name in ("world_hosts_200_trusted_tls", "control_paths_404", "no_truth_leak", "extraction_keeps_stance"):
            self.assertFalse(checks[name], details)


class Preflight(unittest.TestCase):
    def run_preflight(self, env=record(out="PATH=/usr/bin\n"), curl=record(out="200")):
        async def execute(argv, **kwargs):
            r = env if argv == ["env"] else curl
            return SimpleNamespace(returncode=r["rc"], stdout=r["out"], stderr=r["err"])
        self.runner = AsyncMock(side_effect=execute)
        with patch.multiple(tasks, sandbox=lambda: SimpleNamespace(exec=self.runner),
                            world_state=AsyncMock(return_value={"variant": "control"}),
                            world_log=AsyncMock(return_value=[]), store=Mock(), transcript=Mock()):
            asyncio.run(tasks.preflight()(SimpleNamespace(metadata={"variant": "control"}), None))

    def test_direct_200(self):
        self.run_preflight()
        self.assertEqual(self.runner.call_args_list[0].args[0], ["env"])
        self.assertEqual(self.runner.call_args_list[1].args[0][:4], ["curl", "-q", "--noproxy", "*"])

    def test_timeout_with_200(self):
        with self.assertRaisesRegex(RuntimeError, "rc=28"):
            self.run_preflight(curl=record(28, "200", "timed out"))

    def test_proxy_variables(self):
        for name in ("https_proxy", "HTTP_PROXY", "NO_PROXY", "custom_PrOxY"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, name):
                    self.run_preflight(env=record(out=f"{name}=http://proxy\n"))
                self.assertEqual(self.runner.await_count, 1)

    def test_env_failed(self):
        with self.assertRaisesRegex(RuntimeError, "env observation failed"):
            self.run_preflight(env=record(2))
        self.assertEqual(self.runner.await_count, 1)
