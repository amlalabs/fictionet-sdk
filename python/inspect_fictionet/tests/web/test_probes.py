"""Checked transfers, diagnostics and complete request inventories fail closed."""
import contextlib
import copy
import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import quote_plus, urlsplit

from . import probes
from .probes import request_metadata_complete


class RequestMetadata(unittest.TestCase):
    def test_missing_metadata(self):
        self.assertFalse(request_metadata_complete([
            {"type": "http", "answer": "handler", "status": 200},
        ]))

    def test_malformed_kind(self):
        for kind in (None, "", 1, []):
            with self.subTest(kind=kind):
                self.assertFalse(request_metadata_complete([{"answer": "handler", "kind": kind}]))

    def test_page_and_search_need_cache(self):
        for kind in ("page", "search"):
            for cache in (None, "", 1, []):
                with self.subTest(kind=kind, cache=cache):
                    self.assertFalse(request_metadata_complete([
                        {"answer": "handler", "kind": kind, "cache": cache},
                    ]))

    def test_errors_fail_even_with_cache(self):
        self.assertFalse(request_metadata_complete([
            {"answer": "handler", "kind": "error", "cache": "cached"},
        ]))

    def test_valid_metadata_and_world_redirect(self):
        self.assertTrue(request_metadata_complete([
            {"answer": "handler", "kind": "page", "cache": "cached"},
            {"answer": "handler", "kind": "search", "cache": "generated"},
            {"answer": "handler", "kind": "redirect", "location": "https://example.com/"},
            {"answer": "redirect", "status": 301},
        ]))


# The fixture records sequential requests, including both fetches of each page.
def observation(rc=0, out="", err=""):
    return {"rc": rc, "out": out, "err": err}


def evidence():
    query = "example query"
    google = "https://www.google.com/search?q=example+query"
    ddg = "https://html.duckduckgo.com/html/?q=example+query"
    urls = [f"https://example.org/page{i}" for i in range(10)]
    web = {"searches": [], "engines": [], "pages": [], "requests": [],
           "date_header": "Wed, 07 Oct 2026 12:00:00 GMT", "cert_dates": []}
    log = []

    def fetch(url, kind, cache=None):
        web["requests"].append(url)
        parts = urlsplit(url)
        event = {"type": "http", "scheme": parts.scheme, "host": parts.netloc,
                 "path": parts.path + ("?" + parts.query if parts.query else ""),
                 "ua": "curl/8.5.0", "method": "GET", "status": 200,
                 "complete": True, "bytes": 100, "sent": 100,
                 "answer": "handler", "kind": kind}
        if cache is not None:
            event["cache"] = cache
        log.append(event)
        return {"url": url, "rc": 0, "out": "200 1.2.3.4 0", "err": "",
                "status": "200", "ip": "1.2.3.4", "verify": "0"}

    web["searches"].append({"query": query, "first": fetch(google, "search", "generated"),
                            "second": fetch(google, "search", "cached"), "same": True, "results": 10})
    web["engines"].append({"query": query, "fetch": fetch(ddg, "search", "cached"),
                           "status": "200", "google": urls, "duckduckgo": urls})
    for i, url in enumerate(urls[:4]):
        web["pages"].append({"query": query, "url": url, "result_title": "Page", "page_title": "Page",
                             "first": fetch(url, "page", "fixed" if i == 0 else "generated"),
                             "second": fetch(url, "page", "fixed" if i == 0 else "cached"), "same": True})
    web["date_fetch"] = fetch("https://www.google.com/", "search_home")
    web["made_up"] = fetch("https://shop.never-mentioned-anywhere.co.uk/basket", "page", "generated")
    info = {
        "ip -brief addr": observation(out="lo UNKNOWN 127.0.0.1/8\ntun0 UNKNOWN 10.0.0.2/24\n"),
        "ip route": observation(out="default via 10.0.0.1 dev tun0\n10.0.0.0/24 dev tun0\n"),
        "ps": observation(out="    PID USER     COMMAND\n      1 root     sleep infinity\n"),
        "env": observation(out="PATH=/usr/bin\n"),
        "ls world dirs": observation(out="ls: /var/lib/fictionet: No such file or directory\nrc=2"),
    }
    for path in ("/var/lib/fictionet", "/var/lib/web", "/run/fictionet", "/run/relay"):
        info[f"test -e {path}"] = observation(1)
        info[f"ls -ld {path}"] = observation(2, err=f"ls: cannot access '{path}': No such file or directory\n")
    outside = {}
    for name, argv in probes.OUTSIDE.items():
        if argv[0] == "curl":
            outside[name] = observation(35 if "--resolve" in argv else 7,
                                       err="curl: TLS alert" if "--resolve" in argv else "curl: Failed to connect")
        elif argv[0] == "dig":
            outside[name] = observation(9, out=";; no servers could be reached\n")
        elif argv[0] == "python3":
            outside[name] = observation(1, err="Traceback (most recent call last):\nOSError: [Errno 113] No route to host\n")
        else:
            outside[name] = observation(2, err="RTNETLINK answers: Operation not permitted\n")
    return {"state": {"seed": "test-seed", "date": "2026-10-07"}, "web": web,
            "web_exec": observation(out=json.dumps(web)), "info": info, "outside": outside, "log": log}


class ProbeEvidence(unittest.TestCase):
    def setUp(self):
        self.ev = evidence()

    def checks(self):
        return probes.score_evidence(self.ev, "test-seed")[0]

    def test_complete_control(self):
        self.assertTrue(all(self.checks().values()), self.checks())

    def test_failed_200(self):
        self.ev["web"]["pages"][0]["first"].update(rc=18, err="transfer closed with bytes remaining")
        self.assertFalse(self.checks()["results_resolve_trusted"])
        self.assertFalse(self.checks()["result_titles_match_pages"])

    def test_partial_equal_bodies(self):
        for which in ("first", "second"):
            self.ev["web"]["pages"][0][which].update(rc=18, err="partial transfer")
        self.assertFalse(self.checks()["same_url_same_bytes"])

    def test_missing_duplicate_request(self):
        del self.ev["log"][1]
        self.assertFalse(self.checks()["world_logged_every_request"])

    def test_empty_cache_events(self):
        for event in self.ev["log"]:
            event["kind"] = "asset"
            event.pop("cache", None)
        self.assertFalse(self.checks()["world_logged_every_request"])

    def test_empty_evidence(self):
        self.ev["web"] = {}
        self.ev["log"] = []
        self.assertFalse(self.checks()["world_logged_every_request"])

    def test_failed_ps(self):
        self.ev["info"]["ps"] = observation(127)
        checks = self.checks()
        self.assertFalse(checks["world_process_invisible"])

    def test_failed_ip(self):
        self.ev["info"]["ip -brief addr"] = observation(1)
        self.assertFalse(self.checks()["routes_only_into_world"])

    def test_proxy_env_token(self):
        self.ev["info"]["env"] = observation(127, out="(no proxy variables)")
        self.ev["info"]["env | grep -i proxy"] = observation(2, out="(no proxy variables)")
        self.assertFalse(self.checks()["no_proxy_env"])

    def test_visible_private_path(self):
        path = "/run/fictionet"
        self.ev["info"][f"test -e {path}"] = observation()
        self.ev["info"][f"ls -ld {path}"] = observation(out=f"drwxr-xr-x root root {path}\n")
        self.ev["info"]["ls world dirs"]["out"] = f"{path}:\nsock\nls: /var/lib/fictionet: No such file or directory\nrc=2"
        checks = self.checks()
        self.assertFalse(checks["world_files_invisible"])

    def test_evil_com_preconnect_failure(self):
        key = "curl --resolve evil.com to Google's world address"
        self.ev["outside"][key] = observation(7, err="curl: Failed to connect")
        self.assertFalse(self.checks()["outside_all_fail"])

    def test_web_exec_failed(self):
        self.ev["web_exec"].update(rc=1, err="script failed after printing JSON")
        for name in ("same_url_same_bytes", "ten_results_each", "results_resolve_trusted",
                     "result_titles_match_pages", "any_name_resolves", "engines_agree",
                     "dated_on_the_seed_day", "world_logged_every_request"):
            with self.subTest(check=name):
                self.assertFalse(self.checks()[name])


class ProbeEdgeCases(unittest.TestCase):
    def setUp(self):
        self.ev = evidence()

    def checks(self):
        return probes.score_evidence(self.ev, "test-seed")[0]

    def test_second_transfer_and_auxiliary_transfers(self):
        cases = [("pages", 0, "second", "results_resolve_trusted"),
                 ("searches", 0, "second", "same_url_same_bytes"),
                 ("engines", 0, "fetch", "engines_agree")]
        for group, index, field, check in cases:
            with self.subTest(group=group):
                self.ev = evidence()
                self.ev["web"][group][index][field]["rc"] = 18
                self.assertFalse(self.checks()[check])
                self.assertFalse(self.checks()["world_logged_every_request"])
        for field, check in (("made_up", "any_name_resolves"), ("date_fetch", "dated_on_the_seed_day")):
            with self.subTest(field=field):
                self.ev = evidence()
                self.ev["web"][field]["rc"] = 18
                self.assertFalse(self.checks()[check])

    def test_log_cache_status_category_and_delivery(self):
        for index, update in ((0, {"cache": "cached"}), (1, {"cache": "generated"}),
                              (2, {"cache": "generated"}), (3, {"cache": "budget"}),
                              (3, {"cache": "missing"}), (3, {"status": 503}),
                              (3, {"complete": False}), (3, {"sent": 99}),
                              (3, {"method": "HEAD"}), (3, {"kind": "unknown"}),
                              (3, {"kind": "search"}), (0, {"cache": None})):
            with self.subTest(index=index, update=update):
                self.ev = evidence()
                self.ev["log"][index].update(update)
                self.assertFalse(self.checks()["world_logged_every_request"])
        self.ev = evidence()
        self.ev["log"][5]["cache"] = "prefetched"
        self.assertTrue(self.checks()["world_logged_every_request"])

    def test_every_auxiliary_request_is_required(self):
        for index in (2, -2, -1):
            with self.subTest(index=index):
                self.ev = evidence()
                del self.ev["log"][index]
                self.assertFalse(self.checks()["world_logged_every_request"])

    def test_extra_or_reordered_request(self):
        self.ev["log"].append(copy.deepcopy(self.ev["log"][0]))
        self.assertFalse(self.checks()["world_logged_every_request"])
        self.ev = evidence()
        self.ev["log"][0], self.ev["log"][1] = self.ev["log"][1], self.ev["log"][0]
        self.assertFalse(self.checks()["world_logged_every_request"])

    def test_missing_from_both_inventories(self):
        del self.ev["web"]["requests"][1]
        del self.ev["log"][1]
        self.assertFalse(self.checks()["world_logged_every_request"])
        self.ev = evidence()
        del self.ev["web"]["pages"][0]
        del self.ev["web"]["requests"][3:5]
        del self.ev["log"][3:5]
        self.assertFalse(self.checks()["world_logged_every_request"])

    def test_shared_page_and_normalized_query_keys(self):
        web = self.ev["web"]
        query = "  EXAMPLE   QUERY  "
        search, engine = copy.deepcopy(web["searches"][0]), copy.deepcopy(web["engines"][0])
        search["query"] = engine["query"] = query
        search["first"]["url"] = search["second"]["url"] = "https://www.google.com/search?q=" + quote_plus(query)
        engine["fetch"]["url"] = "https://html.duckduckgo.com/html/?q=" + quote_plus(query)
        pages = copy.deepcopy(web["pages"])
        for page in pages:
            page["query"] = query
        web["searches"].append(search)
        web["engines"].append(engine)
        web["pages"].extend(pages)
        repeated = [search["first"]["url"], search["second"]["url"], engine["fetch"]["url"],
                    *[p["url"] for p in pages for _ in range(2)]]
        web["requests"][-2:-2] = repeated
        events = copy.deepcopy(self.ev["log"][:-2])
        for url, event in zip(repeated, events, strict=True):
            parts = urlsplit(url)
            event["path"] = parts.path + ("?" + parts.query if parts.query else "")
            if event["cache"] != "fixed":
                event["cache"] = "cached"
        self.ev["log"][-2:-2] = events
        with patch.dict(probes.QUERIES, {"test-seed": ["example query", query]}):
            self.assertTrue(all(self.checks().values()), self.checks())
            del self.ev["log"][14]
            self.assertFalse(self.checks()["world_logged_every_request"])

    def test_malformed_and_missing_evidence(self):
        for field in ("searches", "pages", "requests", "engines", "date_fetch", "made_up"):
            for value in (None, [], {}, "invalid"):
                with self.subTest(field=field, value=value):
                    self.ev = evidence()
                    self.ev["web"][field] = value
                    self.assertFalse(self.checks()["world_logged_every_request"])
        self.assertFalse(any(probes.score_evidence({}, "test-seed")[0].values()))

    def test_required_diagnostics(self):
        for name, check in (("ip route", "routes_only_into_world"),
                            ("ip -brief addr", "routes_only_into_world"),
                            ("ps", "world_process_invisible"), ("env", "no_proxy_env")):
            for bad in (observation(127), observation(1, "plausible output", "failed"), None):
                with self.subTest(name=name, bad=bad):
                    self.ev = evidence()
                    self.ev["info"][name] = bad
                    self.assertFalse(self.checks()[check])
        for text in ("", "PID USER COMMAND\n", "1 root sleep infinity\n"):
            with self.subTest(ps=text):
                self.ev = evidence()
                self.ev["info"]["ps"] = observation(out=text)
                self.assertFalse(self.checks()["world_process_invisible"])
        for text in ("", "lo UNKNOWN\n", "tun0 UNKNOWN\n", "lo UNKNOWN\ntun0 UNKNOWN\neth0 UP\n"):
            with self.subTest(ifaces=text):
                self.ev = evidence()
                self.ev["info"]["ip -brief addr"] = observation(out=text)
                self.assertFalse(self.checks()["routes_only_into_world"])

    def test_permission_denied_is_not_absence(self):
        self.ev["info"]["ls -ld /run/fictionet"] = observation(2, err="ls: Permission denied")
        self.assertFalse(self.checks()["world_files_invisible"])
        self.assertTrue(self.checks()["world_process_invisible"])

    def test_visible_process_is_separate(self):
        self.ev["info"]["ps"]["out"] += "  2 root web-world\n"
        self.assertFalse(self.checks()["world_process_invisible"])
        self.assertTrue(self.checks()["world_files_invisible"])

    def test_outside_missing_tools_empty_or_wrong_phase(self):
        for name in probes.OUTSIDE:
            for bad in (observation(127, err="missing tool"), observation(126, err="permission denied"),
                        observation(7), None):
                with self.subTest(name=name, bad=bad):
                    self.ev = evidence()
                    self.ev["outside"][name] = bad
                    self.assertFalse(self.checks()["outside_all_fail"])
        for rc, out, err in ((28, "1.1.1.1\t1\t0.000001\n", "curl: timed out"),
                             (60, "", "curl: certificate verify failed")):
            self.ev = evidence()
            self.ev["outside"]["curl https://1.1.1.1"] = observation(rc, out, err)
            self.assertFalse(self.checks()["outside_all_fail"])
        self.ev = evidence()
        self.ev["outside"]["ip route add default (needs NET_ADMIN)"] = observation(2, err="RTNETLINK answers: File exists")
        self.assertFalse(self.checks()["outside_all_fail"])
        self.ev["outside"] = {}
        self.assertFalse(self.checks()["outside_all_fail"])


class WebScript(unittest.TestCase):
    def run_web(self, failed_url=None):
        files, fetched = {}, []
        urls = evidence()["web"]["engines"][0]["google"]

        def run(argv, **kwargs):
            if argv[0] == "cmp":
                return SimpleNamespace(returncode=int(files[argv[2]] != files[argv[3]]), stdout="", stderr="")
            self.assertEqual(argv[:4], ["curl", "-q", "--noproxy", "*"])
            self.assertIn("-sS", argv)
            self.assertNotIn("-f", argv)
            url = argv[-1]
            fetched.append(url)
            if "/search?q=" in url:
                body = "".join(f'<div class="yuRUbf"><a href="{u}"><h3>Page</h3>' for u in urls)
            elif "/html/?q=" in url:
                body = "".join(f'<div class="result "><a class="result__a" href="//duckduckgo.com/l/?uddg={quote_plus(u)}">Page</a>' for u in urls)
            else:
                body = "<title>Page</title>"
            files[argv[argv.index("-o") + 1]] = body
            rc = 18 if url == failed_url else 0
            err = "transfer closed with bytes remaining" if rc else ""
            if "-v" in argv:
                err += "\n< date: Wed, 07 Oct 2026 12:00:00 GMT\n"
            return SimpleNamespace(returncode=rc, stdout="200 1.2.3.4 0", stderr=err)

        output = io.StringIO()
        with patch("subprocess.run", side_effect=run), \
             patch("builtins.open", side_effect=lambda path, **kwargs: io.StringIO(files[path])), \
             patch("sys.argv", ["web", '["example query"]']), contextlib.redirect_stdout(output):
            exec(probes.WEB, {"__name__": __name__})
        web = json.loads(output.getvalue())
        self.assertEqual(web["requests"], fetched)
        return web

    def test_script_records_every_fetch(self):
        ev = evidence()
        ev["web"] = self.run_web()
        self.assertTrue(all(probes.score_evidence(ev, "test-seed")[0].values()))

    def test_script_retains_failed_200_and_equal_partial_bodies(self):
        ev = evidence()
        ev["web"] = self.run_web("https://example.org/page0")
        page = ev["web"]["pages"][0]
        self.assertEqual(page["first"]["rc"], 18)
        self.assertEqual(page["second"]["rc"], 18)
        self.assertEqual(page["first"]["out"], "200 1.2.3.4 0")
        self.assertEqual(page["first"]["err"], "transfer closed with bytes remaining")
        self.assertTrue(page["same"])
        checks, _ = probes.score_evidence(ev, "test-seed")
        self.assertFalse(checks["same_url_same_bytes"])
        self.assertFalse(checks["results_resolve_trusted"])
        self.assertFalse(checks["world_logged_every_request"])


class ProbeRunner(unittest.IsolatedAsyncioTestCase):
    async def collect(self, result):
        ev = evidence()
        by_argv = {tuple(argv): ev["info"][name] for name, argv in probes.INFO.items()
                   if name in ev["info"]}
        by_argv.update({tuple(argv): ev["outside"][name] for name, argv in probes.OUTSIDE.items()})
        by_argv[("cat", "/etc/resolv.conf")] = observation(out="nameserver 10.0.0.1\n")

        async def execute(argv, **kwargs):
            value = result if argv[:3] == ["python3", "-c", probes.WEB] else by_argv[tuple(argv)]
            return SimpleNamespace(returncode=value["rc"], stdout=value["out"], stderr=value["err"])

        outputs = {}
        store = Mock()
        store.set.side_effect = outputs.__setitem__
        log = AsyncMock(side_effect=[[{"type": "tls_reject", "sni": "evil.com"}], ev["log"]])
        state = SimpleNamespace(metadata={"seed": "test-seed"})
        with patch.object(probes, "sandbox", return_value=SimpleNamespace(exec=execute)), \
             patch.object(probes, "world_state", AsyncMock(return_value=ev["state"])), \
             patch.object(probes, "world_log", log), patch.object(probes, "store", return_value=store):
            await probes.run_probes()(state, None)
        self.assertEqual(log.await_args_list[-1].args, (1,))
        self.assertEqual(outputs["outputs"]["web_exec"], result)
        return outputs["outputs"]

    async def test_failed_exec_preserves_output_and_fails_web_checks(self):
        result = observation(1, json.dumps(evidence()["web"]), "script failed")
        ev = await self.collect(result)
        checks, details = probes.score_evidence(ev, "test-seed")
        self.assertIn("script failed", details["web_failed_observation"])
        self.assertTrue(all(checks[name] is False for name in probes.WEB_CHECKS))

    async def test_malformed_json_is_visible_failed_observation(self):
        ev = await self.collect(observation(out="{partial JSON"))
        self.assertIn("invalid WEB output", ev["web"]["error"])
        checks, details = probes.score_evidence(ev, "test-seed")
        self.assertIn("web_failed_observation", details)
        self.assertTrue(all(checks[name] is False for name in probes.WEB_CHECKS))

    async def test_complete_runner_control(self):
        ev = await self.collect(observation(out=json.dumps(evidence()["web"])))
        self.assertTrue(all(probes.score_evidence(ev, "test-seed")[0].values()))


if __name__ == "__main__":
    unittest.main()
