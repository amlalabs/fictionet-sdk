"""Tests of the backend. Standard library only, no network:

    cd examples/adaptive-web/world/backend && python3 -m unittest discover tests

Most use the offline generator. `ModelGenerator` runs the model generator
against a fake OpenRouter on 127.0.0.1.
"""
from __future__ import annotations

import io
import json
import multiprocessing
import os
import queue
import re
import shutil
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote

from adaptive import llm, prompts, seed as seeds, tells
from adaptive.generate import Made, Model
from adaptive.seed import target_of
from adaptive.store import Error as StoreError, Store, url_parts
from adaptive.stub import Stub
from adaptive.world import World, check_snippets, rescore_snippets, snippet_pieces, text_of

SEEDS = Path(__file__).resolve().parents[3] / "seeds"
SEED = seeds.load(seeds.find("halvard-cve", SEEDS))


def world(root: Path, replay: bool = False) -> World:
    return World(SEED, Store(root / SEED.name), None if replay else Stub(SEED))


def results(body: bytes) -> list[tuple[str, str]]:
    return re.findall(r'<div class="yuRUbf"><a href="([^"]+)"><h3>([^<]+)</h3>', body.decode())


class StorePaths(unittest.TestCase):
    def test_paths_are_readable_and_distinct(self):
        self.assertEqual(url_parts("/"), [])
        self.assertEqual(url_parts("/a/b"), ["a", "b"])
        self.assertEqual(url_parts("/a/"), ["a", "%"])
        self.assertEqual(url_parts("/search?q=x y"), ["search", "?q=x%20y"])
        self.assertEqual(url_parts("/a/../b"), ["a", "%2E%2E", "b"])
        self.assertEqual(url_parts("/@page.json"), ["%40page.json"])
        long = url_parts("/" + "x" * 400)
        self.assertEqual([len(p) for p in long], [180, 181, 41])
        self.assertTrue(long[1].startswith("+"))


def slow_make(root: str, out) -> None:
    """Makes one page in its own process, slowly, and reports what it got."""
    store = Store(Path(root))

    def make() -> dict:
        time.sleep(0.3)
        return {"url": "https://a.com/x", "maker": os.getpid(), "claims": []}

    record, made = store.page_once("a.com", "/x", make)
    out.put((record["maker"], made))


class FirstWriterWins(unittest.TestCase):
    def test_two_processes_make_one_page(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = multiprocessing.get_context("fork")
            out = ctx.Queue()
            procs = [ctx.Process(target=slow_make, args=(d, out)) for _ in range(3)]
            for p in procs:
                p.start()
            got = [out.get(timeout=10) for _ in procs]
            for p in procs:
                p.join()
            makers = {maker for maker, _ in got}
            self.assertEqual(len(makers), 1, "every process reads the first maker's page")
            self.assertEqual(sum(made for _, made in got), 1, "only one process made it")

    def test_two_threads_make_one_page(self):
        with tempfile.TemporaryDirectory() as d:
            store, calls = Store(Path(d)), []

            def make() -> dict:
                calls.append(1)
                time.sleep(0.2)
                return {"url": "https://a.com/y", "claims": ["c"]}

            threads = [threading.Thread(target=store.page_once, args=("a.com", "/y", make)) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(store.recent_claims()), 1, "claims are logged once")


class Consistency(unittest.TestCase):
    def test_rendering_preserves_generated_status_and_fields(self):
        for status in (200, 404, 403, 410, 500):
            for ctype, body in (("text/html", "<h1>Answer</h1>"),
                                ("application/json", '{"message": "Answer"}'),
                                ("text/plain", "Answer")):
                for referenced in (False, True):
                    with self.subTest(status=status, ctype=ctype, referenced=referenced), \
                            tempfile.TemporaryDirectory() as d:
                        w = world(Path(d))
                        host, target = "example.com", "/answer"
                        if referenced:
                            w.store.add_mention(host, target, {"via": "search", "title": "Result title"})
                        fields = {"status": status, "content_type": ctype, "title": "Generated title",
                                  "body": body, "claims": [], "sidebar": [], "ad": ""}
                        made = Made(dict(fields), "test", 0, raw=f"STATUS: {status}\nBODY:\n{body}")
                        # Bypass the model parser to guard the rendering and storage paths themselves.
                        with patch.object(w.generator, "page", return_value=made):
                            response = w.page(host, target)
                        self.assertEqual(response.status, status)
                        self.assertEqual(w.store.page(host, target)["status"], status)
                        self.assertEqual(made.fields, fields)
                        logged = [json.loads(line) for line in (w.store.root / "generations.jsonl").read_text().splitlines()]
                        self.assertEqual(logged[-1]["raw"], made.raw)

    def test_same_inputs_same_world(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            wa, wb = world(Path(a)), world(Path(b))
            sa = wa.handle("GET", "www.google.com", "/search?q=halvard+gateway+vulnerability")
            sb = wb.handle("GET", "www.google.com", "/search?q=halvard+gateway+vulnerability")
            self.assertEqual(sa.body, sb.body)
            for url, _ in results(sa.body)[:5]:
                host, target = target_of(url)
                self.assertEqual(wa.handle("GET", host, target).body, wb.handle("GET", host, target).body)

    def test_pages_have_their_results_titles_and_snippets(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            found = results(w.handle("GET", "www.google.com", "/search?q=halvard+firmware+upgrade").body)
            self.assertEqual(len(found), 10)
            for url, title in found:
                host, target = target_of(url)
                page = w.handle("GET", host, target)
                self.assertEqual(page.status, 200, url)
                self.assertIn(f"<title>{title}</title>", page.body.decode(), url)
                self.assertEqual(page.meta.get("unsupported_snippets", []), [], url)
                self.assertEqual(w.handle("GET", host, target).body, page.body, url)

    def test_a_known_page_keeps_its_title_in_later_results(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            url, title = results(w.handle("GET", "www.google.com", "/search?q=halvard+portal").body)[3]
            host, target = target_of(url)
            w.handle("GET", host, target)
            again = dict((u, t) for u, t in results(w.handle("GET", "www.google.com", "/search?q=halvard+portal+flaw").body))
            self.assertEqual(again.get(url), title)

    def test_engines_share_one_result_list(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            google = [u for u, _ in results(w.handle("GET", "www.google.com", "/search?q=HG-400+firmware").body)]
            ddg = w.handle("POST", "html.duckduckgo.com", "/html/", {"q": "hg-400  FIRMWARE"})
            self.assertEqual(ddg.meta["cache"], "cached")
            organic = [c for c in ddg.body.decode().split('<div class="result ')[1:] if "result--ad" not in c]
            links = [unquote(re.search(r'class="result__a" href="//duckduckgo.com/l/\?uddg=([^"]+)"', c).group(1))
                     for c in organic]
            self.assertEqual(links, google)

    def test_links_give_context(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            page = w.handle("GET", "news.example-site.com", "/story")
            link = re.search(r'<a href="(/[^"]+follow-up)">([^<]+)</a>', page.body.decode())
            mentions = w.store.mentions("news.example-site.com", link.group(1))
            self.assertEqual(mentions[0]["via"], "link")
            self.assertEqual(mentions[0]["anchor"], text_of(link.group(2)))

    def test_snippet_checks(self):
        mention = {"via": "search", "snippet": "Oct 3, 2026 — Halvard has released firmware 7.2.4, which fixes ..."}
        self.assertEqual(snippet_pieces(mention["snippet"]), ["halvard has released firmware 7.2.4, which fixes"])
        self.assertEqual(check_snippets([mention], "Today Halvard has released  firmware 7.2.4, which fixes it"), ([], []))
        self.assertEqual(check_snippets([mention], "Halvard released 7.2.4"), ([mention["snippet"]], []))

    def test_stitched_fragments_present(self):
        # A snippet stitched from a thread's header and its first post.
        stitched = {"via": "search", "snippet": "12 replies. Kwame Osei: Just finished the HG-900 updates last night. "
                                                "Any issues with the 7.2.4 release so far?"}
        page = ("Kwame Osei | Oct 5 Just finished the HG-900 updates last night. "
                "Any issues with the 7.2.4 release so far? 12 replies")
        self.assertEqual(check_snippets([stitched], page), ([], []))

    def test_half_missing_snippet(self):
        present = "Halvard released firmware 7.2.4 for the gateway."
        snippet = present + " The release also fixes the remote access vulnerability."
        self.assertEqual(check_snippets([{"via": "search", "snippet": snippet}], present), ([snippet], []),
                         "Every fragment must match; finding half is not enough")

    def test_unsupported_short_claim(self):
        for snippet in ("HG-400 7.2.4 fix. CVE-2026-41877.", "X", "7"):
            with self.subTest(snippet=snippet):
                self.assertEqual(check_snippets([{"via": "search", "snippet": snippet}], ""), ([snippet], []),
                                 "Even one letter or digit is substantive; no length cutoff")

    def test_contradiction_after_60_chars(self):
        prefix = "The vendor's advisory for the affected Halvard gateways confirms that "
        self.assertGreater(len(prefix), 60)
        snippet = prefix + "firmware 7.2.4 fixes the vulnerability."
        page = prefix + "firmware 7.2.4 does not fix the vulnerability."
        self.assertEqual(check_snippets([{"via": "search", "snippet": snippet}], page), ([snippet], []),
                         "The full fragment must match, including the suffix after character 60")

    def test_empty_snippet_unchecked(self):
        for snippet in ("", " ... … !? ", "Oct 3, 2026 — ..."):
            with self.subTest(snippet=snippet):
                self.assertEqual(check_snippets([{"via": "search", "snippet": snippet}], "anything"),
                                 ([], [snippet]))
        self.assertEqual(check_snippets([{"via": "search"}, {"via": "link"}], "anything"), ([], [""]))

    def test_snippet_presentation_and_boundaries(self):
        snippet = 'Oct 3, 2026 — “Vendor’s HG‑400” ... Firmware 7.2.4 … READY! | Details: 2 replies.'
        self.assertEqual(snippet_pieces(snippet),
                         ["vendor's hg-400", "firmware 7.2.4", "ready", "details", "2 replies"])
        page = "Details | 2 replies | Ready | Firmware\n7.2.4 installed | Vendor's HG-400 gateway"
        self.assertEqual(check_snippets([{"via": "search", "snippet": snippet}], page), ([], []))
        for page in ("HG-400 724 fix", "HG-400 7 2 4 fix"):
            snippet = "HG-400 7.2.4 fix."
            self.assertEqual(check_snippets([{"via": "search", "snippet": snippet}], page), ([snippet], []),
                             "Interior punctuation is substantive")
        for snippet in ("Absent author: Firmware 7.2.4", "99 replies. Firmware 7.2.4"):
            self.assertEqual(check_snippets([{"via": "search", "snippet": snippet}], "Firmware 7.2.4"), ([snippet], []),
                             "Labels and reply counts must not be discarded")

    def test_rescore_snippets_uses_body_and_creation_mentions(self):
        record = {"context": {"mentions": [{"via": "search", "snippet": "Missing."},
                                            {"via": "search", "snippet": "…"}]},
                  "body": "<p>Present.</p>", "content_type": "text/html; charset=utf-8",
                  "unsupported_snippets": [], "unchecked_snippets": []}
        self.assertEqual(rescore_snippets(record), (["Missing."], ["…"]))
        record["body"] = "<p>Missing.</p>"
        self.assertEqual(rescore_snippets(record), ([], ["…"]))
        for key in ("body", "content_type", "context"):
            with self.subTest(key=key), self.assertRaises(KeyError):
                rescore_snippets({k: v for k, v in record.items() if k != key})
        for changes in ({"body": ["Missing."]}, {"body": {"Missing.": 1}},
                        {"content_type": None}, {"content_type": ""}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                rescore_snippets(record | changes)
        record["context"] = {}
        with self.assertRaises(KeyError):
            rescore_snippets(record)
        for mentions in ({}, None, ["snippet"], [{"via": None, "snippet": "Missing."}],
                         [{"via": "search", "snippet": None}]):
            record["context"] = {"mentions": mentions}
            with self.subTest(mentions=mentions), self.assertRaises(ValueError):
                rescore_snippets(record)

    def test_json_snippets_use_decoded_string_values(self):
        snippet = 'Renée said "fixed" … Firmware 7.2.4'
        record = {"context": {"mentions": [{"via": "search", "snippet": snippet}]},
                  "body": json.dumps({"notes": ['Renée said "fixed"', {"version": "Firmware 7.2.4"}]}),
                  "content_type": "application/json; charset=utf-8"}
        for ctype in ("application/json", "application/problem+json"):
            record["content_type"] = ctype
            self.assertEqual(rescore_snippets(record), ([], []))
        for body in (json.dumps({snippet: 1}), json.dumps(["Renée said", '"fixed"', "Firmware 7.2.4"])):
            record["body"] = body
            self.assertEqual(rescore_snippets(record), ([snippet], []))
        record["body"] = "not JSON"
        with self.assertRaises(json.JSONDecodeError):
            rescore_snippets(record)

    def test_snippet_results_stored_and_returned(self):
        supported = 'Renée said "fixed".'
        for ctype, body in (("text/html", f"<p>{supported}</p>"),
                            ("application/json", json.dumps({"message": supported})),
                            ("text/plain", supported)):
            with self.subTest(ctype=ctype), tempfile.TemporaryDirectory() as d:
                w = world(Path(d))
                for snippet in (supported, "Missing.", "…"):
                    w.store.add_mention("example.com", "/page", {"via": "search", "snippet": snippet})
                made = Made({"status": 200, "content_type": ctype, "body": body, "title": "Title",
                             "claims": [], "sidebar": [], "ad": ""}, "test", 0)
                with patch.object(w.generator, "page", return_value=made):
                    for cache in ("generated", "cached"):
                        response = w.page("example.com", "/page")
                        self.assertEqual(response.meta["cache"], cache)
                        self.assertEqual(response.meta["unsupported_snippets"], ["Missing."])
                        self.assertEqual(response.meta["unchecked_snippets"], ["…"])
                record = w.store.page("example.com", "/page")
                self.assertEqual(record["unsupported_snippets"], ["Missing."])
                self.assertEqual(record["unchecked_snippets"], ["…"])
                self.assertEqual(rescore_snippets(record), (["Missing."], ["…"]))


RACE_HOST = "race.example-site.com"
RACE_TARGET = "/story"
RACE_URL = f"https://{RACE_HOST}{RACE_TARGET}"


class CompetingTitles(Stub):
    def search(self, query, known, claims, cast):
        return Made({"results": [{"url": RACE_URL, "title": query, "snippet": f"Snippet for {query}.",
                                  "date": "1 Oct 2026"}]}, self.model, 0)


class PausedMetadata(Store):
    """Pause the first reader with an empty mention snapshot. The other
    request reaches the URL lock before the first reader continues."""

    def __init__(self, root, first, ready, contending):
        super().__init__(root)
        self.pause = first
        self.signal = not first
        self.ready = ready
        self.contending = contending

    def _read(self, path):
        value = super()._read(path)
        if self.pause and path == self.page_dir(RACE_HOST, RACE_TARGET) / "@mentions.json":
            self.pause = False
            self.ready.wait(timeout=10)
            self.contending.wait(timeout=10)
        return value

    @contextmanager
    def _locked(self, path):
        if (self.signal and path.parent == self.page_dir(RACE_HOST, RACE_TARGET)
                and path.name in ("@page.lock", "@mentions.lock")):
            # The old search path only locked the append, after choosing
            # its title. The new path locks before reading any metadata.
            self.signal = False
            self.contending.wait(timeout=10)
        with super()._locked(path):
            yield


def competing_request(root, first, action, ready, contending, out):
    try:
        store = PausedMetadata(Path(root), first, ready, contending)
        w = World(SEED, store, CompetingTitles(SEED))
        if not first:
            ready.wait(timeout=10)
        response = (w.page(RACE_HOST, RACE_TARGET) if action == "page"
                    else w.search("google", action))
        out.put((action, response, None))
    except Exception as err:
        out.put((action, None, repr(err)))


class ConcurrentMetadata(unittest.TestCase):
    def race(self, first, processes, second="second"):
        with tempfile.TemporaryDirectory() as d:
            if processes:
                context = multiprocessing.get_context("spawn")
                ready, contending = context.Barrier(2), context.Barrier(2)
                out, worker = context.Queue(), context.Process
            else:
                ready, contending = threading.Barrier(2), threading.Barrier(2)
                out, worker = queue.Queue(), threading.Thread
            workers = [worker(target=competing_request,
                              args=(d, i == 0, action, ready, contending, out), daemon=True)
                       for i, action in enumerate((first, second))]
            try:
                for w in workers:
                    w.start()
                got = [out.get(timeout=15) for _ in workers]
                for w in workers:
                    w.join(timeout=10)
                    self.assertFalse(w.is_alive(), "URL metadata lock deadlocked")
                for _, _, error in got:
                    self.assertIsNone(error)
            finally:
                ready.abort()
                contending.abort()
                for w in workers:
                    if processes and w.is_alive():
                        w.terminate()
                    w.join(timeout=10)
                if processes:
                    out.close()
                    out.join_thread()

            w = World(SEED, Store(Path(d)), CompetingTitles(SEED))
            page = w.page(RACE_HOST, RACE_TARGET)
            title = "Story" if first == "page" else first
            self.assertEqual(page.meta["title"], title)
            self.assertIn(f"<title>{title}</title>".encode(), page.body)
            replay = World(SEED, Store(Path(d)), None)
            self.assertEqual(replay.page(RACE_HOST, RACE_TARGET).body, page.body)
            queries = []
            for action, response, _ in got:
                if action == "page":
                    self.assertEqual(response.body, page.body)
                    continue
                queries.append(action)
                self.assertEqual(results(response.body), [(RACE_URL, title)])
                cached = replay.search("google", action)
                self.assertEqual(cached.meta["cache"], "cached")
                self.assertEqual(cached.body, response.body)
                record = w.store.search(action)["results"][0]
                self.assertEqual(record["title"], title)
                self.assertEqual(record["date"], "1 Oct 2026")
                snippet = (w.store.page(RACE_HOST, RACE_TARGET)["description"] if first == "page"
                           else f"Snippet for {action}.")
                self.assertEqual(record["snippet"], snippet)
            mentions = w.store.mentions(RACE_HOST, RACE_TARGET)
            self.assertEqual(sorted(m["query"] for m in mentions), sorted(queries))
            self.assertEqual({m["title"] for m in mentions}, {title})
            self.assertTrue(all(m["rank"] == 1 for m in mentions))

    def test_competing_searches_in_threads(self):
        self.race("first", processes=False)

    def test_competing_searches_in_processes(self):
        self.race("first", processes=True)

    def test_direct_page_and_search_in_threads(self):
        self.race("page", processes=False)

    def test_direct_page_and_search_in_processes(self):
        self.race("page", processes=True)

    def test_search_and_direct_page_in_threads(self):
        self.race("first", processes=False, second="page")

    def test_search_and_direct_page_in_processes(self):
        self.race("first", processes=True, second="page")


class Tells(unittest.TestCase):
    def test_tells_are_found(self):
        text = "We leverage a robust platform \u2014 and another \u2014 said Elena Vance. Landscapes are nice."
        self.assertEqual(tells.find(text), ["em dash x2", "robust", "leverage", "elena vance"])
        self.assertEqual(tells.find("Plain text, no tells."), [])


class Serving(unittest.TestCase):
    def test_replay_serves_the_store_and_nothing_new(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            s = w.handle("GET", "html.duckduckgo.com", "/html/?q=halvard")
            p = w.handle("GET", "www.halvardsystems.com", "/support/")
            r = world(Path(d), replay=True)
            self.assertEqual(r.handle("GET", "html.duckduckgo.com", "/html/?q=halvard").body, s.body)
            again = r.handle("GET", "www.halvardsystems.com", "/support/")
            self.assertEqual((again.body, again.meta["cache"]), (p.body, "cached"))
            missing = r.handle("GET", "www.halvardsystems.com", "/never-asked")
            self.assertEqual((missing.status, missing.meta["cache"]), (404, "missing"))

    def test_engines_redirects_and_assets(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            self.assertEqual(w.handle("GET", "google.com", "/search?q=x").headers["Location"],
                             "https://www.google.com/search?q=x")
            self.assertEqual(w.handle("GET", "duckduckgo.com", "/l/?uddg=https%3A%2F%2Fa.com%2Fb").headers["Location"],
                             "https://a.com/b")
            self.assertEqual(w.handle("GET", "www.bing.com", "/search?q=halvard&first=x").status, 200)
            css = w.handle("GET", "a.com", "/static/css/main.css")
            self.assertEqual((css.content_type, css.meta["kind"]), ("text/css", "asset"))
            self.assertIsNone(w.store.page("a.com", "/static/css/main.css"))

    def test_fixed_pages_are_served_as_written(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            fixed = SEED.fixed[0]
            r = w.handle("GET", fixed.host, fixed.target)
            self.assertEqual(r.body, fixed.file.read_bytes())
            self.assertEqual(r.meta["cache"], "fixed")
            # Its links are written down for the pages behind them.
            self.assertTrue(w.store.mentions(fixed.host, "/support/kb/KB-3381"))


class FixedSnapshots(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        shutil.copytree(SEEDS, self.root / "seeds")
        self.seed_path = self.root / "seeds" / SEED.path.name
        self.seed = seeds.load(self.seed_path)
        self.fixed = self.seed.fixed[0]
        self.store = Store(self.root / "store" / self.seed.name)

    def open(self, replay=False, seed=None):
        seed = seed or self.seed
        return World(seed, self.store, None if replay else Stub(seed))

    def fetch(self, world):
        return world.handle("GET", self.fixed.host, self.fixed.target)

    def test_fixed_snapshot_survives_changed_and_deleted_sources(self):
        w = self.open()
        first = self.fetch(w)
        self.fixed.file.write_bytes(b"a changed advisory")
        self.assertEqual(self.fetch(w), first)
        # A newly loaded seed and store represent a backend restart.
        for replay in (False, True):
            seed = seeds.load(self.seed_path)
            restarted = World(seed, Store(self.store.root), None if replay else Stub(seed))
            self.assertEqual(self.fetch(restarted), first)
        self.fixed.file.unlink()
        seed = seeds.load(self.seed_path)
        for replay in (False, True):
            restarted = World(seed, Store(self.store.root), None if replay else Stub(seed))
            self.assertEqual(self.fetch(restarted), first)
        # Response metadata also comes from the retained record.
        self.fixed.title = "Changed title"
        self.fixed.content_type = "application/octet-stream"
        self.assertEqual(self.fetch(w), first)

    def test_fixed_binary_and_empty_bodies_round_trip(self):
        self.fixed.content_type = "application/octet-stream"
        bodies = (bytes(range(256)) + b'<a href="/binary-link">Not HTML</a>', b"")
        for i, body in enumerate(bodies):
            with self.subTest(body=body):
                self.store = Store(self.root / f"binary-{i}")
                self.fixed.file.write_bytes(body)
                first = self.fetch(self.open())
                self.assertEqual((first.status, first.content_type, first.body, first.headers),
                                 (200, "application/octet-stream", body, {"Server": "nginx"}))
                self.fixed.file.unlink()
                self.assertEqual(self.fetch(self.open(replay=True)), first)
                self.assertEqual(self.store.mentions(self.fixed.host, "/binary-link"), [])

    def test_source_is_read_once_under_concurrent_requests(self):
        w = self.open()
        read_bytes, calls = Path.read_bytes, []

        def read(path):
            calls.append(path)
            return read_bytes(path)

        with patch.object(Path, "read_bytes", autospec=True, side_effect=read):
            with ThreadPoolExecutor(max_workers=8) as pool:
                responses = list(pool.map(lambda _: self.fetch(w), range(16)))
        self.assertEqual(calls, [self.fixed.file])
        self.assertTrue(all(r == responses[0] for r in responses))

    def test_first_use_captures_source_and_failed_read_can_be_retried(self):
        w = self.open()
        self.fixed.file.unlink()
        with self.assertRaises(FileNotFoundError):
            self.fetch(w)
        self.assertIsNone(self.store.page(self.fixed.host, self.fixed.target))
        self.fixed.file.write_bytes(b"written after store initialization")
        self.assertEqual(self.fetch(w).body, b"written after store initialization")

    def test_generation_requires_readable_uncaptured_sources(self):
        open_file = Path.open

        def open(path, *args, **kwargs):
            if path == self.fixed.file:
                raise PermissionError("source is unreadable")
            return open_file(path, *args, **kwargs)

        with patch.object(Path, "open", autospec=True, side_effect=open):
            with self.assertRaises(ValueError) as raised:
                self.open()
        self.assertEqual(str(raised.exception),
                         f"{self.seed_path}: fixed page file {self.fixed.file} does not exist")

    def test_backend_rejects_missing_fixed_source_before_listening(self):
        import backend
        self.fixed.file.unlink()
        for kind in ("stub", "openrouter", "anthropic"):
            with self.subTest(generator=kind), \
                    patch.dict(os.environ, {"ADAPTIVE_WEB_SEED": str(self.seed_path),
                                            "ADAPTIVE_WEB_STORE": str(self.root / kind),
                                            "ADAPTIVE_WEB_GENERATOR": kind, "ADAPTIVE_WEB_PREFETCH": "0",
                                            "OPENROUTER_API_KEY": "test", "ANTHROPIC_API_KEY": "test"}), \
                    patch.object(backend.sys, "argv", ["backend.py", "0"]), \
                    patch.object(backend, "Server") as server, \
                    patch("sys.stdout"), patch("sys.stderr") as stderr:
                self.assertEqual(backend.main(), 2)
                server.assert_not_called()
                self.assertEqual("".join(c.args[0] for c in stderr.write.call_args_list),
                                 f"{self.seed_path}: fixed page file {self.fixed.file} does not exist\n")

    def test_replay_never_snapshots_an_unseen_fixed_page(self):
        self.open()
        for deleted in (False, True):
            if deleted:
                self.fixed.file.unlink()
            replay = self.open(replay=True, seed=seeds.load(self.seed_path))
            with patch.object(Path, "read_bytes", side_effect=AssertionError("replay read a source")):
                response = self.fetch(replay)
            self.assertEqual((response.status, response.meta["cache"]), (404, "missing"))
            self.assertIsNone(self.store.page(self.fixed.host, self.fixed.target))

    def test_seed_identity_checks_all_declarations_but_not_installation_path(self):
        self.open()
        self.assertEqual(self.seed.fingerprint(), SEED.fingerprint())
        changes = [replace(self.seed, **{key: value}) for key, value in (
            ("date", "2026-12-01"), ("question", "A different question"),
            ("scenario", "A different scenario"), ("facts", ["A different fact"]),
            ("sites", [replace(self.seed.sites[0], about="A different site")]),
            ("addresses", {"example.com": "203.0.113.1"}),
        )]
        changes += [replace(self.seed, fixed=[replace(self.fixed, **{key: value})]) for key, value in (
            ("url", "https://example.com/other"), ("title", "A different title"),
            ("description", "A different description"), ("content_type", "text/plain"),
            ("file", self.fixed.file.with_name("other.html")),
        )]
        for changed in changes:
            for replay in (False, True):
                with self.subTest(seed=changed, replay=replay):
                    with self.assertRaisesRegex(StoreError, "seed fingerprint mismatch.*rebuild"):
                        self.open(replay=replay, seed=changed)

    def test_generator_identity_checks_provider_model_and_reasoning(self):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test", "ADAPTIVE_WEB_REASONING": "low"}):
            client = llm.client("openrouter", "some/model")
        World(self.seed, self.store, Model(self.seed, client))
        # Operational limits can change without changing response configuration.
        World(self.seed, self.store, Model(self.seed, client), generation_budget=0)
        self.open(replay=True)
        for field, value in (("provider", "anthropic"), ("model", "other/model"), ("reasoning", "high")):
            with self.subTest(field=field), patch.object(client, field, value):
                with self.assertRaisesRegex(StoreError, "generator configuration mismatch"):
                    World(self.seed, self.store, Model(self.seed, client))
        with self.assertRaisesRegex(StoreError, "generator configuration mismatch"):
            self.open()

    def test_legacy_store_is_rejected_and_rebuild_is_explicit(self):
        legacy = {"url": self.fixed.url, "status": 200, "title": self.fixed.title,
                  "model": "fixed", "file": self.fixed.file.name}
        self.store.page_once(self.fixed.host, self.fixed.target, lambda: legacy)
        for replay in (False, True):
            with self.assertRaisesRegex(StoreError, "legacy store.*rebuild in a fresh ADAPTIVE_WEB_STORE_DIR"):
                self.open(replay=replay)
        self.assertEqual(self.store.page(self.fixed.host, self.fixed.target), legacy)
        self.assertFalse((self.store.root / "@store.json").exists())
        self.store = Store(self.root / "rebuilt")
        self.assertEqual(self.fetch(self.open()).body, self.fixed.file.read_bytes())

    def test_initialization_cannot_mix_different_seeds(self):
        changed = replace(self.seed, facts=["A different fact"])
        barrier = threading.Barrier(2)

        def initialize(seed):
            barrier.wait()
            try:
                self.open(seed=seed)
                return seed
            except StoreError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            initialized = list(pool.map(initialize, [self.seed, changed]))
        winners = [seed for seed in initialized if seed is not None]
        self.assertEqual(len(winners), 1)
        self.open(replay=True, seed=winners[0])

    def test_empty_replay_store_requires_initialization(self):
        with self.assertRaisesRegex(StoreError, "replay needs an initialized snapshot"):
            self.open(replay=True)
        self.assertFalse((self.store.root / "@store.json").exists())
        self.open()
        self.open(replay=True)

    def test_unsupported_version_and_incomplete_fixed_records_are_rejected(self):
        w = self.open()
        self.store.page_once(self.fixed.host, self.fixed.target, lambda: {"model": "fixed"})
        with self.assertRaisesRegex(StoreError, "incomplete fixed snapshot.*rebuild"):
            self.fetch(w)
        with self.assertRaisesRegex(StoreError, "incomplete fixed snapshot.*rebuild"):
            self.fetch(self.open(replay=True))
        path = self.store.root / "@store.json"
        manifest = json.loads(path.read_text())
        manifest["version"] = 999
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(StoreError, "unsupported store format version"):
            self.open(replay=True)

    def test_backend_reports_incompatible_store_before_listening(self):
        import backend
        self.open()
        self.seed_path.write_text(self.seed_path.read_text() + "\nA different scenario\n")
        with patch.dict(os.environ, {"ADAPTIVE_WEB_SEED": str(self.seed_path),
                                     "ADAPTIVE_WEB_STORE": str(self.store.root.parent),
                                     "ADAPTIVE_WEB_GENERATOR": "replay"}), \
                patch.object(backend.sys, "argv", ["backend.py", "0"]), \
                patch.object(backend, "Server") as server, \
                patch("sys.stderr") as stderr:
            self.assertEqual(backend.main(), 2)
        server.assert_not_called()
        self.assertIn("seed fingerprint mismatch", "".join(c.args[0] for c in stderr.write.call_args_list))


class FakeOpenRouter(BaseHTTPRequestHandler):
    """Answers like OpenRouter's chat completions: a result list for a
    search prompt, a page for a page prompt. Remembers the keys sent."""

    keys: list[str] = []
    systems: list[str] = []
    bad_answers = 0  # how many unreadable answers to give first
    page_answers: list[str] = []
    page_prompts: list[str] = []
    echo_errors: list[tuple[int, str]] = []  # statuses and prefixes for errors echoing the key

    def log_message(self, *args):
        pass

    def do_POST(self):
        FakeOpenRouter.keys.append(self.headers.get("Authorization", ""))
        ask = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOpenRouter.systems.append(ask["messages"][0]["content"])
        if FakeOpenRouter.echo_errors:
            status, prefix = FakeOpenRouter.echo_errors.pop(0)
            reply = json.dumps({"error": f"{prefix}rejected Authorization: {self.headers['Authorization']}"}).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
            return
        prompt = ask["messages"][1]["content"]
        if FakeOpenRouter.bad_answers:
            FakeOpenRouter.bad_answers -= 1
            text = "Sorry, I can't help with that."
        elif prompt.startswith("List the people"):
            text = "Tomasz Wierzbicki | CEO | Halvard Systems\nAmara Nwosu | analyst | Brightline Research\n" \
                   "Keiko Arai | reporter | The Register"
        elif "Someone searched for" in prompt:
            text = "\n".join(f"RESULT\nURL: https://news{i}.krantvandaag.nl/a{i}\nTITLE: Story {i}\nDATE: Oct 1, 2026\n"
                             f"SNIPPET: Snippet number {i} about the flaw..." for i in range(10)) + "\nRELATED: r | s"
        else:
            FakeOpenRouter.page_prompts.append(prompt)
            url = re.search(r"Write the page at: (\S+)", prompt).group(1)
            snippet = re.search(r'snippet "([^"]+?)(\.\.\.)?"', prompt)
            text = (f"STATUS: 200\nCONTENT_TYPE: text/html\nTITLE: Some other title\nDESCRIPTION: d\nDATE: 2026-10-01\n"
                    f"CLAIMS:\n- a claim about {url}\nSITE_NAME: Krant Vandaag\nSITE_NAV: Home|/\nSITE_FOOTER: Over ons|/over\n"
                    f"SIDEBAR:\n- Andere zaak | /andere\nAD: none\nBODY:\n<h1>Story</h1><p>{snippet.group(1) if snippet else ''}</p>")
            if FakeOpenRouter.page_answers:
                text = FakeOpenRouter.page_answers.pop(0)
        reply = json.dumps({"model": ask["model"], "choices": [{"message": {"content": text}}],
                            "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "cost": 0.0021}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


class ModelGenerator(unittest.TestCase):
    KEY = "sk-or-test-key-must-not-be-stored"

    def setUp(self):
        FakeOpenRouter.keys, FakeOpenRouter.systems, FakeOpenRouter.bad_answers = [], [], 0
        FakeOpenRouter.page_answers, FakeOpenRouter.page_prompts = [], []
        FakeOpenRouter.echo_errors = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenRouter)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.old = (llm.OPENROUTER_URL, os.environ.get("OPENROUTER_API_KEY"))
        llm.OPENROUTER_URL = f"http://127.0.0.1:{self.server.server_address[1]}/api/v1/chat/completions"
        os.environ["OPENROUTER_API_KEY"] = self.KEY

    def tearDown(self):
        llm.OPENROUTER_URL = self.old[0]
        if self.old[1] is None:
            del os.environ["OPENROUTER_API_KEY"]
        else:
            os.environ["OPENROUTER_API_KEY"] = self.old[1]
        self.server.shutdown()
        self.server.server_close()

    def test_pages_keep_titles_count_cost_and_never_store_the_key(self):
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d) / SEED.name), Model(SEED, llm.client("openrouter", "some/model")), prefetch=2)
            r = w.handle("GET", "www.google.com", "/search?q=halvard+flaw")
            self.assertEqual((r.meta["cache"], r.meta["cost"]), ("generated", 0.0021))
            url, title = results(r.body)[0]
            w.pool.shutdown(wait=True)
            host, target = target_of(url)
            page = w.handle("GET", host, target)
            self.assertEqual(page.meta["cache"], "prefetched")
            self.assertEqual(page.status, 200, "a page a result points at is never a 404")
            self.assertIn(f"<title>{title}</title>", page.body.decode())
            self.assertEqual(page.meta["unsupported_snippets"], [])
            self.assertEqual(w.handle("GET", host, target).meta["cache"], "cached")
            self.assertEqual(set(FakeOpenRouter.keys), {f"Bearer {self.KEY}"})
            # The cast was made once, and every later prompt names it.
            self.assertEqual(w.cast()[0]["name"], "Tomasz Wierzbicki")
            self.assertEqual(sum(1 for x in FakeOpenRouter.systems if "Tomasz Wierzbicki" not in x), 1)
            for f in Path(d).rglob("*"):
                if f.is_file():
                    self.assertNotIn(self.KEY, f.read_text(errors="replace"), f)

    def test_an_unreadable_answer_is_asked_again_and_counted(self):
        FakeOpenRouter.bad_answers = 1
        gen = Model(SEED, llm.client("openrouter", "some/model"))
        made = gen.search("halvard", [], [], [])
        self.assertEqual(len(made.fields["results"]), 10)
        self.assertAlmostEqual(made.cost, 0.0042)
        self.assertEqual((made.attempts, made.asks, made.cost_unknown), (2, 2, 0))
        self.assertAlmostEqual(made.cost_known, 0.0042)
        FakeOpenRouter.bad_answers = 2
        with self.assertRaises(prompts.Error):
            gen.search("halvard", [], [], [])

    def test_invalid_header_key(self):
        for provider in ("openrouter", "anthropic"):
            name = f"{provider.upper()}_API_KEY"
            for character in ("\n", "\r", "\t", " ", "\x1f", "\x7f", "é"):
                with self.subTest(provider=provider, character=character), \
                        patch.dict(os.environ, {name: self.KEY + character}):
                    with self.assertRaises(llm.Error) as raised:
                        llm.client(provider, "some/model")
                    self.assertIn(name, str(raised.exception))
                    self.assertIn("HTTP header cannot carry", str(raised.exception))
                    self.assertNotIn(self.KEY, str(raised.exception))
            # os.environ itself rejects NUL, but the validator also excludes it.
            with patch.object(llm.os, "environ", {name: self.KEY + "\0"}):
                with self.assertRaisesRegex(llm.Error, f"{name} holds characters"):
                    llm.client(provider, "some/model")
        self.assertEqual(FakeOpenRouter.keys, [])

    def test_backend_rejects_invalid_header_key(self):
        import backend
        for provider in ("openrouter", "anthropic"):
            name = f"{provider.upper()}_API_KEY"
            with tempfile.TemporaryDirectory() as d, \
                    patch.dict(os.environ, {name: self.KEY + "\n", "ADAPTIVE_WEB_SEED": str(SEED.path),
                                            "ADAPTIVE_WEB_GENERATOR": provider, "ADAPTIVE_WEB_STORE": d}), \
                    patch.object(backend.sys, "argv", ["backend.py", "0"]), \
                    patch.object(backend, "Server") as server, \
                    patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(backend.main(), 2)
                server.assert_not_called()
                self.assertIn(name, stderr.getvalue())
                self.assertNotIn(self.KEY, stderr.getvalue())
                self.assertEqual(list(Path(d).rglob("*")), [])
        self.assertEqual(FakeOpenRouter.keys, [])

    def test_only_the_validated_key_is_sent(self):
        for provider, header in (("openrouter", "Authorization"), ("anthropic", "X-api-key")):
            name = f"{provider.upper()}_API_KEY"
            with self.subTest(provider=provider), patch.dict(os.environ, {name: self.KEY}):
                client = llm.client(provider, "some/model")
                os.environ[name] = self.KEY + "\n"
                with patch.object(llm, "_open", return_value=io.BytesIO(b"{}")) as opened:
                    client.complete("system", "user", 10)
                request = opened.call_args.args[0]
                expected = f"Bearer {self.KEY}" if provider == "openrouter" else self.KEY
                self.assertEqual(request.get_header(header), expected)

    def test_echoed_provider_error_never_stores_the_key(self):
        for status, prefix in ((400, ""), (400, "x" * 330), (200, ""), (200, "x" * 330)):
            with self.subTest(status=status, prefix=prefix), tempfile.TemporaryDirectory() as d:
                w = World(SEED, Store(Path(d) / SEED.name), Model(SEED, llm.client("openrouter", "some/model")))
                w.cast()
                FakeOpenRouter.echo_errors = [(status, prefix)]
                before = len(FakeOpenRouter.keys)
                with self.assertRaises(llm.Error) as raised:
                    w.handle("GET", "www.google.com", "/search?q=halvard+flaw")
                self.assertEqual(len(FakeOpenRouter.keys), before + 1)
                message = str(raised.exception)
                self.assertIn("rejected Authorization: Bearer <OPENROUTER_API_KEY>", message)
                self.assertNotIn(self.KEY, message)
                self.assertNotIn(self.KEY[:12], message, "truncation must not expose part of the key")
                rows = [json.loads(line) for line in (w.store.root / "generations.jsonl").read_text().splitlines()]
                self.assertEqual(rows[-1]["generation"]["status"], "error")
                self.assertIn("<OPENROUTER_API_KEY>", rows[-1]["error"])
                for f in Path(d).rglob("*"):
                    if f.is_file():
                        self.assertNotIn(self.KEY, f.read_text(errors="replace"), f)
                        self.assertNotIn(self.KEY[:12], f.read_text(errors="replace"), f)

    def test_request_errors_redact_the_key(self):
        import backend
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            handler = object.__new__(backend.Handler)
            handler.world, handler.headers, handler.path = w, {"Host": "news.example"}, "/story"
            failure = RuntimeError(f"generation failed with {self.KEY}")
            with patch.object(w, "handle", side_effect=failure), \
                    patch.object(handler, "_send") as send, \
                    patch("sys.stderr", new_callable=io.StringIO) as stderr:
                handler._serve("GET")
            self.assertEqual(send.call_args.args[0], 503)
            self.assertEqual(send.call_args.args[4],
                             {"kind": "error", "error": "RuntimeError: generation failed with <OPENROUTER_API_KEY>"})
            self.assertIn("Traceback", stderr.getvalue())
            self.assertIn("RuntimeError: generation failed with <OPENROUTER_API_KEY>", stderr.getvalue())
            self.assertNotIn(self.KEY, stderr.getvalue())

    def test_background_generation_errors_redact_the_key(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            failure = RuntimeError(f"generation failed with {self.KEY}")
            with patch.object(w, "page", side_effect=failure):
                w._prefetch("news.example", "/story")
            rows = [json.loads(line) for line in (w.store.root / "generations.jsonl").read_text().splitlines()]
            self.assertEqual(rows[-1]["kind"], "prefetch_error")
            self.assertEqual(rows[-1]["error"], "RuntimeError: generation failed with <OPENROUTER_API_KEY>")
            for f in Path(d).rglob("*"):
                if f.is_file():
                    self.assertNotIn(self.KEY, f.read_text(errors="replace"), f)

    def test_redact_configured_keys(self):
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": self.KEY, "ANTHROPIC_API_KEY": self.KEY + "-long"}):
            message = f"{self.KEY}-long and {self.KEY} and {self.KEY}-long"
            self.assertEqual(llm.redact(message), "<ANTHROPIC_API_KEY> and <OPENROUTER_API_KEY> and <ANTHROPIC_API_KEY>")
            self.assertEqual(llm.describe(ValueError(message)), "ValueError: " + llm.redact(message))
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "", "ANTHROPIC_API_KEY": ""}):
            self.assertEqual(llm.redact("unchanged"), "unchanged")

    def test_referenced_404_not_relabelled(self):
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d)), Model(SEED, llm.client("openrouter", "some/model")))
            result = results(w.handle("GET", "www.google.com", "/search?q=halvard").body)[0]
            host, target = target_of(result[0])
            for path, body in ((target, "Page not found"), (target + ".json", '{"message": "Not Found"}'),
                               (target + ".txt", "Page not found")):
                with self.subTest(path=path):
                    if path != target:
                        w.store.add_mention(host, path, {"via": "link", "from": result[0], "anchor": "Details"})
                    bad = f"STATUS: 404\nTITLE: Missing\nBODY:\n{body}"
                    FakeOpenRouter.page_answers = [bad] * 4
                    for _ in range(2):
                        before = len(FakeOpenRouter.page_prompts)
                        with self.assertRaisesRegex(prompts.Error, "referenced.*404"):
                            w.handle("GET", host, path)
                        self.assertEqual(len(FakeOpenRouter.page_prompts) - before, 2)
                        self.assertIsNone(w.store.page(host, path))
                        self.assertNotIn(f"https://{host}{path}", [p["url"] for p in w._known()])
                    good_body = '{"message": "Details"}' if path.endswith(".json") else "Details"
                    good = f"STATUS: 200\nTITLE: Details\nBODY:\n{good_body}"
                    FakeOpenRouter.page_answers = [bad, good]
                    before = len(FakeOpenRouter.page_prompts)
                    response = w.handle("GET", host, path)
                    self.assertEqual((response.status, response.meta["cache"]), (200, "generated"))
                    self.assertAlmostEqual(response.meta["cost"], 0.0042)
                    self.assertIn(b"Details", response.body)
                    self.assertEqual(len(FakeOpenRouter.page_prompts) - before, 2)
                    self.assertIn("referenced", FakeOpenRouter.page_prompts[-1])
                    cached = w.handle("GET", host, path)
                    self.assertEqual((cached.status, cached.meta["cache"], cached.body), (200, "cached", response.body))
                    self.assertEqual(len(FakeOpenRouter.page_prompts) - before, 2)

    def test_generated_error_not_200(self):
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d)), Model(SEED, llm.client("openrouter", "some/model")))
            FakeOpenRouter.page_answers = ["STATUS: 500\nTITLE: Error\nBODY:\nGeneration failed"] * 2
            with self.assertRaisesRegex(prompts.Error, "STATUS.*200 or 404"):
                w.handle("GET", "example.com", "/error")
            self.assertEqual(len(FakeOpenRouter.page_prompts), 2)
            self.assertIsNone(w.store.page("example.com", "/error"))

    def test_json_404_keeps_status_and_body(self):
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d)), Model(SEED, llm.client("openrouter", "some/model")))
            body = '{"message": "Not Found"}'
            raw = f"STATUS: 404\nTITLE: Missing\nBODY:\n{body}"
            FakeOpenRouter.page_answers = [raw]
            for cache in ("generated", "cached"):
                response = w.page("example.com", "/missing.json")
                self.assertEqual((response.status, response.meta["cache"]), (404, cache))
                self.assertEqual(response.content_type, "application/json; charset=utf-8")
                self.assertEqual(response.body.decode(), body)
                self.assertEqual(json.loads(response.body), {"message": "Not Found"})
            self.assertEqual(len(FakeOpenRouter.page_prompts), 1)
            record = w.store.page("example.com", "/missing.json")
            self.assertEqual((record["status"], record["body"]), (404, body))
            logged = [json.loads(line) for line in (w.store.root / "generations.jsonl").read_text().splitlines()]
            self.assertEqual(logged[-1]["raw"], raw)

    def test_unreferenced_html_404_stays_not_found(self):
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d)), Model(SEED, llm.client("openrouter", "some/model")))
            FakeOpenRouter.page_answers = ["STATUS: 404\nTITLE: Missing\nBODY:\nPage not found"]
            for cache in ("generated", "cached"):
                response = w.page("example.com", "/missing")
                self.assertEqual((response.status, response.meta["cache"]), (404, cache))
                self.assertIn(b"<h1>Page not found</h1>", response.body)
            self.assertEqual(len(FakeOpenRouter.page_prompts), 1)

    def test_malformed_json_is_not_cached(self):
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d)), Model(SEED, llm.client("openrouter", "some/model")))
            for status in (201, 404):
                with self.subTest(status=status):
                    FakeOpenRouter.page_answers = [f"STATUS: {status}\nTITLE: x\nBODY:\nNot found"] * 2
                    before = len(FakeOpenRouter.page_prompts)
                    with self.assertRaisesRegex(prompts.Error, "not JSON"):
                        w.handle("GET", "example.com", "/missing.json")
                    self.assertEqual(len(FakeOpenRouter.page_prompts) - before, 2)
                    self.assertIsNone(w.store.page("example.com", "/missing.json"))

    def test_a_missing_key_says_so(self):
        del os.environ["OPENROUTER_API_KEY"]
        with self.assertRaisesRegex(llm.Error, "OPENROUTER_API_KEY is not set"):
            llm.client("openrouter")
        os.environ["OPENROUTER_API_KEY"] = self.KEY


class Reading(unittest.TestCase):
    def test_malformed_json_201(self):
        with self.assertRaisesRegex(prompts.Error, "not JSON"):
            prompts.read_page("STATUS: 201\nTITLE: x\nBODY:\nNot found", "application/json")

    def test_malformed_json_404(self):
        for body in ("Not found", "", "<h1>Missing</h1>"):
            with self.subTest(body=body), self.assertRaisesRegex(prompts.Error, "not JSON"):
                prompts.read_page(f"STATUS: 404\nTITLE: x\nBODY:\n{body}", "application/json")

    def test_declared_json_must_parse(self):
        for status in (200, 404):
            for ctype in ("application/json", "application/problem+json"):
                with self.subTest(status=status, ctype=ctype), self.assertRaisesRegex(prompts.Error, "not JSON"):
                    prompts.read_page(f"STATUS: {status}\nCONTENT_TYPE: {ctype}\nTITLE: x\nBODY:\nNot found")

    def test_json_404_is_valid(self):
        page = prompts.read_page('STATUS: 404\nTITLE: x\nBODY:\n{"message": "Not Found"}', "application/json")
        self.assertEqual(page["status"], 404)
        self.assertEqual(json.loads(page["body"]), {"message": "Not Found"})

    def test_referenced_404_is_rejected_for_every_type(self):
        for expected, body in ((None, "Page not found"), ("application/json", '{"message": "Not Found"}'),
                               ("text/plain", "Page not found"), ("application/xml", "<error>Not Found</error>")):
            with self.subTest(expected=expected), self.assertRaisesRegex(prompts.Error, "referenced.*404"):
                prompts.read_page(f"STATUS: 404\nTITLE: x\nBODY:\n{body}", expected, referenced=True)

    def test_unsupported_status_is_rejected(self):
        for status in (100, 101, 201, 204, 301, 304, 403, 410, 500):
            with self.subTest(status=status), self.assertRaisesRegex(prompts.Error, "STATUS.*200 or 404"):
                prompts.read_page(f'STATUS: {status}\nTITLE: x\nBODY:\n{{"message": "x"}}', "application/json")

    def test_page_answer(self):
        text = """STATUS: 200
CONTENT_TYPE: text/html
TITLE: Halvard patches gateway flaw | The Register
DESCRIPTION: Halvard has fixed a critical flaw.
DATE: 2026-09-23
CLAIMS:
- Halvard fixed CVE-2026-41877 in 7.2.4.
SITE_NAME: The Register
SITE_TAGLINE: Biting the hand that feeds IT
SITE_NAV: Security|/security/, Software|/software/
SITE_FOOTER: About|/about/, Privacy|/privacy/
SIDEBAR:
- Printer firmware bricks fleet | /2026/10/01/printer/
AD: none
BODY:
<h1>Halvard patches gateway flaw</h1>
<p>Text.</p>"""
        page = prompts.read_page(text)
        self.assertEqual(page["title"], "Halvard patches gateway flaw | The Register")
        self.assertEqual(page["claims"], ["Halvard fixed CVE-2026-41877 in 7.2.4."])
        self.assertEqual(page["sidebar"], [("Printer firmware bricks fleet", "/2026/10/01/printer/")])
        self.assertEqual(page["site"]["nav"], ["Security|/security/", "Software|/software/"])
        self.assertEqual(page["ad"], "")
        self.assertTrue(page["body"].startswith("<h1>"))
        with self.assertRaisesRegex(prompts.Error, "no BODY"):
            prompts.read_page("TITLE: x")

    def test_urls_that_promise_a_type_get_it(self):
        self.assertEqual(prompts.expected_type("https://pypi.org/pypi/orjson/json"), "application/json")
        self.assertEqual(prompts.expected_type("https://api.github.com/repos/a/b"), "application/json")
        self.assertIsNone(prompts.expected_type("https://pypi.org/project/orjson/"))
        html_answer = "TITLE: orjson\nCONTENT_TYPE: text/html\nBODY:\n<h1>orjson</h1>"
        with self.assertRaisesRegex(prompts.Error, "not JSON"):
            prompts.read_page(html_answer, "application/json")
        page = prompts.read_page('TITLE: orjson\nBODY:\n{"info": {"name": "orjson"}}', "application/json")
        self.assertEqual(page["content_type"], "application/json; charset=utf-8")

    def test_search_answer(self):
        text = """RESULT
URL: https://a.com/x
TITLE: A thing | A
DATE: Oct 3, 2026
SNIPPET: Some text of the page...
RESULT
URL: not a url
TITLE: B
RELATED: one | two
QUESTIONS: Is it? | Why?
AD: https://ad.example-shop.de/ | Buy | Now 20% off"""
        found = prompts.read_search(text)
        self.assertEqual(found["results"], [{"url": "https://a.com/x", "title": "A thing | A", "date": "Oct 3, 2026",
                                             "snippet": "Some text of the page..."}])
        self.assertEqual(found["related"], ["one", "two"])
        self.assertEqual(found["ads"][0]["title"], "Buy")
        with self.assertRaisesRegex(prompts.Error, "no results"):
            prompts.read_search("Sorry, I can't help with that.")




class GenerationBudget(unittest.TestCase):
    def test_budget_refuses_new_work_but_keeps_cached_pages(self):
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d)), Stub(SEED), generation_budget=2)
            first = w.page("example.com", "/first")
            self.assertEqual(first.status, 200)
            self.assertEqual(w.generation_budget, 0)  # Page and cast.
            self.assertEqual(w.page("example.com", "/second").status, 503)
            self.assertEqual(w.search("google", "new query").status, 503)
            self.assertEqual(w.page("example.com", "/first").body, first.body)
            self.assertIsNone(w.store.page("example.com", "/second"))

    def test_concurrent_reservations_cannot_exceed_budget(self):
        from concurrent.futures import ThreadPoolExecutor
        from adaptive.world import GenerationBudgetExceeded
        with tempfile.TemporaryDirectory() as d:
            w = World(SEED, Store(Path(d)), Stub(SEED), generation_budget=3)
            def reserve(_):
                try:
                    w._reserve_generation()
                    return True
                except GenerationBudgetExceeded:
                    return False
            with ThreadPoolExecutor(max_workers=8) as pool:
                self.assertEqual(sum(pool.map(reserve, range(20))), 3)
            self.assertEqual(w.generation_budget, 0)


if __name__ == "__main__":
    unittest.main()
