"""Tests of the backend. Standard library only, no network:

    cd examples/adaptive-web/world/backend && python3 -m unittest discover tests

Most use the offline generator. `ModelGenerator` runs the model generator
against a fake OpenRouter on 127.0.0.1.
"""
from __future__ import annotations

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
from adaptive.world import World, snippet_core, text_of, unsupported_snippets

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
        self.assertEqual(snippet_core(mention["snippet"]), "Halvard has released firmware 7.2.4, which fixes")
        self.assertEqual(unsupported_snippets([mention], "Today Halvard has released  firmware 7.2.4, which fixes it"), [])
        self.assertEqual(unsupported_snippets([mention], "Halvard released 7.2.4"), [mention["snippet"]])
        # A snippet stitched from a thread's header and its first post.
        stitched = {"via": "search", "snippet": "12 replies. Kwame Osei: Just finished the HG-900 updates last night. "
                                                "Any issues with the 7.2.4 release so far?"}
        page = ("Kwame Osei | Oct 5 Just finished the HG-900 updates last night. "
                "Any issues with the 7.2.4 release so far? 12 replies")
        self.assertEqual(unsupported_snippets([stitched], page), [])


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

    def log_message(self, *args):
        pass

    def do_POST(self):
        FakeOpenRouter.keys.append(self.headers.get("Authorization", ""))
        ask = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOpenRouter.systems.append(ask["messages"][0]["content"])
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
            url = re.search(r"Write the page at: (\S+)", prompt).group(1)
            snippet = re.search(r'snippet "([^"]+?)(\.\.\.)?"', prompt)
            text = (f"STATUS: 404\nCONTENT_TYPE: text/html\nTITLE: Some other title\nDESCRIPTION: d\nDATE: 2026-10-01\n"
                    f"CLAIMS:\n- a claim about {url}\nSITE_NAME: Krant Vandaag\nSITE_NAV: Home|/\nSITE_FOOTER: Over ons|/over\n"
                    f"SIDEBAR:\n- Andere zaak | /andere\nAD: none\nBODY:\n<h1>Story</h1><p>{snippet.group(1) if snippet else ''}</p>")
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
        FakeOpenRouter.bad_answers = 2
        with self.assertRaises(prompts.Error):
            gen.search("halvard", [], [], [])

    def test_a_missing_key_says_so(self):
        del os.environ["OPENROUTER_API_KEY"]
        with self.assertRaisesRegex(llm.Error, "OPENROUTER_API_KEY is not set"):
            llm.client("openrouter")
        os.environ["OPENROUTER_API_KEY"] = self.KEY


class Reading(unittest.TestCase):
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
