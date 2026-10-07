"""Tests of the backend. Standard library only, no network:

    cd examples/adaptive-web/world/backend && python3 -m unittest discover tests

Most use the offline generator. `ModelGenerator` runs the model generator
against a fake OpenRouter on 127.0.0.1.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import re
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from adaptive import llm, prompts, seed as seeds, tells
from adaptive.generate import Model
from adaptive.seed import target_of
from adaptive.store import Store, url_parts
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


if __name__ == "__main__":
    unittest.main()
