"""Tests of the backend with the offline generator. Standard library only:

    cd examples/adaptive-web/world/backend && python3 -m unittest discover tests
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from adaptive import model, seed as seeds
from adaptive.seed import target_of
from adaptive.store import Store, url_parts
from adaptive.world import World, text_of

SEEDS = Path(__file__).resolve().parents[3] / "seeds"


def world(root: Path, mode: str = "stub") -> World:
    s = seeds.load(seeds.find("halvard-cve", SEEDS))
    return World(s, Store(root / s.name), mode)


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


class Stub(unittest.TestCase):
    def test_same_inputs_same_world(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            wa, wb = world(Path(a)), world(Path(b))
            sa = wa.handle("GET", "www.google.com", "/search?q=halvard+gateway+vulnerability")
            sb = wb.handle("GET", "www.google.com", "/search?q=halvard+gateway+vulnerability")
            self.assertEqual(sa.body, sb.body)
            for url, _ in results(sa.body)[:5]:
                host, target = target_of(url)
                self.assertEqual(wa.handle("GET", host, target).body, wb.handle("GET", host, target).body)

    def test_pages_match_their_results(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            r = w.handle("GET", "www.google.com", "/search?q=halvard+firmware+upgrade")
            found = results(r.body)
            self.assertEqual(len(found), 10)
            for url, title in found:
                host, target = target_of(url)
                page = w.handle("GET", host, target)
                self.assertEqual(page.status, 200, url)
                self.assertIn(f"<title>{title}</title>", page.body.decode(), url)
                self.assertEqual(page.meta.get("unsupported_snippets", []), [], url)
                self.assertEqual(w.handle("GET", host, target).body, page.body, url)

    def test_links_give_context(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            page = w.handle("GET", "news.example-site.com", "/story")
            link = re.search(r'<a href="(/[^"]+follow-up)">([^<]+)</a>', page.body.decode())
            mentions = w.store.mentions("news.example-site.com", link.group(1))
            self.assertEqual(mentions[0]["via"], "link")
            self.assertEqual(mentions[0]["anchor"], text_of(link.group(2)))

    def test_replay_serves_the_store_and_nothing_new(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            s = w.handle("GET", "html.duckduckgo.com", "/html/?q=halvard")
            p = w.handle("GET", "www.halvardsystems.com", "/support/")
            r = world(Path(d), "replay")
            self.assertEqual(r.handle("GET", "html.duckduckgo.com", "/html/?q=halvard").body, s.body)
            again = r.handle("GET", "www.halvardsystems.com", "/support/")
            self.assertEqual((again.body, again.meta["cache"]), (p.body, "cached"))
            missing = r.handle("GET", "www.halvardsystems.com", "/never-asked")
            self.assertEqual((missing.status, missing.meta["cache"]), (404, "missing"))

    def test_engines_and_redirects(self):
        with tempfile.TemporaryDirectory() as d:
            w = world(Path(d))
            self.assertEqual(w.handle("GET", "google.com", "/search?q=x").headers["Location"],
                             "https://www.google.com/search?q=x")
            self.assertEqual(w.handle("GET", "duckduckgo.com", "/l/?uddg=https%3A%2F%2Fa.com%2Fb").headers["Location"],
                             "https://a.com/b")
            post = w.handle("POST", "html.duckduckgo.com", "/html/", {"q": "halvard"})
            self.assertEqual(post.meta["search"], "halvard")
            self.assertEqual(w.handle("GET", "www.bing.com", "/search?q=halvard").status, 200)


class FakeApi(BaseHTTPRequestHandler):
    """Answers like the Messages API: a result list for a search prompt, a
    page for a page prompt. Remembers the keys it was sent."""

    keys: list[str] = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        FakeApi.keys.append(self.headers.get("x-api-key", ""))
        ask = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        prompt = ask["messages"][0]["content"]
        if "Someone searched for" in prompt:
            text = json.dumps({"results": [{"url": f"https://news{i}.example-press.com/a{i}", "title": f"Story {i}",
                                            "snippet": f"Snippet number {i} about the flaw.", "date": "1 Oct 2026"}
                                           for i in range(10)], "related": ["r"], "questions": ["q?"], "ads": []})
        else:
            url = re.search(r"Write the page at: (\S+)", prompt).group(1)
            snippet = re.search(r'snippet "([^"]+)"', prompt)
            text = (f"STATUS: 200\nCONTENT_TYPE: text/html\nTITLE: Some title\nDESCRIPTION: d\nDATE: 2026-10-01\n"
                    f"CLAIMS:\n- a claim about {url}\nSITE_NAME: Example Press\nSITE_NAV: Home|/\nSITE_FOOTER: About|/about\n"
                    f"SIDEBAR:\n- Other story | /other\nAD: Buy now\nBODY:\n<h1>Story</h1><p>{snippet.group(1) if snippet else ''}</p>")
        reply = json.dumps({"model": ask["model"], "stop_reason": "end_turn", "content": [{"type": "text", "text": text}],
                            "usage": {"input_tokens": 100, "output_tokens": 50}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


class Live(unittest.TestCase):
    """The anthropic generator against a fake API on 127.0.0.1."""

    def test_pages_from_the_api_keep_titles_and_never_store_the_key(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeApi)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        old = (model.API, os.environ.get("ANTHROPIC_API_KEY"))
        model.API = f"http://127.0.0.1:{server.server_address[1]}/v1/messages"
        os.environ["ANTHROPIC_API_KEY"] = "sk-test-key-must-not-be-stored"
        try:
            with tempfile.TemporaryDirectory() as d:
                s = seeds.load(seeds.find("halvard-cve", SEEDS))
                w = World(s, Store(Path(d) / s.name), "anthropic", "claude-haiku-4-5-20251001", prefetch=2)
                r = w.handle("GET", "www.google.com", "/search?q=halvard+flaw")
                self.assertEqual(r.meta["cache"], "generated")
                url, title = results(r.body)[0]
                w.pool.shutdown(wait=True)
                host, target = target_of(url)
                page = w.handle("GET", host, target)
                self.assertEqual(page.meta["cache"], "prefetched")
                self.assertIn(f"<title>{title}</title>", page.body.decode())
                self.assertEqual(page.meta["unsupported_snippets"], [])
                self.assertEqual(w.handle("GET", host, target).meta["cache"], "cached")
                self.assertTrue(FakeApi.keys and set(FakeApi.keys) == {"sk-test-key-must-not-be-stored"})
                for f in Path(d).rglob("*"):
                    if f.is_file():
                        self.assertNotIn("sk-test-key", f.read_text(errors="replace"), f)
        finally:
            model.API = old[0]
            if old[1] is None:
                del os.environ["ANTHROPIC_API_KEY"]
            else:
                os.environ["ANTHROPIC_API_KEY"] = old[1]
            server.shutdown()
            server.server_close()


class Parsing(unittest.TestCase):
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
        page = model.parse_page(text)
        self.assertEqual(page["title"], "Halvard patches gateway flaw | The Register")
        self.assertEqual(page["claims"], ["Halvard fixed CVE-2026-41877 in 7.2.4."])
        self.assertEqual(page["sidebar"], [("Printer firmware bricks fleet", "/2026/10/01/printer/")])
        self.assertEqual(page["site"]["nav"], ["Security|/security/", "Software|/software/"])
        self.assertEqual(page["ad"], "")
        self.assertTrue(page["body"].startswith("<h1>"))

    def test_search_answer(self):
        text = '```json\n{"results": [{"url": "https://a.com/x", "title": "A", "snippet": "S", "date": ""},' \
               ' {"url": "not a url", "title": "B"}], "related": ["r"], "ads": []}\n```'
        found = model.parse_search(text)
        self.assertEqual([r["url"] for r in found["results"]], ["https://a.com/x"])
        self.assertEqual(found["related"], ["r"])


if __name__ == "__main__":
    unittest.main()
