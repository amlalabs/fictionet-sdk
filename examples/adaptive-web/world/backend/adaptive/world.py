"""What the world answers for one request.

Every request is one of:

- a search (Google, DuckDuckGo, Bing): the result list is made once per
  query and kept. Each result is written down as a mention of its URL, with
  its title and snippet, before anyone asks for that URL.
- a fixed page from the seed: served exactly as written.
- a page already in the store: served exactly as stored.
- a new page: made from the seed, its mentions (the searches and links that
  led to it) and what the world has already said, then stored. Its links
  are written down as mentions of their targets in turn.

In replay mode nothing new is made: a URL the store does not hold is a 404.
"""
from __future__ import annotations

import html
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin

from . import model, render, stub
from .seed import Seed, target_of
from .store import Store

SEARCH_HOSTS = {"www.google.com", "google.com", "html.duckduckgo.com", "duckduckgo.com", "lite.duckduckgo.com",
                "www.bing.com", "bing.com"}


@dataclass
class Response:
    status: int
    content_type: str
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)
    # What the log records about it. Sent to the Rust world in one header,
    # which it takes off before the agent sees the response.
    meta: dict = field(default_factory=dict)


def norm_query(q: str) -> str:
    return " ".join(q.lower().split())


def text_of(markup: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", markup)).split())


def snippet_core(snippet: str) -> str:
    s = snippet.replace("...", " ").replace("…", " ")
    s = re.sub(r"^\s*\w{3} \d{1,2}, \d{4}\s*[—-]\s*", "", s)
    return " ".join(s.split())


LINK = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)[^"']*["'][^>]*>(.*?)</a>""", re.I | re.S)


class World:
    def __init__(self, seed: Seed, store: Store, generator: str = "stub", model_name: str = model.DEFAULT_MODEL,
                 prefetch: int = 0):
        self.seed = seed
        self.store = store
        self.mode = generator
        self.year = seed.date[:4]
        self.prefetch = prefetch
        self.llm = model.Anthropic(model_name) if generator == "anthropic" else None
        self.pool = ThreadPoolExecutor(max_workers=4) if prefetch else None
        self.served: set[tuple[str, str]] = set()
        self.served_lock = threading.Lock()

    @property
    def model_name(self) -> str:
        return self.llm.model if self.llm else self.mode

    # --- entry point ---------------------------------------------------
    def handle(self, method: str, host: str, target: str, form: dict[str, str] | None = None) -> Response:
        host = host.lower()
        path, _, query = target.partition("?")
        args = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}
        if form:
            args.update(form)
        if host in ("google.com", "bing.com"):
            return redirect(f"https://www.{host}{target}", 301)
        if host == "www.google.com":
            if path == "/search" and args.get("q", "").strip():
                return self.search("google", args["q"], int(args.get("start", "0") or 0))
            if path == "/url" and args.get("q", "").startswith("http"):
                return redirect(args["q"], 302)
            if path in ("/", "/webhp"):
                return html_response(render.google_home(), {"kind": "search_home"})
        if host in ("html.duckduckgo.com", "duckduckgo.com", "lite.duckduckgo.com"):
            if path == "/l/" and args.get("uddg", "").startswith("http"):
                return redirect(args["uddg"], 302)
            if path in ("/html", "/html/", "/lite", "/lite/", "/"):
                if args.get("q", "").strip():
                    return self.search("duckduckgo", args["q"], int(args.get("s", "0") or 0))
                return html_response(render.duckduckgo_home(), {"kind": "search_home"})
        if host == "www.bing.com" and path == "/search" and args.get("q", "").strip():
            return self.search("bing", args["q"], int(args.get("first", "1") or 1) - 1)
        asset = static_asset(path)
        if asset and not self.seed.fixed_for(host, target):
            return asset
        return self.page(host, target)

    # --- searches ------------------------------------------------------
    def search(self, engine: str, query: str, start: int = 0) -> Response:
        start = max(0, start)
        key = norm_query(query) + (f" (from {start})" if start >= 10 else "")
        record = self.store.search(key)
        cache = "cached"
        if record is None:
            with self.store.lock("search " + key):
                record = self.store.search(key)
                if record is None:
                    if self.mode == "replay":
                        record = {"query": query, "results": [], "related": [], "questions": [], "ads": []}
                        cache = "missing"
                    else:
                        record = self._make_search(key, query)
                        cache = "generated"
        if engine == "google":
            body = render.google(query, record, start)
        elif engine == "duckduckgo":
            body = render.duckduckgo(query, record)
        else:
            body = render.bing(query, record)
        meta = {"kind": "search", "engine": engine, "search": query, "cache": cache,
                "gen_ms": record.get("gen_ms") if cache == "generated" else None,
                "model": record.get("model"), "results": len(record["results"])}
        return html_response(body, meta)

    def _known(self) -> list[dict]:
        known = [{"url": f.url, "title": f.title, "snippet": f.description} for f in self.seed.fixed]
        pages = self.store.root / "pages"
        if pages.is_dir():
            for p in sorted(pages.rglob("@page.json"), key=lambda p: p.stat().st_mtime)[-40:]:
                r = self.store._read(p) or {}
                if r.get("status") == 200 and r.get("title"):
                    known.append({"url": r["url"], "title": r["title"], "snippet": r.get("description", "")})
        return known

    def _make_search(self, key: str, query: str) -> dict:
        started = time.monotonic()
        known = self._known()
        info: dict = {"model": self.model_name}
        if self.llm:
            system, user = model.search_prompt(self.seed, query, known, self.store.recent_claims())
            text, info = self.llm.complete(system, user, max_tokens=2500)
            raw = text
            made = model.parse_search(text)
        else:
            made = stub.search(self.seed, query, known)
            raw = None
        gen_ms = round((time.monotonic() - started) * 1000)
        results = []
        seen = set()
        for rank, r in enumerate(made["results"], 1):
            host, target = target_of(r["url"])
            if not host or r["url"] in seen:
                continue
            seen.add(r["url"])
            # A result for a URL the world already knows keeps what it said.
            page = self.store.page(host, target)
            fixed = self.seed.fixed_for(host, target)
            earlier = [m for m in self.store.mentions(host, target) if m.get("title")]
            if page and page.get("title"):
                r = dict(r, title=page["title"], snippet=page.get("description") or r["snippet"])
            elif fixed:
                r = dict(r, title=fixed.title or r["title"], snippet=fixed.description or r["snippet"])
            elif earlier:
                r = dict(r, title=earlier[0]["title"])
            results.append(r)
            self.store.add_mention(host, target, {"via": "search", "query": query, "rank": rank, "title": r["title"],
                                                  "snippet": r["snippet"], "date": r.get("date", "")})
        record = {"query": query, "key": key, "results": results, "related": made.get("related", []),
                  "questions": made.get("questions", []), "ads": made.get("ads", []),
                  "model": info.get("model"), "gen_ms": gen_ms, "created": time.time()}
        self.store.save_search(key, record)
        self.store.log_generation({"kind": "search", "query": query, "model": info.get("model"), "gen_ms": gen_ms,
                                   "input_tokens": info.get("input_tokens"), "output_tokens": info.get("output_tokens"),
                                   "raw": raw})
        if self.pool:
            for r in results[:self.prefetch]:
                host, target = target_of(r["url"])
                self.pool.submit(self._prefetch, host, target)
        return record

    def _prefetch(self, host: str, target: str) -> None:
        try:
            self.page(host, target, prefetch=True)
        except Exception as err:  # noqa: BLE001 - a failed prefetch is retried on request
            self.store.log_generation({"kind": "prefetch_error", "url": f"https://{host}{target}", "error": str(err)})

    # --- pages ---------------------------------------------------------
    def page(self, host: str, target: str, prefetch: bool = False) -> Response:
        fixed = self.seed.fixed_for(host, target)
        if fixed:
            body = fixed.file.read_bytes()
            if self.store.page(host, target) is None:
                with self.store.lock(f"page {host}{target}"):
                    if self.store.page(host, target) is None:
                        record = {"url": fixed.url, "status": 200, "title": fixed.title, "description": fixed.description,
                                  "claims": [], "generated_by": "fixed", "created": time.time(), "file": str(fixed.file)}
                        self.store.save_page(host, target, record)
                        self._note_links(fixed.url, body.decode("utf-8", "replace"))
            return Response(200, fixed.content_type, body, meta={"kind": "page", "cache": "fixed", "title": fixed.title})
        record = self.store.page(host, target)
        cache = "cached"
        if record is not None and record.get("prefetched") and not prefetch and self.mode != "replay":
            # The first request for a page made ahead of time says so, with
            # the time it took to make.
            with self.served_lock:
                if (host, target) not in self.served:
                    cache = "prefetched"
        if record is None:
            with self.store.lock(f"page {host}{target}"):
                record = self.store.page(host, target)
                if record is None:
                    if self.mode == "replay":
                        return self._not_found(host, target, "missing")
                    record = self._make_page(host, target, prefetch)
                    cache = "generated"
        if not prefetch:
            with self.served_lock:
                self.served.add((host, target))
        meta = {"kind": "page", "cache": cache, "title": record.get("title"), "model": record.get("model"),
                "gen_ms": record.get("gen_ms") if cache != "cached" else None,
                "prefetched": bool(record.get("prefetched")), "claims": record.get("claims", []),
                "mentions": len(record.get("context", {}).get("mentions", [])),
                "unsupported_snippets": record.get("unsupported_snippets", [])}
        return Response(record["status"], record["content_type"], record["body"].encode("utf-8"), meta=meta)

    def _not_found(self, host: str, target: str, cache: str) -> Response:
        body = render.not_found(host, self.store.site(host), target, self.year)
        return html_response(body, {"kind": "page", "cache": cache}, status=404)

    def _make_page(self, host: str, target: str, prefetch: bool) -> dict:
        url = f"https://{host}{target}"
        mentions = self.store.mentions(host, target)
        profile = self.store.site(host)
        host_pages = self.store.pages_on(host)
        claims = self.store.recent_claims()
        started = time.monotonic()
        raw = None
        info: dict = {"model": self.model_name}
        if self.llm:
            system, user = model.page_prompt(self.seed, url, mentions, profile, host_pages, claims, self.seed.about(host))
            raw, info = self.llm.complete(system, user, max_tokens=3000)
            made = model.parse_page(raw)
        else:
            made = stub.page(self.seed, host, target, mentions, host_pages)
        gen_ms = round((time.monotonic() - started) * 1000)
        if profile is None:
            profile = self.store.save_site_once(host, made.get("site") or stub.site_profile(host))
        titles = [m["title"] for m in mentions if m.get("title")]
        if titles:
            made["title"] = titles[0]
        is_html = made["content_type"].startswith("text/html")
        text = text_of(made["body"]) if is_html else made["body"]
        unsupported = [m["snippet"] for m in mentions if m.get("via") == "search" and m.get("snippet")
                       and snippet_core(m["snippet"])[:80].lower() not in " ".join(text.split()).lower()]
        if is_html:
            if made["status"] == 404:
                body = render.not_found(host, profile, target, self.year)
            else:
                body = render.page(host, profile, made, self.year)
        else:
            body = made["body"]
        record = {"url": url, "status": made["status"], "content_type": made["content_type"], "title": made["title"],
                  "description": made.get("description", ""), "date": made.get("date", ""), "claims": made["claims"],
                  "body": body, "generated_by": "anthropic" if self.llm else "stub", "model": info.get("model"),
                  "gen_ms": gen_ms, "input_tokens": info.get("input_tokens"),
                  "output_tokens": info.get("output_tokens"), "prefetched": prefetch, "created": time.time(),
                  "context": {"mentions": mentions}, "unsupported_snippets": unsupported}
        self.store.save_page(host, target, record)
        self.store.log_generation({"kind": "page", "url": url, "model": info.get("model"), "gen_ms": gen_ms,
                                   "input_tokens": info.get("input_tokens"),
                                   "output_tokens": info.get("output_tokens"), "raw": raw})
        if is_html:
            self._note_links(url, body)
        return record

    def _note_links(self, url: str, markup: str) -> None:
        """Writes down every link of a page as a mention of its target, so a
        later request for it has context even without a Referer."""
        for href, anchor in LINK.findall(markup)[:80]:
            absolute = urljoin(url, html.unescape(href.strip()))
            if not absolute.startswith(("http://", "https://")):
                continue
            host, target = target_of(absolute)
            if not host or host in SEARCH_HOSTS or self.store.page(host, target) is not None:
                continue
            anchor_text = text_of(anchor)[:160]
            if anchor_text:
                self.store.add_mention(host, target, {"via": "link", "from": url, "anchor": anchor_text})


# A 1x1 transparent GIF.
PIXEL = bytes.fromhex("47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b")
ASSETS = {
    ".css": ("text/css", b"/* site styles */\n"),
    ".js": ("application/javascript", b"/* site scripts */\n"),
    ".gif": ("image/gif", PIXEL), ".png": ("image/gif", PIXEL), ".jpg": ("image/gif", PIXEL),
    ".jpeg": ("image/gif", PIXEL), ".webp": ("image/gif", PIXEL), ".svg": ("image/gif", PIXEL),
    ".ico": ("image/gif", PIXEL), ".woff": ("font/woff", b""), ".woff2": ("font/woff2", b""),
}


def static_asset(path: str) -> Response | None:
    """Stylesheets, scripts, images and fonts are not made by the generator:
    they get a small fixed answer, so a browser-like client costs no model
    calls. robots.txt allows everything."""
    if path == "/robots.txt":
        return Response(200, "text/plain; charset=utf-8", b"User-agent: *\nAllow: /\n", meta={"kind": "asset", "cache": "none"})
    dot = path.rfind(".")
    if dot > path.rfind("/") and path[dot:].lower() in ASSETS:
        ctype, body = ASSETS[path[dot:].lower()]
        return Response(200, ctype, body, meta={"kind": "asset", "cache": "none"})
    return None


def redirect(location: str, status: int) -> Response:
    body = f'<html><head><title>{status} Moved</title></head><body><a href="{html.escape(location)}">here</a></body></html>'
    return Response(status, "text/html; charset=utf-8", body.encode(), {"Location": location},
                    meta={"kind": "redirect", "cache": "none", "location": location})


def html_response(body: str, meta: dict, status: int = 200) -> Response:
    return Response(status, "text/html; charset=utf-8", body.encode("utf-8"), meta=meta)


def decode_form(body: bytes) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
