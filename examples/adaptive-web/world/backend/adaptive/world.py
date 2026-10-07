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
- a stylesheet, script, image or font: a small fixed answer.

The consistency rules live here: a page takes the title its first mention
showed, a result for a URL the world already knows shows what the world
said about it, and every snippet is checked against the page behind it.

Without a generator (replay) nothing new is made: a URL the store does not
hold is a 404, and a query it does not hold has no results.
"""
from __future__ import annotations

import html
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin

from . import render, stub, tells
from .generate import Made, Model, PageAsk
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
    """The text of an HTML fragment, as one line."""
    markup = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", markup)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", markup)).split())


def snippet_core(snippet: str) -> str:
    """A snippet without its ellipses and a leading date, the part that must
    appear on the page word for word."""
    s = snippet.replace("...", " ").replace("…", " ")
    s = re.sub(r"^\s*(\w{3} \d{1,2}, \d{4}|\d+ (days?|hours?) ago)\s*[—–-]\s*", "", s)
    return " ".join(s.split())


def unsupported_snippets(mentions: list[dict], page_text: str) -> list[str]:
    """The search snippets for a page that the page does not back up.

    A snippet is often stitched together from several places on the page
    ("12 replies. Kwame Osei: Just finished ..."), so it is split into
    sentences and fields, and each piece of 20 characters or more is looked
    for on the page by its first 60 characters, ignoring case and spacing.
    A snippet is backed up when at least half of its pieces are found."""
    text = " ".join(page_text.split()).lower()
    out = []
    for m in mentions:
        if m.get("via") != "search" or not m.get("snippet"):
            continue
        pieces = [p for p in re.split(r"(?<=[.!?:])\s+|\s+[|·]\s+", snippet_core(m["snippet"])) if len(p) >= 20]
        found = sum(" ".join(p.split())[:60].lower() in text for p in pieces)
        if pieces and found * 2 < len(pieces):
            out.append(m["snippet"])
    return out


LINK = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)[^"']*["'][^>]*>(.*?)</a>""", re.I | re.S)


class World:
    def __init__(self, seed: Seed, store: Store, generator: Model | stub.Stub | None, prefetch: int = 0):
        """`generator` makes new results and pages; None replays the store.
        `prefetch` is how many pages behind each new result list to make
        ahead of time."""
        self.seed = seed
        self.store = store
        self.generator = generator
        self.year = seed.date[:4]
        self.prefetch = prefetch if generator else 0
        self.pool = ThreadPoolExecutor(max_workers=4) if self.prefetch else None
        # Pages made ahead of time that have not been asked for yet: their
        # first request is logged as `prefetched`, with the time they took.
        self.unserved: set[tuple[str, str]] = set()
        self.unserved_lock = threading.Lock()

    def cast(self) -> list[dict]:
        """The people the world names, made by the generator the first time
        a page or result list needs them."""
        def make() -> dict:
            made = self.generator.cast()
            self.store.log_generation({"kind": "cast", **made.usage(), "raw": made.raw})
            return {"people": made.fields, **made.usage()}
        return self.store.cast_once(make)["people"]

    @property
    def model(self) -> str:
        return self.generator.model if self.generator else "replay"

    # --- entry point ---------------------------------------------------
    def handle(self, method: str, host: str, target: str, form: dict[str, str] | None = None) -> Response:
        host = host.lower()
        path, _, query = target.partition("?")
        args = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}
        if form:
            args.update(form)
        q = args.get("q", "").strip()
        if host in ("google.com", "bing.com"):
            return redirect(f"https://www.{host}{target}", 301)
        if host == "www.google.com":
            if path == "/search" and q:
                return self.search("google", q, number(args.get("start")))
            if path == "/url" and args.get("q", "").startswith("http"):
                return redirect(args["q"], 302)
            if path in ("/", "/webhp"):
                return html_response(render.google_home(), {"kind": "search_home"}, server="gws")
        if host in ("html.duckduckgo.com", "duckduckgo.com", "lite.duckduckgo.com"):
            if path == "/l/" and args.get("uddg", "").startswith("http"):
                return redirect(args["uddg"], 302)
            if path in ("/html", "/html/", "/lite", "/lite/", "/"):
                if q:
                    return self.search("duckduckgo", q, number(args.get("s")))
                return html_response(render.duckduckgo_home(), {"kind": "search_home"}, server="nginx")
        if host == "www.bing.com" and path == "/search" and q:
            return self.search("bing", q, max(0, number(args.get("first")) - 1))
        if not self.seed.fixed_for(host, target) and (asset := static_asset(path)):
            return asset
        return self.page(host, target)

    # --- searches ------------------------------------------------------
    def search(self, engine: str, query: str, start: int = 0) -> Response:
        key = norm_query(query) + (f" (from {start})" if start >= 10 else "")
        record, cache = self.store.search(key), "cached"
        if record is None and self.generator is None:
            record, cache = {"query": query, "results": []}, "missing"
        elif record is None:
            record, made = self.store.search_once(key, lambda: self._make_search(key, query))
            if made:
                cache = "generated"
                for r in record["results"][:self.prefetch]:
                    self.pool.submit(self._prefetch, *target_of(r["url"]))
        body = {"google": render.google, "duckduckgo": render.duckduckgo, "bing": render.bing}[engine](query, record, start)
        meta = {"kind": "search", "engine": engine, "search": query, "cache": cache, "model": record.get("model"),
                "results": len(record["results"])}
        if cache == "generated":
            meta |= {"gen_ms": record.get("gen_ms"), "cost": record.get("cost")}
        return html_response(body, meta, server=render.ENGINE_SERVERS[engine])

    def _known(self) -> list[dict]:
        """Pages the world has: the seed's fixed pages and the last 40 made."""
        known = [{"url": f.url, "title": f.title, "snippet": f.description} for f in self.seed.fixed]
        known += [{"url": p["url"], "title": p["title"], "snippet": p["description"]}
                  for p in self.store.pages()[-40:] if p["status"] == 200 and p["title"]]
        return known

    def _make_search(self, key: str, query: str) -> dict:
        made = self.generator.search(query, self._known(), self.store.recent_claims(), self.cast())
        results = []
        for rank, r in enumerate(made.fields["results"], 1):
            host, target = target_of(r["url"])
            if not host or any(x["url"] == r["url"] for x in results):
                continue
            r = self._as_known(host, target, r)
            results.append(r)
            self.store.add_mention(host, target, {"via": "search", "query": query, "rank": rank, "title": r["title"],
                                                  "snippet": r["snippet"], "date": r.get("date", "")})
        self.store.log_generation({"kind": "search", "query": query, **made.usage(), "raw": made.raw})
        return {"query": query, "key": key, "results": results, "related": made.fields.get("related", []),
                "questions": made.fields.get("questions", []), "ads": made.fields.get("ads", []),
                **made.usage(), "created": time.time()}

    def _as_known(self, host: str, target: str, result: dict) -> dict:
        """A result for a URL the world already knows shows what the world
        said about it: the page's title and description, the fixed page's,
        or the title an earlier result showed."""
        page = self.store.page(host, target)
        fixed = self.seed.fixed_for(host, target)
        earlier = [m["title"] for m in self.store.mentions(host, target) if m.get("title")]
        if page and page.get("title"):
            return dict(result, title=page["title"], snippet=page.get("description") or result["snippet"])
        if fixed:
            return dict(result, title=fixed.title or result["title"], snippet=fixed.description or result["snippet"])
        if earlier:
            return dict(result, title=earlier[0])
        return result

    def _prefetch(self, host: str, target: str) -> None:
        try:
            self.page(host, target, prefetch=True)
        except Exception as err:  # noqa: BLE001 - a page that failed ahead of time is made again on request
            self.store.log_generation({"kind": "prefetch_error", "url": f"https://{host}{target}",
                                       "error": f"{type(err).__name__}: {err}"})

    # --- pages ---------------------------------------------------------
    def page(self, host: str, target: str, prefetch: bool = False) -> Response:
        fixed = self.seed.fixed_for(host, target)
        if fixed:
            return self._fixed(host, target, fixed)
        record, cache = self.store.page(host, target), "cached"
        if record is None and self.generator is None:
            return self._not_found(host, target, "missing")
        if record is None:
            record, made = self.store.page_once(host, target, lambda: self._make_page(host, target, prefetch))
            if made:
                cache = "generated"
                if record["content_type"].startswith("text/html"):
                    self._note_links(record["url"], record["body"])
        if not prefetch and record.get("prefetched"):
            with self.unserved_lock:
                if (host, target) in self.unserved:
                    self.unserved.discard((host, target))
                    cache = "prefetched"
        meta = {"kind": "page", "cache": cache, "title": record.get("title"), "model": record.get("model"),
                "prefetched": bool(record.get("prefetched")), "claims": record.get("claims", []),
                "mentions": len(record.get("context", {}).get("mentions", [])),
                "unsupported_snippets": record.get("unsupported_snippets", []), "tells": record.get("tells", [])}
        if cache != "cached":
            meta |= {"gen_ms": record.get("gen_ms"), "cost": record.get("cost")}
        profile = self.store.site(host)
        return Response(record["status"], record["content_type"], record["body"].encode("utf-8"),
                        {"Server": render.server_of(profile)}, meta)

    def _fixed(self, host: str, target: str, fixed) -> Response:
        body = fixed.file.read_bytes()

        def make() -> dict:
            return {"url": fixed.url, "status": 200, "title": fixed.title, "description": fixed.description,
                    "claims": [], "model": "fixed", "created": time.time(), "file": fixed.file.name}

        _, made = self.store.page_once(host, target, make)
        if made:
            self._note_links(fixed.url, body.decode("utf-8", "replace"))
        return Response(200, fixed.content_type, body, {"Server": "nginx"},
                        {"kind": "page", "cache": "fixed", "title": fixed.title})

    def _not_found(self, host: str, target: str, cache: str) -> Response:
        profile = self.store.site(host)
        body = render.not_found(host, profile, target, self.year)
        return html_response(body, {"kind": "page", "cache": cache}, status=404, server=render.server_of(profile))

    def _make_page(self, host: str, target: str, prefetch: bool) -> dict:
        url = f"https://{host}{target}"
        mentions = self.store.mentions(host, target)
        ask = PageAsk(url, host, target, mentions, self.store.site(host), self.store.pages(host)[:20],
                      self.store.recent_claims(), self.cast())
        made: Made = self.generator.page(ask)
        page = made.fields
        profile = ask.profile or self.store.site_once(host, page.get("site") or stub.site_profile(host))
        titles = [m["title"] for m in mentions if m.get("title")]
        if titles:
            page["title"] = titles[0]
        is_html = page["content_type"].startswith("text/html")
        if not is_html:
            body = page["body"]
        elif page["status"] == 404 and not mentions:
            body = render.not_found(host, profile, target, self.year)
        else:
            # A page something pointed at exists, whatever the model said.
            page["status"] = 200
            body = render.page(host, profile, page, self.year)
        self.store.log_generation({"kind": "page", "url": url, **made.usage(), "raw": made.raw})
        if prefetch:
            with self.unserved_lock:
                self.unserved.add((host, target))
        return {"url": url, "status": page["status"], "content_type": page["content_type"], "title": page["title"],
                "description": page.get("description", ""), "date": page.get("date", ""), "claims": page["claims"],
                "body": body, **made.usage(), "prefetched": prefetch, "created": time.time(),
                "context": {"mentions": mentions},
                "unsupported_snippets": unsupported_snippets(mentions, text_of(page["body"]) if is_html else body),
                "tells": tells.find(text_of(page["body"]) if is_html else body)}

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


def number(text: str | None) -> int:
    """A page offset from a query string; 0 when it is missing or not a number."""
    try:
        return max(0, int(text or 0))
    except ValueError:
        return 0


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
        return Response(200, "text/plain; charset=utf-8", b"User-agent: *\nAllow: /\n", {}, {"kind": "asset"})
    dot = path.rfind(".")
    if dot > path.rfind("/") and path[dot:].lower() in ASSETS:
        ctype, body = ASSETS[path[dot:].lower()]
        return Response(200, ctype, body, {}, {"kind": "asset"})
    return None


def redirect(location: str, status: int) -> Response:
    body = f'<html><head><title>{status} Moved</title></head><body><a href="{html.escape(location)}">here</a></body></html>'
    return Response(status, "text/html; charset=utf-8", body.encode(), {"Location": location},
                    {"kind": "redirect", "location": location})


def html_response(body: str, meta: dict, status: int = 200, server: str = "nginx") -> Response:
    return Response(status, "text/html; charset=utf-8", body.encode("utf-8"), {"Server": server}, meta)


def decode_form(body: bytes) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()}
