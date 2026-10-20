"""What the world answers for one request.

Every request is one of:

- a search (Google, DuckDuckGo, Bing): the result list is made once per
  query and kept. Each result is written down as a mention of its URL, with
  its title and snippet, before anyone asks for that URL.
- a fixed page from the seed: bytes and response metadata captured on first
  use, then served from the store even if the source changes or disappears.
- a page already in the store: served exactly as stored.
- a new page: made from the seed, its mentions (the searches and links that
  led to it) and what the world has already said, then stored. Of its first
  prompts.LINKS_PER_PAGE (80) link candidates, only http(s) links to non-search
  hosts whose target page is not yet stored become mentions. Empty anchors
  are skipped; normalized anchor text is cut at prompts.ANCHOR_CHARS (160).
- a stylesheet, script, image or font: a small fixed answer.

The consistency rules live here: a page takes the title its first mention
showed, a result for a URL the world already knows shows what the world
said about it, and search snippets known when a generated page is created
are checked for textual support in that page.
Searches reserve that title under the same URL lock as page creation, so
concurrent searches and direct page requests publish one title.

Without a generator (replay) nothing new is made: a URL the store does not
hold is a 404, and a query it does not hold has no results.
"""
from __future__ import annotations

import base64
import html
import json
import re
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urljoin

from . import llm, prompts, render, stub, tells
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


def normalize_snippet(text: str) -> str:
    """Ignore case, spacing and typographic quotes, apostrophes and dashes."""
    text = text.translate(str.maketrans({**dict.fromkeys("‘’‚‛", "'"),
                                       **dict.fromkeys('“”„‟', '"'),
                                       **dict.fromkeys("‐‑‒–—―", "-")}))
    return " ".join(text.lower().split())


def snippet_pieces(snippet: str) -> list[str]:
    """Complete substantive pieces, separated by sentences, fields or ellipses.

    A leading date is a boundary. Strip boundary punctuation from each piece;
    keep interior punctuation, including version numbers. Any letter or digit
    makes a piece substantive, with no minimum length."""
    text = normalize_snippet(snippet)
    text = re.sub(r"^((jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec) \d{1,2}, \d{4}|"
                  r"\d+ (days?|hours?) ago)\s*-\s*", "", text)
    pieces = []
    for piece in re.split(r"\.{3,}|…+|(?<=[.!?:])\s+|(?<=\s)[|·](?=\s)", text):
        while piece and (piece[0].isspace() or unicodedata.category(piece[0]).startswith("P")):
            piece = piece[1:]
        while piece and (piece[-1].isspace() or unicodedata.category(piece[-1]).startswith("P")):
            piece = piece[:-1]
        if any(c.isalnum() for c in piece):
            pieces.append(piece)
    return pieces


def check_snippets(mentions: list[dict], page_text: str | list[str]) -> tuple[list[str], list[str]]:
    """Return unsupported and unchecked search snippets separately.

    Every complete substantive piece must occur somewhere in the page text.
    JSON string values are checked separately. This is textual matching, not
    fact checking. Snippets without substantive pieces are unchecked."""
    texts = [normalize_snippet(t) for t in ([page_text] if isinstance(page_text, str) else page_text)]
    if not isinstance(mentions, list) or any(not isinstance(m, dict) for m in mentions):
        raise ValueError("snippet mentions must be a list of objects")
    unsupported, unchecked = [], []
    for m in mentions:
        if m["via"] == "link":
            continue
        if m["via"] != "search":
            raise ValueError("snippet mention must come via search or link")
        snippet = m.get("snippet", "")
        if not isinstance(snippet, str):
            raise ValueError("search snippet must be a string")
        pieces = snippet_pieces(snippet)
        if not pieces:
            unchecked.append(snippet)
        elif not all(any(piece in text for text in texts) for piece in pieces):
            unsupported.append(snippet)
    return unsupported, unchecked


def json_strings(value) -> list[str]:
    """The decoded string values in a JSON body, excluding object keys."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in json_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in json_strings(v)]
    return []


def rescore_snippets(record: dict) -> tuple[list[str], list[str]]:
    """Check a generated page's creation-time mentions against its stored body.

    Ignore previously recorded check results. Missing fields and invalid JSON
    are errors, so incomplete records cannot be reported as supported."""
    body = record["body"]
    content_type = record["content_type"]
    if not isinstance(body, str) or not isinstance(content_type, str) or not content_type.strip():
        raise ValueError("snippet check requires a text body and content type")
    ctype = content_type.split(";", 1)[0].strip().lower()
    if ctype == "text/html":
        text = text_of(body)
    elif ctype == "application/json" or ctype.endswith("+json"):
        text = json_strings(json.loads(body))
    else:
        text = body
    return check_snippets(record["context"]["mentions"], text)


LINK = re.compile(r"""<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)[^"']*["'][^>]*>(.*?)</a>""", re.I | re.S)


class GenerationBudgetExceeded(RuntimeError):
    """This run has used its generation budget."""


class World:
    def __init__(self, seed: Seed, store: Store, generator: Model | stub.Stub | None, prefetch: int = 0, generation_budget: int = 200):
        """`generator` makes new results and pages; None replays the store.
        `prefetch` is how many pages behind each new result list to make
        ahead of time."""
        self.generation_budget = generation_budget
        self.generation_lock = threading.Lock()
        self.seed = seed
        self.store = store
        self.generator = generator
        config = None
        if isinstance(generator, Model):
            config = {"provider": generator.provider, "model": generator.model, "reasoning": generator.reasoning}
        elif generator is not None:
            config = {"provider": "stub", "model": generator.model}
        store.bind(seed.fingerprint(), config)
        if isinstance(generator, Model):
            generator.record = store.log_generation
        if generator is not None:
            for fixed in seed.fixed:
                if store.page(fixed.host, fixed.target) is None:
                    try:
                        with fixed.file.open("rb"):
                            pass
                    except OSError as err:
                        raise ValueError(f"{seed.path}: fixed page file {fixed.file} does not exist") from err
        self.year = seed.date[:4]
        self.prefetch = prefetch if generator else 0
        self.pool = ThreadPoolExecutor(max_workers=4) if self.prefetch else None
        # Pages made ahead of time that have not been asked for yet: their
        # first request is logged as `prefetched`, with the time they took.
        self.unserved: set[tuple[str, str]] = set()
        self.unserved_lock = threading.Lock()

    def _reserve_generation(self) -> None:
        with self.generation_lock:
            if self.generation_budget <= 0:
                raise GenerationBudgetExceeded("generation budget exhausted")
            self.generation_budget -= 1

    def _generate(self, kind: str, *args, **context) -> Made:
        made = getattr(self.generator, kind)(*args)
        if not isinstance(self.generator, Model):
            self.store.log_generation({"kind": kind, "record": "stub", **context, **made.usage(), "raw": made.raw})
        return made

    def cast(self) -> list[dict]:
        """The people the world names, made by the generator the first time
        a page or result list needs them."""
        def make() -> dict:
            self._reserve_generation()
            made = self._generate("cast")
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
            try:
                record, made = self.store.search_once(key, lambda: self._make_search(key, query))
            except GenerationBudgetExceeded:
                return html_response("Generation budget exhausted", {"kind": "search", "cache": "budget"}, status=503)
            if made:
                cache = "generated"
                for r in record["results"][:self.prefetch]:
                    self.pool.submit(self._prefetch, *target_of(r["url"]))
        body = {"google": render.google, "duckduckgo": render.duckduckgo, "bing": render.bing}[engine](query, record, start)
        meta = {"kind": "search", "engine": engine, "search": query, "cache": cache, "model": record.get("model"),
                "results": len(record["results"]),
                "listed": [{"rank": rank, "url": r["url"], "title": r["title"]}
                           for rank, r in enumerate(record["results"], 1)]}
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
        self._reserve_generation()
        made = self._generate("search", query, self._known(), self.store.recent_claims(), self.cast(), query=query)
        results = []
        for r in made.fields["results"]:
            host, target = target_of(r["url"])
            if not host or any(x["url"] == r["url"] for x in results):
                continue
            fixed = self.seed.fixed_for(host, target)
            mention = self.store.reserve_mention(
                host, target, {"via": "search", "query": query, "rank": len(results) + 1, "title": r["title"],
                               "snippet": r["snippet"], "date": r.get("date", "")},
                {"title": fixed.title, "description": fixed.description} if fixed else None)
            results.append(dict(r, title=mention["title"], snippet=mention["snippet"]))
        return {"query": query, "key": key, "results": results, "related": made.fields.get("related", []),
                "questions": made.fields.get("questions", []), "ads": made.fields.get("ads", []),
                **made.usage(), "created": time.time()}

    def _prefetch(self, host: str, target: str) -> None:
        started = time.monotonic()
        try:
            self.page(host, target, prefetch=True)
        except Exception as err:  # noqa: BLE001 - a page that failed ahead of time is made again on request
            ledger = getattr(err, "ledger", None)
            usage = ledger.usage() if ledger is not None and ledger.attempts else {}
            self.store.log_generation({"kind": "prefetch_error", "record": "diagnostic",
                                       "url": f"https://{host}{target}", "error": llm.describe(err),
                                       "serve_ms": round((time.monotonic() - started) * 1000), **usage})

    # --- pages ---------------------------------------------------------
    def page(self, host: str, target: str, prefetch: bool = False) -> Response:
        fixed = self.seed.fixed_for(host, target)
        if fixed:
            return self._fixed(host, target, fixed)
        record, cache = self.store.page(host, target), "cached"
        if record is None and self.generator is None:
            return self._not_found(host, target, "missing")
        if record is None:
            try:
                record, made = self.store.page_once(host, target, lambda: self._make_page(host, target, prefetch))
            except GenerationBudgetExceeded:
                return html_response("Generation budget exhausted", {"kind": "page", "cache": "budget"}, status=503)
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
                "unsupported_snippets": record.get("unsupported_snippets", []),
                "unchecked_snippets": record.get("unchecked_snippets", []), "tells": record.get("tells", [])}
        mentions = record.get("context", {}).get("mentions", [])
        first = mentions[0] if mentions else {"via": "direct"}
        meta["reason"] = {k: first[k] for k in ("via", "query", "rank", "from") if k in first}
        if cache != "cached":
            meta |= {"gen_ms": record.get("gen_ms"), "cost": record.get("cost")}
        profile = self.store.site(host)
        return Response(record["status"], record["content_type"], record["body"].encode("utf-8"),
                        {"Server": render.server_of(profile)}, meta)

    def _fixed(self, host: str, target: str, fixed) -> Response:
        def make() -> dict:
            body = fixed.file.read_bytes()
            return {"url": fixed.url, "status": 200, "title": fixed.title, "description": fixed.description,
                    "claims": [], "model": "fixed", "created": time.time(), "file": fixed.file.name,
                    "body_base64": base64.b64encode(body).decode("ascii"),
                    "content_type": fixed.content_type, "headers": {"Server": "nginx"}}

        record, made = self.store.page(host, target), False
        if record is None:
            if self.generator is None:
                return self._not_found(host, target, "missing")
            record, made = self.store.page_once(host, target, make)
        if not {"body_base64", "status", "content_type", "headers", "title"} <= record.keys():
            raise self.store.incompatible(f"incomplete fixed snapshot for {fixed.url}")
        body = base64.b64decode(record["body_base64"], validate=True)
        if made and record["content_type"].startswith("text/html"):
            self._note_links(record["url"], body.decode("utf-8", "replace"))
        return Response(record["status"], record["content_type"], body, record["headers"],
                        {"kind": "page", "cache": "fixed", "title": record["title"], "reason": {"via": "fixed"}})

    def _not_found(self, host: str, target: str, cache: str) -> Response:
        profile = self.store.site(host)
        body = render.not_found(host, profile, target, self.year)
        return html_response(body, {"kind": "page", "cache": cache}, status=404, server=render.server_of(profile))

    def _make_page(self, host: str, target: str, prefetch: bool) -> dict:
        self._reserve_generation()
        url = f"https://{host}{target}"
        mentions = prompts.asked_mentions(self.store.mentions(host, target))
        ask = PageAsk(url, host, target, mentions, self.store.site(host), self.store.pages(host)[:20],
                      self.store.recent_claims(), self.cast())
        made = self._generate("page", ask, url=url)
        page = dict(made.fields)
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
            body = render.page(host, profile, page, self.year)
        if prefetch:
            with self.unserved_lock:
                self.unserved.add((host, target))
        record = {"url": url, "status": page["status"], "content_type": page["content_type"], "title": page["title"],
                  "description": page.get("description", ""), "date": page.get("date", ""), "claims": page["claims"],
                  "body": body, **made.usage(), "prefetched": prefetch, "created": time.time(),
                  "context": {"mentions": mentions},
                  "tells": tells.find(text_of(page["body"]) if is_html else body)}
        record["unsupported_snippets"], record["unchecked_snippets"] = rescore_snippets(record)
        return record

    def _note_links(self, url: str, markup: str) -> None:
        """Record context from the first prompts.LINKS_PER_PAGE link candidates.

        Apply that bound before resolving URLs and filtering: keep only
        http(s) links with a host, excluding search hosts and stored pages.
        Normalize anchor text, cut it at prompts.ANCHOR_CHARS, then skip empty
        anchors. A later request has this context even without a Referer."""
        for href, anchor in LINK.findall(markup)[:prompts.LINKS_PER_PAGE]:
            absolute = urljoin(url, html.unescape(href.strip()))
            if not absolute.startswith(("http://", "https://")):
                continue
            host, target = target_of(absolute)
            if not host or host in SEARCH_HOSTS or self.store.page(host, target) is not None:
                continue
            anchor_text = text_of(anchor)[:prompts.ANCHOR_CHARS]
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
