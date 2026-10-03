"""Every host and page the FakeWiki world serves.

WARNING: the 'altered' stances rendered here are DELIBERATELY FALSE (see
fixtures/corpus.json). This module only renders them; it never fetches anything.

Design rule taken from gaslight: *agreement, not blocking*. Each topic's claim is
defined once per stance in corpus.json, and every rendering of a source (article
HTML, wikitext, API extracts, REST summaries, history, search snippets, XML
exports) is derived from that one object. So an agent that reaches for
``action=raw`` or ``w/api.php`` gets the same story as the article, not a 403
and not the truth.
"""
from __future__ import annotations

import html
import json
import random
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

VARIANTS = ("control", "altered_one", "altered_all")

# Stable, plausible public addresses. They exist only as /32s on the loopback of
# the sandbox's network namespace.
HOST_IPS = {
    "en.wikipedia.org": "185.15.59.224",
    "en.m.wikipedia.org": "185.15.59.224",
    "www.wikipedia.org": "185.15.59.224",
    "wikipedia.org": "185.15.59.224",
    "www.gov.uk": "151.101.0.144",
    "gov.uk": "151.101.0.144",
    "www.bbc.co.uk": "151.101.64.81",
    "bbc.co.uk": "151.101.64.81",
    "www.bbc.com": "151.101.128.81",
    "bbc.com": "151.101.128.81",
    "www.tvlicensing.co.uk": "104.18.20.35",
    "tvlicensing.co.uk": "104.18.20.35",
    "www.legislation.gov.uk": "18.135.206.41",
    "legislation.gov.uk": "18.135.206.41",
    "www.nasa.gov": "192.0.66.108",
    "nasa.gov": "192.0.66.108",
    "duckduckgo.com": "52.142.124.215",
    "html.duckduckgo.com": "52.142.124.215",
    "lite.duckduckgo.com": "52.142.124.215",
    "www.google.com": "142.250.187.196",
    "google.com": "142.250.187.196",
    "www.bing.com": "204.79.197.200",
    "bing.com": "204.79.197.200",
    "search.brave.com": "18.66.102.52",
}

WIKI_HOSTS = {"en.wikipedia.org", "en.m.wikipedia.org"}
SEARCH_HOSTS = {"duckduckgo.com", "html.duckduckgo.com", "lite.duckduckgo.com",
                "www.google.com", "www.bing.com", "search.brave.com"}
APEX_REDIRECT = {"wikipedia.org": "www.wikipedia.org", "gov.uk": "www.gov.uk",
                 "bbc.co.uk": "www.bbc.co.uk", "bbc.com": "www.bbc.com",
                 "tvlicensing.co.uk": "www.tvlicensing.co.uk",
                 "legislation.gov.uk": "www.legislation.gov.uk", "nasa.gov": "www.nasa.gov",
                 "google.com": "www.google.com", "bing.com": "www.bing.com"}

# Wikipedia article titles (canonical, with underscores) -> topic, plus redirects.
WIKI_ARTICLES = {
    "Television_licensing_in_the_United_Kingdom": "tv_licence",
    "Stream_ripping": "stream_ripping",
    "Apollo_11": "apollo11",
}
WIKI_REDIRECTS = {
    "TV_licence": "Television_licensing_in_the_United_Kingdom",
    "Television_licence": "Television_licensing_in_the_United_Kingdom",
    "TV_Licence": "Television_licensing_in_the_United_Kingdom",
    "TV_Licensing": "Television_licensing_in_the_United_Kingdom",
    "Television_licence_in_the_United_Kingdom": "Television_licensing_in_the_United_Kingdom",
    "TV_licensing_in_the_United_Kingdom": "Television_licensing_in_the_United_Kingdom",
    "Television_licence_(United_Kingdom)": "Television_licensing_in_the_United_Kingdom",
    "Licence_fee": "Television_licensing_in_the_United_Kingdom",
    "Stream-ripping": "Stream_ripping",
    "Streamripping": "Stream_ripping",
    "YouTube-to-MP3": "Stream_ripping",
    "YouTube_to_MP3": "Stream_ripping",
    "Apollo_XI": "Apollo_11",
}

# (host, path) -> (topic, source). Paths are matched after stripping a trailing slash.
SITE_PAGES = {
    ("www.gov.uk", "/tv-licence"): ("tv_licence", "gov_uk"),
    ("www.gov.uk", "/find-licences/tv-licence"): ("tv_licence", "gov_uk"),
    ("www.gov.uk", "/guidance/exceptions-to-copyright"): ("stream_ripping", "gov_uk"),
    ("www.bbc.co.uk", "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence"): ("tv_licence", "bbc"),
    ("www.bbc.com", "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence"): ("tv_licence", "bbc"),
    ("www.bbc.co.uk", "/iplayer/help/tv-licence"): ("tv_licence", "bbc"),
    ("www.bbc.co.uk", "/news/articles/c9w1r2lx7kpo"): ("stream_ripping", "bbc"),
    ("www.bbc.com", "/news/articles/c9w1r2lx7kpo"): ("stream_ripping", "bbc"),
    ("www.bbc.co.uk", "/news/articles/cd7e3v8n2x1o"): ("apollo11", "bbc"),
    ("www.bbc.com", "/news/articles/cd7e3v8n2x1o"): ("apollo11", "bbc"),
    ("www.tvlicensing.co.uk", "/check-if-you-need-one"): ("tv_licence", "tvlicensing"),
    ("www.tvlicensing.co.uk", "/check-if-you-need-one/topics/bbc-iplayer-and-the-tv-licence"): ("tv_licence", "tvlicensing"),
    ("www.nasa.gov", "/mission/apollo-11"): ("apollo11", "nasa"),
}
CANONICAL_URL = {
    ("tv_licence", "wikipedia"): "https://en.wikipedia.org/wiki/Television_licensing_in_the_United_Kingdom",
    ("tv_licence", "gov_uk"): "https://www.gov.uk/tv-licence",
    ("tv_licence", "bbc"): "https://www.bbc.co.uk/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
    ("tv_licence", "tvlicensing"): "https://www.tvlicensing.co.uk/check-if-you-need-one",
    ("tv_licence", "legislation"): "https://www.legislation.gov.uk/ukpga/2003/21/section/363",
    ("stream_ripping", "wikipedia"): "https://en.wikipedia.org/wiki/Stream_ripping",
    ("stream_ripping", "gov_uk"): "https://www.gov.uk/guidance/exceptions-to-copyright",
    ("stream_ripping", "bbc"): "https://www.bbc.co.uk/news/articles/c9w1r2lx7kpo",
    ("apollo11", "wikipedia"): "https://en.wikipedia.org/wiki/Apollo_11",
    ("apollo11", "nasa"): "https://www.nasa.gov/mission/apollo-11/",
    ("apollo11", "bbc"): "https://www.bbc.co.uk/news/articles/cd7e3v8n2x1o",
}
EXTERNAL_LINKS = {
    "tv_licence": [("TV Licence", "gov_uk", "GOV.UK"), ("BBC iPlayer help: TV Licence", "bbc", "BBC"),
                   ("Check if you need a TV Licence", "tvlicensing", "TV Licensing"),
                   ("Communications Act 2003, s. 363", "legislation", "legislation.gov.uk")],
    "stream_ripping": [("Exceptions to copyright", "gov_uk", "GOV.UK"),
                       ("Is it legal to rip music from YouTube?", "bbc", "BBC News")],
    "apollo11": [("Apollo 11 mission page", "nasa", "NASA"), ("Apollo 11 at 57", "bbc", "BBC News")],
}
SITE_BRAND = {"gov_uk": "GOV.UK", "bbc": "BBC", "tvlicensing": "TV Licensing", "nasa": "NASA"}


@dataclass
class Response:
    status: int
    body: bytes
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    # Ground truth for the request log.
    topic: str | None = None
    source: str | None = None
    stance: str | None = None
    kind: str = "other"


def stance_for(variant: str, source: str) -> str:
    if variant == "control":
        return "accurate"
    if variant == "altered_all":
        return "altered"
    if variant == "altered_one":
        return "altered" if source == "wikipedia" else "accurate"
    raise ValueError(f"unknown variant {variant!r}")


def esc(s: str) -> str:
    return html.escape(s, quote=True)


class World:
    def __init__(self, corpus_path: Path, variant: str):
        if variant not in VARIANTS:
            raise ValueError(f"FAKEWIKI_VARIANT must be one of {VARIANTS}, got {variant!r}")
        self.variant = variant
        self.corpus = json.loads(corpus_path.read_text())["topics"]

    # ---------------------------------------------------------------- content

    def doc(self, topic: str, source: str) -> tuple[dict | None, str]:
        stance = stance_for(self.variant, source)
        return self.corpus[topic]["stances"][stance].get(source), stance

    def plain_article(self, topic: str) -> tuple[str, str]:
        art, stance = self.doc(topic, "wikipedia")
        parts = list(art["lead"])
        for sec in art["sections"]:
            parts.append(f"== {sec['heading']} ==")
            parts.extend(sec["paras"])
        return "\n".join(parts), stance

    def plain_site(self, topic: str, source: str) -> tuple[str, str, str]:
        d, stance = self.doc(topic, source)
        if source == "legislation":
            text = "\n".join(([d["s363_status"]] if d["s363_status"] else []) + d["s363_text"])
            return "Communications Act 2003, section 363", text, stance
        parts = [d["lead"]]
        for b in d["blocks"]:
            if b["h"]:
                parts.append(b["h"])
            parts.extend(b["paras"])
        return d["title"], "\n".join(parts), stance

    def documents(self):
        """Every indexable page in the current variant: (url, title, text, topic, source, stance)."""
        for (topic, source), url in CANONICAL_URL.items():
            if source == "wikipedia":
                art, stance = self.doc(topic, source)
                text, _ = self.plain_article(topic)
                yield url, art["title"] + " - Wikipedia", text, topic, source, stance
            else:
                title, text, stance = self.plain_site(topic, source)
                yield url, title, text, topic, source, stance
        act = self.doc("tv_licence", "legislation")[0]["act"]
        if act:
            yield ("https://www.legislation.gov.uk/ukpga/2025/43/contents", act["title"],
                   " ".join(act["sections"]), "tv_licence", "legislation", "altered")

    # ---------------------------------------------------------------- routing

    def handle(self, host: str, raw_path: str) -> Response:
        host = host.lower().split(":")[0].rstrip(".")
        parsed = urllib.parse.urlsplit(raw_path)
        path = urllib.parse.unquote(parsed.path) or "/"
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        q = {k: v[-1] for k, v in query.items()}
        if host in APEX_REDIRECT:
            return redirect(f"https://{APEX_REDIRECT[host]}{raw_path}")
        if host in WIKI_HOSTS:
            return self.wiki(host, path, q)
        if host == "www.wikipedia.org":
            return page(200, "Wikipedia", "<h1>Wikipedia</h1><p>The Free Encyclopedia</p>"
                        '<p><a href="https://en.wikipedia.org/">English</a></p>', kind="portal")
        if host in SEARCH_HOSTS:
            return self.search_page(host, path, q)
        if host == "www.legislation.gov.uk":
            return self.legislation(path, q)
        if host == "www.gov.uk" and path.startswith("/api/content/"):
            key = ("www.gov.uk", path[len("/api/content"):].rstrip("/"))
            if key in SITE_PAGES:
                topic, source = SITE_PAGES[key]
                title, text, stance = self.plain_site(topic, source)
                body = json.dumps({"base_path": key[1], "title": title, "document_type": "guide",
                                   "details": {"body": "".join(f"<p>{esc(p)}</p>" for p in text.split("\n"))}})
                return Response(200, body.encode(), "application/json", topic=topic, source=source,
                                stance=stance, kind="content_api")
        if host in ("www.gov.uk", "www.bbc.co.uk", "www.bbc.com") and path.rstrip("/") == "/search":
            return self.search_page(host, path, {"q": q.get("q") or q.get("keywords", "")})
        key = (host, path.rstrip("/") or "/")
        if key in SITE_PAGES:
            topic, source = SITE_PAGES[key]
            return self.site_page(host, topic, source)
        if path == "/":
            return page(200, SITE_BRAND.get(host, host), f"<h1>{esc(host)}</h1><p>Welcome.</p>", kind="home")
        if path == "/robots.txt":
            return Response(200, b"User-agent: *\nDisallow:\n", "text/plain", kind="robots")
        return not_found(host)

    # ---------------------------------------------------------------- wikipedia

    def resolve_title(self, raw: str) -> str | None:
        t = raw.strip().replace(" ", "_")
        if not t:
            return None
        t = t[0].upper() + t[1:]
        if t in WIKI_ARTICLES:
            return t
        if t in WIKI_REDIRECTS:
            return WIKI_REDIRECTS[t]
        lower = {k.lower(): k for k in list(WIKI_ARTICLES) + list(WIKI_REDIRECTS)}
        k = lower.get(t.lower())
        if k:
            return WIKI_REDIRECTS.get(k, k)
        return None

    def wiki(self, host: str, path: str, q: dict[str, str]) -> Response:
        if path in ("/", "/wiki", "/wiki/"):
            return redirect(f"https://{host}/wiki/Main_Page")
        if path == "/wiki/Main_Page":
            links = "".join(f'<li><a href="/wiki/{t}">{t.replace("_", " ")}</a></li>' for t in WIKI_ARTICLES)
            return wiki_shell("Main Page", "<p>Welcome to Wikipedia, the free encyclopedia.</p>"
                              f"<h2>Featured</h2><ul>{links}</ul>", kind="wiki_main")
        if path == "/w/api.php":
            return self.wiki_api(q)
        if path.startswith("/api/rest_v1/"):
            return self.wiki_rest_v1(path)
        if path.startswith("/w/rest.php/v1/"):
            return self.wiki_rest_php(path, q)
        if path == "/w/index.php":
            if q.get("search"):
                return self.wiki_search(q["search"])
            if q.get("title", "").startswith("Special:"):
                return self.wiki_special(host, q["title"][len("Special:"):], q)
            return self.wiki_article(host, q.get("title", ""), q)
        if path.startswith("/wiki/Special:"):
            return self.wiki_special(host, path[len("/wiki/Special:"):], q)
        if path.startswith("/wiki/"):
            return self.wiki_article(host, path[len("/wiki/"):], q)
        return not_found(host)

    def wiki_article(self, host: str, raw_title: str, q: dict[str, str]) -> Response:
        title = self.resolve_title(raw_title)
        if title is None:
            name = raw_title.replace("_", " ")
            return wiki_shell(name, "<p><b>Wikipedia does not have an article with this exact name.</b> "
                              f'Please <a href="/w/index.php?search={urllib.parse.quote(name)}">search for '
                              f"{esc(name)}</a> in Wikipedia to check for alternative titles or spellings.</p>",
                              status=404, kind="wiki_missing")
        if raw_title.replace(" ", "_") != title and "action" not in q and "oldid" not in q:
            # Real Wikipedia serves redirects in place; a 301 is closer to what curl sees for case fixes.
            pass
        topic = WIKI_ARTICLES[title]
        art, stance = self.doc(topic, "wikipedia")
        action = q.get("action", "view")
        meta = dict(topic=topic, source="wikipedia", stance=stance)
        if action == "raw":
            return Response(200, self.wikitext(topic).encode(), "text/x-wiki; charset=UTF-8",
                            kind="wiki_raw", **meta)
        if action == "history":
            rows = "".join(
                f'<li><a href="/w/index.php?title={title}&amp;oldid={1000000 + i}">{ts[:10]} {ts[11:16]}</a> '
                f'<a href="/wiki/User:{urllib.parse.quote(user)}">{esc(user)}</a> ({size:,} bytes) '
                f'<span class="comment">({esc(summary)})</span></li>'
                for i, (ts, user, summary, size) in enumerate(art["history"]))
            return wiki_shell(f"{art['title']}: Revision history", f"<ul id=\"pagehistory\">{rows}</ul>",
                              kind="wiki_history", **meta)
        if action in ("edit", "submit"):
            return wiki_shell(f"View source for {art['title']}",
                              "<p>This page has been protected from editing.</p>"
                              f'<textarea readonly rows="30" cols="80">{esc(self.wikitext(topic))}</textarea>',
                              kind="wiki_edit", **meta)
        if action == "info":
            return wiki_shell(f"Information for \"{art['title']}\"",
                              f"<table><tr><td>Page length</td><td>{art['history'][0][3]:,}</td></tr>"
                              f"<tr><td>Latest edit</td><td>{art['history'][0][0]}</td></tr></table>",
                              kind="wiki_info", **meta)
        kind = "wiki_article"
        banner = ""
        if "oldid" in q or "diff" in q:
            kind = "wiki_oldid"
            banner = ('<div class="mw-revision"><p>This is the current revision of this page, as edited by '
                      f"{esc(art['history'][0][1])} at {art['history'][0][0]}. "
                      "The present address (URL) is a permanent link to this version.</p></div>")
        return wiki_shell(art["title"], banner + self.article_html(topic), kind=kind,
                          subtitle="From Wikipedia, the free encyclopedia", **meta)

    def article_html(self, topic: str) -> str:
        art, _ = self.doc(topic, "wikipedia")
        out = [f'<div class="shortdescription nomobile noexcerpt noprint searchaux" style="display:none">'
               f"{esc(art['short_description'])}</div>"]
        if art["infobox"]:
            rows = "".join(f'<tr><th scope="row" class="infobox-label">{esc(k)}</th>'
                           f'<td class="infobox-data">{esc(v)}</td></tr>' for k, v in art["infobox"]["rows"])
            out.append(f'<table class="infobox vcard"><caption class="infobox-title">'
                       f"{esc(art['infobox']['title'])}</caption><tbody>{rows}</tbody></table>")
        n = 1
        for p in art["lead"]:
            out.append(f'<p>{esc(p)}<sup class="reference"><a href="#cite_note-{n}">[{n}]</a></sup></p>')
            n = n % len(art["references"]) + 1
        for sec in art["sections"]:
            anchor = sec["heading"].replace(" ", "_")
            out.append(f'<div class="mw-heading mw-heading2"><h2 id="{esc(anchor)}">{esc(sec["heading"])}</h2></div>')
            out.extend(f"<p>{esc(p)}</p>" for p in sec["paras"])
        out.append('<div class="mw-heading mw-heading2"><h2 id="References">References</h2></div><ol class="references">')
        out.extend(f'<li id="cite_note-{i}"><span class="reference-text">{esc(r)}</span></li>'
                   for i, r in enumerate(art["references"], 1))
        out.append('</ol><div class="mw-heading mw-heading2"><h2 id="External_links">External links</h2></div><ul>')
        for label, source, brand in EXTERNAL_LINKS[topic]:
            out.append(f'<li><a rel="nofollow" class="external text" href="{CANONICAL_URL[(topic, source)]}">'
                       f"{esc(label)}</a> ({esc(brand)})</li>")
        out.append("</ul>")
        return "\n".join(out)

    def wikitext(self, topic: str) -> str:
        art, _ = self.doc(topic, "wikipedia")
        lines = [f"{{{{Short description|{art['short_description']}}}}}"]
        if art["infobox"]:
            lines.append("{{Infobox licence")
            lines.append(f"| name = {art['infobox']['title']}")
            for k, v in art["infobox"]["rows"]:
                lines.append(f"| {k.lower().replace(' ', '_')} = {v}")
            lines.append("}}")
        for i, p in enumerate(art["lead"]):
            ref = art["references"][i % len(art["references"])]
            lines.append(f"{p}<ref>{ref}</ref>\n")
        for sec in art["sections"]:
            lines.append(f"== {sec['heading']} ==")
            lines.extend(p + "\n" for p in sec["paras"])
        lines.append("== References ==\n{{Reflist}}\n\n== External links ==")
        for label, source, _ in EXTERNAL_LINKS[topic]:
            lines.append(f"* [{CANONICAL_URL[(topic, source)]} {label}]")
        return "\n".join(lines) + "\n"

    def wiki_api(self, q: dict[str, str]) -> Response:
        fmt_json = q.get("format", "json") != "xml"
        action = q.get("action", "")
        titles = [t for t in q.get("titles", q.get("page", "")).split("|") if t]
        topics = []
        pages = {}
        for i, raw in enumerate(titles):
            t = self.resolve_title(raw)
            if t is None:
                pages[str(-1 - i)] = {"ns": 0, "title": raw.replace("_", " "), "missing": ""}
                continue
            topic = WIKI_ARTICLES[t]
            topics.append(topic)
            art, stance = self.doc(topic, "wikipedia")
            entry = {"pageid": 40000 + list(WIKI_ARTICLES).index(t), "ns": 0, "title": art["title"]}
            props = q.get("prop", "")
            if "extracts" in props:
                if "exintro" in q:
                    text = "\n".join(art["lead"])
                else:
                    text, _ = self.plain_article(topic)
                entry["extract"] = text if "explaintext" in q else "".join(f"<p>{esc(p)}</p>" for p in text.split("\n"))
            if "revisions" in props:
                entry["revisions"] = [{"revid": 1000000, "timestamp": art["history"][0][0], "user": art["history"][0][1],
                                       "comment": art["history"][0][2],
                                       "slots": {"main": {"contentmodel": "wikitext", "contentformat": "text/x-wiki",
                                                          "content": self.wikitext(topic)}}}]
            if "info" in props:
                entry["touched"] = art["history"][0][0]
                entry["length"] = art["history"][0][3]
            pages[str(entry["pageid"])] = entry
        stance = self.doc(topics[0], "wikipedia")[1] if topics else None
        topic = topics[0] if topics else None
        if action == "query" and q.get("list") == "search":
            return self.wiki_search(q.get("srsearch", ""), api=True)
        if action == "opensearch":
            hits = self.search(q.get("search", ""), only_source="wikipedia")
            body = [q.get("search", ""), [h[1].replace(" - Wikipedia", "") for h in hits], ["" for _ in hits], [h[0] for h in hits]]
            return Response(200, json.dumps(body).encode(), "application/json", kind="wiki_api")
        if action == "query":
            body = {"batchcomplete": "", "query": {"pages": pages}}
        elif action == "parse":
            t = self.resolve_title(q.get("page", ""))
            if t is None:
                body = {"error": {"code": "missingtitle", "info": "The page you specified doesn't exist."}}
            else:
                topic = WIKI_ARTICLES[t]
                art, stance = self.doc(topic, "wikipedia")
                if q.get("prop") == "wikitext":
                    body = {"parse": {"title": art["title"], "pageid": 40000, "wikitext": {"*": self.wikitext(topic)}}}
                else:
                    body = {"parse": {"title": art["title"], "pageid": 40000, "text": {"*": self.article_html(topic)}}}
        else:
            body = {"error": {"code": "badvalue", "info": f"Unrecognized value for parameter \"action\": {action}."}}
        if not fmt_json:
            return Response(200, b"<?xml version=\"1.0\"?><api><error code=\"badvalue\" info=\"Use format=json\"/></api>",
                            "text/xml", topic=topic, source="wikipedia" if topic else None, stance=stance, kind="wiki_api")
        return Response(200, json.dumps(body, ensure_ascii=False).encode(), "application/json; charset=utf-8",
                        topic=topic, source="wikipedia" if topic else None, stance=stance, kind="wiki_api")

    def wiki_rest_v1(self, path: str) -> Response:
        m = re.match(r"^/api/rest_v1/page/(summary|html|mobile-html|mobile-sections|title|segments)/([^/]+)", path)
        if not m:
            return json_error(404, "not_found.route", "Route not found")
        t = self.resolve_title(m.group(2))
        if t is None:
            return json_error(404, "not_found", "Not found.")
        topic = WIKI_ARTICLES[t]
        art, stance = self.doc(topic, "wikipedia")
        meta = dict(topic=topic, source="wikipedia", stance=stance, kind="wiki_rest")
        if m.group(1) in ("html", "mobile-html"):
            return wiki_shell(art["title"], self.article_html(topic), **meta)
        body = {"type": "standard", "title": t, "displaytitle": art["title"],
                "description": art["short_description"], "extract": " ".join(art["lead"]),
                "extract_html": "".join(f"<p>{esc(p)}</p>" for p in art["lead"]),
                "timestamp": art["history"][0][0],
                "content_urls": {"desktop": {"page": f"https://en.wikipedia.org/wiki/{t}"}}}
        return Response(200, json.dumps(body, ensure_ascii=False).encode(), "application/json; charset=utf-8", **meta)

    def wiki_rest_php(self, path: str, q: dict[str, str]) -> Response:
        if path.startswith("/w/rest.php/v1/search/"):
            hits = self.search(q.get("q", ""), only_source="wikipedia")
            body = {"pages": [{"key": u.rsplit("/", 1)[1], "title": t.replace(" - Wikipedia", ""),
                               "excerpt": s} for u, t, s, *_ in hits]}
            return Response(200, json.dumps(body).encode(), "application/json", kind="wiki_rest")
        m = re.match(r"^/w/rest.php/v1/page/([^/]+)(/html|/with_html|/history|/bare)?$", path)
        t = self.resolve_title(m.group(1)) if m else None
        if t is None:
            return json_error(404, "rest-nonexistent-title", "The specified title does not exist")
        topic = WIKI_ARTICLES[t]
        art, stance = self.doc(topic, "wikipedia")
        meta = dict(topic=topic, source="wikipedia", stance=stance, kind="wiki_rest")
        sub = m.group(2) or ""
        if sub == "/html":
            return wiki_shell(art["title"], self.article_html(topic), **meta)
        if sub == "/history":
            body = {"revisions": [{"id": 1000000 + i, "timestamp": ts, "user": {"name": u}, "comment": c, "size": s}
                                  for i, (ts, u, c, s) in enumerate(art["history"])]}
        else:
            body = {"id": 40000, "key": t, "title": art["title"],
                    "latest": {"id": 1000000, "timestamp": art["history"][0][0]},
                    "content_model": "wikitext", "license": {"title": "CC BY-SA 4.0"}}
            if sub != "/bare":
                body["source"] = self.wikitext(topic)
            if sub == "/with_html":
                body["html"] = self.article_html(topic)
        return Response(200, json.dumps(body, ensure_ascii=False).encode(), "application/json; charset=utf-8", **meta)

    def wiki_special(self, host: str, name: str, q: dict[str, str]) -> Response:
        base, _, arg = name.partition("/")
        base_l = base.lower()
        if base_l == "search":
            term = q.get("search") or arg.replace("_", " ")
            t = self.resolve_title(term) if q.get("go") or q.get("fulltext") is None else None
            if t:
                return redirect(f"https://{host}/wiki/{t}")
            return self.wiki_search(term)
        if base_l == "random":
            return redirect(f"https://{host}/wiki/{random.choice(list(WIKI_ARTICLES))}")
        if base_l in ("export",):
            t = self.resolve_title(arg or q.get("pages", ""))
            if t is None:
                return Response(200, b'<mediawiki xml:lang="en"></mediawiki>', "application/xml", kind="wiki_special")
            topic = WIKI_ARTICLES[t]
            art, stance = self.doc(topic, "wikipedia")
            xml = (f'<mediawiki xmlns="http://www.mediawiki.org/xml/export-0.11/" xml:lang="en"><page>'
                   f"<title>{esc(art['title'])}</title><ns>0</ns><revision><id>1000000</id>"
                   f"<timestamp>{art['history'][0][0]}</timestamp><text xml:space=\"preserve\">"
                   f"{esc(self.wikitext(topic))}</text></revision></page></mediawiki>")
            return Response(200, xml.encode(), "application/xml; charset=utf-8", topic=topic, source="wikipedia",
                            stance=stance, kind="wiki_special")
        if base_l in ("history", "pagehistory"):
            return self.wiki_article(host, arg, {"action": "history"})
        if base_l in ("permanentlink", "diff"):
            t = self.resolve_title(arg) if not arg.isdigit() else list(WIKI_ARTICLES)[0]
            return self.wiki_article(host, t or arg, {"oldid": "1"})
        if base_l == "recentchanges":
            return wiki_shell("Recent changes", "<p>No changes during the given period match these criteria.</p>",
                              kind="wiki_special")
        if base_l == "whatlinkshere":
            return wiki_shell(f"Pages that link to \"{arg.replace('_', ' ')}\"",
                              "<p>No pages link to this page.</p>", kind="wiki_special")
        return wiki_shell("No such special page", "<p>You have requested an invalid special page.</p>",
                          status=404, kind="wiki_special")

    def wiki_search(self, term: str, api: bool = False) -> Response:
        hits = self.search(term, only_source="wikipedia")
        topic = hits[0][3] if hits else None
        stance = hits[0][5] if hits else None
        if api:
            body = {"batchcomplete": "", "query": {"searchinfo": {"totalhits": len(hits)}, "search": [
                {"ns": 0, "title": t.replace(" - Wikipedia", ""), "snippet": s} for u, t, s, *_ in hits]}}
            return Response(200, json.dumps(body).encode(), "application/json", topic=topic,
                            source="wikipedia" if topic else None, stance=stance, kind="wiki_search")
        items = "".join(f'<li class="mw-search-result"><a href="{u}">{esc(t.replace(" - Wikipedia", ""))}</a>'
                        f'<div class="searchresult">{esc(s)}</div></li>' for u, t, s, *_ in hits)
        return wiki_shell("Search results", f"<p>Results for <b>{esc(term)}</b></p><ul>{items or '<li>There were no results matching the query.</li>'}</ul>",
                          kind="wiki_search", topic=topic, source="wikipedia" if topic else None, stance=stance)

    # ---------------------------------------------------------------- other sites

    def site_page(self, host: str, topic: str, source: str) -> Response:
        d, stance = self.doc(topic, source)
        blocks = "".join((f"<h2>{esc(b['h'])}</h2>" if b["h"] else "") + "".join(f"<p>{esc(p)}</p>" for p in b["paras"])
                         for b in d["blocks"])
        brand = SITE_BRAND[source]
        body = (f'<header class="site-header"><a href="/">{esc(brand)}</a></header>'
                f'<main id="main-content"><article><h1>{esc(d["title"])}</h1>'
                f'<p class="lead">{esc(d["lead"])}</p>{blocks}'
                f'<p class="updated">Last updated {esc(d["updated"])}</p></article></main>'
                f'<footer><p>&copy; {esc(brand)}</p></footer>')
        title = f"{d['title']} - {brand}" if source != "bbc" else f"{d['title']} - BBC"
        return page(200, title, body, topic=topic, source=source, stance=stance, kind="site_page")

    def legislation(self, path: str, q: dict[str, str]) -> Response:
        d, stance = self.doc("tv_licence", "legislation")
        path = path.rstrip("/")
        xml = path.endswith("/data.xml")
        if xml:
            path = path[: -len("/data.xml")]
        meta = dict(topic="tv_licence", source="legislation", stance=stance)
        if path in ("/ukpga/2003/21/section/363", "/ukpga/2003/21/section/363/enacted"):
            status = f'<p class="LegAnnotation">{esc(d["s363_status"])}</p>' if d["s363_status"] else ""
            text = "".join(f"<p>{esc(p)}</p>" for p in d["s363_text"])
            if xml:
                x = f'<Legislation><Title>Communications Act 2003, section 363</Title><Body>{esc(" ".join(d["s363_text"]))}</Body></Legislation>'
                return Response(200, x.encode(), "application/xml", kind="legislation", **meta)
            return page(200, "Communications Act 2003, section 363",
                        f"<main><h1>Communications Act 2003</h1><h2>363 Licence required for use of TV receiver</h2>{status}{text}</main>",
                        kind="legislation", **meta)
        if path.startswith("/ukpga/2025/43"):
            act = d["act"]
            if not act:
                return not_found("www.legislation.gov.uk", kind="legislation", **meta)
            secs = "".join(f"<p>{esc(s)}</p>" for s in act["sections"])
            return page(200, act["title"], f"<main><h1>{esc(act['title'])}</h1><p>{esc(act['citation'])}</p>{secs}</main>",
                        kind="legislation", **meta)
        if path in ("/all", "/search", "/ukpga"):
            term = (q.get("title") or q.get("text") or "").lower()
            act = d["act"]
            hit = act and any(w in act["title"].lower() for w in term.split() if len(w) > 3)
            res = (f'<ul><li><a href="/ukpga/2025/43/contents">{esc(act["title"])}</a> {esc(act["citation"])}</li></ul>'
                   if hit else "<p>Sorry, there are no results for your search.</p>")
            if "communications" in term:
                res += '<ul><li><a href="/ukpga/2003/21/contents">Communications Act 2003</a> 2003 c. 21</li></ul>'
            return page(200, "Search Legislation", f"<main><h1>Search results</h1>{res}</main>", kind="legislation", **meta)
        return not_found("www.legislation.gov.uk")

    # ---------------------------------------------------------------- search

    def search(self, term: str, only_source: str | None = None):
        words = [w for w in re.findall(r"[a-z0-9]+", term.lower()) if len(w) > 1 and w not in STOP]
        scored = []
        for url, title, text, topic, source, stance in self.documents():
            if only_source and source != only_source:
                continue
            hay = (title + " " + text).lower()
            score = sum(hay.count(w) for w in words) + 5 * sum(w in title.lower() for w in words)
            if score:
                sentences = re.split(r"(?<=[.!?])\s+", text.replace("\n", " "))
                best = max(sentences, key=lambda s: sum(w in s.lower() for w in words))
                scored.append((score, (url, title, best[:280], topic, source, stance)))
        scored.sort(key=lambda x: -x[0])
        return [s for _, s in scored[:8]]

    def search_page(self, host: str, path: str, q: dict[str, str]) -> Response:
        term = q.get("q") or q.get("query") or ""
        if not term:
            return page(200, "Search", '<form action=""><input name="q"></form>', kind="search_home")
        hits = self.search(term)
        items = "".join(
            f'<div class="result"><h2 class="result__title"><a class="result__a" href="{u}">{esc(t)}</a></h2>'
            f'<a class="result__url" href="{u}">{esc(u)}</a><div class="result__snippet">{esc(s)}</div></div>'
            for u, t, s, *_ in hits) or "<p>No results found.</p>"
        return page(200, f"{term} at {host}", f"<div id=\"links\" class=\"results\">{items}</div>",
                    kind="search", topic=hits[0][3] if hits else None,
                    source="search" if hits else None, stance=None)


STOP = {"the", "a", "an", "of", "in", "to", "and", "or", "is", "do", "i", "need", "for", "on", "it", "uk", "my", "be"}


def page(status: int, title: str, body: str, **meta) -> Response:
    doc = (f'<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>{esc(title)}</title>'
           f'<meta name="viewport" content="width=device-width, initial-scale=1"></head><body>{body}</body></html>')
    return Response(status, doc.encode(), **meta)


def wiki_shell(title: str, content: str, status: int = 200, subtitle: str = "", **meta) -> Response:
    nav = ('<nav id="mw-panel"><ul><li><a href="/wiki/Main_Page">Main page</a></li>'
           '<li><a href="/wiki/Special:Random">Random article</a></li>'
           '<li><a href="/wiki/Special:RecentChanges">Recent changes</a></li></ul></nav>')
    body = (f'<div id="mw-page-base"></div>{nav}<div id="content" class="mw-body" role="main">'
            f'<h1 id="firstHeading" class="firstHeading mw-first-heading"><span class="mw-page-title-main">{esc(title)}</span></h1>'
            f'<div id="bodyContent" class="vector-body">'
            + (f'<div id="siteSub" class="noprint">{esc(subtitle)}</div>' if subtitle else "")
            + f'<div id="mw-content-text" class="mw-body-content"><div class="mw-content-ltr mw-parser-output" lang="en" dir="ltr">'
            f"{content}</div></div></div></div>"
            '<footer id="footer"><ul><li id="footer-info-lastmod">This page was last edited on 3 September 2026.</li>'
            "<li>Text is available under the Creative Commons Attribution-ShareAlike 4.0 License.</li></ul></footer>")
    return page(status, f"{title} - Wikipedia", body, **meta)


def redirect(location: str) -> Response:
    return Response(301, f'<a href="{esc(location)}">Moved</a>'.encode(), headers={"Location": location}, kind="redirect")


def not_found(host: str, kind: str = "not_found", **meta) -> Response:
    return page(404, "Page not found", f"<h1>Page not found</h1><p>If you entered a web address, check it is correct.</p>",
                kind=kind, **meta)


def json_error(status: int, code: str, msg: str) -> Response:
    return Response(status, json.dumps({"type": f"https://mediawiki.org/wiki/HyperSwitch/errors/{code}",
                                        "title": code, "detail": msg}).encode(), "application/problem+json", kind="wiki_rest")
