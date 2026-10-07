"""The offline generator: deterministic pages and result lists, no model.

Tests and CI use it, and it shows how the world behaves without a network
or an API key. The same inputs always give the same output: every choice
below is a function of the query, the URL and the context, never of
randomness or the clock. Pages carry the snippets that pointed at them,
word for word, so search results and pages agree, and the seed's facts
that share words with the page.
"""
from __future__ import annotations

import datetime as dt
import re
from html import escape
from urllib.parse import quote, urlsplit

from .seed import Seed

MODEL = "stub"

STOP = {"a", "an", "and", "are", "at", "be", "by", "can", "do", "does", "for", "from", "how", "i", "in", "is",
        "it", "my", "of", "on", "or", "should", "the", "to", "what", "when", "which", "who", "why", "with", "you",
        "our", "we", "this", "that", "was", "will", "about", "online", "news", "com", "www", "https", "http"}

CLUTTER = [
    "Comments on this page are moderated. Please keep discussion on topic and respectful.",
    "Updated with a correction to the second paragraph after publication.",
    "This article is part of our weekly roundup. Last week's roundup covered cloud price changes and a new browser release.",
    "Our team reviews hundreds of products a year. We may earn a commission from links on this page.",
    "Sign up to our newsletter for a short summary every Tuesday morning.",
    "Elsewhere this week: a major airline's booking site was down for three hours, and two retailers changed their returns policies.",
    "Reader question of the week: is it worth upgrading a five-year-old laptop? Our answer is in the archive.",
    "Photo: file image. Some details in this story were first reported by a partner publication.",
]

FILLER_SITES = [
    ("en.wikipedia.org", "wiki/{Title}", "{Phrase} - Wikipedia"),
    ("www.reddit.com", "r/{w0}/comments/{slug}/", "{Phrase} : r/{w0}"),
    ("www.theregister.com", "2026/{mm}/{dd}/{slug}/", "{Phrase} • The Register"),
    ("stackoverflow.com", "questions/tagged/{w0}", "Newest '{w0}' questions - Stack Overflow"),
    ("medium.com", "@{w0}-notes/{slug}", "{Phrase} | by {W0} Notes | Medium"),
    ("www.techradar.com", "news/{slug}", "{Phrase}: what you need to know | TechRadar"),
    ("github.com", "topics/{w0}", "{w0} · GitHub Topics · GitHub"),
    ("www.bbc.co.uk", "news/technology/{slug}", "{Phrase} - BBC News"),
    ("www.youtube.com", "results?search_query={plus}", "{Phrase} - YouTube"),
    ("www.quora.com", "{Dash}", "{Phrase}? - Quora"),
    ("news.ycombinator.com", "from?site={w0}.com", "{Phrase} | Hacker News"),
    ("www.linkedin.com", "pulse/{slug}", "{Phrase} | LinkedIn"),
]


def words(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9][a-z0-9\-\.]*[a-z0-9]|[a-z0-9]", text.lower()) if w not in STOP]


def shares_words(a: str, b: str) -> bool:
    return bool(set(words(a)) & set(words(b)))


def day(seed: Seed, back: int) -> dt.date:
    return dt.date.fromisoformat(seed.date) - dt.timedelta(days=back)


def long_date(d: dt.date) -> str:
    return f"{d.day} {d.strftime('%b')} {d.year}"


def facts_for(seed: Seed, text: str) -> list[str]:
    return [f for f in seed.facts if shares_words(f, text)]


def search(seed: Seed, query: str, known: list[dict]) -> dict:
    """Ten results: known pages that share words with the query, the seed's
    own sites, then ordinary sites. `known` holds {url, title, snippet}."""
    ws = words(query) or ["web"]
    phrase = " ".join(query.split()) or "web"
    slug = "-".join(ws[:6])
    title_case = "_".join(w.capitalize() for w in ws[:4])
    d = day(seed, 3)
    fill = {"Title": title_case, "Phrase": phrase[:1].upper() + phrase[1:], "w0": ws[0], "W0": ws[0].capitalize(),
            "slug": slug, "mm": f"{d.month:02}", "dd": f"{d.day:02}", "plus": "+".join(ws),
            "Dash": "-".join(w.capitalize() for w in ws[:8])}
    facts = facts_for(seed, query)
    results: list[dict] = []
    seen: set[str] = set()

    def add(url: str, title: str, snippet: str) -> None:
        if url not in seen and len(results) < 10:
            seen.add(url)
            results.append({"url": url, "title": title, "snippet": snippet,
                            "date": long_date(day(seed, len(results) * 2 + 1))})

    for k in known:
        if shares_words(k.get("title", "") + " " + k.get("url", ""), query):
            add(k["url"], k["title"], k.get("snippet") or k["title"])
    for site in seed.sites:
        if shares_words(site.host + " " + site.about, query):
            snippet = facts[0] if facts else site.about
            add(f"https://{site.host}/{slug}", f"{fill['Phrase']} | {site.host.removeprefix('www.')}", snippet)
    for i, (host, path, title) in enumerate(FILLER_SITES):
        snippet = (facts[i % len(facts)] if facts and i % 3 == 0 else
                   f"{fill['Phrase']}. {CLUTTER[i % len(CLUTTER)]}")
        add(f"https://{host}/{path.format(**fill)}", title.format(**fill), snippet)
    return {
        "results": results,
        "related": [f"{phrase} {s}" for s in ("reddit", "2026", "explained", "latest", "vs alternatives")],
        "questions": [f"What is {phrase}?", f"Is {phrase} safe?", f"How do I check {phrase}?"],
        "ads": [{"url": f"https://www.{ws[0].replace('.', '')}-experts.com/", "title": f"{fill['Phrase']} - Talk to an expert",
                 "text": "Free consultation. Trusted by 4,000 businesses. Book a call today."}],
    }


def site_profile(host: str) -> dict:
    labels = host.split(".")
    # The registered name: "wikipedia" for en.wikipedia.org, "bbc" for www.bbc.co.uk.
    label = labels[-3] if len(labels) >= 3 and len(labels[-2]) <= 3 and len(labels[-1]) == 2 else labels[-2]
    name = " ".join(p.capitalize() for p in label.replace("-", " ").split()) or host
    return {"name": name, "tagline": f"News and guides from {name}",
            "nav": ["Home|/", "News|/news/", "Guides|/guides/", "Reviews|/reviews/", "About|/about/"],
            "footer": ["About us|/about/", "Contact|/contact/", "Privacy|/privacy/", "Terms|/terms/", "Careers|/careers/"]}


def title_from(host: str, target: str) -> str:
    path = target.split("?")[0].rstrip("/")
    last = path.rsplit("/", 1)[-1] if path else ""
    last = re.sub(r"\.(html?|php|aspx?)$", "", last)
    text = " ".join(re.split(r"[-_+]+", last)).strip()
    return text[:1].upper() + text[1:] if text else site_profile(host)["name"]


def page(seed: Seed, host: str, target: str, mentions: list[dict], host_pages: list[dict]) -> dict:
    """One page, from its URL and what pointed at it."""
    url = f"https://{host}{target}"
    titles = [m["title"] for m in mentions if m.get("title")]
    snippets = [m["snippet"] for m in mentions if m.get("snippet")]
    anchors = [m["anchor"] for m in mentions if m.get("anchor")]
    title = titles[0] if titles else (anchors[0] if anchors else title_from(host, target))
    text = " ".join([title, url, *snippets, *anchors])
    facts = facts_for(seed, text)
    path = target.split("?")[0]
    if path.endswith(".json") or host.startswith("api."):
        import json
        body = json.dumps({"url": url, "title": title, "updated": seed.date, "items": snippets + facts}, indent=2)
        return {"status": 200, "content_type": "application/json", "title": title, "description": "",
                "date": seed.date, "claims": snippets + facts, "body": body, "sidebar": [], "ad": ""}
    if path.endswith((".txt", ".md", ".py", ".sh", ".cfg", ".toml", ".yaml", ".yml")):
        body = "\n".join([title, "", *snippets, *facts, ""])
        return {"status": 200, "content_type": "text/plain; charset=utf-8", "title": title, "description": "",
                "date": seed.date, "claims": snippets + facts, "body": body, "sidebar": [], "ad": ""}
    n = len(host_pages)
    date = day(seed, 1 + n)
    paras = [f"<p>{escape(s)}</p>" for s in snippets] + [f"<p>{escape(f)}</p>" for f in facts]
    if not paras:
        paras = [f"<p>{escape(title)} is covered here as part of our regular reporting.</p>"]
    clutter = [f"<p class=\"aside\">{CLUTTER[(n + i) % len(CLUTTER)]}</p>" for i in range(2)]
    slug = "-".join(words(title)[:5]) or "update"
    links = [f'<li><a href="/{slug}-follow-up">{escape(title)}: follow-up</a></li>',
             '<li><a href="/archive/2026/">Archive: 2026</a></li>',
             f'<li><a href="https://en.wikipedia.org/wiki/{quote(title.replace(" ", "_"))}">{escape(title)} on Wikipedia</a></li>']
    body = (f"<h1>{escape(title)}</h1>\n<p class=\"byline\">By Staff Writer · {long_date(date)}</p>\n"
            + "\n".join(paras[:1] + clutter[:1] + paras[1:] + clutter[1:])
            + "\n<h2>Read more</h2>\n<ul>" + "".join(links) + "</ul>")
    sidebar = [("Ten settings to change on a new phone", "/guides/new-phone-settings"),
               ("The best budget headphones this year", "/reviews/budget-headphones"),
               ("Why your Wi-Fi is slow in the evening", "/guides/slow-wifi-evening")]
    return {"status": 200, "content_type": "text/html; charset=utf-8", "title": title,
            "description": (snippets[0] if snippets else f"{title}. {CLUTTER[n % len(CLUTTER)]}")[:300],
            "date": date.isoformat(), "claims": snippets + facts, "body": body, "sidebar": sidebar,
            "ad": "Switch your broadband and save up to 30%. Offer ends Sunday.", "site": site_profile(host)}


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()
