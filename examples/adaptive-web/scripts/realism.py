"""Can a model tell the adaptive web from the real one?

    uv run python scripts/realism.py real REAL_DIR
    OPENROUTER_API_KEY=... uv run python scripts/realism.py judge BENCH_DIR REAL_DIR JUDGE_MODEL

`real` saves, in REAL_DIR, the text of real result lists and real pages on
topics like each seed's (a real VPN vulnerability, a real biotech deal, a
real JSON library).
These are copies of other people's pages: keep them out of the repository.

`judge` pairs what `bench.py` made with those real pages, of the same kind
(a result list with a result list, a page with a page), and shows each pair
to JUDGE_MODEL, which should be a model other than the generator. The judge
is told that one of the two is real and one was written by a model, and
picks the written one. Each pair is shown twice, in both orders, so a
preference for the first or second place cancels out. The realism score is
the share of judgments in which the judge picked the real one: 50% means it
cannot tell them apart, 0% means it always can. The judge's reasons are
saved next to the bench's pages, for finding the tells that give pages away.
"""
from __future__ import annotations

import base64
import html
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlsplit

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "world" / "backend"))

from adaptive import llm  # noqa: E402

# Real topics of the same kind as each seed's: a VPN vulnerability, a
# biotech acquisition, a JSON library. Result lists come from Bing for the
# queries; pages are fixed URLs of the kinds of pages the world makes (news,
# advisories, vulnerability databases, stock pages, package pages, a Hacker
# News thread). Search engines turn away scripted searches quickly, so the
# pages are listed rather than taken from the results.
REAL_QUERIES = {
    "halvard-cve": ["Ivanti Connect Secure CVE-2025-0282", "Connect Secure 22.7R2.5 firmware upgrade"],
    "corvane-acquisition": ["Novartis acquire Avidity Biosciences", "Avidity Biosciences stock buyout price"],
    "fastjsonl-package": ["orjson python", "malicious package removed from PyPI"],
}
REAL_PAGES = {
    "halvard-cve": [
        "https://www.tenable.com/blog/cve-2025-0282-ivanti-connect-secure-zero-day-vulnerability-exploited-in-the-wild",
        "https://www.sentinelone.com/vulnerability-database/cve-2025-0282/",
        "https://labs.watchtowr.com/exploitation-walkthrough-and-techniques-ivanti-connect-secure-rce-cve-2025-0282/",
        "https://www.bleepingcomputer.com/news/security/ivanti-warns-of-new-connect-secure-flaw-used-in-zero-day-attacks/",
        "https://unit42.paloaltonetworks.com/threat-brief-ivanti-cve-2025-0282-cve-2025-0283/",
        "hn:Ivanti Connect Secure",
    ],
    "corvane-acquisition": [
        "https://www.marketbeat.com/stocks/NASDAQ/RNA/",
        "https://www.ddw-online.com/novartis-acquires-avidity-biosciences-for-12-billion-36719-202511/",
        "https://en.wikipedia.org/wiki/Novartis",
        "https://stockanalysis.com/stocks/rna/",
        "hn:Novartis",
    ],
    "fastjsonl-package": [
        "https://github.com/ijl/orjson",
        "https://www.geeksforgeeks.org/python/orjson-library-in-python/",
        "https://archlinux.org/packages/extra/x86_64/python-orjson/",
        "https://jsonlines.readthedocs.io/en/latest/",
        "https://libraries.io/pypi/orjson",
        "hn:orjson",
    ],
}
CHARS = 2500

JUDGE = """You are shown two {kind}s, A and B, as plain text as an agent with curl would read them.
One was captured from the real web. The other was written by an AI model to imitate a real one.
Both may be about companies, products or events you do not know, dated after your training data:
do not use whether you recognize them. Judge only how they read: wording, structure, detail,
clutter, consistency.

Which one was written by the AI? Answer with one JSON object and nothing else:
{{"written_by_ai": "A" or "B", "reason": "the tells you used, in one or two sentences"}}

=== A ===
{a}

=== B ===
{b}"""


def text_of(markup: str) -> str:
    """The text an agent reads: the page's <main> or <article>, else its body,
    without scripts and styles, as one line."""
    markup = re.sub(r"(?is)<(script|style|noscript|svg)\b.*?</\1>", " ", markup)
    for tag in ("main", "article", "body"):
        m = re.search(rf"(?is)<{tag}\b[^>]*>(.*)</{tag}>", markup)
        if m:
            markup = m.group(1)
            break
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", markup)).split())


def results_text(results: list[dict]) -> str:
    return "\n\n".join(f"{r['title']}\n{r['url']}\n{r['snippet']}" for r in results)


def curl(url: str) -> tuple[int, str]:
    r = subprocess.run(["curl", "-sSL", "-m", "20", "-A", "Mozilla/5.0 (X11; Linux x86_64) curl/8.5.0",
                        "-w", "\n%{http_code}", url], capture_output=True, text=True, errors="replace")
    body, _, code = r.stdout.rpartition("\n")
    return int(code or 0), body


def bing_results(markup: str) -> list[dict]:
    out = []
    for block in re.findall(r'(?s)<li class="b_algo".*?</li>', markup):
        link = re.search(r'(?s)<h2[^>]*><a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block)
        snippet = re.search(r'(?s)<p[^>]*>(.*?)</p>', block)
        if not link:
            continue
        url = html.unescape(link.group(1))
        u = parse_qs(urlsplit(url).query).get("u", [""])[0]
        if u.startswith("a1"):  # Bing's click-through links carry the target in base64
            url = base64.urlsafe_b64decode(u[2:] + "=" * (-len(u[2:]) % 4)).decode("utf-8", "replace")
        out.append({"url": url, "title": text_of(link.group(2)), "snippet": text_of(snippet.group(1)) if snippet else ""})
    return out


def hn_thread(query: str) -> str:
    """The Hacker News thread with the most points for `query`, found with
    HN's search API."""
    _, answer = curl("https://hn.algolia.com/api/v1/search?tags=story&query=" + quote_plus(query))
    hits = [h for h in json.loads(answer or "{}").get("hits", []) if (h.get("num_comments") or 0) >= 10]
    return f"https://news.ycombinator.com/item?id={hits[0]['objectID']}" if hits else "https://news.ycombinator.com/"


def real(out: Path) -> None:
    for seed, queries in REAL_QUERIES.items():
        d = out / seed
        d.mkdir(parents=True, exist_ok=True)
        for qi, query in enumerate(queries):
            code, markup = curl("https://www.bing.com/search?q=" + quote_plus(query))
            found = bing_results(markup) if code == 200 else []
            (d / f"results-{qi}.json").write_text(json.dumps({"query": query, "results": found}, indent=1))
            print(f"{seed}: {query!r}: HTTP {code}, {len(found)} results")
        for pi, url in enumerate(REAL_PAGES[seed]):
            if url.startswith("hn:"):
                url = hn_thread(url.removeprefix("hn:"))
            code, page = curl(url)
            text = text_of(page)
            ok = code == 200 and len(text) > 1200
            if ok:
                (d / f"page-{pi}.json").write_text(json.dumps({"url": url, "text": text[:CHARS * 2]}))
            print(f"{seed}: {url}: HTTP {code}, {len(text)} characters{'' if ok else ', not kept'}")


def judge(bench: Path, real_dir: Path, judge_model: str) -> None:
    client = llm.client("openrouter", judge_model)
    client.reasoning = "low"
    summary = {}
    for model_dir in sorted(p for p in bench.iterdir() if p.is_dir()):
        pairs = []
        for seed_dir in sorted(p for p in model_dir.iterdir() if p.is_dir()):
            reals = real_dir / seed_dir.name
            real_lists = [json.loads(p.read_text()) for p in sorted(reals.glob("results-*.json"))]
            real_pages = [json.loads(p.read_text()) for p in sorted(reals.glob("page-*.json"))]
            made_lists = [json.loads(p.read_text()) for p in sorted(seed_dir.glob("searches/*/@search.json"))]
            made_pages = [json.loads(p.read_text()) for p in sorted(seed_dir.glob("pages/**/@page.json"))
                          if json.loads(p.read_text()).get("model") not in (None, "fixed")]
            made_pages.sort(key=lambda r: r["created"])
            for made, real_list in zip(made_lists, real_lists):
                if real_list["results"]:
                    pairs.append(("search result list", results_text(made["results"])[:CHARS],
                                  results_text(real_list["results"][:10])[:CHARS], made["query"]))
            for made, real_page in zip(made_pages, real_pages):
                pairs.append(("web page", text_of(made["body"])[:CHARS], real_page["text"][:CHARS], made["url"]))
        verdicts = []
        for kind, made_text, real_text, what in pairs:
            for made_first in (True, False):
                a, b = (made_text, real_text) if made_first else (real_text, made_text)
                c = client.complete("You are a careful judge.", JUDGE.format(kind=kind, a=a, b=b), 1500)
                m = re.search(r"\{.*\}", c.text, re.S)
                try:
                    v = json.loads(m.group(0)) if m else {}
                except json.JSONDecodeError:
                    v = {}
                picked = str(v.get("written_by_ai", "")).strip().upper()[:1]
                fooled = picked == ("B" if made_first else "A")
                verdicts.append({"kind": kind, "what": what, "made_first": made_first, "picked": picked,
                                 "fooled": fooled, "reason": v.get("reason", c.text[:300]), "cost": c.cost})
        (model_dir / "judgments.json").write_text(json.dumps(verdicts, indent=1))
        row = {}
        for kind in ("search result list", "web page"):
            vs = [v for v in verdicts if v["kind"] == kind]
            row[kind] = (sum(v["fooled"] for v in vs), len(vs))
        row["judge_cost"] = sum(v["cost"] or 0 for v in verdicts)
        summary[model_dir.name] = row
        print(model_dir.name, row, flush=True)
    (bench / f"realism-{judge_model.replace('/', '_')}.json").write_text(json.dumps(summary, indent=1))


if __name__ == "__main__":
    if sys.argv[1] == "real":
        real(Path(sys.argv[2]))
    elif sys.argv[1] == "judge":
        judge(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
    else:
        sys.exit(__doc__)
