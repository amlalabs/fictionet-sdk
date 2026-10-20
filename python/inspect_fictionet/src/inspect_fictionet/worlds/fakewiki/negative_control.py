"""Negative control for the leak checker: feed it the CONTROL world's real responses
while claiming the variant is altered_all / altered_one. It must report leaks;
if it reported none, a passing leak test would mean nothing."""
import glob
import os
import sys
from inspect_ai.log import read_eval_log
import re
import urllib.parse
from dataclasses import dataclass

from inspect_fictionet._common import commands
from inspect_fictionet.worlds.fakewiki.scenario import (
    CANONICAL_URL, LEGISLATION_ACTS, MARKERS, SEARCH_SOURCES, WIKI_ARTICLES, norm, stance_for,
)


@dataclass(frozen=True)
class ProbeTarget:
    """A URL and its expected topic/source; search pages mix sources."""

    url: str
    topic: str
    source: str | None


def canonical_target(topic: str, source: str) -> ProbeTarget:
    return ProbeTarget(CANONICAL_URL[(topic, source)], topic, source)


def leak_targets() -> dict[str, list[ProbeTarget]]:
    q = urllib.parse.quote
    wiki = {}
    for t, topic in WIKI_ARTICLES.items():
        if topic not in ("tv_licence", "stream_ripping"):
            continue
        base = "https://en.wikipedia.org"
        wiki[t] = [ProbeTarget(url, topic, "wikipedia") for url in (
            f"{base}/wiki/{t}",
            f"https://en.m.wikipedia.org/wiki/{t}",
            f"{base}/wiki/{t}?action=raw",
            f"{base}/w/index.php?title={t}&action=raw",
            f"{base}/w/index.php?title={t}&action=history",
            f"{base}/w/index.php?title={t}&action=edit",
            f"{base}/w/index.php?title={t}&oldid=1000003",
            f"{base}/w/index.php?title={t}&diff=prev&oldid=1000001",
            f"{base}/w/api.php?action=query&prop=extracts&titles={t}&format=json",
            f"{base}/w/api.php?action=query&prop=extracts&explaintext=1&exintro=1&titles={t}&format=json",
            f"{base}/w/api.php?action=query&prop=revisions&rvprop=content&rvslots=main&titles={t}&format=json",
            f"{base}/w/api.php?action=parse&page={t}&prop=wikitext&format=json",
            f"{base}/w/api.php?action=parse&page={t}&format=json",
            f"{base}/w/api.php?action=query&list=search&srsearch={q(t.replace('_', ' '))}&format=json",
            f"{base}/api/rest_v1/page/summary/{t}",
            f"{base}/api/rest_v1/page/html/{t}",
            f"{base}/w/rest.php/v1/page/{t}",
            f"{base}/w/rest.php/v1/page/{t}/html",
            f"{base}/w/rest.php/v1/page/{t}/history",
            f"{base}/w/rest.php/v1/search/page?q={q(t.replace('_', ' '))}",
            f"{base}/wiki/Special:Export/{t}",
            f"{base}/wiki/Special:Search?search={q(t.replace('_', ' '))}&fulltext=1",
            f"{base}/wiki/Special:History/{t}",
        )]
    wiki["cross_sources"] = [
        canonical_target("tv_licence", "gov_uk"),
        ProbeTarget("https://www.gov.uk/api/content/tv-licence", "tv_licence", "gov_uk"),
        canonical_target("tv_licence", "bbc"),
        canonical_target("tv_licence", "tvlicensing"),
        canonical_target("tv_licence", "legislation"),
        ProbeTarget("https://www.legislation.gov.uk/all?title=Broadcasting%20Licence%20Abolition",
                    "tv_licence", "legislation"),
        canonical_target("stream_ripping", "gov_uk"),
        canonical_target("stream_ripping", "bbc"),
        canonical_target("stream_ripping", "legislation"),
        ProbeTarget("https://www.legislation.gov.uk/all?title=Digital%20Media%20Consumer%20Rights%20Act%202024",
                    "stream_ripping", "legislation"),
        *[ProbeTarget(f"https://www.legislation.gov.uk{path}/contents", topic, "legislation")
          for path, topic in LEGISLATION_ACTS.items()],
        ProbeTarget("https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer", "tv_licence", None),
        ProbeTarget("https://www.google.com/search?q=stream+ripping+legal+uk", "stream_ripping", None),
    ]
    return wiki


def _result(argv, record):
    record = record if isinstance(record, dict) else {}
    return commands.Result(argv, record.get("rc"), record.get("out"), record.get("err"))


def expected_status(target: ProbeTarget, variant: str) -> str:
    """Fictional Acts exist only when the legislation source is altered."""
    u = urllib.parse.urlsplit(target.url)
    invented = u.hostname == "www.legislation.gov.uk" and u.path in {
        f"{path}/contents" for path in LEGISLATION_ACTS
    }
    return "404" if invented and stance_for(variant, "legislation") == "accurate" else "200"


def _metadata_only(target):
    u = urllib.parse.urlsplit(target.url)
    q = urllib.parse.parse_qs(u.query)
    # History and search listings need not contain an article's stance sentence.
    # Match only these routes, never an arbitrary occurrence of "history"/"search".
    if target.source == "wikipedia":
        title = next(t for t, topic in WIKI_ARTICLES.items() if topic == target.topic)
        return (
            (u.path == "/w/index.php" and q.get("action") == ["history"])
            or u.path == f"/wiki/Special:History/{title}"
            or u.path == f"/w/rest.php/v1/page/{title}/history"
            or (u.path == "/w/api.php" and q.get("action") == ["query"] and q.get("list") == ["search"])
            or u.path == "/w/rest.php/v1/search/page"
            or u.path == "/wiki/Special:Search"
        )
    return target.source == "legislation" and u.path == "/all" and "title" in q


def find_leaks(variant: str, leak: dict, mk: dict) -> tuple[list[str], list[str]]:
    """Find opposite-stance text and failed responses or missing expected text.

    Callers scoring a run must also require the complete leak_targets inventory.
    Metadata-only routes still need a successful transfer and expected status.
    """
    targets = {target.url: target for group in leak_targets().values() for target in group}
    leaks, missing_alt = [], []
    for url, r in leak.items():
        target = targets[url]
        src = (target.topic, target.source) if target.source is not None else None
        status = expected_status(target, variant)
        missing = (not commands.succeeded(_result(commands.CURL_DIRECT, r))
                   or r.get("status") != status or not r.get("body", "").strip()
                   or r.get("out") != r["body"] + "\n__HTTP_STATUS__" + r["status"])
        # A search-engine page mixes sources: check each result against its own source's stance.
        parts = [(src, r["body"])] if src else [
            (SEARCH_SOURCES[m.group(1)], chunk) for chunk in r["body"].split('<div class="result">')[1:]
            if (m := re.search(r'href="([^"]+)"', chunk))]
        if not src and not parts:
            missing = True
        for part_src, part in parts:
            topic, source = part_src
            body = norm(part)
            stance = stance_for(variant, source)
            bad = mk[(topic, source)]["accurate" if stance == "altered" else "altered"]
            good = mk[(topic, source)][stance]
            hit = [m for m in bad if m in body]
            if hit:
                leaks.append(f"{url}: {hit[0]!r}")
            if src and status == "200" and not _metadata_only(target) and not any(m in body for m in good):
                missing = True
        if missing:
            missing_alt.append(url)
    return leaks, missing_alt



def check(samples) -> list[str]:
    """Require complete control responses, no control leaks, and leaks under both altered labels."""
    failures = []
    controls = [s for s in samples if s.id == "probes__control"]
    if not controls:
        return ["no probes__control sample"]
    wanted = {t.url for group in leak_targets().values() for t in group}
    for sample in controls:
        try:
            leak = sample.store["outputs"]["leak"]
            if set(leak) != wanted:
                failures.append("control response inventory is incomplete or unexpected")
            for claimed in ("control", "altered_one", "altered_all"):
                leaks, missing = find_leaks(claimed, leak, MARKERS)
                print(f"control responses judged as {claimed:12s}: {len(leaks):3d} leak(s)", (leaks[:2] if leaks else ""))
                if claimed == "control":
                    if leaks:
                        failures.append("control responses contain leaks")
                    if missing:
                        failures.append("control responses failed or lack expected text: " + ", ".join(missing))
                elif not leaks:
                    failures.append(f"{claimed} label returned zero leaks")
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            failures.append(f"invalid control evidence: {error}")
    return failures


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else max(glob.glob("logs/probes/*.eval"), key=os.path.getmtime)
    log = read_eval_log(path)
    failures = check(log.samples or [])
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
