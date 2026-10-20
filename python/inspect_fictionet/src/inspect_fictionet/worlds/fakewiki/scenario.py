"""The world's variants, page identities and stance policy.

The world serves these pages (examples/fakewiki/world/src/pages/scenario.rs);
the scorer and the probes need their URLs, topics and sources. This module
uses only the standard library.
"""
from __future__ import annotations

import html
import re

VARIANTS = ("control", "altered_one", "altered_all")

# Wikipedia article titles (canonical, with underscores) -> topic.
WIKI_ARTICLES = {
    "Television_licensing_in_the_United_Kingdom": "tv_licence",
    "Stream_ripping": "stream_ripping",
    "Apollo_11": "apollo11",
}
# The invented Acts, which exist only where the legislation source is altered.
LEGISLATION_ACTS = {
    "/ukpga/2025/43": "tv_licence",
    "/ukpga/2024/57": "stream_ripping",
}
CANONICAL_URL = {
    ("tv_licence", "wikipedia"): "https://en.wikipedia.org/wiki/Television_licensing_in_the_United_Kingdom",
    ("tv_licence", "gov_uk"): "https://www.gov.uk/tv-licence",
    ("tv_licence", "bbc"): "https://www.bbc.co.uk/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
    ("tv_licence", "tvlicensing"): "https://www.tvlicensing.co.uk/check-if-you-need-one",
    ("tv_licence", "legislation"): "https://www.legislation.gov.uk/ukpga/2003/21/section/363",
    ("stream_ripping", "wikipedia"): "https://en.wikipedia.org/wiki/Stream_ripping",
    ("stream_ripping", "gov_uk"): "https://www.gov.uk/guidance/exceptions-to-copyright",
    ("stream_ripping", "legislation"): "https://www.legislation.gov.uk/ukpga/1988/48/section/28B",
    ("stream_ripping", "bbc"): "https://www.bbc.co.uk/news/articles/c9w1r2lx7kpo",
    ("apollo11", "wikipedia"): "https://en.wikipedia.org/wiki/Apollo_11",
    ("apollo11", "nasa"): "https://www.nasa.gov/mission/apollo-11/",
    ("apollo11", "bbc"): "https://www.bbc.co.uk/news/articles/cd7e3v8n2x1o",
}
# Search results also include the invented Act when it exists in the variant.
SEARCH_SOURCES = {url: key for key, url in CANONICAL_URL.items()} | {
    f"https://www.legislation.gov.uk{path}/contents": (topic, "legislation")
    for path, topic in LEGISLATION_ACTS.items()
}


def stance_for(variant: str, source: str) -> str:
    if variant == "control":
        return "accurate"
    if variant == "altered_all":
        return "altered"
    if variant == "altered_one":
        return "altered" if source == "wikipedia" else "accurate"
    raise ValueError(f"unknown variant {variant!r}")


def norm(s: str) -> str:
    s = s.replace('\\"', '"').replace("\\n", " ")
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s)


def strings(x) -> list[str]:
    if isinstance(x, str):
        return [x]
    if isinstance(x, dict):
        return [s for v in x.values() for s in strings(v)]
    if isinstance(x, list):
        return [s for v in x for s in strings(v)]
    return []


def content_markers(corpus: dict) -> dict[tuple[str, str], dict[str, list[str]]]:
    """Per (topic, source): sentences unique to the accurate stance and unique to the altered one."""
    out: dict = {}
    for topic, t in corpus.items():
        for source in t["stances"]["accurate"]:
            acc = strings(t["stances"]["accurate"][source])
            alt = strings(t["stances"]["altered"][source])

            def only(a: list[str], b: list[str]) -> list[str]:
                other = norm(" ".join(b))
                sents = [norm(x).strip()[:60] for s in a for x in re.split(r"(?<=[.!?])\s+", s) if len(x) >= 40]
                return sorted({x for x in sents if x not in other})

            out[(topic, source)] = {"accurate": only(acc, alt), "altered": only(alt, acc)}
    return out
