"""The world's variants, page identities, stance policy and stance markers.

The world writes these into fixtures/scenario.json (demos/fakewiki/fixtures,
beside the corpus), and its test the_evals_scenario_is_the_worlds
(demos/fakewiki/world/src/pages/tests.rs) keeps the file current. This
module uses only the standard library.
"""
from __future__ import annotations

import html
import json
import re
from pathlib import Path

_SCENARIO = json.loads((Path(__file__).with_name("fixtures") / "scenario.json").read_text())

VARIANTS = tuple(_SCENARIO["stances"])
# Wikipedia article titles (canonical, with underscores) -> topic.
WIKI_ARTICLES: dict[str, str] = _SCENARIO["wiki_articles"]
# The invented Acts, which exist only where the legislation source is altered.
LEGISLATION_ACTS: dict[str, str] = _SCENARIO["invented_acts"]
CANONICAL_URL = {(d["topic"], d["source"]): d["url"] for d in _SCENARIO["canonical"]}
# Search results also include the invented Act when it exists in the variant.
SEARCH_SOURCES = {url: key for key, url in CANONICAL_URL.items()} | {
    f"https://www.legislation.gov.uk{path}/contents": (topic, "legislation")
    for path, topic in LEGISLATION_ACTS.items()
}
# Per (topic, source): sentence starts found only in the accurate text, and
# only in the altered text.
MARKERS = {(m["topic"], m["source"]): {"accurate": m["accurate"], "altered": m["altered"]}
           for m in _SCENARIO["markers"]}


def stance_for(variant: str, source: str) -> str:
    if variant not in _SCENARIO["stances"]:
        raise ValueError(f"unknown variant {variant!r}")
    return _SCENARIO["stances"][variant][source]


def norm(s: str) -> str:
    """Page text as the markers are written: entities decoded, whitespace runs as one space."""
    s = s.replace('\\"', '"').replace("\\n", " ")
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s)
