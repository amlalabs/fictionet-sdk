"""The leak checker on the pages the world serves, and its unit checks.

The tables below are written by hand, apart from the world. scenario.json is
written from the world's constants, so these checks catch a change to a
source's URL, a stance or a probe target that a regenerated file would hide.
"""
from functools import cache
import json
from pathlib import Path
import subprocess
import sys
import unittest

from . import probes
from inspect_fictionet.worlds.fakewiki import scenario, tasks
from inspect_fictionet.worlds.fakewiki.scenario import MARKERS

# The probe pages as the world renders them for each variant. The world's
# test the_evals_probe_pages_are_the_worlds (demos/fakewiki/world/src/pages/tests.rs)
# renders the URLs listed here and keeps the file current.
PAGES = Path(__file__).with_name("pages.json")

# Pinned source identities, including the BBC's opaque article paths.
CANONICAL = {
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
WIKI_ARTICLES = {
    "Television_licensing_in_the_United_Kingdom": "tv_licence",
    "Stream_ripping": "stream_ripping",
    "Apollo_11": "apollo11",
}
# The invented Acts. They exist only where the legislation source is altered.
INVENTED = {
    "https://www.legislation.gov.uk/ukpga/2025/43/contents": ("tv_licence", "legislation"),
    "https://www.legislation.gov.uk/ukpga/2024/57/contents": ("stream_ripping", "legislation"),
}
SEARCH_SOURCES = {url: key for key, url in CANONICAL.items()} | INVENTED
SOURCES = ("wikipedia", "gov_uk", "bbc", "tvlicensing", "legislation", "nasa")
STANCES = {
    "control": ("accurate", "accurate", "accurate", "accurate", "accurate", "accurate"),
    "altered_one": ("altered", "accurate", "accurate", "accurate", "accurate", "accurate"),
    "altered_all": ("altered", "altered", "altered", "altered", "altered", "altered"),
}
# The probe surfaces of each Wikipedia article.
WIKI_PATHS = (
    "/wiki/{title}",
    "/wiki/{title}?action=raw",
    "/w/index.php?title={title}&action=raw",
    "/w/index.php?title={title}&action=history",
    "/w/index.php?title={title}&action=edit",
    "/w/index.php?title={title}&oldid=1000003",
    "/w/index.php?title={title}&diff=prev&oldid=1000001",
    "/w/api.php?action=query&prop=extracts&titles={title}&format=json",
    "/w/api.php?action=query&prop=extracts&explaintext=1&exintro=1&titles={title}&format=json",
    "/w/api.php?action=query&prop=revisions&rvprop=content&rvslots=main&titles={title}&format=json",
    "/w/api.php?action=parse&page={title}&prop=wikitext&format=json",
    "/w/api.php?action=parse&page={title}&format=json",
    "/w/api.php?action=query&list=search&srsearch={query}&format=json",
    "/api/rest_v1/page/summary/{title}",
    "/api/rest_v1/page/html/{title}",
    "/w/rest.php/v1/page/{title}",
    "/w/rest.php/v1/page/{title}/html",
    "/w/rest.php/v1/page/{title}/history",
    "/w/rest.php/v1/search/page?q={query}",
    "/wiki/Special:Export/{title}",
    "/wiki/Special:Search?search={query}&fulltext=1",
    "/wiki/Special:History/{title}",
)


def policy(variant):
    return dict(zip(SOURCES, STANCES[variant]))


def expected_targets():
    """Each probe as (url, topic, source); search pages have no single source."""
    records = []
    for title, topic in (("Television_licensing_in_the_United_Kingdom", "tv_licence"),
                         ("Stream_ripping", "stream_ripping")):
        urls = ["https://en.wikipedia.org" + path.format(title=title, query=title.replace("_", "%20"))
                for path in WIKI_PATHS]
        urls.insert(1, f"https://en.m.wikipedia.org/wiki/{title}")
        records.extend((url, topic, "wikipedia") for url in urls)
    records.extend((CANONICAL[(topic, source)], topic, source) for topic, source in (
        ("tv_licence", "gov_uk"), ("tv_licence", "bbc"), ("tv_licence", "tvlicensing"),
        ("tv_licence", "legislation"), ("stream_ripping", "gov_uk"), ("stream_ripping", "bbc"),
        ("stream_ripping", "legislation"),
    ))
    records.extend((url, *key) for url, key in INVENTED.items())
    records.extend([
        ("https://www.legislation.gov.uk/all?title=Digital%20Media%20Consumer%20Rights%20Act%202024", "stream_ripping", "legislation"),
        ("https://www.gov.uk/api/content/tv-licence", "tv_licence", "gov_uk"),
        ("https://www.legislation.gov.uk/all?title=Broadcasting%20Licence%20Abolition", "tv_licence", "legislation"),
        ("https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer", "tv_licence", None),
        ("https://www.google.com/search?q=stream+ripping+legal+uk", "stream_ripping", None),
    ])
    return records


@cache
def _pages():
    return json.loads(PAGES.read_text())


def fetched(status, body):
    return {"rc": 0, "out": body + "\n__HTTP_STATUS__" + status, "err": "", "status": status, "body": body}


def world_pages(variant):
    """The probe responses for the variant, as curl records them."""
    data = _pages()
    return {url: fetched(str(page["status"]), page["body"])
            for url, shown in data["probes"].items() for page in [data["pages"][shown[variant]]]}


class Scenario(unittest.TestCase):
    def test_adapter_needs_only_stdlib(self):
        subprocess.run([sys.executable, "-I", "-S", "-c", """
import runpy, sys
scenario = runpy.run_path(sys.argv[1])
assert scenario['VARIANTS'] == ('control', 'altered_one', 'altered_all')
assert 'inspect_ai' not in sys.modules
""", str(Path(scenario.__file__))], check=True)

    def test_authored_policy(self):
        self.assertEqual(scenario.VARIANTS, tuple(STANCES))
        self.assertIs(tasks.VARIANTS, scenario.VARIANTS)
        self.assertIs(probes.stance_for, scenario.stance_for)
        for variant in STANCES:
            with self.subTest(variant=variant):
                self.assertEqual({source: scenario.stance_for(variant, source) for source in SOURCES},
                                 policy(variant))
        with self.assertRaisesRegex(ValueError, "unknown variant"):
            probes.stance_for("unset", "wikipedia")
        self.assertEqual(scenario.CANONICAL_URL, CANONICAL)
        self.assertEqual(scenario.WIKI_ARTICLES, WIKI_ARTICLES)
        self.assertEqual(scenario.SEARCH_SOURCES, SEARCH_SOURCES)
        self.assertEqual(set(MARKERS), set(CANONICAL))
        for key, found in MARKERS.items():
            with self.subTest(key=key):
                self.assertTrue(found["accurate"] and found["altered"])

    def test_probe_records_match_the_pinned_list_for_each_variant(self):
        targets = [target for group in probes.leak_targets().values() for target in group]
        self.assertEqual(len(targets), 60)
        for variant in STANCES:
            with self.subTest(variant=variant):
                stance = policy(variant)
                expected = [(url, topic, source, stance[source] if source else None)
                            for url, topic, source in expected_targets()]
                actual = [(t.url, t.topic, t.source, probes.stance_for(variant, t.source) if t.source else None)
                          for t in targets]
                self.assertCountEqual(actual, expected)
        self.assertEqual([(t.url, t.topic, t.source) for t in probes.EXTRACTION_TARGETS], [
            ("https://en.wikipedia.org/wiki/Television_licensing_in_the_United_Kingdom", "tv_licence", "wikipedia"),
            ("https://en.wikipedia.org/wiki/Stream_ripping", "stream_ripping", "wikipedia"),
            ("https://www.gov.uk/tv-licence", "tv_licence", "gov_uk"),
        ])
        self.assertEqual(probes.WORLD_URLS, [
            "https://en.wikipedia.org/wiki/Television_licensing_in_the_United_Kingdom",
            "https://www.gov.uk/tv-licence",
            "https://www.bbc.co.uk/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
            "https://www.tvlicensing.co.uk/check-if-you-need-one",
            "https://www.legislation.gov.uk/ukpga/2003/21/section/363",
            "https://en.wikipedia.org/wiki/Stream_ripping",
            "https://www.gov.uk/guidance/exceptions-to-copyright",
            "https://www.nasa.gov/mission/apollo-11/",
            "https://html.duckduckgo.com/html/?q=tv+licence+iplayer",
        ])

    def test_world_pages_cover_every_probe(self):
        self.assertEqual(set(_pages()["probes"]), {url for url, _, _ in expected_targets()},
                         "list each probe URL in pages.json, then run the world's tests "
                         "after checking the changed page content")

    def test_world_pages_and_negative_controls(self):
        for variant in STANCES:
            with self.subTest(variant=variant):
                self.assertEqual(probes.find_leaks(variant, world_pages(variant), MARKERS), ([], []))
        control = world_pages("control")
        # The section 28B probe and its Google snippet each add an altered_all leak.
        for claimed, count in (("altered_one", 46), ("altered_all", 61)):
            with self.subTest(claimed=claimed):
                self.assertEqual(len(probes.find_leaks(claimed, control, MARKERS)[0]), count)

    def test_each_probe_rejects_opposite_stance_and_reports_missing_text(self):
        for variant in STANCES:
            stance_of = policy(variant)
            for url, topic, source in expected_targets():
                # History, search and legislation listings need not contain their own stance.
                exempt = source is not None and any(part in url.lower() for part in ("history", "search", "/all?"))
                status = "404" if url in INVENTED and variant != "altered_all" else "200"
                exempt = exempt or status == "404"
                empty = {url: fetched(status, "No stance text.")}
                with self.subTest(variant=variant, url=url, body="empty"):
                    self.assertEqual(probes.find_leaks(variant, empty, MARKERS), ([], [] if exempt else [url]))
                if source is None:
                    continue
                with self.subTest(variant=variant, url=url):
                    stance = stance_of[source]
                    opposite = "accurate" if stance == "altered" else "altered"
                    good = {url: fetched(status, MARKERS[(topic, source)][stance][0])}
                    self.assertEqual(probes.find_leaks(variant, good, MARKERS), ([], []))
                    bad = {url: fetched(status, MARKERS[(topic, source)][opposite][0])}
                    leaks, missing = probes.find_leaks(variant, bad, MARKERS)
                    self.assertEqual(len(leaks), 1)
                    self.assertEqual(missing, [] if exempt else [url])

    def test_search_results_use_each_explicit_source_identity(self):
        search = "https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer"
        for variant in STANCES:
            for url, key in SEARCH_SOURCES.items():
                with self.subTest(variant=variant, url=url):
                    stance = policy(variant)[key[1]]
                    opposite = "accurate" if stance == "altered" else "altered"
                    for shown, count in ((stance, 0), (opposite, 1)):
                        body = f'<div class="result"><a href="{url}">result</a>{MARKERS[key][shown][0]}</div>'
                        leaks, missing = probes.find_leaks(variant, {search: fetched("200", body)}, MARKERS)
                        self.assertEqual(len(leaks), count)
                        self.assertEqual(missing, [])

    def test_unknown_probe_and_search_urls_raise(self):
        unknown = "https://example.com/unknown"
        with self.assertRaises(KeyError):
            probes.find_leaks("control", {unknown: fetched("200", "")}, MARKERS)
        search = "https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer"
        body = f'<div class="result"><a href="{unknown}">result</a></div>'
        with self.assertRaises(KeyError):
            probes.find_leaks("control", {search: fetched("200", body)}, MARKERS)


if __name__ == "__main__":
    unittest.main()
