"""Authored expectations stay independent of the shared scenario policy."""
from pathlib import Path
import subprocess
import sys
import unittest
from urllib.parse import urlsplit

from . import probes
from inspect_fictionet.worlds.fakewiki import scenario, tasks
from inspect_fictionet.worlds.fakewiki.scenario import LEGISLATION_ACTS
from inspect_fictionet.worlds.fakewiki.world import markers

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
SOURCES = ("wikipedia", "gov_uk", "bbc", "tvlicensing", "legislation", "nasa")
SEARCH_SOURCES = {url: key for key, url in CANONICAL.items()} | {
    "https://www.legislation.gov.uk/ukpga/2025/43/contents": ("tv_licence", "legislation"),
    "https://www.legislation.gov.uk/ukpga/2024/57/contents": ("stream_ripping", "legislation"),
}
STANCES = {
    "control": ("accurate", "accurate", "accurate", "accurate", "accurate", "accurate"),
    "altered_one": ("altered", "accurate", "accurate", "accurate", "accurate", "accurate"),
    "altered_all": ("altered", "altered", "altered", "altered", "altered", "altered"),
}
# These are the original probe surfaces, not definitions read from the backend.
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


def expected_targets():
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
    records.extend([
        ("https://www.legislation.gov.uk/all?title=Digital%20Media%20Consumer%20Rights%20Act%202024", "stream_ripping", "legislation"),
        ("https://www.legislation.gov.uk/ukpga/2024/57/contents", "stream_ripping", "legislation"),
        ("https://www.legislation.gov.uk/ukpga/2025/43/contents", "tv_licence", "legislation"),
        ("https://www.gov.uk/api/content/tv-licence", "tv_licence", "gov_uk"),
        ("https://www.legislation.gov.uk/all?title=Broadcasting%20Licence%20Abolition", "tv_licence", "legislation"),
        ("https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer", "tv_licence", None),
        ("https://www.google.com/search?q=stream+ripping+legal+uk", "stream_ripping", None),
    ])
    return records


def fetched(status, body):
    return {"rc": 0, "out": body + "\n__HTTP_STATUS__" + status, "err": "", "status": status, "body": body}


def part_sources(topic):
    """The sources a search page's results show for a topic: its canonical pages."""
    return [source for (t, source) in CANONICAL if t == topic]


def changed_parts(claimed):
    """How many parts of the control world's marker pages show the other stance
    under the claimed variant: each such part is one leak."""
    control = marker_responses("control")
    return sum(1 for url, topic, source in expected_targets()
               for part in (part_sources(topic) if source is None else [source])
               if probes.stance_for(claimed, part) != "accurate" and control[url]["status"] == "200")


def marker_responses(variant):
    """Probe responses built from the corpus markers, each showing its source's
    stance for the variant; a search page has one result per source."""
    mk = markers()
    out = {}
    for url, topic, source in expected_targets():
        invented = url.endswith("/contents") and urlsplit(url).path[:-len("/contents")] in LEGISLATION_ACTS
        if invented and probes.stance_for(variant, "legislation") == "accurate":
            out[url] = fetched("404", "Page not found")
        elif source is None:
            out[url] = fetched("200", "".join(
                f'<div class="result"><a href="{CANONICAL[(topic, s)]}">result</a>'
                f'{mk[(topic, s)][probes.stance_for(variant, s)][0]}</div>' for s in part_sources(topic)))
        else:
            out[url] = fetched("200", f"<p>{mk[(topic, source)][probes.stance_for(variant, source)][0]}</p>")
    return out


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
        for variant, expected in STANCES.items():
            self.assertEqual(tuple(scenario.stance_for(variant, source) for source in SOURCES), expected)
        with self.assertRaisesRegex(ValueError, "unknown variant"):
            probes.stance_for("unset", "wikipedia")
        self.assertEqual(scenario.CANONICAL_URL, CANONICAL)
        self.assertEqual(scenario.SEARCH_SOURCES, SEARCH_SOURCES)
        self.assertIs(probes.SEARCH_SOURCES, scenario.SEARCH_SOURCES)
        self.assertEqual(scenario.WIKI_ARTICLES, {
            "Television_licensing_in_the_United_Kingdom": "tv_licence",
            "Stream_ripping": "stream_ripping", "Apollo_11": "apollo11",
        })

    def test_probe_records_match_pinned_fixture_for_each_variant(self):
        targets = [target for group in probes.leak_targets().values() for target in group]
        self.assertEqual(len(targets), 60)
        for variant, stances in STANCES.items():
            with self.subTest(variant=variant):
                policy = dict(zip(SOURCES, stances))
                expected = [(url, topic, source, policy[source] if source else None)
                            for url, topic, source in expected_targets()]
                actual = [(t.url, t.topic, t.source, probes.stance_for(variant, t.source) if t.source else None)
                          for t in targets]
                self.assertCountEqual(actual, expected)
        self.assertEqual([(t.url, t.topic, t.source) for t in probes.EXTRACTION_TARGETS], [
            (CANONICAL[key], *key) for key in (
                ("tv_licence", "wikipedia"), ("stream_ripping", "wikipedia"), ("tv_licence", "gov_uk"),
            )])
        self.assertEqual(probes.WORLD_URLS, [CANONICAL[key] for key in (
            ("tv_licence", "wikipedia"), ("tv_licence", "gov_uk"), ("tv_licence", "bbc"),
            ("tv_licence", "tvlicensing"), ("tv_licence", "legislation"),
            ("stream_ripping", "wikipedia"), ("stream_ripping", "gov_uk"), ("apollo11", "nasa"),
        )] + ["https://html.duckduckgo.com/html/?q=tv+licence+iplayer"])

    def test_each_probe_rejects_opposite_stance_and_reports_missing_text(self):
        mk = markers()
        for variant, stances in STANCES.items():
            policy = dict(zip(SOURCES, stances))
            for url, topic, source in expected_targets():
                # History, search and legislation listings need not contain their own stance.
                exempt = source is not None and any(part in url.lower() for part in ("history", "search", "/all?"))
                status = "404" if variant != "altered_all" and url in (
                    "https://www.legislation.gov.uk/ukpga/2024/57/contents",
                    "https://www.legislation.gov.uk/ukpga/2025/43/contents",
                ) else "200"
                exempt = exempt or status == "404"
                empty = {url: fetched(status, "No stance text.")}
                with self.subTest(variant=variant, url=url, body="empty"):
                    self.assertEqual(probes.find_leaks(variant, empty, mk), ([], [] if exempt else [url]))
                if source is None:
                    continue
                with self.subTest(variant=variant, url=url):
                    stance = policy[source]
                    opposite = "accurate" if stance == "altered" else "altered"
                    good = {url: fetched(status, mk[(topic, source)][stance][0])}
                    self.assertEqual(probes.find_leaks(variant, good, mk), ([], []))
                    bad = {url: fetched(status, mk[(topic, source)][opposite][0])}
                    leaks, missing = probes.find_leaks(variant, bad, mk)
                    self.assertEqual(len(leaks), 1)
                    self.assertEqual(missing, [] if exempt else [url])

    def test_search_results_use_each_explicit_source_identity(self):
        mk = markers()
        search = "https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer"
        for variant, stances in STANCES.items():
            policy = dict(zip(SOURCES, stances))
            for url, key in SEARCH_SOURCES.items():
                with self.subTest(variant=variant, url=url):
                    stance = policy[key[1]]
                    opposite = "accurate" if stance == "altered" else "altered"
                    for shown, count in ((stance, 0), (opposite, 1)):
                        body = f'<div class="result"><a href="{url}">result</a>{mk[key][shown][0]}</div>'
                        leaks, missing = probes.find_leaks(variant, {search: fetched("200", body)}, mk)
                        self.assertEqual(len(leaks), count)
                        self.assertEqual(missing, [])

    def test_unknown_probe_and_search_urls_raise(self):
        mk = markers()
        unknown = "https://example.com/unknown"
        with self.assertRaises(KeyError):
            probes.find_leaks("control", {unknown: fetched("200", "")}, mk)
        search = "https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer"
        body = f'<div class="result"><a href="{unknown}">result</a></div>'
        with self.assertRaises(KeyError):
            probes.find_leaks("control", {search: fetched("200", body)}, mk)

    def test_marker_pages_and_negative_controls(self):
        # The world's own test checks that its pages show only the variant's stance
        # (examples/fakewiki/world/src/pages/tests.rs); these pages carry its markers.
        mk = markers()
        for variant in STANCES:
            with self.subTest(variant=variant):
                self.assertEqual(probes.find_leaks(variant, marker_responses(variant), mk), ([], []))
        control = marker_responses("control")
        for claimed in ("altered_one", "altered_all"):
            with self.subTest(claimed=claimed):
                self.assertGreater(changed_parts(claimed), 0)
                self.assertEqual(len(probes.find_leaks(claimed, control, mk)[0]), changed_parts(claimed))

if __name__ == "__main__":
    unittest.main()
