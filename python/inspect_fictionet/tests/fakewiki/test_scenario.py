"""The leak checker on the pages the world serves, and its unit checks."""
from functools import cache
import json
from pathlib import Path
import subprocess
import sys
import unittest
from urllib.parse import urlsplit

from . import probes
from inspect_fictionet.worlds.fakewiki import scenario, tasks
from inspect_fictionet.worlds.fakewiki.scenario import LEGISLATION_ACTS, MARKERS

# The probe pages as the world renders them for each variant. The world's
# test the_evals_probe_pages_are_the_worlds (examples/fakewiki/world/src/pages/tests.rs)
# renders the URLs listed here and keeps the file current.
PAGES = Path(__file__).with_name("pages.json")


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


def targets():
    return [target for group in probes.leak_targets().values() for target in group]


class Scenario(unittest.TestCase):
    def test_adapter_needs_only_stdlib(self):
        subprocess.run([sys.executable, "-I", "-S", "-c", """
import runpy, sys
scenario = runpy.run_path(sys.argv[1])
assert scenario['VARIANTS'] == ('control', 'altered_one', 'altered_all')
assert 'inspect_ai' not in sys.modules
""", str(Path(scenario.__file__))], check=True)

    def test_one_policy(self):
        self.assertIs(tasks.VARIANTS, scenario.VARIANTS)
        self.assertIs(probes.stance_for, scenario.stance_for)
        with self.assertRaisesRegex(ValueError, "unknown variant"):
            probes.stance_for("unset", "wikipedia")
        for key, found in MARKERS.items():
            with self.subTest(key=key):
                self.assertTrue(found["accurate"] and found["altered"])

    def test_world_pages_cover_every_probe(self):
        urls = [target.url for target in targets()]
        self.assertEqual(len(urls), 60)
        self.assertEqual(set(_pages()["probes"]), set(urls),
                         "list each probe URL in pages.json, then run the world's tests "
                         "with FAKEWIKI_GOLDEN_WRITE=1")
        self.assertEqual([(t.url, t.topic, t.source) for t in probes.EXTRACTION_TARGETS], [
            (scenario.CANONICAL_URL[key], *key) for key in (
                ("tv_licence", "wikipedia"), ("stream_ripping", "wikipedia"), ("tv_licence", "gov_uk"),
            )])
        self.assertEqual(probes.WORLD_URLS, [scenario.CANONICAL_URL[key] for key in (
            ("tv_licence", "wikipedia"), ("tv_licence", "gov_uk"), ("tv_licence", "bbc"),
            ("tv_licence", "tvlicensing"), ("tv_licence", "legislation"),
            ("stream_ripping", "wikipedia"), ("stream_ripping", "gov_uk"), ("apollo11", "nasa"),
        )] + ["https://html.duckduckgo.com/html/?q=tv+licence+iplayer"])

    def test_world_pages_and_negative_controls(self):
        for variant in scenario.VARIANTS:
            with self.subTest(variant=variant):
                self.assertEqual(probes.find_leaks(variant, world_pages(variant), MARKERS), ([], []))
        control = world_pages("control")
        # The section 28B probe and its Google snippet each add an altered_all leak.
        for claimed, count in (("altered_one", 46), ("altered_all", 61)):
            with self.subTest(claimed=claimed):
                self.assertEqual(len(probes.find_leaks(claimed, control, MARKERS)[0]), count)

    def test_each_probe_rejects_opposite_stance_and_reports_missing_text(self):
        for variant in scenario.VARIANTS:
            for target in targets():
                url, topic, source = target.url, target.topic, target.source
                # History, search and legislation listings need not contain their own stance.
                exempt = source is not None and any(part in url.lower() for part in ("history", "search", "/all?"))
                invented = urlsplit(url).path in {f"{path}/contents" for path in LEGISLATION_ACTS}
                status = "404" if invented and variant != "altered_all" else "200"
                exempt = exempt or status == "404"
                empty = {url: fetched(status, "No stance text.")}
                with self.subTest(variant=variant, url=url, body="empty"):
                    self.assertEqual(probes.find_leaks(variant, empty, MARKERS), ([], [] if exempt else [url]))
                if source is None:
                    continue
                with self.subTest(variant=variant, url=url):
                    stance = probes.stance_for(variant, source)
                    opposite = "accurate" if stance == "altered" else "altered"
                    good = {url: fetched(status, MARKERS[(topic, source)][stance][0])}
                    self.assertEqual(probes.find_leaks(variant, good, MARKERS), ([], []))
                    bad = {url: fetched(status, MARKERS[(topic, source)][opposite][0])}
                    leaks, missing = probes.find_leaks(variant, bad, MARKERS)
                    self.assertEqual(len(leaks), 1)
                    self.assertEqual(missing, [] if exempt else [url])

    def test_search_results_use_each_explicit_source_identity(self):
        search = "https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer"
        for variant in scenario.VARIANTS:
            for url, key in scenario.SEARCH_SOURCES.items():
                with self.subTest(variant=variant, url=url):
                    stance = probes.stance_for(variant, key[1])
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
