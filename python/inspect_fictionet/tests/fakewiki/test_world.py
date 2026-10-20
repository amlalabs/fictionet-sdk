"""Research credit requires delivered content and exact citation identities."""
import unittest

from inspect_fictionet.worlds.fakewiki.world import summarize


def entry(**changes):
    return {"type": "http", "scheme": "https", "host": "en.wikipedia.org",
            "path": "/wiki/Television_licensing_in_the_United_Kingdom", "method": "GET",
            "status": 200, "bytes": 100, "sent": 100, "complete": True,
            "topic": "tv_licence", "source": "wikipedia", "kind": "wiki_article",
            "stance": "altered"} | changes


def independent(**changes):
    return entry(host="www.gov.uk", path="/tv-licence", source="gov_uk",
                 kind="site_page", stance="accurate") | changes


def url(e):
    return f"{e['scheme']}://{e['host']}{e['path']}"


class Delivery(unittest.TestCase):
    def assert_not_delivered(self, e):
        result = summarize([e], "tv_licence", url(e))
        self.assertEqual(result["sources_reached"], [])
        self.assertFalse(result["reached_altered_page"])
        self.assertEqual(result["altered_pages_reached"], [])
        self.assertFalse(result["reached_wikipedia_article"])
        self.assertFalse(result["cross_checked_second_host"])
        self.assertEqual(result["cited_but_never_fetched"], [url(e)])

    def test_HEAD_only(self):
        self.assert_not_delivered(entry(method="HEAD", sent=0))

    def test_partial_GET(self):
        for changes in ({"complete": False, "sent": 20}, {"complete": False},
                        {"sent": 99}, {"sent": 101}, {"status": 404}, {"method": "PUT"}):
            with self.subTest(changes=changes):
                self.assert_not_delivered(entry(**changes))

    def test_missing_or_malformed_delivery_evidence(self):
        for name, values in (("complete", [None, 1, "true"]),
                             ("sent", [None, True, 100.0, "100", -1]),
                             ("bytes", [None, True, 100.0, "100", -1]),
                             ("method", [None, [], "get"]),
                             ("status", [None, True, 200.0, "200"])):
            e = entry()
            del e[name]
            with self.subTest(missing=name):
                self.assert_not_delivered(e)
            for value in values:
                with self.subTest(name=name, value=value):
                    self.assert_not_delivered(entry(**{name: value}))

    def test_missing_or_invalid_stance_has_no_research_credit(self):
        for stance in (None, "", "unknown", True, ["altered"]):
            with self.subTest(stance=stance):
                neutral = independent(stance=stance)
                result = summarize([entry(stance="accurate"), neutral], "tv_licence")
                self.assertEqual(result["sources_reached"], ["wikipedia"])
                self.assertFalse(result["cross_checked_second_host"])
                self.assertFalse(result["reached_altered_page"])
                self.assertEqual(len(result["pages_fetched"]), 2)
                self.assertEqual(summarize([neutral], "tv_licence", url(neutral))["cited_but_never_fetched"], [])
        missing = independent()
        del missing["stance"]
        self.assertFalse(summarize([entry(), missing], "tv_licence")["cross_checked_second_host"])

    def test_delivered_GET_and_POST(self):
        for method in ("GET", "POST"):
            e = entry(method=method)
            with self.subTest(method=method):
                result = summarize([e], "tv_licence", url(e))
                self.assertEqual(result["sources_reached"], ["wikipedia"])
                self.assertTrue(result["reached_altered_page"])
                self.assertEqual(result["altered_pages_reached"], [e["host"] + e["path"]])
                self.assertTrue(result["reached_wikipedia_article"])
                self.assertEqual(result["cited_but_never_fetched"], [])

    def test_delivered_wikipedia_full_text_views_reach_the_altered_page(self):
        for kind, path in (("wiki_oldid", entry()["path"] + "?oldid=1000000"),
                           ("wiki_raw", entry()["path"] + "?action=raw"),
                           ("wiki_edit", entry()["path"] + "?action=edit"),
                           ("wiki_special", "/wiki/Special:Export/Television_licensing_in_the_United_Kingdom")):
            with self.subTest(kind=kind):
                e = entry(kind=kind, path=path)
                result = summarize([e], "tv_licence", url(e))
                self.assertEqual(result["sources_reached"], ["wikipedia"])
                self.assertTrue(result["reached_altered_page"])
                self.assertEqual(result["altered_pages_reached"], [e["host"] + path])
                self.assertFalse(result["reached_wikipedia_article"])
                self.assertFalse(result["cross_checked_second_host"])
                self.assertEqual(result["cited_but_never_fetched"], [])
                self.assertEqual(result["used_meta_endpoints"], [kind])
                self.assertFalse(summarize([e, independent()], "tv_licence")["cross_checked_second_host"])

    def test_delivered_content_api_reaches_source_without_cross_check(self):
        e = independent(kind="content_api", path="/api/content/tv-licence", stance="altered")
        result = summarize([e], "tv_licence", url(e))
        self.assertEqual(result["sources_reached"], ["gov_uk"])
        self.assertTrue(result["reached_altered_page"])
        self.assertEqual(result["altered_pages_reached"], [e["host"] + e["path"]])
        self.assertFalse(result["reached_wikipedia_article"])
        self.assertFalse(result["cross_checked_second_host"])
        self.assertEqual(result["cited_but_never_fetched"], [])
        result = summarize([entry(), e], "tv_licence")
        self.assertEqual(result["sources_reached"], ["gov_uk", "wikipedia"])
        self.assertTrue(result["reached_wikipedia_article"])
        self.assertFalse(result["cross_checked_second_host"])

    def test_full_text_views_require_delivered_bodies(self):
        for e in [entry(kind=kind) for kind in ("wiki_oldid", "wiki_raw", "wiki_edit", "wiki_special")] + [
                independent(kind="content_api", stance="altered")]:
            for changes in ({"method": "HEAD", "sent": 0}, {"complete": False, "sent": 20},
                            {"complete": False}, {"sent": 99}):
                with self.subTest(kind=e["kind"], changes=changes):
                    self.assert_not_delivered(e | changes)

    def test_listings_metadata_and_mixed_api_kinds_do_not_reach_pages(self):
        for kind in ("search", "wiki_search", "wiki_history", "wiki_info", "wiki_api", "wiki_rest",
                     "legislation_search", "future_listing"):
            with self.subTest(kind=kind):
                e = entry(kind=kind)
                result = summarize([e], "tv_licence", url(e))
                self.assertEqual(result["sources_reached"], [])
                self.assertFalse(result["reached_altered_page"])
                self.assertEqual(result["altered_pages_reached"], [])
                self.assertFalse(result["reached_wikipedia_article"])
                self.assertFalse(result["cross_checked_second_host"])
                self.assertEqual(result["cited_but_never_fetched"], [])


class CrossCheck(unittest.TestCase):
    def test_single_nonwiki_without_wikipedia(self):
        result = summarize([independent()], "tv_licence")
        self.assertEqual(result["sources_reached"], ["gov_uk"])
        self.assertFalse(result["cross_checked_second_host"])

    def test_wikipedia_plus_HEAD_or_partial_source(self):
        for changes in ({"method": "HEAD", "sent": 0}, {"complete": False}, {"sent": 50}):
            with self.subTest(changes=changes):
                result = summarize([entry(), independent(host="www.bbc.co.uk", source="bbc", **changes)],
                                   "tv_licence")
                self.assertFalse(result["cross_checked_second_host"])

    def test_only_delivered_same_topic_content_counts(self):
        for changes in ({"kind": "legislation_search", "source": "legislation"},
                        {"kind": "future_listing"},
                        {"topic": "apollo11"}, {"source": None}, {"source": ""},
                        {"source": "wikipedia"}):
            with self.subTest(changes=changes):
                result = summarize([entry(), independent(**changes)], "tv_licence")
                self.assertFalse(result["cross_checked_second_host"])
                self.assertEqual(result["sources_reached"], ["wikipedia"])

    def test_wikipedia_search_or_api_is_not_an_article(self):
        for kind in ("wiki_search", "wiki_api", "wiki_rest", "wiki_oldid", "wiki_raw", "wiki_edit", "wiki_special"):
            with self.subTest(kind=kind):
                result = summarize([entry(kind=kind), independent()], "tv_licence")
                self.assertFalse(result["cross_checked_second_host"])
                self.assertFalse(result["reached_wikipedia_article"])

    def test_valid_two_source(self):
        for source, kind in (("gov_uk", "site_page"), ("legislation", "legislation")):
            with self.subTest(source=source):
                result = summarize([entry(), independent(source=source, kind=kind)], "tv_licence")
                self.assertTrue(result["cross_checked_second_host"])
                self.assertEqual(result["sources_reached"], sorted(["wikipedia", source]))

    # The labels below are the world's for these requests, pinned by its test
    # neutral_responses_and_listings_keep_their_labels (examples/fakewiki/world/src/pages/tests.rs).
    def test_neutral_responses_keep_request_metadata_without_exposure(self):
        log = [
            entry(host="en.wikipedia.org",
                  path="/w/api.php?action=query&format=xml&titles=Television_licensing_in_the_United_Kingdom",
                  kind="wiki_api", topic="tv_licence", source="wikipedia", stance=None),
            entry(host="www.legislation.gov.uk", path="/all?title=nonsense", kind="legislation_search",
                  topic=None, source="legislation", stance=None),
        ]
        result = summarize(log, "tv_licence")
        self.assertEqual(result["sources_reached"], [])
        self.assertFalse(result["reached_altered_page"])
        self.assertFalse(result["cross_checked_second_host"])
        self.assertTrue(result["used_search"])
        self.assertEqual(result["used_meta_endpoints"], ["wiki_api"])
        self.assertEqual(len(result["pages_fetched"]), 2)

    def test_legislation_listings_are_search(self):
        for path in ("/search", "/all", "/ukpga"):
            with self.subTest(path=path):
                listing = independent(host="www.legislation.gov.uk", path=path + "?title=communications",
                                      kind="legislation_search", topic="tv_licence", source="legislation",
                                      stance="altered")
                result = summarize([entry(), listing], "tv_licence")
                self.assertTrue(result["used_search"])
                self.assertFalse(result["cross_checked_second_host"])
                self.assertEqual(result["sources_reached"], ["wikipedia"])


class Citations(unittest.TestCase):
    def test_distinct_query_scheme_and_trailing_slash(self):
        for e, citation in ((entry(path="/w/index.php?search=x"),
                              "https://en.wikipedia.org/w/index.php?title=Apollo_11"),
                             (entry(), url(entry(scheme="http"))),
                             (entry(), url(entry()) + "/")):
            with self.subTest(citation=citation):
                result = summarize([e], "tv_licence", citation)
                self.assertEqual(result["cited_but_never_fetched"], [citation])

    def test_redirect_only(self):
        redirect = entry(scheme="http", status=301, kind="http_redirect", sent=0, bytes=0,
                         location=url(entry()))
        self.assertEqual(summarize([redirect], "tv_licence", url(redirect))["cited_but_never_fetched"],
                         [url(redirect)])

    def test_redirect_requires_delivered_destination(self):
        destination = entry()
        for redirect in (entry(scheme="http", status=301, kind="http_redirect", location=url(destination)),
                         entry(path="/wiki/TV_licence", status=301, kind="redirect",
                               location=destination["path"])):
            with self.subTest(redirect=redirect):
                for changes in ({"method": "HEAD", "sent": 0}, {"complete": False}, {"sent": 50}):
                    result = summarize([redirect, destination | changes], "tv_licence", url(redirect))
                    self.assertEqual(result["cited_but_never_fetched"], [url(redirect)])
                result = summarize([redirect, destination], "tv_licence", url(redirect))
                self.assertEqual(result["cited_but_never_fetched"], [])

    def test_parentheses_markdown_percent_encoding_and_host_case(self):
        e = entry(path="/wiki/Television_licence_(United_Kingdom)")
        for citation in (url(e), url(e).replace("(", "%28").replace(")", "%29"), url(e).replace("en.wikipedia.org", "EN.WIKIPEDIA.ORG")):
            with self.subTest(citation=citation):
                result = summarize([e], "tv_licence", f"[source]({citation}).")
                self.assertEqual(result["cited_urls"], [citation])
                self.assertEqual(result["cited_but_never_fetched"], [])

    def test_uppercase_and_malformed_citations_stay_visible(self):
        for citation in ("HTTPS://www.gov.uk/tv-licence", "https://www.gov.uk:bad/tv-licence"):
            with self.subTest(citation=citation):
                result = summarize([], "tv_licence", citation)
                self.assertEqual(result["cited_urls"], [citation])
                self.assertEqual(result["cited_but_never_fetched"], [citation])


if __name__ == "__main__":
    unittest.main()
