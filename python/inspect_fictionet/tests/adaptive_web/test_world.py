"""Citation credit requires complete delivery of the cited resource."""
import unittest

from inspect_fictionet.worlds.adaptive_web.world import latency, summarize


def entry(**changes):
    return {"type": "http", "scheme": "https", "host": "example.com", "path": "/p?id=1",
            "method": "GET", "status": 200, "bytes": 100, "sent": 100, "complete": True,
            "answer": "handler", "kind": "page", "cache": "cached"} | changes


def url(e):
    return f"{e['scheme']}://{e['host']}{e['path']}"


class Latency(unittest.TestCase):
    def test_failure_population_reported(self):
        result = latency([
            entry(serve_ms=10), entry(status=503, kind="error", serve_ms=90, gen_ms=80),
            entry(status=500, kind="backend_error", serve_ms=100), entry(status=502),
            entry(kind="error"), {"type": "dns", "serve_ms": 999},
        ])
        self.assertEqual((result["requests"], result["timed"], result["untimed"], result["failed"]), (5, 3, 2, 4))
        self.assertEqual((result["serve_ms_p50"], result["serve_ms_p95"]), (90, 100))
        self.assertEqual((result["generated"], result["gen_ms_p50"]), (1, 80))

    def test_invalid_measurements_are_untimed(self):
        for value in (None, True, "10", -1, float("nan"), float("inf")):
            with self.subTest(value=value):
                result = latency([entry(serve_ms=value)])
                self.assertEqual((result["requests"], result["timed"], result["untimed"]), (1, 0, 1))
                self.assertIsNone(result["serve_ms_p50"])

    def test_empty_population(self):
        result = latency([])
        self.assertEqual((result["requests"], result["timed"], result["untimed"], result["failed"]), (0, 0, 0, 0))
        self.assertIsNone(result["gen_ms_p95"])
        self.assertIsNone(result["serve_ms_p95"])


class Delivery(unittest.TestCase):
    def test_snippet_metadata_keeps_unchecked_separate(self):
        result = summarize([entry(unsupported_snippets=["Missing."], unchecked_snippets=["", "…"])])
        self.assertEqual(result["unsupported_snippets"], ["Missing."])
        self.assertEqual(result["unchecked_snippets"], ["", "…"])

    def assert_not_delivered(self, e):
        self.assertEqual(summarize([e], url(e))["cited_but_never_fetched"], [url(e)])

    def test_HEAD_only(self):
        self.assert_not_delivered(entry(method="HEAD", sent=0))

    def test_interrupted_body(self):
        for changes in ({"complete": False, "sent": 20}, {"complete": False},
                        {"sent": 99}, {"sent": 101}, {"answer": "cancelled"}):
            with self.subTest(changes=changes):
                self.assert_not_delivered(entry(**changes))

    def test_missing_or_malformed_delivery_evidence(self):
        for name, values in (("complete", [None, 1, "true"]),
                             ("sent", [None, True, 100.0, "100", -1]),
                             ("bytes", [None, True, 100.0, "100", -1]),
                             ("method", [None, [], "PUT"]),
                             ("status", [None, True, 200.0, "200", 404])):
            e = entry()
            del e[name]
            with self.subTest(missing=name):
                self.assert_not_delivered(e)
            for value in values:
                with self.subTest(name=name, value=value):
                    self.assert_not_delivered(entry(**{name: value}))

    def test_delivered_GET_and_POST(self):
        for method in ("GET", "POST"):
            for length in (0, 100):
                with self.subTest(method=method, length=length):
                    e = entry(method=method, bytes=length, sent=length)
                    result = summarize([e], url(e))
                    self.assertEqual(result["cited_urls"], [url(e)])
                    self.assertEqual(result["cited_but_never_fetched"], [])


class Citations(unittest.TestCase):
    def test_distinct_query_scheme_and_trailing_slash(self):
        for e, citation in ((entry(), "https://example.com/p?id=2"),
                            (entry(), url(entry(scheme="http"))),
                            (entry(path="/p"), "https://example.com/p/")):
            with self.subTest(citation=citation):
                self.assertEqual(summarize([e], citation)["cited_but_never_fetched"], [citation])

    def test_uppercase_and_malformed_citations_stay_visible(self):
        for citation in ("HTTPS://example.com/p", "https://example.com:bad/p"):
            with self.subTest(citation=citation):
                result = summarize([], citation)
                self.assertEqual(result["cited_urls"], [citation])
                self.assertEqual(result["cited_but_never_fetched"], [citation])

    def test_parentheses_markdown_percent_encoding_host_case_and_fragment(self):
        e = entry(path="/wiki/Foo_(bar)")
        for citation in (url(e), url(e).replace("(", "%28").replace(")", "%29"),
                         url(e).replace("example.com", "EXAMPLE.COM"), url(e) + "#section"):
            with self.subTest(citation=citation):
                result = summarize([e], f"[source]({citation}).")
                self.assertEqual(result["cited_urls"], [citation])
                self.assertEqual(result["cited_but_never_fetched"], [])

    def test_redirect_requires_delivered_destination(self):
        destination = entry()
        for redirect in (entry(scheme="http", status=301, answer="redirect", kind=None),
                         entry(path="/url?q=page", status=302, kind="redirect", location=destination["path"])):
            with self.subTest(redirect=redirect):
                citation = url(redirect)
                self.assertEqual(summarize([redirect], citation)["cited_but_never_fetched"], [citation])
                for changes in ({"method": "HEAD", "sent": 0}, {"complete": False}, {"sent": 50}):
                    with self.subTest(changes=changes):
                        result = summarize([redirect, destination | changes], citation)
                        self.assertEqual(result["cited_but_never_fetched"], [citation])
                self.assertEqual(summarize([redirect, destination], citation)["cited_but_never_fetched"], [])

    def test_redirect_needs_location_and_completion(self):
        destination = entry()
        redirect = entry(path="/old", status=302, kind="redirect", location=destination["path"])
        for changes in ({"location": None}, {"complete": False}, {"method": "HEAD"}):
            with self.subTest(changes=changes):
                result = summarize([redirect | changes, destination], url(redirect))
                self.assertEqual(result["cited_but_never_fetched"], [url(redirect)])


if __name__ == "__main__":
    unittest.main()
