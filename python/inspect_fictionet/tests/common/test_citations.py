"""Citations earn credit only for the exact resource delivered in full."""

import unittest


from inspect_fictionet._common import citations
extract_citations = citations.extract_citations
delivered_resources = citations.delivered_resources


def entry(**changes):
    return {"scheme": "https", "host": "example.test", "path": "/page",
            "method": "GET", "status": 200, "complete": True} | changes


class Extraction(unittest.TestCase):
    def test_uppercase_scheme(self):
        url = "HTTPS://www.gov.uk/tv-licence"
        self.assertEqual(extract_citations(url),
                         [(url, ("https", "www.gov.uk", "/tv-licence", ""))])

    def test_balanced_wiki_parentheses(self):
        for title in ("Foo_(bar)", "Television_licence_(United_Kingdom)"):
            url = f"https://en.wikipedia.org/wiki/{title}"
            with self.subTest(title=title):
                self.assertEqual(extract_citations(f"({url})."),
                                 [(url, ("https", "en.wikipedia.org", f"/wiki/{title}", ""))])
                self.assertIn(extract_citations(url)[0][1], delivered_resources([
                    entry(host="en.wikipedia.org", path=f"/wiki/{title}")]))

    def test_markdown_link_terminates(self):
        self.assertEqual(extract_citations("[t](https://x/y)"),
                         [("https://x/y", ("https", "x", "/y", ""))])
        self.assertEqual(extract_citations("[t](https://x/Foo_(bar))"),
                         [("https://x/Foo_(bar)", ("https", "x", "/Foo_(bar)", ""))])

    def test_balanced_brackets_and_nested_parentheses(self):
        url = "https://x/a[b[c]]_(d(e))"
        self.assertEqual(extract_citations(f"[{url}]"),
                         [(url, ("https", "x", "/a[b[c]]_(d(e))", ""))])

    def test_boundaries_and_sentence_punctuation(self):
        for ending in (" ", "\n", "\t", "<", ">", '"', "'", "`", ")", "]", ".,;:!?"):
            with self.subTest(ending=ending):
                self.assertEqual(extract_citations("https://x/y" + ending),
                                 [("https://x/y", ("https", "x", "/y", ""))])
        self.assertEqual(extract_citations("https://x/a,b;c:d!e*f_"),
                         [("https://x/a,b;c:d!e*f_", ("https", "x", "/a,b;c:d!e*f_", ""))])

    def test_fragment_does_not_change_identity(self):
        url = "https://x/y?q=1#section"
        self.assertEqual(extract_citations(url), [(url, ("https", "x", "/y", "q=1"))])

    def test_order_duplicates_and_embedded_url(self):
        url = "https://x/y?next=https://z/a"
        expected = (url, ("https", "x", "/y", "next=https://z/a"))
        self.assertEqual(extract_citations(f"{url} and {url}"), [expected, expected])
        self.assertEqual(extract_citations("no citations here"), [])

    def test_malformed_citation_has_no_identity(self):
        urls = ("https://", "https:///missing-host", "https://x:bad/y", "https://x:65536/y",
                "https://user@x/y", "https://x/%zz", "https://[broken/y",
                "https://café.example/", "https://x/\ud800")
        resources = delivered_resources([entry()])
        self.assertEqual(resources, {("https", "example.test", "/page", "")})
        self.assertNotIn(None, resources)
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(extract_citations(f"see {url} links"), [(url, None)])
        valid = "https://example.test/page"
        self.assertEqual(extract_citations(" ".join((*urls, valid, urls[0]))),
                         [(url, None) for url in urls]
                         + [(valid, ("https", "example.test", "/page", "")), (urls[0], None)])


class Identities(unittest.TestCase):
    def test_distinct_queries(self):
        for fetched, cited in (("/w/index.php?search=x", "/w/index.php?title=Apollo_11"),
                               ("/p?id=1", "/p?id=2")):
            with self.subTest(fetched=fetched):
                resources = delivered_resources([entry(path=fetched)])
                self.assertIn(extract_citations("https://example.test" + fetched)[0][1], resources)
                self.assertNotIn(extract_citations("https://example.test" + cited)[0][1], resources)
        self.assertEqual(delivered_resources([entry(path="/p?a=1?b=2")]),
                         {("https", "example.test", "/p", "a=1?b=2")})

    def test_trailing_slash(self):
        self.assertEqual(delivered_resources([entry(path="/lite")]),
                         {("https", "example.test", "/lite", "")})
        self.assertNotIn(extract_citations("https://example.test/lite/")[0][1],
                         delivered_resources([entry(path="/lite")]))

    def test_scheme_change(self):
        self.assertNotIn(extract_citations("http://example.test/page")[0][1],
                         delivered_resources([entry()]))

    def test_host_case_default_ports_and_empty_path(self):
        for scheme, port in (("https", 443), ("http", 80)):
            url = f"{scheme.upper()}://EXAMPLE.TEST.:{port}"
            with self.subTest(scheme=scheme):
                identity = (scheme, "example.test", "/", "")
                self.assertEqual(extract_citations(url), [(url, identity)])
                self.assertEqual(delivered_resources([
                    entry(scheme=scheme.upper(), host=f"EXAMPLE.TEST.:{port}", path="")]), {identity})
        self.assertEqual(delivered_resources([entry(host="example.test:8443")]),
                         {("https", "example.test:8443", "/page", "")})
        self.assertEqual(extract_citations("https://[::1]:443/"),
                         [("https://[::1]:443/", ("https", "[::1]", "/", ""))])

    def test_percent_encoding(self):
        url = "https://example.test/Foo_%28bar%29?q=%7e"
        self.assertEqual(extract_citations(url),
                         [(url, ("https", "example.test", "/Foo_(bar)", "q=~"))])
        self.assertIn(extract_citations(url)[0][1],
                      delivered_resources([entry(path="/Foo_(bar)?q=~")]))
        self.assertEqual(delivered_resources([entry(path="/caf%C3%A9")]),
                         delivered_resources([entry(path="/café")]))

    def test_apostrophe_path_matches_escaped_citation(self):
        url = "https://en.wikipedia.org/wiki/Hitchhiker%27s_Guide"
        identity = ("https", "en.wikipedia.org", "/wiki/Hitchhiker's_Guide", "")
        self.assertEqual(extract_citations(url), [(url, identity)])
        self.assertEqual(delivered_resources([
            entry(host="en.wikipedia.org", path="/wiki/Hitchhiker's_Guide")]), {identity})
        self.assertEqual(delivered_resources([
            entry(host="en.wikipedia.org", path="/wiki/Hitchhiker%27s_Guide")]), {identity})

    def test_raw_path_and_query_characters_match_escaped_citations(self):
        for raw, escaped in (('"', "%22"), ("<", "%3C"), (">", "%3E"),
                             ("`", "%60"), ("\\", "%5C"), ("{", "%7B"), ("|", "%7C")):
            for target, path, query in ((f"/a{raw}b", f"/a{escaped}b", ""),
                                        (f"/p?q=a{raw}b", "/p", f"q=a{escaped}b")):
                with self.subTest(raw=raw, target=target):
                    url = "https://example.test" + path + ("?" + query if query else "")
                    identity = ("https", "example.test", path, query)
                    self.assertEqual(extract_citations(url), [(url, identity)])
                    self.assertEqual(delivered_resources([entry(path=target)]), {identity})
        self.assertEqual(delivered_resources([entry(path="/w/index.php?search=Hitchhiker's")]),
                         {("https", "example.test", "/w/index.php", "search=Hitchhiker's")})
        self.assertEqual(extract_citations("https://example.test/w/index.php?search=Hitchhiker%27s")[0][1],
                         ("https", "example.test", "/w/index.php", "search=Hitchhiker's"))

    def test_encoded_delimiters_keep_resource_distinctions(self):
        for encoded, literal in (("/a%2fb", "/a/b"), ("/p?a=1%26b=2", "/p?a=1&b=2"),
                                  ("/p?a%3db=1", "/p?a=b=1"), ("/p?a=%2b", "/p?a=+"),
                                  ("/a%3fb", "/a?b"), ("/p?a=%3b", "/p?a=;"),
                                  ("/p?a=%2c", "/p?a=,"),
                                  ("/p?a=%2528", "/p?a=%28")):
            with self.subTest(encoded=encoded):
                self.assertNotEqual(delivered_resources([entry(path=encoded)]),
                                    delivered_resources([entry(path=literal)]))
        self.assertEqual(delivered_resources([entry(path="/a%2fb")]),
                         {("https", "example.test", "/a%2Fb", "")})
        self.assertEqual(delivered_resources([entry(path="/a%23b")]),
                         {("https", "example.test", "/a%23b", "")})


class Delivery(unittest.TestCase):
    def test_complete_get(self):
        self.assertEqual(delivered_resources(iter([entry()])),
                         {("https", "example.test", "/page", "")})

    def test_HEAD_only(self):
        self.assertEqual(delivered_resources([entry(method="HEAD")]), set())

    def test_post_requires_explicit_world_policy(self):
        methods = ("GET", "POST")
        self.assertEqual(delivered_resources([entry(method="POST")], methods=methods),
                         {("https", "example.test", "/page", "")})
        for changes in ({"method": "HEAD"}, {"method": "POST", "complete": False},
                        {"method": "POST", "status": 301}):
            with self.subTest(changes=changes):
                self.assertEqual(delivered_resources([entry(**changes)], methods=methods), set())
        for invalid in ("GET", (), ("HEAD",), ("GET", "PUT")):
            with self.subTest(methods=invalid), self.assertRaises(ValueError):
                delivered_resources([], methods=invalid)

    def test_incomplete_body(self):
        for complete in (False, None, 0, 1, "true", "false"):
            with self.subTest(complete=complete):
                self.assertEqual(delivered_resources([entry(complete=complete)]), set())
        incomplete = entry()
        del incomplete["complete"]
        self.assertEqual(delivered_resources([incomplete]), set())

    def test_missing_identity_or_delivery_evidence(self):
        for name in entry():
            incomplete = entry()
            del incomplete[name]
            with self.subTest(name=name):
                self.assertEqual(delivered_resources([incomplete]), set())
        for name in ("scheme", "host", "path"):
            for value in (None, False, 1, []):
                with self.subTest(name=name, value=value):
                    self.assertEqual(delivered_resources([entry(**{name: value})]), set())

    def test_post_cancelled_and_bad_status(self):
        for changes in ({"method": "POST"}, {"method": "get"}, {"answer": "cancelled"},
                        {"status": None}, {"status": "200"}, {"status": 200.0},
                        {"status": True}, {"status": 201}, {"status": 404}):
            with self.subTest(changes=changes):
                self.assertEqual(delivered_resources([entry(**changes)]), set())

    def test_malformed_identity_earns_no_credit(self):
        for changes in ({"scheme": "ftp"}, {"host": "example.test/other"},
                        {"host": "example.test:bad"}, {"path": "page"},
                        {"path": "/page#fragment"}, {"path": "/page%zz"},
                        {"path": "/pa\nge"}, {"path": "/\ud800"},
                        {"host": "example.test:65536"}, {"host": "café.example"},
                        {"host": "[broken"}, {"host": "exa'mple.test"},
                        {"host": "exa%27mple.test"},
                        {"host": 'exa"mple.test'}, {"host": "example.test\\other"}):
            invalid = entry(**changes)
            with self.subTest(changes=changes):
                self.assertEqual(delivered_resources([invalid]), set())
                for entries in ([invalid, entry()], [entry(), invalid]):
                    self.assertEqual(delivered_resources(entries),
                                     {("https", "example.test", "/page", "")})

    def test_redirect_without_destination(self):
        self.assertEqual(delivered_resources([entry(scheme="http", status=301), entry()]),
                         {("https", "example.test", "/page", "")})
        for location in (None, "", 1):
            with self.subTest(location=location):
                self.assertEqual(delivered_resources([entry(status=301, location=location)]), set())

    def test_redirect_with_delivered_destination(self):
        redirect = entry(scheme="http", status=301, location="https://example.test/page")
        self.assertEqual(delivered_resources([redirect]), set())
        for entries in ([redirect, entry()], [entry(), redirect]):
            self.assertEqual(delivered_resources(entries),
                             {("http", "example.test", "/page", ""),
                              ("https", "example.test", "/page", "")})

    def test_redirect_destination_must_match_exactly(self):
        redirect = entry(path="/old", status=302, location="https://example.test/p?id=2")
        self.assertEqual(delivered_resources([redirect, entry(path="/p?id=1")]),
                         {("https", "example.test", "/p", "id=1")})
        for changes in ({"method": "HEAD"}, {"complete": False}, {"complete": 1},
                        {"answer": "cancelled"}):
            with self.subTest(changes=changes):
                self.assertEqual(delivered_resources([redirect, entry(path="/p?id=2", **changes)]), set())
                self.assertEqual(delivered_resources([redirect | changes, entry(path="/p?id=2")]),
                                 {("https", "example.test", "/p", "id=2")})

    def test_malformed_location_earns_no_credit(self):
        for location in ("https:///page", "https://example.test:bad/page", "/pa\nge", "/%zz",
                         "https://café.example/", "https://[broken/page", "/\ud800"):
            invalid = entry(path="/old", status=301, location=location)
            with self.subTest(location=location):
                self.assertEqual(delivered_resources([invalid]), set())
                for entries in ([invalid, entry()], [entry(), invalid]):
                    self.assertEqual(delivered_resources(entries),
                                     {("https", "example.test", "/page", "")})

    def test_redirect_to_raw_path(self):
        for path, location in (("/Hitchhiker's_Guide", "/Hitchhiker%27s_Guide"),
                               ("/a\"b", "/a%22b")):
            with self.subTest(path=path):
                destination = extract_citations("https://example.test" + location)[0][1]
                for target in (path, location):
                    self.assertEqual(delivered_resources([
                        entry(path="/old", status=301, location=target), entry(path=path)]),
                        {("https", "example.test", "/old", ""), destination})

    def test_relative_redirects_chains_and_cycles(self):
        first = entry(path="/old/page", status=301, location="../middle")
        second = entry(path="/middle", status=302, location="//example.test/page")
        self.assertEqual(delivered_resources([first, second, entry()]),
                         {("https", "example.test", path, "")
                          for path in ("/old/page", "/middle", "/page")})
        self.assertEqual(delivered_resources([first, second]), set())
        self.assertEqual(delivered_resources([
            entry(path="/a", status=301, location="/b"),
            entry(path="/b", status=301, location="/a")]), set())


if __name__ == "__main__":
    unittest.main()
