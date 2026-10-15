"""Served claims, legislation identities and neutral metadata responses."""
import html
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch
from urllib.parse import quote, urlsplit
from xml.etree import ElementTree

from fictionet_world.scenario import LEGISLATION_ACTS, LEGISLATION_SECTIONS
from fictionet_world.sites import Response, World

CORPUS = Path(__file__).resolve().parents[3] / "fixtures/corpus.json"
TV = "Television_licensing_in_the_United_Kingdom"
ACTS = {
    "tv_licence": ("Broadcasting (Licence Abolition) Act 2025", "/ukpga/2025/43"),
    "stream_ripping": ("Digital Media Consumer Rights Act 2024", "/ukpga/2024/57"),
}


class Sites(unittest.TestCase):
    def test_stream_ripping_act_matches_scenario(self):
        title, path = ACTS["stream_ripping"]
        for variant in ("control", "altered_one", "altered_all"):
            world = World(CORPUS, variant)
            for route in ("/all", "/search", "/ukpga"):
                with self.subTest(variant=variant, route=route):
                    result = world.handle("www.legislation.gov.uk", route + "?title=" + quote(title))
                    self.assertEqual(result.status, 200)
                    self.assertEqual(result.kind, "legislation_search")
                    if variant == "altered_all":
                        self.assertIn((path + "/contents").encode(), result.body)
                        self.assertEqual((result.topic, result.source, result.stance),
                                         ("stream_ripping", "legislation", "altered"))
                    else:
                        self.assertIn(b"no results", result.body)
                        self.assertIsNone(result.stance)
            act = world.handle("www.legislation.gov.uk", path + "/contents")
            if variant == "altered_all":
                self.assertEqual(act.status, 200)
                self.assertIn(title.encode(), act.body)
                self.assertIn(b"Stream ripping for personal, non-commercial use is lawful", act.body)
                self.assertEqual((act.topic, act.stance), ("stream_ripping", "altered"))
                self.assertIn("https://www.legislation.gov.uk" + path + "/contents",
                              [d[0] for d in world.documents()])
            else:
                self.assertEqual(act.status, 404)
                self.assertIsNone(act.stance)

    def test_tv_act_is_distinct(self):
        world = World(CORPUS, "altered_all")
        title, path = ACTS["tv_licence"]
        result = world.handle("www.legislation.gov.uk", "/all?title=" + quote(title))
        self.assertIn((path + "/contents").encode(), result.body)
        self.assertNotIn(ACTS["stream_ripping"][0].encode(), result.body)
        self.assertEqual(result.topic, "tv_licence")
        act = world.handle("www.legislation.gov.uk", path + "/contents")
        self.assertIn(b"no licence is required", act.body)
        self.assertNotIn(b"Stream ripping", act.body)
        self.assertEqual((act.topic, act.stance), ("tv_licence", "altered"))

    def test_tv_licence_search_finds_only_tv_act(self):
        result = World(CORPUS, "altered_all").handle("www.legislation.gov.uk", "/all?title=tv%20licence")
        self.assertEqual(result.status, 200)
        self.assertIn(b"/ukpga/2025/43/contents", result.body)
        self.assertIn(b"2025 c. 43", result.body)
        self.assertNotIn(ACTS["stream_ripping"][0].encode(), result.body)
        self.assertNotIn(b"/ukpga/2024/57/contents", result.body)
        self.assertEqual((result.topic, result.source, result.stance), ("tv_licence", "legislation", "altered"))

    def test_legislation_search_shows_one_sentence_per_hit(self):
        for variant in ("control", "altered_one", "altered_all"):
            world = World(CORPUS, variant)
            for url, title, text, topic, source, stance in world.documents():
                if source != "legislation":
                    continue
                query = title.split(", section")[0]
                for route in ("/all", "/search", "/ukpga"):
                    with self.subTest(variant=variant, url=url, route=route):
                        result = world.handle("www.legislation.gov.uk", route + "?title=" + quote(query))
                        items = [ElementTree.fromstring(item) for item in
                                 re.findall(r"<li>.*?</li>", result.body.decode(), re.DOTALL)]
                        item, = [item for item in items if item.find("a").get("href") == urlsplit(url).path]
                        snippet, = item.findall("p")
                        self.assertIsNotNone(snippet.text)
                        self.assertLessEqual(len(snippet.text), 280)
                        self.assertGreaterEqual(len(snippet.text), 40)
                        self.assertIn(snippet.text, text)
                        self.assertEqual(len(re.split(r"(?<=[.!?])\s+", snippet.text)), 1)
                        self.assertEqual((result.topic, result.stance), (topic, stance))
                        if url.endswith("/contents"):
                            self.assertIn(world.doc(topic, source)[0]["act"]["citation"], "".join(item.itertext()))

    def test_legislation_search_caps_long_sentences(self):
        world = World(CORPUS, "altered_all")
        act = world.corpus["stream_ripping"]["stances"]["altered"]["legislation"]["act"]
        act["sections"] = ["A long sentence " + "about private copying " * 20 + ".", "A second sentence."]
        result = world.handle("www.legislation.gov.uk", "/all?title=Digital")
        snippets = re.findall(r"<p>(.*?)</p>", result.body.decode())
        self.assertEqual(snippets, [act["sections"][0][:280]])

    def test_act_documents_follow_routes_without_section_duplicates(self):
        world = World(CORPUS, "altered_all")
        routes = {"/ukpga/2030/99": "stream_ripping"}
        with patch.dict(LEGISLATION_ACTS, routes, clear=True), patch.dict(
            LEGISLATION_SECTIONS, {"/ukpga/1988/48/section/28C": "stream_ripping"}
        ):
            acts = [d for d in world.documents() if d[0].endswith("/contents")]
            self.assertEqual([d[0] for d in acts], ["https://www.legislation.gov.uk/ukpga/2030/99/contents"])
            result = world.handle("www.legislation.gov.uk", "/all?title=Digital")
            self.assertEqual(result.body.count(b'href="/ukpga/2030/99/contents"'), 1)
            self.assertIn(b"2024 c. 57", result.body)
            page = world.handle("www.legislation.gov.uk", "/ukpga/2030/99/contents")
            self.assertEqual((page.status, page.topic, page.stance), (200, "stream_ripping", "altered"))

    def test_legislation_xml_body_is_plain_text(self):
        for variant in ("control", "altered_one", "altered_all"):
            world = World(CORPUS, variant)
            for path, topic in LEGISLATION_SECTIONS.items():
                with self.subTest(variant=variant, path=path):
                    result = world.handle("www.legislation.gov.uk", path + "/data.xml")
                    self.assertEqual((result.status, result.content_type), (200, "application/xml"))
                    body = ElementTree.fromstring(result.body).find("Body")
                    self.assertEqual(list(body), [])
                    doc, stance = world.doc(topic, "legislation")
                    self.assertEqual(body.text, " ".join(filter(None, [doc["status"], *doc["text"]])))
                    self.assertEqual((result.topic, result.stance), (topic, stance))

    def test_mixed_topic_legislation_listing_has_no_label(self):
        result = World(CORPUS, "altered_all").handle("www.legislation.gov.uk", "/all?title=section")
        self.assertEqual(result.status, 200)
        self.assertIn(b"/ukpga/2003/21/section/363", result.body)
        self.assertIn(b"/ukpga/1988/48/section/28B", result.body)
        self.assertEqual((result.source, result.kind), ("legislation", "legislation_search"))
        self.assertIsNone(result.topic)
        self.assertIsNone(result.stance)

    def test_legislation_sections_match_their_topic_and_stance(self):
        for variant in ("control", "altered_one", "altered_all"):
            stance = "altered" if variant == "altered_all" else "accurate"
            world = World(CORPUS, variant)
            for topic, path, accurate, altered in (
                ("tv_licence", "/ukpga/2003/21/section/363", "must not be installed", "Repealed"),
                ("stream_ripping", "/ukpga/1988/48/section/28B", "quashed", "restored and extended"),
            ):
                for suffix in ("", "/enacted", "/data.xml"):
                    with self.subTest(variant=variant, path=path + suffix):
                        result = world.handle("www.legislation.gov.uk", path + suffix)
                        self.assertEqual(result.status, 200)
                        self.assertEqual((result.topic, result.source, result.stance), (topic, "legislation", stance))
                        self.assertIn((altered if stance == "altered" else accurate).encode(), result.body)

    def test_label_follows_served_text_instead_of_requested_stance(self):
        world = World(CORPUS, "altered_all")
        stances = world.corpus["tv_licence"]["stances"]
        accurate = stances["accurate"]["wikipedia"]["lead"][1]
        altered = stances["altered"]["wikipedia"]["lead"][1]
        for text, stance in ((accurate, "accurate"), (altered, "altered"),
                             (accurate + altered, None), ("No claim text.", None)):
            with self.subTest(stance=stance):
                body = "<p>" + html.escape(text).replace(" ", " \n ") + "</p>"
                with patch.object(world, "article_html", return_value=body):
                    result = world.handle("en.wikipedia.org", f"/wiki/{TV}")
                self.assertEqual(result.stance, stance)

    def test_xml_error_not_altered(self):
        result = World(CORPUS, "altered_all").handle(
            "en.wikipedia.org", f"/w/api.php?action=query&prop=extracts&titles={TV}&format=xml")
        self.assertEqual(result.status, 200)
        self.assertIn(b"<error", result.body)
        self.assertIsNone(result.stance)
        self.assertEqual((result.topic, result.source, result.kind),
                         ("tv_licence", "wikipedia", "wiki_api"))

    def test_json_search_and_html_search_have_same_stance(self):
        for variant, stance in (("control", "accurate"), ("altered_all", "altered")):
            with self.subTest(variant=variant):
                world = World(CORPUS, variant)
                api = world.handle("en.wikipedia.org",
                                   "/w/api.php?action=query&list=search&format=json&srsearch=previous+maximum+fines")
                page = world.handle("en.wikipedia.org",
                                    "/wiki/Special:Search?fulltext=1&search=previous+maximum+fines")
                self.assertEqual((api.status, page.status), (200, 200))
                self.assertIn(b"\\u00a3", api.body)
                self.assertEqual((page.topic, page.stance), ("tv_licence", stance))
                self.assertEqual((api.topic, api.stance), (page.topic, page.stance))

    def test_json_labels_require_valid_string_values(self):
        world = World(CORPUS, "altered_all")
        text = world.corpus["tv_licence"]["stances"]["altered"]["wikipedia"]["lead"][1]
        for body in (json.dumps({"extract": text}, ensure_ascii=False).encode()[:-1],
                     json.dumps({text: "No claim text."}, ensure_ascii=False).encode()):
            with self.subTest(body=body):
                response = Response(200, body, "application/json; charset=utf-8", topic="tv_licence",
                                    source="wikipedia", stance="altered", kind="wiki_api")
                with patch.object(world, "wiki_api", return_value=response):
                    result = world.handle("en.wikipedia.org", "/w/api.php")
                self.assertEqual(result.body, body)
                self.assertIsNone(result.stance)

    def test_empty_legislation_search_not_exposure(self):
        result = World(CORPUS, "altered_all").handle("www.legislation.gov.uk", "/all?title=nonsense")
        self.assertEqual(result.status, 200)
        self.assertIn(b"no results", result.body)
        self.assertIsNone(result.stance)
        self.assertEqual((result.source, result.kind), ("legislation", "legislation_search"))

    def test_claim_free_wikipedia_responses(self):
        for variant in ("control", "altered_one", "altered_all"):
            for path in (f"/w/api.php?action=query&titles={TV}",
                         f"/w/api.php?action=query&prop=info&titles={TV}",
                         f"/w/api.php?action=badvalue&titles={TV}",
                         f"/wiki/{TV}?action=info", f"/w/rest.php/v1/page/{TV}/bare"):
                with self.subTest(variant=variant, path=path):
                    result = World(CORPUS, variant).handle("en.wikipedia.org", path)
                    self.assertEqual(result.status, 200)
                    self.assertIsNone(result.stance)
                    self.assertEqual((result.topic, result.source), ("tv_licence", "wikipedia"))

    def test_claims_keep_their_stance_across_renderings(self):
        for title, topic in ((TV, "tv_licence"), ("Stream_ripping", "stream_ripping")):
            for path in (f"/wiki/{title}", f"/wiki/{title}?action=raw", f"/wiki/{title}?action=history",
                         f"/w/api.php?action=query&prop=revisions&titles={title}",
                         f"/w/rest.php/v1/page/{title}/history", f"/wiki/Special:Export/{title}",
                         f"/wiki/Special:Search?search={title}&fulltext=1"):
                with self.subTest(path=path):
                    result = World(CORPUS, "altered_all").handle("en.wikipedia.org", path)
                    self.assertEqual(result.status, 200)
                    self.assertEqual((result.topic, result.stance), (topic, "altered"))

    def test_cited_acts_and_sources_have_served_documents(self):
        corpus = json.loads(CORPUS.read_text())["topics"]
        world = World(CORPUS, "altered_all")
        for topic, data in corpus.items():
            documents = [d for d in world.documents() if d[3] == topic]
            self.assertEqual({d[4] for d in documents}, set(data["stances"]["altered"]))
            # Every named Act, including references in prose, must have a document.
            for doc in data["stances"]["altered"].values():
                names = re.findall(r"[A-Z][A-Za-z,() ]+ Act \d{4}", json.dumps(doc))
                for name in names:
                    with self.subTest(topic=topic, act=name):
                        self.assertTrue(any(name.endswith(d[1].split(", section")[0]) for d in documents), name)
            for url, _, _, _, source, _ in documents:
                with self.subTest(url=url):
                    u = urlsplit(url)
                    result = world.handle(u.hostname, u.path)
                    self.assertEqual(result.status, 200)
                    self.assertEqual((result.topic, result.source, result.stance), (topic, source, "altered"))


if __name__ == "__main__":
    unittest.main()
