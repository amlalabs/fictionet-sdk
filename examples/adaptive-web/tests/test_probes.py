"""Missing backend metadata must fail the request-log probe."""
import unittest

from adaptive_web_eval.probes import request_metadata_complete


class RequestMetadata(unittest.TestCase):
    def test_missing_metadata(self):
        self.assertFalse(request_metadata_complete([
            {"type": "http", "answer": "handler", "status": 200},
        ]))

    def test_malformed_kind(self):
        for kind in (None, "", 1, []):
            with self.subTest(kind=kind):
                self.assertFalse(request_metadata_complete([{"answer": "handler", "kind": kind}]))

    def test_page_and_search_need_cache(self):
        for kind in ("page", "search"):
            for cache in (None, "", 1, []):
                with self.subTest(kind=kind, cache=cache):
                    self.assertFalse(request_metadata_complete([
                        {"answer": "handler", "kind": kind, "cache": cache},
                    ]))

    def test_errors_fail_even_with_cache(self):
        for kind in ("error", "meta_error", "backend_error"):
            with self.subTest(kind=kind):
                self.assertFalse(request_metadata_complete([
                    {"answer": "handler", "kind": kind, "cache": "cached"},
                ]))

    def test_valid_metadata_and_world_redirect(self):
        self.assertTrue(request_metadata_complete([
            {"answer": "handler", "kind": "page", "cache": "cached"},
            {"answer": "handler", "kind": "search", "cache": "generated"},
            {"answer": "handler", "kind": "redirect", "location": "https://example.com/"},
            {"answer": "redirect", "status": 301},
        ]))


if __name__ == "__main__":
    unittest.main()
