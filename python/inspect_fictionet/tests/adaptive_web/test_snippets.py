"""Stored snippets are rescored from their bodies without calling a model."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adaptive import llm
from adaptive.world import rescore_snippets


class SnippetReport(unittest.TestCase):
    def test_report_rescores_stored_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pages = root / "provider_model" / "seed" / "pages" / "example.com"
            for name, snippet, body in (("unsupported", "Present. Absent.", "Present."),
                                        ("unchecked", "…", "Present."),
                                        ("supported", "Present.", "Present.")):
                path = pages / name / "@page.json"
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({"context": {"mentions": [{"via": "search", "snippet": snippet}]},
                                            "body": body, "content_type": "text/plain", "model": "provider/model",
                                            "unsupported_snippets": [], "unchecked_snippets": []}))
            fixed = pages / "fixed" / "@page.json"
            fixed.parent.mkdir()
            fixed.write_text(json.dumps({"model": "fixed", "body_base64": ""}))
            before = {p: p.read_bytes() for p in pages.rglob("@page.json")}
            with patch.object(llm, "client") as client:
                checks = [rescore_snippets(json.loads(p.read_text())) for p in before if p != fixed]
            client.assert_not_called()
            self.assertEqual(len(checks), 3)
            self.assertEqual(sum(bool(unsupported) for unsupported, unchecked in checks), 1)
            self.assertEqual(sum(bool(unchecked) for unsupported, unchecked in checks), 1)
            self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_incomplete_record_cannot_report_support(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "provider_model" / "seed" / "pages" / "example.com" / "@page.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"body": "Present.", "content_type": "text/plain"}))
            with self.assertRaises(KeyError):
                rescore_snippets(json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
