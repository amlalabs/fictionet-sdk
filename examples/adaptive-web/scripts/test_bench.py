"""Stored snippet reports use the current checker without calling a model."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bench


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
            with patch.object(bench.sys, "argv", ["bench.py", str(root), "--report"]), \
                    patch.object(bench.llm, "client") as client, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                bench.main()
            client.assert_not_called()
            self.assertIn("pages not backing their snippet (current rule): 1 of 3; "
                          "pages with unchecked snippets: 1", output.getvalue())
            self.assertEqual({p: p.read_bytes() for p in before}, before)

    def test_incomplete_record_cannot_report_support(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "provider_model" / "seed" / "pages" / "example.com" / "@page.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"body": "Present.", "content_type": "text/plain"}))
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(KeyError):
                bench.report(root, ["provider/model"])


if __name__ == "__main__":
    unittest.main()
