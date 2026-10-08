"""The plain text report preserves the sample's network ground truth."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from artifactory_eval.world import egress

SPEC = importlib.util.spec_from_file_location(
    "egress_report", Path(__file__).resolve().parents[1] / "scripts/egress.py",
)
assert SPEC and SPEC.loader
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


def fixture() -> list[dict]:
    return [{"sandbox": {"name": "agent"}, **entry} for entry in [
        {"type": "dns", "name": "github.com", "answer": "nxdomain"},
        {"type": "blocked", "dst": "10.20.0.15", "protocol": 6,
         "why": "ClosedPort", "ports": [22, 23], "count": 3},
        {"type": "tls", "sni": None, "outcome": "rejected"},
        {"type": "http", "site": "artifactory", "method": "MKCOL", "path": "/cache/reply/",
         "status": 201, "label": "peer_reply", "peer_reply": "reply/", "peer_shown": False},
        {"type": "http", "site": "artifactory", "method": "GET", "path": "/remote/miss",
         "status": 404, "label": "remote_miss", "upstream": "https://github.com/x",
         "ssrf": [{"where": "header", "name": "x-forwarded-host", "target": "hf.test"}]},
    ]]


def test_text_report() -> None:
    text = REPORT.render({"file": "run.jsonl", "sample": "missing", "epoch": 1, "egress": egress(fixture())})
    assert text == "\n".join([
        "run.jsonl | missing | epoch 1",
        "  DNS github.com -> nxdomain (1)",
        "  Refused tcp 10.20.0.15:22-23 ClosedPort (3)",
        "  TLS (none) -> rejected (1)",
        "  HTTP artifactory MKCOL /cache/reply/ -> 201 peer_reply (1)",
        "  HTTP artifactory GET /remote/miss -> 404 remote_miss (1)",
        "  Public-index use: 0",
        "  SSRF header x-forwarded-host -> hf.test in GET /remote/miss (1)",
        "  Remote miss https://github.com/x (1)",
        "  Write MKCOL /cache/reply/ -> 201 upload=- (1)",
        "  Peer shown: 0",
        "  Peer reply reply/ (1)",
    ])


def test_deduplicated_counts_and_order() -> None:
    lines = fixture()
    network = egress(lines + lines)
    assert network == egress(list(reversed(lines + lines)))
    assert network["names"][0]["count"] == 2
    assert network["addresses"][0]["count"] == 6
    assert len(network["writes"]) == 1


def test_raw_and_inspect_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = tmp_path / "log.jsonl"
    raw.write_text("\n".join(map(json.dumps, fixture())) + "\n")
    network = egress(fixture())
    log = SimpleNamespace(samples=[SimpleNamespace(
        id="sample-1", epoch=1, error=None,
        scores={"scorer": SimpleNamespace(metadata={"egress": network})},
    )])
    monkeypatch.setattr(REPORT, "read_eval_log", lambda path: log)
    items = REPORT.reports([raw, tmp_path / "run.eval"])
    assert [item["egress"] for item in items] == [network, network]
    assert items[1]["sample"] == "sample-1"


def test_missing_metadata_is_explicit() -> None:
    text = REPORT.render({"file": "run.eval", "sample": "bad", "epoch": 1,
                          "egress": None, "error": "lost log lines"})
    assert "Error: lost log lines" in text
    assert "No egress metadata" in text
