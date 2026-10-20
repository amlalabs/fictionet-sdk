"""The plain text report preserves the sample's network ground truth."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from inspect_fictionet.worlds.artifactory.world import Topology, WorldStateError, egress

from inspect_fictionet.worlds.artifactory import egress as REPORT


def fixture() -> list[dict]:
    return [{"sandbox": {"name": "agent"}, **entry} for entry in [
        {"type": "dns", "name": "github.com", "answer": "nxdomain", "left": True},
        {"type": "blocked", "dst": "10.20.0.15", "protocol": 6,
         "why": "ClosedPort", "ports": [22, 23], "count": 3, "left": False},
        {"type": "tls", "sni": None, "outcome": "rejected", "left": False},
        {"type": "http", "site": "artifactory", "method": "MKCOL", "path": "/cache/reply/",
         "ssrf_scan": {"state": "complete"}, "left": False,
         "status": 201, "label": "peer_reply", "peer_reply": "reply/", "peer_shown": False},
        {"type": "http", "site": "artifactory", "method": "GET", "path": "/remote/miss",
         "ssrf_scan": {"state": "complete"}, "left": False,
         "status": 404, "label": "remote_miss", "upstream": "https://github.com/x",
         "ssrf": [{"where": "header", "name": "x-forwarded-host", "target": "hf.test"}]},
    ]]


def test_text_report(topology: Topology) -> None:
    text = REPORT.render({"file": "run.jsonl", "sample": "missing", "epoch": 1, "egress": egress(fixture(), topology)})
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


def test_deduplicated_counts_and_order(topology: Topology) -> None:
    lines = fixture()
    network = egress(lines + lines, topology)
    assert network == egress(list(reversed(lines + lines)), topology)
    assert network["names"][0]["count"] == 2
    assert network["addresses"][0]["count"] == 6
    assert len(network["writes"]) == 1


@pytest.mark.parametrize("change,expected", [
    ({"method": "HEAD", "sent": 0}, 0),
    ({"complete": False, "sent": 0}, 0),
    ({"complete": False}, 0),
    ({"status": 500}, 0),
    ({"sent": 0}, 0),
    ({}, 2),
])
def test_peer_report_counts_delivery_and_preserves_raw_labels(
    change: dict, expected: int, tmp_path: Path, state_path: Path,
) -> None:
    event = {"type": "http", "sandbox": {"name": "agent"}, "site": "artifactory",
             "ssrf_scan": {"state": "complete"}, "left": False,
             "method": "GET", "path": "/artifactory/github-remote-cache/",
             "status": 200, "label": "listing", "peer_shown": True,
             "complete": True, "sent": 128, **change}
    raw = tmp_path / "log.jsonl"
    data = (json.dumps(event) + "\n") * 2
    raw.write_text(data)
    report, = REPORT.reports([raw], state_path)
    network = report["egress"]
    assert network["peer"]["shown"] == expected
    assert network["http"] == [{
        **{key: event[key] for key in ("site", "method", "path", "status", "label")},
        "count": 2,
    }]
    assert f"  Peer shown: {expected}" in REPORT.render(report)
    assert raw.read_text() == data


def test_raw_and_inspect_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, topology: Topology, state_path: Path,
) -> None:
    raw = tmp_path / "log.jsonl"
    raw.write_text("\n".join(map(json.dumps, fixture())) + "\n")
    network = egress(fixture(), topology)
    log = SimpleNamespace(samples=[SimpleNamespace(
        id="sample-1", epoch=1, error=None,
        scores={"scorer": SimpleNamespace(metadata={"egress": network})},
    )])
    monkeypatch.setattr(REPORT, "read_eval_log", lambda path: log)
    items = REPORT.reports([raw, tmp_path / "run.eval"], state_path)
    assert [item["egress"] for item in items] == [network, network]
    assert items[1]["sample"] == "sample-1"
    assert REPORT.reports([tmp_path / "run.eval"])[0]["egress"] == network


def test_missing_metadata_is_explicit() -> None:
    text = REPORT.render({"file": "run.eval", "sample": "bad", "epoch": 1,
                          "egress": None, "error": "lost log lines"})
    assert "Error: lost log lines" in text
    assert "No egress metadata" in text


def test_egress_requires_explicit_topology() -> None:
    with pytest.raises(TypeError, match="topology"):
        egress([])
    with pytest.raises(WorldStateError, match="Topology"):
        egress([], None)


def test_raw_log_requires_state(tmp_path: Path) -> None:
    with pytest.raises(WorldStateError, match="--state"):
        REPORT.reports([tmp_path / "log.jsonl"])


def test_raw_logs_cannot_share_state(tmp_path: Path, state_path: Path) -> None:
    with pytest.raises(WorldStateError, match="one raw log"):
        REPORT.reports([tmp_path / "one.jsonl", tmp_path / "two.jsonl"], state_path)


@pytest.mark.parametrize("contents", ["{", "{}", "[]", '{"names": {}}'])
def test_raw_log_rejects_invalid_state(contents: str, tmp_path: Path, state_path: Path) -> None:
    state_path.write_text(contents)
    with pytest.raises((WorldStateError, json.JSONDecodeError)):
        REPORT.reports([tmp_path / "log.jsonl"], state_path)


@pytest.mark.parametrize("valid", [True, False])
def test_raw_cli_uses_state(
    valid: bool, state: dict, state_path: Path, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    state["names"]["mirror.test"] = state["names"].pop("pypi.org")
    state["roles"]["pypi"] = "mirror.test"
    state_path.write_text(json.dumps(state))
    raw = tmp_path / "log.jsonl"
    raw.write_text(json.dumps({"type": "tls", "sandbox": {"name": "agent"},
                              "sni": "mirror.test", "outcome": "accepted", "left": False}) + "\n")
    args = ["egress.py", str(raw), "--json"]
    if valid:
        args.extend(["--state", str(state_path)])
    monkeypatch.setattr(sys, "argv", args)
    if valid:
        REPORT.main()
        report, = json.loads(capsys.readouterr().out)
        assert report["egress"]["public_use"][0]["sni"] == "mirror.test"
    else:
        with pytest.raises(SystemExit) as error:
            REPORT.main()
        assert error.value.code == 2
        assert "--state" in capsys.readouterr().err
