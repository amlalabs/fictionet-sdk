"""Print network ground truth from Inspect .eval logs or raw world JSON lines.

    uv run --project python/inspect_fictionet --locked python -m inspect_fictionet.worlds.artifactory.egress logs/run.eval [--json]
    uv run --project python/inspect_fictionet --locked python -m inspect_fictionet.worlds.artifactory.egress world/log.jsonl --state world/state.json [--json]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from inspect_ai.log import read_eval_log

from inspect_fictionet._common.logs import parse_log
from inspect_fictionet.worlds.artifactory.world import Topology, WorldLogError, WorldStateError, egress

# IP protocol numbers in blocked lines, by name.
PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp"}


def reports(paths: list[Path], state: Path | None = None) -> list[dict[str, Any]]:
    """Read stored score metadata or one raw log with its matching state file."""
    raw = [path for path in paths if path.suffix != ".eval"]
    if raw and state is None:
        raise WorldStateError("raw logs require --state from the same world run")
    if len(raw) > 1:
        raise WorldStateError("report one raw log at a time with its matching --state")
    topology = Topology.from_state(json.loads(state.read_text())) if raw and state else None
    result = []
    for path in sorted(paths):
        if path.suffix == ".eval":
            log = read_eval_log(str(path))
            for sample in sorted(log.samples or [], key=lambda s: (str(s.id), s.epoch)):
                network = next((
                    score.metadata["egress"] for score in (sample.scores or {}).values()
                    if score.metadata and "egress" in score.metadata
                ), None)
                result.append({
                    "file": str(path), "sample": str(sample.id), "epoch": sample.epoch,
                    "egress": network, "error": sample.error.message if sample.error else None,
                })
        else:
            assert topology is not None
            result.append({
                "file": str(path), "sample": path.stem, "epoch": 1,
                "egress": egress(parse_log(path.read_text()), topology), "error": None,
            })
    return result


def render(report: dict[str, Any]) -> str:
    """Render a short deterministic report without omitting refused traffic."""
    lines = [f"{report['file']} | {report['sample']} | epoch {report['epoch']}"]
    if report.get("error"):
        lines.append(f"  Error: {report['error']}")
    network = report.get("egress")
    if network is None:
        lines.append("  No egress metadata. This sample cannot be summarized.")
        return "\n".join(lines)
    for entry in network["names"]:
        lines.append(f"  DNS {entry['name']} -> {entry['answer']} ({entry['count']})")
    for entry in network["addresses"]:
        ports = entry["ports"]
        port = "-".join(map(str, ports)) if isinstance(ports, list) else str(ports)
        protocol = PROTOCOLS.get(str(entry["protocol"]), entry["protocol"])
        lines.append(
            f"  Refused {protocol} {entry['dst']}:{port} "
            f"{entry['why']} ({entry['count']})"
        )
    for entry in network["tls"]:
        lines.append(f"  TLS {entry['sni']} -> {entry['outcome']} ({entry['count']})")
    for entry in network["http"]:
        lines.append(
            f"  HTTP {entry['site']} {entry['method']} {entry['path']} -> "
            f"{entry['status']} {entry['label']} ({entry['count']})"
        )
    lines.append(f"  Public-index use: {sum(e['count'] for e in network['public_use'])}")
    for entry in network["ssrf_targets"]:
        lines.append(
            f"  SSRF {entry['where']} {entry['name']} -> {entry['target']} "
            f"in {entry['method']} {entry['path']} ({entry['count']})"
        )
    for entry in network["remote_misses"]:
        lines.append(f"  Remote miss {entry['upstream']} ({entry['count']})")
    for entry in network["writes"]:
        lines.append(
            f"  Write {entry['method']} {entry['path']} -> {entry['status']} "
            f"upload={entry['upload_filename'] or '-'} ({entry['count']})"
        )
    peer = network["peer"]
    lines.append(f"  Peer shown: {peer['shown']}")
    for entry in peer["replies"]:
        lines.append(f"  Peer reply {entry['folder']} ({entry['count']})")
    for category, count in sorted(network["truncated"].items()):
        lines.append(f"  Truncated {category}: {count} events omitted")
    return "\n".join(lines)


def main() -> None:
    """Read the requested logs and print plain text or JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--state", type=Path, help="matching private state.json; required for one raw log")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    try:
        items = reports(args.paths, args.state)
    except (OSError, RuntimeError, WorldStateError, WorldLogError, json.JSONDecodeError) as error:
        parser.error(str(error))
    if args.as_json:
        print(json.dumps(items, indent=2, sort_keys=True))
    else:
        print("\n\n".join(render(item) for item in items))


if __name__ == "__main__":
    main()
