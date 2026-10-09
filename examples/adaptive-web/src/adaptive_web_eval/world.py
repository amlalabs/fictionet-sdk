"""The eval's view of the world: its state, its log, its store, and seeds.

The world exposes nothing to the agent but its websites and DNS. Everything
here uses the world's sandbox to read files or run commands in its container,
which the agent cannot reach.
"""
from __future__ import annotations

import json
import re
import tomllib
import urllib.parse
from pathlib import Path
from typing import Any

from inspect_ai.util import sandbox

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = str(ROOT / "compose.yaml")
SEEDS = ROOT / "seeds"

WORLD = "fictionet"
LOG = "/var/lib/fictionet/log.jsonl"
STATE = "/var/lib/fictionet/state.json"


def seed_names() -> list[str]:
    return sorted(p.stem for p in SEEDS.glob("*.md"))


def seed_front(name: str) -> dict[str, Any]:
    text = (SEEDS / f"{name}.md").read_text()
    return tomllib.loads(text.split("+++", 2)[1])


async def world_state() -> dict[str, Any]:
    r = await sandbox(WORLD).exec(["cat", STATE])
    if not r.success:
        msg = f"cannot read world state: {r.stderr}"
        raise RuntimeError(msg)
    return json.loads(r.stdout)


async def world_log(offset: int = 0) -> list[dict[str, Any]]:
    """Copy the log and use read_file because Inspect cuts command output to its last
    10 MiB without an error. Check completeness before applying the line offset.
    """
    snapshot = LOG + ".snapshot"
    r = await sandbox(WORLD).exec(
        ["sh", "-c", 'cp "$1" "$2" && wc -c < "$2"', "copy", LOG, snapshot]
    )
    if not r.success:
        msg = f"cannot read world log: {r.stderr}"
        raise RuntimeError(msg)
    want = int(r.stdout)
    data = await sandbox(WORLD).read_file(snapshot, text=False)
    if len(data) != want or (data and not data.endswith(b"\n")):
        msg = f"read {len(data)} of the log's {want} bytes; this sample cannot be scored"
        raise RuntimeError(msg)
    lines = [ln for ln in data.decode().splitlines() if ln.strip()]
    entries = [json.loads(ln) for ln in lines]
    if any(entry.get("type") == "lost" for entry in entries):
        msg = "the world lost log lines; this sample cannot be scored"
        raise RuntimeError(msg)
    return entries[offset:]


def sorted_percentile(values: list[float], p: float) -> float | None:
    """The p-th percentile (0 to 100) of sorted values by nearest rank."""
    if not values:
        return None
    rank = max(1, -(-len(values) * p // 100))
    return values[int(rank) - 1]


def latency(log: list[dict[str, Any]]) -> dict[str, Any]:
    """Generation time, in ms, of every page and result list made during the
    run, and how long the agent waited for every request the backend answered."""
    made = [e["gen_ms"] for e in log if e.get("type") == "http" and e.get("cache") in ("generated", "prefetched")
            and isinstance(e.get("gen_ms"), (int, float))]
    served = [e["serve_ms"] for e in log if e.get("type") == "http" and isinstance(e.get("serve_ms"), (int, float))]
    made.sort()
    served.sort()
    return {"generated": len(made), "gen_ms_p50": sorted_percentile(made, 50), "gen_ms_p95": sorted_percentile(made, 95),
            "requests": len(served), "serve_ms_p50": sorted_percentile(served, 50), "serve_ms_p95": sorted_percentile(served, 95)}


def summarize(log: list[dict[str, Any]], answer: str = "") -> dict[str, Any]:
    """The world's view of one sample, for the score's metadata."""
    http = [e for e in log if e.get("type") == "http"]
    fetched = {(e.get("host"), (e.get("path") or "").split("?")[0].rstrip("/")) for e in http if e.get("status") == 200}
    cited = sorted({u.rstrip(".;:") for u in re.findall(r"https?://[^\s)\]>\"'`*,]+", answer)})
    not_fetched = [u for u in cited
                   if ((urllib.parse.urlsplit(u).hostname or ""), urllib.parse.urlsplit(u).path.rstrip("/")) not in fetched]
    return {
        "searches": [f"{e.get('engine')}: {e.get('search')} ({e.get('cache')})" for e in http if e.get("kind") == "search"],
        "pages": [f"{e.get('scheme')}://{e.get('host')}{e.get('path')} -> {e.get('status')} ({e.get('cache')})"
                  for e in http if e.get("kind") == "page"],
        "hosts_made": [e["host"] for e in log if e.get("type") == "site" and e.get("why") == "pool"],
        "names_refused": [f"{e['host']}: {e['why']}" for e in log if e.get("type") == "refused"],
        "tls_errors": [e for e in log if e.get("type") in ("tls_error", "tls_reject")],
        "unsupported_snippets": [s for e in http for s in e.get("unsupported_snippets") or []],
        "cited_urls": cited,
        "cited_but_never_fetched": not_fetched,
        "latency": latency(log),
    }
