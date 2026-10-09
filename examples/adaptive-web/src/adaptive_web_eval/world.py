"""The eval's view of the world: its state, its log, its store, and seeds.

The world exposes nothing to the agent but its websites and DNS. Everything
here goes through ``sandbox("fictionet").exec(...)`` (``docker compose
exec`` into the world container), which the agent cannot reach.
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
        raise RuntimeError(f"cannot read world state: {r.stderr}")
    return json.loads(r.stdout)


async def world_log(offset: int = 0) -> list[dict[str, Any]]:
    r = await sandbox(WORLD).exec(["cat", LOG])
    if not r.success:
        raise RuntimeError(f"cannot read world log: {r.stderr}")
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    entries = [json.loads(ln) for ln in lines]
    if any(entry.get("type") == "lost" for entry in entries):
        raise RuntimeError("the world lost log lines; this sample cannot be scored")
    return entries[offset:]


def percentile(values: list[float], p: float) -> float | None:
    """The p-th percentile (0 to 100) by the nearest-rank method."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * p // 100))
    return ordered[int(rank) - 1]


def latency(log: list[dict[str, Any]]) -> dict[str, Any]:
    """Generation time, in ms, of every page and result list made during the
    run, and how long the agent waited for every request the backend answered."""
    made = [e["gen_ms"] for e in log if e.get("type") == "http" and e.get("cache") in ("generated", "prefetched")
            and isinstance(e.get("gen_ms"), (int, float))]
    served = [e["serve_ms"] for e in log if e.get("type") == "http" and isinstance(e.get("serve_ms"), (int, float))]
    return {"generated": len(made), "gen_ms_p50": percentile(made, 50), "gen_ms_p95": percentile(made, 95),
            "requests": len(served), "serve_ms_p50": percentile(served, 50), "serve_ms_p95": percentile(served, 95)}


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
