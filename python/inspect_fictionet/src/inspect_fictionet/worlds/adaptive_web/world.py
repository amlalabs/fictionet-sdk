"""The eval's view of the world: its state, its log, its store, and seeds.

The world exposes nothing to the agent but its websites and DNS. Everything
here uses the world's sandbox to read files or run commands in its container,
which the agent cannot reach.
"""
from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from inspect_ai.util import sandbox
from inspect_fictionet import fictionet_sandbox

from inspect_fictionet._common.world_io import WorldFiles
from inspect_fictionet._common import evidence as _evidence
from inspect_fictionet._common import citations as _citations
from adaptive import accounting as _accounting
_METHODS = ("GET", "POST")
SEEDS = Path(__file__).with_name("seeds")

WORLD = "world"
LOG = "/var/lib/fictionet/log.jsonl"
STATE = "/var/lib/fictionet/state.json"


def seed_names() -> list[str]:
    return sorted(p.stem for p in SEEDS.glob("*.md"))


def seed_front(name: str) -> dict[str, Any]:
    text = (SEEDS / f"{name}.md").read_text()
    return tomllib.loads(text.split("+++", 2)[1])


def world_sandbox():
    generator = os.environ.get("ADAPTIVE_WEB_GENERATOR", "stub")
    network = "bridge" if generator in ("openrouter", "anthropic") else "none"
    store_dir = os.environ.get("ADAPTIVE_WEB_STORE_DIR")
    mounts = {}
    if store_dir:
        path = Path(store_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        mounts[str(path)] = "/var/lib/adaptive-web"
    return fictionet_sandbox(
        "fictionet-adaptive-web-world:dev",
        world_args=["adaptive-web-world", "--socket", "/run/relay/relay.sock"],
        world_env={
            "ADAPTIVE_WEB_SEED": "${SAMPLE_METADATA_SEED:-${ADAPTIVE_WEB_SEED:-halvard-cve}}",
            "ADAPTIVE_WEB_GENERATOR": generator,
            **{key: "${" + key + ":-}" for key in (
                "ADAPTIVE_WEB_MODEL", "ADAPTIVE_WEB_PREFETCH", "ADAPTIVE_WEB_REASONING",
                "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY",
            )},
        },
        world_network=os.environ.get("ADAPTIVE_WEB_NETWORK", network),
        world_mounts=mounts,
        world_ca="/app/ca/ca.pem",
        world_healthcheck=["test", "-f", "/run/fictionet/ready"],
        agent_image="fictionet-adaptive-web-agent:dev",
        attach_image="fictionet-adaptive-web-attach:dev",
    )


async def world_state() -> dict[str, Any]:
    return await WorldFiles(sandbox(WORLD), state=STATE, log=LOG).state()


async def world_log(offset: int = 0, *, finalize: bool = True) -> list[dict[str, Any]]:
    """Finalize the world, then read its log with read_file because Inspect cuts
    command output to its last 10 MiB without an error. Check completeness before
    applying the line offset. Set finalize=False only for a preflight read.
    """
    files = WorldFiles(sandbox(WORLD), sandbox() if finalize else None, state=STATE, log=LOG)
    return await files.log_lines(offset, finalize=finalize)


def sorted_percentile(values: list[float], p: float) -> float | None:
    """The p-th percentile (0 to 100) of sorted values by nearest rank."""
    return _accounting.percentile(values, p)


def latency(log: list[dict[str, Any]]) -> dict[str, Any]:
    """Count every HTTP event, including failures and requests without timing.

    Serving percentiles cover `timed` requests. Generation percentiles cover
    `generated` measured totals carried by HTTP responses, including failures.
    Casts and prefetches not represented in responses require generations.jsonl.
    """
    http = [e for e in log if e.get("type") == "http"]
    made = [e for e in http if e.get("cache") in ("generated", "prefetched")
            or e.get("kind") == "error" and "gen_ms" in e]
    gen = _accounting.population(made, "gen_ms")
    served = _accounting.population(http, "serve_ms")
    return {"generated": gen["timed"], "generation_untimed": gen["untimed"], "generation_failed": gen["failed"],
            "gen_ms_p50": gen["p50"], "gen_ms_p95": gen["p95"],
            "requests": served["count"], "timed": served["timed"], "untimed": served["untimed"], "failed": served["failed"],
            "serve_ms_p50": served["p50"], "serve_ms_p95": served["p95"]}


def delivered(e: dict[str, Any]) -> bool:
    """Credit only completed page bodies with known, matching byte counts."""
    evidence = _evidence.delivered(e, _METHODS, 0, length_field="bytes")
    return isinstance(evidence, _evidence.Known) and bool(evidence)


def summarize(log: list[dict[str, Any]], answer: str = "") -> dict[str, Any]:
    """The world's view of one sample, for the score's metadata."""
    http = [e for e in log if e.get("type") == "http"]
    evidence = []
    for e in http:
        if delivered(e):
            evidence.append(e)
        elif type(e.get("status")) is int and 300 <= e["status"] < 400:
            if e.get("answer") == "redirect":
                # httpd redirects plain HTTP to the same host and target over HTTPS.
                e = e | {"location": f"https://{e.get('host')}{e.get('path')}"}
            elif e.get("kind") != "redirect":
                continue
            evidence.append(e)
    fetched = _citations.delivered_resources(evidence, methods=_METHODS)
    citations = dict(_citations.extract_citations(answer))
    cited = sorted(citations)
    not_fetched = [u for u in cited if citations[u] not in fetched]
    return {
        "searches": [f"{e.get('engine')}: {e.get('search')} ({e.get('cache')})" for e in http if e.get("kind") == "search"],
        "pages": [f"{e.get('scheme')}://{e.get('host')}{e.get('path')} -> {e.get('status')} ({e.get('cache')})"
                  for e in http if e.get("kind") == "page"],
        "hosts_made": [e["host"] for e in log if e.get("type") == "site" and e.get("why") == "pool"],
        "names_refused": [f"{e['host']}: {e['why']}" for e in log if e.get("type") == "refused"],
        "tls_errors": [e for e in log if e.get("type") in ("tls_error", "tls_reject")],
        "unsupported_snippets": [s for e in http for s in e.get("unsupported_snippets") or []],
        "unchecked_snippets": [s for e in http for s in e.get("unchecked_snippets") or []],
        "cited_urls": cited,
        "cited_but_never_fetched": not_fetched,
        "latency": latency(log),
    }
