"""The eval's view of the world: its state, its log, its store, and seeds.

The world exposes nothing to the agent but its websites and DNS. Everything
here uses the world's sandbox to read files or run commands in its container,
which the agent cannot reach.
"""
from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from inspect_fictionet import fictionet_sandbox

from inspect_fictionet._common.evidence import PAGE_METHODS, page_delivered
from inspect_fictionet._common import citations as _citations
from inspect_fictionet.worlds.adaptive_web import accounting as _accounting
SEEDS = Path(__file__).with_name("seeds")


def seed_names() -> list[str]:
    return sorted(p.stem for p in SEEDS.glob("*.md"))


def seed_front(name: str) -> dict[str, Any]:
    text = (SEEDS / f"{name}.md").read_text()
    return tomllib.loads(text.split("+++", 2)[1])


def world_sandbox(generator="stub", store_dir=None, model="", reasoning="", prefetch="",
                  seed="${SAMPLE_METADATA_SEED:-halvard-cve}"):
    network = "bridge" if generator in ("openrouter", "anthropic") else "none"
    mounts = {}
    if store_dir:
        path = Path(store_dir).resolve()
        path.mkdir(parents=True, exist_ok=True)
        mounts[str(path)] = "/var/lib/adaptive-web"
    return fictionet_sandbox(
        "fictionet-adaptive-web-world:dev",
        world_args=["adaptive-web-world", "--socket", "/run/relay/relay.sock",
                    "--seed", seed, "--generator", generator, "--model", model,
                    "--reasoning", reasoning, "--prefetch", str(prefetch)],
        world_env={key: "${" + key + ":-}" for key in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY")},
        world_network=network,
        world_mounts=mounts,
        world_ca="/app/ca/ca.pem",
        world_healthcheck=["test", "-f", "/run/fictionet/ready"],
        agent_image="fictionet-adaptive-web-agent:dev",
        attach_image="fictionet-adaptive-web-attach:dev",
    )


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


def summarize(log: list[dict[str, Any]], answer: str = "") -> dict[str, Any]:
    """The world's view of one sample, for the score's metadata."""
    http = [e for e in log if e.get("type") == "http"]
    evidence = []
    for e in http:
        if page_delivered(e):
            evidence.append(e)
        elif type(e.get("status")) is int and 300 <= e["status"] < 400:
            if e.get("answer") == "redirect":
                # httpd redirects plain HTTP to the same host and target over HTTPS.
                e = e | {"location": f"https://{e.get('host')}{e.get('path')}"}
            elif e.get("kind") != "redirect":
                continue
            evidence.append(e)
    fetched = _citations.delivered_resources(evidence, methods=PAGE_METHODS)
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
