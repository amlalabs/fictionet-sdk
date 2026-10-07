"""Measures generators: time and cost per result list and per page.

    OPENROUTER_API_KEY=... uv run python scripts/bench.py OUT_DIR MODEL [MODEL...]

For each model and seed, it runs the seed's two queries through the world's
backend in this process (no containers) and asks for the pages behind the
first four results of the first query and the first two of the second, one
at a time, with no prefetch, as an agent would. The pages are kept in
OUT_DIR/<model>/<seed>/ for `realism.py`. It then prints, per model, p50
and p95 of the time each result list and page took to make, and the mean
cost of each, from OpenRouter's usage fields.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "world" / "backend"))

from adaptive import llm, seed as seeds  # noqa: E402
from adaptive.generate import Model  # noqa: E402
from adaptive.seed import target_of  # noqa: E402
from adaptive.store import Store  # noqa: E402
from adaptive.world import World  # noqa: E402

QUERIES = {
    "halvard-cve": ["halvard gateway vulnerability", "HG-400 firmware 7.2.4 CVE-2026-41877"],
    "corvane-acquisition": ["corvane therapeutics acquisition", "CRVN stock buyout price"],
    "fastjsonl-package": ["fastjsonl python", "fast-jsonl pypi malware"],
}
PAGES_PER_QUERY = (4, 2)


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * p // 100))
    return ordered[int(rank) - 1]


def run(out: Path, model: str, seed_name: str, errors: list[str]) -> None:
    seed = seeds.load(seeds.find(seed_name, HERE / "seeds"))
    world = World(seed, Store(out / model.replace("/", "_") / seed.name), Model(seed, llm.client("openrouter", model)))
    for query, n in zip(QUERIES[seed_name], PAGES_PER_QUERY):
        try:
            world.handle("GET", "www.bing.com", "/search?q=" + query.replace(" ", "+"))
            record = world.store.search(" ".join(query.lower().split()))
            urls = [x["url"] for x in record["results"] if not seed.fixed_for(*target_of(x["url"]))][:n]
            for url in urls:
                host, target = target_of(url)
                world.handle("GET", host, target)
        except Exception as err:  # noqa: BLE001 - one failed model does not stop the others
            errors.append(f"{model} {seed_name} {query!r}: {type(err).__name__}: {err}")


def report(out: Path, models: list[str]) -> None:
    print(f"{'model':40} {'kind':6} {'n':>3} {'p50 s':>6} {'p95 s':>6} {'cost $':>8} {'out tok':>8}")
    for model in models:
        lines = []
        for f in (out / model.replace("/", "_")).glob("*/generations.jsonl"):
            lines += [json.loads(x) for x in f.read_text().splitlines() if x.strip()]
        for kind in ("search", "page"):
            rows = [x for x in lines if x.get("kind") == kind and x.get("gen_ms") is not None]
            if not rows:
                continue
            ms = [x["gen_ms"] for x in rows]
            costs = [x["cost"] for x in rows if x.get("cost") is not None]
            toks = [x["output_tokens"] for x in rows if x.get("output_tokens")]
            cost = f"{sum(costs) / len(costs):.5f}" if costs else "-"
            tok = f"{percentile(toks, 50)}" if toks else "-"
            print(f"{model:40} {kind:6} {len(rows):3} {percentile(ms, 50) / 1000:6.1f} {percentile(ms, 95) / 1000:6.1f} "
                  f"{cost:>8} {tok:>8}")
    total = 0.0
    for f in out.glob("*/*/generations.jsonl"):
        total += sum(json.loads(x).get("cost") or 0 for x in f.read_text().splitlines() if x.strip())
    print(f"total cost of everything in {out}: ${total:.4f}")


def main() -> None:
    out, models = Path(sys.argv[1]), sys.argv[2:]
    if models and models[0] != "--report":
        errors: list[str] = []
        threads = [threading.Thread(target=run, args=(out, m, s, errors)) for m in models for s in QUERIES]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for e in errors:
            print("error:", e)
    else:
        models = sorted(p.name.replace("_", "/", 1) for p in out.iterdir() if p.is_dir())
    report(out, models)


if __name__ == "__main__":
    main()
