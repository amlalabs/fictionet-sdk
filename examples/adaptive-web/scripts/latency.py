"""Generation times from a store: p50 and p95 for result lists and pages.

    uv run python scripts/latency.py STORE_DIR [SEED]

STORE_DIR is the directory given as ADAPTIVE_WEB_STORE_DIR. Each seed has
its own directory under it with a generations.jsonl, one line per model
(or stub) call, with the time it took, the tokens it used and its cost when
the API reports one.
"""
import json
import sys
from pathlib import Path


def percentile(values, p):
    ordered = sorted(values)
    rank = max(1, -(-len(ordered) * p // 100))
    return ordered[int(rank) - 1]


root = Path(sys.argv[1])
dirs = [root / sys.argv[2]] if len(sys.argv) > 2 else sorted(p for p in root.iterdir() if (p / "generations.jsonl").is_file())
for d in dirs:
    lines = [json.loads(x) for x in (d / "generations.jsonl").read_text().splitlines() if x.strip()]
    print(f"{d.name}:")
    for kind in ("search", "page"):
        ms = [x["gen_ms"] for x in lines if x.get("kind") == kind and isinstance(x.get("gen_ms"), (int, float))]
        if not ms:
            continue
        out_tokens = [x["output_tokens"] for x in lines if x.get("kind") == kind and x.get("output_tokens")]
        costs = [x["cost"] for x in lines if x.get("kind") == kind and x.get("cost") is not None]
        tokens = f", output tokens p50 {percentile(out_tokens, 50)}" if out_tokens else ""
        cost = f", ${sum(costs):.4f} in all" if costs else ""
        print(f"  {kind:6} n={len(ms):3}  p50 {percentile(ms, 50):6} ms  p95 {percentile(ms, 95):6} ms  max {max(ms):6} ms{tokens}{cost}")
    errors = [x for x in lines if x.get("kind") == "prefetch_error"]
    if errors:
        print(f"  prefetch errors: {len(errors)}")
