"""Generation times from a store: p50 and p95 for result lists and pages.

    uv run python scripts/latency.py STORE_DIR [SEED]

STORE_DIR is the directory given as ADAPTIVE_WEB_STORE_DIR. Each seed has
its own directory under it with a generations.jsonl. Model attempt rows
include failures; terminal rows hold total generation time and usage.
Reports state measured populations and unknown costs. Individual call times
remain in attempt rows as `ms`; generation times include backoff and re-asks.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE / "world" / "backend"))

from adaptive.accounting import cost_report, generation_report  # noqa: E402


def main() -> None:
    root = Path(sys.argv[1])
    dirs = ([root / sys.argv[2]] if len(sys.argv) > 2 else
            sorted(p for p in root.iterdir() if (p / "generations.jsonl").is_file()))
    for d in dirs:
        lines = [json.loads(x) for x in (d / "generations.jsonl").read_text().splitlines() if x.strip()]
        print(f"{d.name}:")
        for line in generation_report(lines):
            print(f"  {line}")
        print(f"  recorded cost: {cost_report(lines)}")


if __name__ == "__main__":
    main()
