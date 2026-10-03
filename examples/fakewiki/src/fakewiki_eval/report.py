"""Metrics table from FakeWiki eval logs: model x variant (and optionally x topic).

    uv run python -m fakewiki_eval.report logs/run1 [--by-topic] [--markdown]
"""
from __future__ import annotations

import glob
import os
import sys
from collections import defaultdict

from inspect_ai.log import read_eval_log


def rate(xs: list[float]) -> str:
    return f"{sum(xs) / len(xs):.2f}" if xs else "-"


def main(argv: list[str]) -> None:
    by_topic = "--by-topic" in argv
    paths = [a for a in argv if not a.startswith("--")] or ["logs"]
    files = sorted({f for p in paths for f in (glob.glob(os.path.join(p, "**", "*.eval"), recursive=True)
                                               if os.path.isdir(p) else [p])})
    rows: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    usage: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in files:
        log = read_eval_log(f)
        if log.eval.task not in ("fakewiki",) or not log.samples:
            continue
        model = log.eval.model
        grader = str((log.eval.task_args or {}).get("grader_model", "ollama/gpt-oss:20b"))
        for m, u in (log.stats.model_usage or {}).items():
            # A model can be both subject and grader; model_usage cannot split those, so label it.
            role = "subject" if m == model and m != grader else ("grader" if m == grader and m != model else "subject+grader")
            m = (m, role)
            usage[m]["input"] += u.input_tokens
            usage[m]["output"] += u.output_tokens
            usage[m]["total"] += u.total_tokens
            usage[m]["reasoning"] += u.reasoning_tokens or 0
        for s in log.samples:
            md = s.metadata
            key = (model, md["variant"]) + ((md["topic"],) if by_topic else ())
            r = rows[key]
            if s.error or not s.scores:
                r["errors"].append(1)
                continue
            sc = next(iter(s.scores.values()))
            meta = sc.metadata or {}
            r["n"].append(1)
            r["fooled"].append(sc.value["fooled"])
            r["detected"].append(sc.value["detected"])
            r["correct"].append(sc.value["correct"])
            r["reached_altered"].append(int(meta.get("reached_altered_page", False)))
            saw = int(meta.get("saw_planted_text", False))
            r["saw_planted"].append(saw)
            if saw:
                r["fooled_given_saw"].append(sc.value["fooled"])
            r["no_answer"].append(int(not (sc.answer or "").strip() or s.limit is not None))
            r["cross_checked"].append(int(meta.get("cross_checked_second_host", False)))
            r["cited_unfetched"].append(int(bool(meta.get("cited_but_never_fetched"))))
            r["outside"].append(len(meta.get("outside_world_requests", [])))
            r["grader_failed"].append(int(bool(meta.get("grader_failed"))))
    head = ["model", "variant"] + (["topic"] if by_topic else []) + [
        "n", "fooled", "detected", "correct", "no_answer", "reached_altered", "saw_planted", "fooled|saw", "cross_checked", "cited_unfetched",
        "outside_reqs", "grader_fail", "errors"]
    out = [head]
    for key in sorted(rows):
        r = rows[key]
        out.append(list(key) + [str(len(r["n"])), rate(r["fooled"]), rate(r["detected"]), rate(r["correct"]),
                                rate(r["no_answer"]), rate(r["reached_altered"]), rate(r["saw_planted"]),
                                rate(r["fooled_given_saw"]), rate(r["cross_checked"]), rate(r["cited_unfetched"]),
                                str(sum(r["outside"])), str(sum(r["grader_failed"])), str(len(r["errors"]))])
    if "--markdown" in argv:
        print("| " + " | ".join(head) + " |")
        print("|" + "---|" * len(head))
        for row in out[1:]:
            print("| " + " | ".join(row) + " |")
    else:
        widths = [max(len(row[i]) for row in out) for i in range(len(head))]
        for row in out:
            print("  ".join(c.ljust(w) for c, w in zip(row, widths)))
    print("\ncontrol accuracy = 'correct' on the control rows. fooled|saw = fooled rate among samples whose tool"
          "\noutputs contained planted text. no_answer = empty answer or message limit hit.")
    print("\ntoken usage (all logs, includes grader calls):")
    for (m, role), u in sorted(usage.items()):
        print(f"  {m} [{role}]: total={u['total']:,} input={u['input']:,} output={u['output']:,} reasoning={u['reasoning']:,}")


if __name__ == "__main__":
    main(sys.argv[1:])
