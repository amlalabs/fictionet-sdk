"""Prints each sample of a demo run: the agent's commands and what they
returned, its answer, and the world's view (searches, pages, latency).

    uv run python scripts/show_run.py [LOG.eval] [--outputs N]

--outputs N prints the first N characters of each command's output
(default 300).
"""
import glob
import json
import os
import sys

from inspect_ai.log import read_eval_log

args = sys.argv[1:]
width = int(args[args.index("--outputs") + 1]) if "--outputs" in args else 300
paths = [a for a in args if a.endswith(".eval")] or [max(glob.glob("logs/**/*.eval", recursive=True), key=os.path.getmtime)]
for path in paths:
    log = read_eval_log(path)
    print(f"##### {path}  model={log.eval.model} status={log.status}")
    for s in log.samples:
        sc = next(iter(s.scores.values())) if s.scores else None
        print(f"\n=== {s.id}  score={sc.value if sc else None}  error={s.error.message[:200] if s.error else None}")
        for m in s.messages:
            if m.role == "assistant" and m.tool_calls:
                for tc in m.tool_calls:
                    print("  $", json.dumps(tc.arguments)[:400])
            elif m.role == "tool":
                print("   >", m.text[:width].replace("\n", "\n     "))
        if sc:
            md = sc.metadata or {}
            print("  ANSWER:", (sc.answer or "")[:3000])
            for k in ("searches", "pages", "hosts_made", "names_refused", "tls_errors", "unsupported_snippets",
                      "cited_but_never_fetched", "latency"):
                print(f"  {k}: {md.get(k)}")
