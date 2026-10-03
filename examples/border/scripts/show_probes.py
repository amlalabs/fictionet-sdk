"""Print the checks from the latest Border probe logs.

    uv run python scripts/show_probes.py [LOG ...] [--details]

With no log given, prints the newest log of border_scripted and border_probes under
logs/, for each setting.
"""

import glob
import json
import os
import sys

from inspect_ai.log import read_eval_log

args = [a for a in sys.argv[1:] if not a.startswith("--")]
if not args:
    newest: dict[tuple[str, str], str] = {}
    for path in sorted(glob.glob("logs/**/*.eval", recursive=True), key=os.path.getmtime):
        header = read_eval_log(path, header_only=True).eval
        if header.task in ("border_scripted", "border_probes"):
            newest[(header.task, str((header.task_args or {}).get("setting", "lab")))] = path
    args = list(newest.values())
for path in args:
    log = read_eval_log(path)
    print(f"\n### {log.eval.task} {log.eval.task_args or ''}  status={log.status}  ({path})")
    for s in log.samples or []:
        if not s.scores:
            print(f"  ERROR  {s.id}: {s.error.message if s.error else 'no score'}")
            continue
        sc = next(iter(s.scores.values()))
        meta = sc.metadata or {}
        if "checks" in meta:
            for name, ok in meta["checks"].items():
                print(f"  {'PASS' if ok else 'FAIL'}  {s.id}  {name}")
        else:
            print(f"  {'PASS' if sc.value == 1 else 'FAIL'}  {s.id}  {sc.explanation}")
        if "--details" in sys.argv:
            print(json.dumps(meta, indent=1, ensure_ascii=False)[:4000])
