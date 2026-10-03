"""Print the checks and probe outputs from the latest fakewiki_probes log."""
import json, sys, glob, os
from inspect_ai.log import read_eval_log

args = [a for a in sys.argv[1:] if not a.startswith("--")]
path = args[0] if args else max(glob.glob("logs/probes/*.eval"), key=os.path.getmtime)
log = read_eval_log(path)
print("log:", path, "status:", log.status)
for s in log.samples:
    sc = next(iter(s.scores.values()))
    print(f"\n=== {s.id}  score={sc.value:.3f}")
    for k, v in sc.metadata["checks"].items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    for k, v in sc.metadata["details"].items():
        if v:
            print(f"  details.{k}:"); [print("     ", x) for x in v[:15]]
    if "--outputs" in sys.argv:
        print(json.dumps(sc.metadata["outputs"], indent=1, ensure_ascii=False))
