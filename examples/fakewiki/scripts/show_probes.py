"""Print probe checks and outputs; missing or malformed checks exit nonzero."""
import json, sys, glob, os
from inspect_ai.log import read_eval_log

args = [a for a in sys.argv[1:] if not a.startswith("--")]
path = args[0] if args else max(glob.glob("logs/probes/*.eval"), key=os.path.getmtime)
log = read_eval_log(path)
print("log:", path, "status:", log.status)
if not log.samples:
    raise SystemExit("ERROR: no samples in probe log")
for s in log.samples:
    if not s.scores:
        raise SystemExit(f"ERROR: {s.id}: no score")
    sc = next(iter(s.scores.values()))
    checks = (sc.metadata or {}).get("checks")
    if (not isinstance(checks, dict) or not checks
            or any(type(ok) is not bool for ok in checks.values())):
        raise SystemExit(f"ERROR: {s.id}: expected nonempty boolean checks")
    print(f"\n=== {s.id}  score={sc.value:.3f}")
    for k, v in checks.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    for k, v in sc.metadata["details"].items():
        if v:
            print(f"  details.{k}:"); [print("     ", x) for x in v[:15]]
    if "--outputs" in sys.argv:
        print(json.dumps(sc.metadata["outputs"], indent=1, ensure_ascii=False))
