"""Negative control for the leak checker: feed it the CONTROL world's real responses
while claiming the variant is altered_all / altered_one. It must report leaks;
if it reported none, a passing leak test would mean nothing."""
import glob, os, sys
from inspect_ai.log import read_eval_log
from fakewiki_eval.probes import find_leaks, markers, run_probes  # noqa

path = sys.argv[1] if len(sys.argv) > 1 else max(glob.glob("logs/probes/*.eval"), key=os.path.getmtime)
log = read_eval_log(path)
mk = markers()
for s in log.samples:
    if s.id != "probes__control":
        continue
    leak = s.store["outputs"]["leak"]
    for claimed in ("control", "altered_one", "altered_all"):
        leaks, _ = find_leaks(claimed, leak, mk)
        print(f"control responses judged as {claimed:12s}: {len(leaks):3d} leak(s)", (leaks[:2] if leaks else ""))
