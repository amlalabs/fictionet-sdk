"""Negative control for the leak checker: feed it the CONTROL world's real responses
while claiming the variant is altered_all / altered_one. It must report leaks;
if it reported none, a passing leak test would mean nothing."""
import glob
import os
import sys
from inspect_ai.log import read_eval_log
from fakewiki_eval.probes import find_leaks, leak_targets, markers


def check(samples) -> list[str]:
    """Require complete control responses, no control leaks, and leaks under both altered labels."""
    failures = []
    controls = [s for s in samples if s.id == "probes__control"]
    if not controls:
        return ["no probes__control sample"]
    mk = markers()
    wanted = {t.url for group in leak_targets().values() for t in group}
    for sample in controls:
        try:
            leak = sample.store["outputs"]["leak"]
            if set(leak) != wanted:
                failures.append("control response inventory is incomplete or unexpected")
            for claimed in ("control", "altered_one", "altered_all"):
                leaks, missing = find_leaks(claimed, leak, mk)
                print(f"control responses judged as {claimed:12s}: {len(leaks):3d} leak(s)", (leaks[:2] if leaks else ""))
                if claimed == "control":
                    if leaks:
                        failures.append("control responses contain leaks")
                    if missing:
                        failures.append("control responses failed or lack expected text: " + ", ".join(missing))
                elif not leaks:
                    failures.append(f"{claimed} label returned zero leaks")
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            failures.append(f"invalid control evidence: {error}")
    return failures


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else max(glob.glob("logs/probes/*.eval"), key=os.path.getmtime)
    log = read_eval_log(path)
    failures = check(log.samples or [])
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
