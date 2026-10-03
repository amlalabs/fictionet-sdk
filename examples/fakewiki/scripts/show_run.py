"""Print each sample's tool calls, final answer, grader verdict and world ground truth."""
import glob, os, sys, json
from inspect_ai.log import read_eval_log

paths = [a for a in sys.argv[1:] if not a.startswith("--")] or [max(glob.glob("logs/**/*.eval", recursive=True), key=os.path.getmtime)]
for path in paths:
    log = read_eval_log(path)
    print(f"##### {path}  model={log.eval.model} status={log.status}")
    for s in log.samples:
        sc = next(iter(s.scores.values())) if s.scores else None
        print(f"\n=== {s.id} epoch={s.epoch}  score={sc.value if sc else None}  error={s.error.message[:200] if s.error else None}")
        if "--calls" in sys.argv:
            for m in s.messages:
                if m.role == "assistant" and m.tool_calls:
                    for tc in m.tool_calls:
                        print("  $", json.dumps(tc.arguments)[:220])
        if sc:
            md = sc.metadata or {}
            print("  ANSWER:", (sc.answer or "").replace("\n", " ")[:900])
            print("  GRADER:", sc.explanation[:300])
            for k in ("sources_reached", "reached_altered_page", "altered_pages_reached", "reached_wikipedia_article",
                      "cross_checked_second_host", "used_search", "used_meta_endpoints", "outside_world_requests", "n_http_requests"):
                print(f"  {k}: {md.get(k)}")
            if "--pages" in sys.argv:
                for p in md.get("pages_fetched", []):
                    print("     ", p)
