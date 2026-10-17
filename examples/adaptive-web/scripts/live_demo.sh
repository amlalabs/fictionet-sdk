#!/usr/bin/env bash
# A few searches and the pages behind their first results, through a world
# that makes them with the model, then the generation times.
#
#   OPENROUTER_API_KEY=... scripts/live_demo.sh [SEED] [QUERY...]
#
# The pages are kept in ./store (or ADAPTIVE_WEB_STORE_DIR), so a second run
# with ADAPTIVE_WEB_GENERATOR=replay serves the same pages with no model.
set -euo pipefail
cd "$(dirname "$0")/.."
seed=${1:-halvard-cve}
if (( $# )); then shift; fi
if (( $# == 0 )); then
  query=$(python3 - "$seed" <<'PYSEED'
import pathlib, sys, tomllib
seed = tomllib.loads((pathlib.Path("seeds") / (sys.argv[1] + ".md")).read_text().split("+++", 2)[1])
print(seed["question"])
PYSEED
  )
  set -- "$query"
fi
generator=${ADAPTIVE_WEB_GENERATOR:-openrouter}
if [ "$generator" = openrouter ] && [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY is not set" >&2
  exit 2
fi
store=${ADAPTIVE_WEB_STORE_DIR:-$PWD/store}
mkdir -p "$store"
export ADAPTIVE_WEB_SEED=$seed ADAPTIVE_WEB_GENERATOR=$generator ADAPTIVE_WEB_STORE_DIR=$store
case $generator in openrouter|anthropic) network=bridge ;; *) network=none ;; esac
export ADAPTIVE_WEB_NETWORK=${ADAPTIVE_WEB_NETWORK:-$network}
project=adaptive-web-demo
trap 'docker compose -p "$project" down -v -t 1' EXIT
# Build images from this checkout every time so they stay current and are not pulled.
docker compose -p "$project" up -d --wait --quiet-pull --build

docker compose -p $project exec -T default python3 - "$@" <<'PY'
import html, re, subprocess, sys, urllib.parse
queries = sys.argv[1:]

def curl(url):
    r = subprocess.run(["curl", "-f", "-sS", "-m", "180", "-w", "\n%{http_code} %{time_total}", url], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(f"curl failed for {url}: {r.stderr.strip()} (exit {r.returncode})")
    body, _, tail = r.stdout.rpartition("\n")
    code, secs = (tail.split() + ["", "0"])[:2]
    return body, code, float(secs)

for q in queries:
    body, code, secs = curl("https://www.google.com/search?q=" + urllib.parse.quote_plus(q))
    print(f"\n=== google: {q}  ({code}, {secs:.1f} s)")
    found = re.findall(r'<div class="yuRUbf"><a href="([^"]+)"><h3>(.*?)</h3>.*?<div class="VwiC3b">(.*?)</div>', body, re.S)
    if len(found) != 10:
        raise RuntimeError(f"search returned {len(found)} results; expected 10")
    for url, title, snippet in found:
        print(f"- {html.unescape(title)}\n  {html.unescape(url)}\n  {html.unescape(re.sub('<[^>]+>', '', snippet))[:200]}")
    for url, title, _ in found[:3]:
        page, code, secs = curl(html.unescape(url))
        text = " ".join(html.unescape(re.sub(r"(?s)<(script|style).*?</\1>|<[^>]+>", " ", page)).split())
        print(f"\n--- {html.unescape(url)}  ({code}, {secs:.1f} s, {len(page)} bytes)\n{text[:700]}")
PY
echo
printf '%s\n' "World request log:"
docker compose -p "$project" exec -T fictionet cat /var/lib/fictionet/log.jsonl
uv run --quiet python scripts/latency.py "$store" "$seed"
