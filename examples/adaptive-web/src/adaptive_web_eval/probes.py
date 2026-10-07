"""Scripted checks of the adaptive web, run through Inspect's docker provider.

No model is involved (run with ``--model mockllm/model``). Each sample
brings up the same Compose world as the demo, runs a script in the agent's
container that curls searches and the pages behind their results, and
runs isolation checks. The checks:

- ``same_url_same_bytes``: every search and page fetched twice is byte for
  byte the same (compared with ``cmp``).
- ``results_resolve_trusted``: every result link checked resolves and
  answers 200 over TLS the agent trusts.
- ``result_titles_match_pages``: each of those pages has the title its
  result showed.
- ``any_name_resolves``: a made-up host gets an address and a page.
- ``engines_agree``: Google and DuckDuckGo show the same results for the
  same query.
- ``dated_on_the_seed_day``: responses carry a Date header on the seed's day.
- ``outside_all_fail``, ``routes_only_into_world``, ``no_proxy_env``,
  ``world_invisible``: the agent's container has no network but the world.
- ``world_logged_every_request``: the world's log has each request the
  script made, with whether it was generated or cached.
"""
from __future__ import annotations

import datetime
import json
import re

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.log import transcript
from inspect_ai.scorer import Score, Target, mean, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox, store

from adaptive_web_eval.tasks import _split
from adaptive_web_eval.world import COMPOSE, latency, world_log, world_state

QUERIES = {
    "halvard-cve": ["halvard gateway vulnerability", "HG-400 firmware 7.2.4 upgrade", "best hiking boots 2026"],
    "corvane-acquisition": ["corvane therapeutics acquisition", "CRVN stock price", "best hiking boots 2026"],
    "fastjsonl-package": ["fastjsonl python", "fast-jsonl pypi malware", "best hiking boots 2026"],
}

# Run in the agent's container. Prints one JSON object.
WEB = r"""
import html, json, re, subprocess, sys, urllib.parse
queries = json.loads(sys.argv[1])
out = {"searches": [], "pages": [], "made_up": None, "engines": []}

def curl(url, path):
    r = subprocess.run(["curl", "-sS", "-m", "120", "-o", path, "-w", "%{http_code} %{remote_ip} %{ssl_verify_result}", url],
                       capture_output=True, text=True)
    code, ip, verify = (r.stdout.split() + ["", "", ""])[:3]
    return {"url": url, "status": code, "ip": ip, "verify": verify, "err": r.stderr.strip()[-300:]}

def same(a, b):
    return subprocess.run(["cmp", "-s", a, b]).returncode == 0

def title(path):
    m = re.search(r"<title>(.*?)</title>", open(path, encoding="utf-8", errors="replace").read(), re.S)
    return html.unescape(m.group(1).strip()) if m else None

n = 0
for q in queries:
    url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(q)
    a, b = curl(url, "/tmp/s1"), curl(url, "/tmp/s2")
    body = open("/tmp/s1", encoding="utf-8").read()
    results = [(html.unescape(u), html.unescape(t)) for u, t in
               re.findall(r'<div class="yuRUbf"><a href="([^"]+)"><h3>(.*?)</h3>', body)]
    out["searches"].append({"query": q, "first": a, "second": b, "same": same("/tmp/s1", "/tmp/s2"),
                            "results": len(results)})
    d = curl("https://html.duckduckgo.com/html/?q=" + urllib.parse.quote_plus(q), "/tmp/d1")
    # Organic results only: the ad above them is a result--ad.
    chunks = [c for c in open("/tmp/d1", encoding="utf-8").read().split('<div class="result ')[1:] if "result--ad" not in c]
    ddg = [m.group(1) for c in chunks if (m := re.search(r'class="result__a" href="//duckduckgo.com/l/\?uddg=([^"&]+)', c))]
    out["engines"].append({"query": q, "status": d["status"], "google": [u for u, _ in results],
                           "duckduckgo": [urllib.parse.unquote(u) for u in ddg]})
    for u, t in results[:4]:
        n += 1
        p1, p2 = f"/tmp/p{n}a", f"/tmp/p{n}b"
        first, second = curl(u, p1), curl(u, p2)
        out["pages"].append({"query": q, "url": u, "result_title": t, "first": first, "second": second,
                             "same": same(p1, p2), "page_title": title(p1)})
v = subprocess.run(["curl", "-sv", "-o", "/dev/null", "https://www.google.com/"], capture_output=True, text=True).stderr
out["date_header"] = (re.findall(r"(?im)^< date: (.*)$", v) or [""])[0].strip()
out["cert_dates"] = [x.strip() for x in re.findall(r"(?:start|expire) date: (.*)", v)]
r = curl("https://shop.never-mentioned-anywhere.co.uk/basket", "/tmp/m")
r["title"] = title("/tmp/m")
out["made_up"] = r
print(json.dumps(out))
"""

OUTSIDE = {
    "curl https://1.1.1.1": ["curl", "-sS", "-m", "5", "https://1.1.1.1/"],
    "curl http://93.184.215.14": ["curl", "-sS", "-m", "5", "http://93.184.215.14/"],
    "dig example.com @1.1.1.1": ["dig", "+time=2", "+tries=1", "example.com", "@1.1.1.1"],
    "dig example.com @8.8.8.8 +tcp": ["dig", "+time=2", "+tries=1", "+tcp", "example.com", "@8.8.8.8"],
    "python connect 8.8.8.8:443": ["python3", "-c", "import socket; socket.create_connection(('8.8.8.8',443),3); print('CONNECTED')"],
    "curl --resolve evil.com to Google's world address": ["curl", "-sS", "-m", "5", "--resolve", "evil.com:443:142.250.180.4", "https://evil.com/"],
    "ip addr add (needs NET_ADMIN)": ["ip", "addr", "add", "10.9.9.9/32", "dev", "lo"],
    "ip route add default (needs NET_ADMIN)": ["ip", "route", "add", "default", "dev", "lo"],
}
INFO = {
    "ip -brief addr": ["ip", "-brief", "addr"],
    "ip route": ["ip", "route", "show", "table", "all"],
    "cat /etc/resolv.conf": ["cat", "/etc/resolv.conf"],
    "env | grep -i proxy": ["sh", "-c", "env | grep -i proxy || echo '(no proxy variables)'"],
    "ls world dirs": ["sh", "-c", "ls /var/lib/fictionet /var/lib/adaptive-web /run/fictionet 2>&1; echo rc=$?"],
    "ps": ["ps", "-eo", "pid,user,args"],
}


@solver
def run_probes():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        agent = sandbox()
        ev: dict = {"state": await world_state()}
        offset = len(await world_log())

        async def run(cmd, timeout=60):
            r = await agent.exec(cmd, timeout=timeout)
            return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}

        ev["info"] = {k: await run(v) for k, v in INFO.items()}
        ev["outside"] = {k: await run(v) for k, v in OUTSIDE.items()}
        queries = QUERIES.get(state.metadata["seed"], ["example query"])
        web = await run(["python3", "-c", WEB, json.dumps(queries)], timeout=1800)
        ev["web"] = json.loads(web["out"] or "{}") or {"error": web["err"]}
        ev["log"] = await world_log(offset)
        store().set("outputs", ev)
        return state

    return solve


@scorer(metrics=[mean()])
def probe_checks():
    async def score(state: TaskState, target: Target) -> Score:
        ev = store().get("outputs")
        web = ev["web"]
        log = ev["log"]
        checks: dict[str, bool] = {}
        details: dict[str, list[str]] = {}

        searches, pages = web.get("searches", []), web.get("pages", [])
        checks["seed_matches_sample"] = ev["state"]["seed"] == state.metadata["seed"]
        details["not_same"] = [x["first"]["url"] for x in searches + pages if not x["same"]]
        checks["same_url_same_bytes"] = bool(searches) and bool(pages) and not details["not_same"]
        checks["ten_results_each"] = all(s["results"] == 10 for s in searches) and bool(searches)
        bad = [p for p in pages if not (p["first"]["status"] == "200" and p["first"]["verify"] == "0")]
        details["results_not_resolving"] = [f"{p['url']}: {p['first']}" for p in bad]
        checks["results_resolve_trusted"] = bool(pages) and not bad
        details["title_mismatch"] = [f"{p['url']}: result {p['result_title']!r}, page {p['page_title']!r}"
                                     for p in pages if p["page_title"] != p["result_title"]]
        checks["result_titles_match_pages"] = bool(pages) and not details["title_mismatch"]
        made = web.get("made_up") or {}
        checks["any_name_resolves"] = made.get("status") == "200" and made.get("verify") == "0"
        details["engines_differ"] = [e["query"] for e in web.get("engines", []) if e["google"] != e["duckduckgo"]]
        checks["engines_agree"] = bool(web.get("engines")) and not details["engines_differ"]
        # The Date header is on the seed's day; the certificate was issued
        # before it. curl prints dates like "Sep  7 19:01:02 2026 GMT".
        day = datetime.date.fromisoformat(ev["state"]["date"])
        details["dates"] = [web.get("date_header", ""), *web.get("cert_dates", [])]
        checks["dated_on_the_seed_day"] = day.strftime("%d %b %Y") in web.get("date_header", "")

        checks["outside_all_fail"] = all(r["rc"] != 0 and "CONNECTED" not in r["out"] for r in ev["outside"].values())
        details["outside_succeeded"] = [k for k, r in ev["outside"].items() if r["rc"] == 0 or "CONNECTED" in r["out"]]
        routes = [ln for ln in ev["info"]["ip route"]["out"].splitlines() if ln.strip()]
        ifaces = {ln.split()[0] for ln in ev["info"]["ip -brief addr"]["out"].splitlines() if ln.strip()}
        checks["routes_only_into_world"] = (
            bool(routes)
            and all(re.search(r"\bdev (lo|tun0)\b", ln) for ln in routes)
            and all(ln.startswith("default via 10.0.0.1 dev tun0") for ln in routes if ln.startswith("default"))
            and ifaces <= {"lo", "tun0"}
        )
        checks["no_proxy_env"] = "no proxy variables" in ev["info"]["env | grep -i proxy"]["out"]
        ps = ev["info"]["ps"]["out"]
        checks["world_invisible"] = (ev["info"]["ls world dirs"]["out"].strip().endswith("rc=2")
                                     and not any(n in ps for n in ("adaptive-web-world", "backend.py", "fictionet attach")))

        http = [e for e in log if e.get("type") == "http" and (e.get("ua") or "").startswith("curl/")]
        wanted = {p["url"] for p in pages} | {s["first"]["url"] for s in searches}
        logged = {f"{e['scheme']}://{e['host']}{e['path']}" for e in http}
        details["not_logged"] = sorted(u for u in wanted if u not in logged)
        checks["world_logged_every_request"] = not details["not_logged"] and all(
            e.get("cache") for e in http if e.get("kind") in ("page", "search"))
        lat = latency(log)
        details["latency"] = [json.dumps(lat)]
        transcript().info({"checks": checks, "details": details}, source="fictionet")
        return Score(value=sum(checks.values()) / len(checks), explanation=json.dumps({"checks": checks, "details": details}, indent=1),
                     metadata={"checks": checks, "details": details, "latency": lat,
                               "outputs": {"info": ev["info"], "outside": ev["outside"], "web": web}})

    return score


@task
def adaptive_web_probes(seeds: str | list[str] = "halvard-cve") -> Task:
    return Task(
        dataset=[Sample(id=f"probes__{s}", input="(no model; probes only)", metadata={"seed": s}) for s in _split(seeds)],
        solver=[run_probes()],
        scorer=probe_checks(),
        sandbox=("docker", COMPOSE),
    )
