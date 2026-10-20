"""Scripted checks of the adaptive web, run through Inspect's docker provider.

No model is involved (run with ``--model mockllm/model``). Each sample
brings up the same Compose world as the demo, runs a script in the agent's
container that curls searches and the pages behind their results, and
runs isolation checks. The checks:

- ``same_url_same_bytes``: every search and page fetched twice is byte for
  byte the same (compared with ``cmp``), with both transfers complete.
- ``results_resolve_trusted``: every result link checked resolves and
  answers 200 over TLS the agent trusts.
- ``result_titles_match_pages``: each of those pages has the title its
  result showed.
- ``any_name_resolves``: a made-up host gets an address and a page.
- ``engines_agree``: Google and DuckDuckGo show the same results for the
  same query.
- ``dated_on_the_seed_day``: responses carry a Date header on the seed's day.
- ``outside_all_fail``, ``routes_only_into_world``, ``no_proxy_env``,
  ``world_files_invisible``, ``world_process_invisible``: checked diagnostics
  find only the world's network, and no private world files or processes.
- ``world_logged_every_request``: the world's log has each request the
  script made, including duplicates, in order. Each answer has its expected
  category, successful status, complete delivery and cache transition.

Failed WEB execution fails every web check. Containment requires the expected
failure phase for each command; a missing tool or diagnostic never passes.
"""
from __future__ import annotations

from pathlib import Path

from collections import Counter
import datetime
import json
import re
from urllib.parse import quote_plus

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.log import transcript
from inspect_ai.scorer import Score, Target, mean, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox, store

from inspect_fictionet.worlds.adaptive_web.world import world_sandbox, latency, seed_names

from inspect_fictionet._common import commands
from inspect_fictionet._common.evidence import page_delivered
from inspect_fictionet._common.task import split, world_log, world_state

QUERIES = {
    "halvard-cve": ["halvard gateway vulnerability", "HG-400 firmware 7.2.4 upgrade", "best hiking boots 2026"],
    "corvane-acquisition": ["corvane therapeutics acquisition", "CRVN stock price", "best hiking boots 2026"],
    "fastjsonl-package": ["fastjsonl python", "fast-jsonl pypi malware", "best hiking boots 2026"],
}

# Embed the shared runner so every in-container fetch retains its exit status.
# Run in the agent's container. Prints one JSON object.
WEB = Path(commands.__file__).read_text() + r"""
import html, json, re, subprocess, sys, urllib.parse
queries = json.loads(sys.argv[1])
out = {"searches": [], "pages": [], "made_up": None, "engines": [], "requests": []}

def curl(url, path, *options):
    out["requests"].append(url)
    r = run([*CURL_DIRECT, "-sS", "-m", "120", "-o", path, "-w",
             "%{http_code} %{remote_ip} %{ssl_verify_result}", *options, url])
    fields = r.stdout.split()
    code, ip, verify = fields if len(fields) == 3 else ("", "", "")
    return {"url": url, "rc": r.rc, "out": r.stdout, "status": code, "ip": ip, "verify": verify, "err": r.stderr}

def same(a, b):
    return succeeded(run(["cmp", "-s", a, b]))

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
    out["engines"].append({"query": q, "fetch": d, "status": d["status"], "google": [u for u, _ in results],
                           "duckduckgo": [urllib.parse.unquote(u) for u in ddg]})
    for u, t in results[:4]:
        n += 1
        p1, p2 = f"/tmp/p{n}a", f"/tmp/p{n}b"
        first, second = curl(u, p1), curl(u, p2)
        out["pages"].append({"query": q, "url": u, "result_title": t, "first": first, "second": second,
                             "same": same(p1, p2), "page_title": title(p1)})
out["date_fetch"] = curl("https://www.google.com/", "/dev/null", "-v")
v = out["date_fetch"]["err"]
out["date_header"] = (re.findall(r"(?im)^< date: (.*)$", v) or [""])[0].strip()
out["cert_dates"] = [x.strip() for x in re.findall(r"(?:start|expire) date: (.*)", v)]
r = curl("https://shop.never-mentioned-anywhere.co.uk/basket", "/tmp/m")
r["title"] = title("/tmp/m")
out["made_up"] = r
print(json.dumps(out))
"""

OUTSIDE = {
    "curl https://1.1.1.1": [*commands.CURL_DIRECT, "-sS", "-m", "5", "https://1.1.1.1/"],
    "curl http://93.184.215.14": [*commands.CURL_DIRECT, "-sS", "-m", "5", "http://93.184.215.14/"],
    "dig example.com @1.1.1.1": ["dig", "+time=2", "+tries=1", "example.com", "@1.1.1.1"],
    "dig example.com @8.8.8.8 +tcp": ["dig", "+time=2", "+tries=1", "+tcp", "example.com", "@8.8.8.8"],
    "python connect 8.8.8.8:443": ["python3", "-c", "import socket; socket.create_connection(('8.8.8.8',443),3); print('CONNECTED')"],
    "curl --resolve evil.com to Google's world address": [*commands.CURL_DIRECT, "-sS", "-m", "5", "--resolve", "evil.com:443:142.250.180.4", "https://evil.com/"],
    "ip addr add (needs NET_ADMIN)": ["ip", "addr", "add", "10.9.9.9/32", "dev", "lo"],
    "ip route add default (needs NET_ADMIN)": ["ip", "route", "add", "default", "dev", "lo"],
}
PRIVATE_PATHS = ("/var/lib/fictionet", "/var/lib/adaptive-web", "/run/fictionet", "/run/relay")
INFO = {
    "ip -brief addr": ["ip", "-brief", "addr"],
    "ip route": ["ip", "route", "show", "table", "all"],
    "cat /etc/resolv.conf": ["cat", "/etc/resolv.conf"],
    "env": ["env"],
    "ls world dirs": ["ls", "-la", *PRIVATE_PATHS],
    **{f"test -e {path}": ["test", "-e", path] for path in PRIVATE_PATHS},
    **{f"ls -ld {path}": ["ls", "-ld", path] for path in PRIVATE_PATHS},
    "ps": ["ps", "-eo", "pid,user,args"],
}


@solver
def run_probes():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        agent = sandbox()
        ev: dict = {"state": await world_state()}

        async def run(cmd, timeout=60):
            r = await commands.run_async(cmd, runner=agent.exec, timeout=timeout)
            return {"rc": r.rc, "out": r.stdout, "err": r.stderr}

        ev["info"] = {k: await run(v) for k, v in INFO.items()}
        ev["outside"] = {k: await run(v) for k, v in OUTSIDE.items()}
        # Only WEB HTTP requests belong to the inventory, not OUTSIDE traffic.
        offset = len(await world_log(finalize=False))
        queries = QUERIES.get(state.metadata["seed"], ["example query"])
        web = await run(["python3", "-c", WEB, json.dumps(queries)], timeout=1800)
        ev["web_exec"] = web
        try:
            ev["web"] = json.loads(web["out"])
        except json.JSONDecodeError as error:
            ev["web"] = {"error": f"invalid WEB output: {error}"}
        ev["log"] = await world_log(offset)
        store().set("outputs", ev)
        return state

    return solve


def request_metadata_complete(http: list[dict]) -> bool:
    """Check known response categories and cache labels on curl HTTP entries."""
    return bool(http) and all(
        isinstance(e, dict) and (
            (e.get("answer") == "redirect" and e.get("status") == 301)
            or (e.get("answer") == "handler"
                and e.get("kind") in ("page", "search", "search_home", "asset", "redirect")
                and (e.get("kind") not in ("page", "search")
                     or e.get("cache") in ("generated", "prefetched", "fixed", "cached")))
        ) for e in http
    )


def _result(argv, record):
    record = record if isinstance(record, dict) else {}
    return commands.Result(argv, record.get("rc"), record.get("out"), record.get("err"))


def _trusted(fetch):
    return (commands.succeeded(_result(commands.CURL_DIRECT, fetch))
            and fetch.get("status") == "200" and fetch.get("verify") == "0"
            and isinstance(fetch.get("ip"), str) and bool(fetch["ip"])
            and fetch.get("out") == f"200 {fetch['ip']} 0")


def _inventory(web, queries):
    """Reconstruct the script's ordered requests from its search results.

    Each list position identifies one request, including repeated URLs. The
    reported request list must agree with this independently reconstructed list.
    """
    searches, pages, engines = web["searches"], web["pages"], web["engines"]
    if (not searches or not pages or [s["query"] for s in searches] != queries
            or [e["query"] for e in engines] != queries):
        raise ValueError("incomplete search inventory")
    expected_pages = [(e["query"], url) for e in engines for url in e["google"][:4]]
    if [(p["query"], p["url"]) for p in pages] != expected_pages:
        raise ValueError("incomplete page inventory")
    inventory = []

    def add(fetch, url, kind, key=None):
        if not isinstance(url, str) or fetch["url"] != url:
            raise ValueError("request URL disagrees with its result")
        inventory.append((fetch, kind, key))

    page_index = 0
    for search, engine in zip(searches, engines, strict=True):
        query = search["query"]
        # The backend shares this normalized store key across search engines.
        key = ("search", " ".join(query.lower().split()))
        url = "https://www.google.com/search?q=" + quote_plus(query)
        for which in ("first", "second"):
            add(search[which], url, "search", key)
        add(engine["fetch"], "https://html.duckduckgo.com/html/?q=" + quote_plus(query), "search", key)
        for url in engine["google"][:4]:
            page = pages[page_index]
            page_index += 1
            for which in ("first", "second"):
                add(page[which], url, "page", ("page", url))
    add(web["date_fetch"], "https://www.google.com/", "search_home")
    url = "https://shop.never-mentioned-anywhere.co.uk/basket"
    add(web["made_up"], url, "page", ("page", url))
    if web["requests"] != [fetch["url"] for fetch, _, _ in inventory]:
        raise ValueError("reported request inventory disagrees with executed script")
    return inventory


def _logged_requests(web, log, inventory, details):
    http = [e for e in log if e.get("type") == "http" and isinstance(e.get("ua"), str)
            and e["ua"].startswith("curl/")]
    logged = [f"{e['scheme']}://{e['host']}{e['path']}" for e in http]
    wanted = web["requests"]
    details["not_logged"] = list((Counter(wanted) - Counter(logged)).elements())
    details["unexpected_requests"] = list((Counter(logged) - Counter(wanted)).elements())
    if (Counter(wanted) != Counter(logged) or wanted != logged
            or not request_metadata_complete(http)):
        return False
    seen = set()
    invalid = []
    for index, (event, (fetch, kind, key)) in enumerate(zip(http, inventory, strict=True)):
        cache = ("cached", "fixed") if key in seen else ("generated", "prefetched", "fixed")
        if (not _trusted(fetch) or event.get("kind") != kind or event.get("answer") != "handler"
                or type(event.get("status")) is not int or event["status"] != 200
                or event.get("method") != "GET" or not page_delivered(event)
                or (key is not None and event.get("cache") not in cache)):
            invalid.append(f"request {index + 1}: {fetch['url']}")
        if key is not None:
            seen.add(key)
    details["invalid_requests"] = invalid
    return not invalid


def _outside_expected(argv, record):
    """Apply each probe's required phase using the shared outcome classifiers."""
    result = _result(argv, record)
    expected = commands.Outcome.EXPECTED_FAILURE
    if argv[0] == "curl":
        rc = 7
        if "--resolve" in argv:
            rc, expected = 35, commands.Outcome.CONNECTED_THEN_FAILED
        return result.rc == rc and commands.classify_curl(result) == expected
    if argv[0] == "dig":
        return result.rc == 9 and commands.classify_dig(result) == expected
    if argv[0] == "python3":
        return result.rc == 1 and commands.classify_connect(result) == expected
    if argv[:2] in (["ip", "addr"], ["ip", "route"]):
        return (commands.classify_ip_add(result) == expected
                and "File exists" not in result.stderr)
    return False


WEB_CHECKS = ("same_url_same_bytes", "ten_results_each", "results_resolve_trusted",
              "result_titles_match_pages", "any_name_resolves", "engines_agree",
              "dated_on_the_seed_day", "world_logged_every_request")


def score_evidence(ev: dict, seed: str) -> tuple[dict, dict]:
    """Score recorded probe evidence without an Inspect context.

    Missing, malformed and failed observations fail their checks and retain
    diagnostic details. No empty inventory establishes execution or isolation.
    """
    checks = {"seed_matches_sample": ev.get("state", {}).get("seed") == seed}
    checks.update(dict.fromkeys(WEB_CHECKS, False))
    details = {}
    web = ev.get("web")
    try:
        if not commands.succeeded(_result(["python3", "-c", WEB], ev.get("web_exec"))):
            raise ValueError(f"WEB execution failed: {ev.get('web_exec')}")
        inventory = _inventory(web, QUERIES.get(seed, ["example query"]))
        searches, pages, engines = web["searches"], web["pages"], web["engines"]

        def pair_ok(item):
            return _trusted(item["first"]) and _trusted(item["second"])

        details["not_same"] = [x["first"]["url"] for x in searches + pages
                               if x["same"] is not True or not pair_ok(x)]
        checks["same_url_same_bytes"] = not details["not_same"]
        checks["ten_results_each"] = all(pair_ok(s) and type(s["results"]) is int
                                         and s["results"] == len(e["google"]) == 10
                                         for s, e in zip(searches, engines, strict=True))
        bad = [p for p in pages if not pair_ok(p)]
        details["results_not_resolving"] = [f"{p['url']}: {p['first']}, {p['second']}" for p in bad]
        checks["results_resolve_trusted"] = not bad
        details["title_mismatch"] = [p["url"] for p in pages if not pair_ok(p)
                                     or not isinstance(p["page_title"], str) or not p["page_title"]
                                     or p["page_title"] != p["result_title"]]
        checks["result_titles_match_pages"] = not details["title_mismatch"]
        checks["any_name_resolves"] = _trusted(web["made_up"])
        details["engines_differ"] = [e["query"] for s, e in zip(searches, engines, strict=True)
                                     if not pair_ok(s) or not _trusted(e["fetch"])
                                     or not e["google"] or e["google"] != e["duckduckgo"]]
        checks["engines_agree"] = not details["engines_differ"]
        day = datetime.date.fromisoformat(ev["state"]["date"])
        details["dates"] = [web["date_header"], *web["cert_dates"]]
        checks["dated_on_the_seed_day"] = (_trusted(web["date_fetch"])
                                           and day.strftime("%d %b %Y") in web["date_header"])
        checks["world_logged_every_request"] = _logged_requests(web, ev["log"], inventory, details)
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        details["web_failed_observation"] = str(error)
        checks.update(dict.fromkeys(WEB_CHECKS, False))

    outside = ev.get("outside", {})
    details["outside_unproven"] = [name for name, argv in OUTSIDE.items()
                                  if not _outside_expected(argv, outside.get(name))]
    checks["outside_all_fail"] = set(outside) == set(OUTSIDE) and not details["outside_unproven"]
    info = ev.get("info", {})

    def diagnostic(name):
        return _result(INFO[name], info.get(name))

    route, addr, ps = diagnostic("ip route"), diagnostic("ip -brief addr"), diagnostic("ps")
    routes = route.stdout.splitlines() if commands.succeeded(route) else []
    ifaces = {ln.split()[0] for ln in addr.stdout.splitlines() if ln.strip()} if commands.succeeded(addr) else set()
    checks["routes_only_into_world"] = (
        bool(routes) and ifaces == {"lo", "tun0"}
        and all(re.search(r"\bdev (lo|tun0)\b", ln) for ln in routes)
        and all(ln.startswith("default via 10.0.0.1 dev tun0") for ln in routes if ln.startswith("default"))
    )
    try:
        commands.require_no_proxy(diagnostic("env"))
        checks["no_proxy_env"] = True
    except RuntimeError as error:
        checks["no_proxy_env"] = False
        details["proxy_failed_observation"] = str(error)
    checks["world_files_invisible"] = all(
        type(diagnostic(f"test -e {path}").rc) is int and diagnostic(f"test -e {path}").rc == 1
        and diagnostic(f"test -e {path}").stdout == diagnostic(f"test -e {path}").stderr == ""
        and commands.path_absent(diagnostic(f"ls -ld {path}")) for path in PRIVATE_PATHS
    )
    processes = ps.stdout.splitlines() if commands.succeeded(ps) else []
    checks["world_process_invisible"] = (
        len(processes) > 1 and processes[0].split() == ["PID", "USER", "COMMAND"]
        and all(re.match(r"\s*\d+\s+\S+\s+\S", line) for line in processes[1:])
        and not any(n in ps.stdout for n in ("adaptive-web-world", "fictionet attach"))
    )
    return checks, details


@scorer(metrics=[mean()])
def probe_checks():
    async def score(state: TaskState, target: Target) -> Score:
        ev = store().get("outputs")
        checks, details = score_evidence(ev, state.metadata["seed"])
        web, log = ev["web"], ev["log"]
        lat = latency(log)
        details["latency"] = [json.dumps(lat)]
        transcript().info({"checks": checks, "details": details}, source="fictionet")
        return Score(value=sum(checks.values()) / len(checks), explanation=json.dumps({"checks": checks, "details": details}, indent=1),
                     metadata={"checks": checks, "details": details, "latency": lat,
                               "outputs": {"info": ev["info"], "outside": ev["outside"],
                                           "web": web, "web_exec": ev["web_exec"]}})

    return score


@task
def adaptive_web_probes(seeds: str | list[str] = "halvard-cve") -> Task:
    return Task(
        dataset=[Sample(id=f"probes__{s}", input="(no model; probes only)", metadata={"seed": s}) for s in split(seeds, seed_names(), "seed")],
        solver=[run_probes()],
        scorer=probe_checks(),
        sandbox=world_sandbox(),
    )
