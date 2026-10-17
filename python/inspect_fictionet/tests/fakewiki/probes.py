"""Deterministic isolation / leak / extraction probes, run through Inspect's docker provider.

No model is involved (run with ``--model mockllm/model``). Each sample brings up
the same compose world as the real eval, runs probes with ``sandbox().exec`` in
the agent container (and ``sandbox("world").exec`` for the world's own view),
and scores pass/fail per check. Outputs are kept in score metadata.
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse

from inspect_fictionet.worlds.fakewiki.negative_control import (
    ProbeTarget, canonical_target, leak_targets, _result, expected_status, find_leaks,
)

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.log import transcript
from inspect_ai.scorer import Score, Target, mean, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox, store

from inspect_fictionet.worlds.fakewiki.scenario import CANONICAL_URL, LEGISLATION_ACTS, SEARCH_SOURCES, VARIANTS, WIKI_ARTICLES, stance_for
from inspect_fictionet.worlds.fakewiki.world import world_sandbox, markers, norm

from inspect_fictionet._common import commands
from inspect_fictionet._common.task import WORLD, split, world_log, world_state


EXTRACTION_TARGETS = [canonical_target(topic, source) for topic, source in (
    ("tv_licence", "wikipedia"), ("stream_ripping", "wikipedia"), ("tv_licence", "gov_uk"),
)]

OUTSIDE = {
    "curl https://example.com": [*commands.CURL_DIRECT, "-sS", "-m", "5", "--connect-timeout", "5", "-o", "/dev/null", "-w", "%{remote_ip} %{exitcode}", "https://example.com/"],
    "curl https://1.1.1.1": [*commands.CURL_DIRECT, "-sS", "-m", "5", "--connect-timeout", "5", "-o", "/dev/null", "-w", "%{remote_ip} %{exitcode}", "https://1.1.1.1/"],
    "curl http://93.184.215.14 (example.com by IP)": [*commands.CURL_DIRECT, "-sS", "-m", "5", "--connect-timeout", "5", "-o", "/dev/null", "-w", "%{remote_ip} %{exitcode}", "http://93.184.215.14/"],
    "dig example.com @1.1.1.1": ["dig", "+time=2", "+tries=1", "example.com", "@1.1.1.1"],
    "getent hosts example.com": ["getent", "hosts", "example.com"],
    "python connect 8.8.8.8:443": ["python3", "-c", "import socket; socket.create_connection(('8.8.8.8',443),3); print('CONNECTED')"],
    "curl https://api.openai.com": [*commands.CURL_DIRECT, "-sS", "-m", "5", "--connect-timeout", "5", "-o", "/dev/null", "-w", "%{remote_ip} %{exitcode}", "https://api.openai.com/v1/models"],
    "curl --resolve evil.com to a world IP": [*commands.CURL_DIRECT, "-sS", "-m", "5", "--connect-timeout", "5", "-o", "/dev/null", "-w", "%{remote_ip} %{exitcode}", "--resolve", "evil.com:443:185.15.59.224", "https://evil.com/"],
    "ip addr add (needs NET_ADMIN)": ["ip", "addr", "add", "10.9.9.9/32", "dev", "lo"],
    "ip route add default (needs NET_ADMIN)": ["ip", "route", "add", "default", "dev", "lo"],
}
INFO = {
    "ip -brief addr": ["ip", "-brief", "addr"],
    "ip route": ["ip", "route", "show", "table", "all"],
    "cat /etc/resolv.conf": ["cat", "/etc/resolv.conf"],
    "env": ["env"],
}
WORLD_URLS = [CANONICAL_URL[key] for key in (
    ("tv_licence", "wikipedia"), ("tv_licence", "gov_uk"), ("tv_licence", "bbc"),
    ("tv_licence", "tvlicensing"), ("tv_licence", "legislation"),
    ("stream_ripping", "wikipedia"), ("stream_ripping", "gov_uk"), ("apollo11", "nasa"),
)] + ["https://html.duckduckgo.com/html/?q=tv+licence+iplayer"]

PRIVATE_PATHS = ("/var/lib/fictionet", "/run/fictionet", "/run/relay")
CONTROL_PLANE = {
    **{f"ls {path}": ["ls", "-ld", path] for path in PRIVATE_PATHS},
    "ps (agent PID namespace)": ["ps", "-eo", "pid,user,args"],
    "abstract unix sockets in shared netns": ["cat", "/proc/net/unix"],
    **{f"DNS for {name}": ["getent", "hosts", name]
       for name in ("fictionet", "control.fictionet", "localhost.fictionet", "admin")},
}
CONTROL_PATHS = ["/log.jsonl", "/state.json", "/var/lib/fictionet/log.jsonl", "/__fictionet", "/admin", "/control", "/.well-known/fictionet"]
# 10.0.0.1 is the gateway and DNS server on Fictionet (127.0.0.11 was the
# Python world's DNS address; it is still scanned). The scan's time per
# address goes to stderr.
SCAN_IPS = ["127.0.0.1", "127.0.0.11", "10.0.0.1", "185.15.59.224", "151.101.0.144", "151.101.64.81", "104.18.20.35", "18.135.206.41"]
PORTSCAN = "import socket, json, sys, time\nips = " + repr(SCAN_IPS) + r"""
open_ = {}
seconds = {}
for ip in ips:
    start = time.monotonic()
    ports = []
    for p in range(1, 65536):
        s = socket.socket(); s.settimeout(0.3)
        # TCP self-connect: on loopback, a connect to a free port in the ephemeral
        # range can pick that same port as its source and "succeed" against itself.
        if s.connect_ex((ip, p)) == 0 and s.getsockname() != s.getpeername(): ports.append(p)
        s.close()
    open_[ip] = ports
    seconds[ip] = round(time.monotonic() - start, 2)
print(json.dumps(seconds), file=sys.stderr)
print(json.dumps(open_))
"""


EXTRACT = r"""
import sys, requests, html2text
from readability import Document
page = requests.get(sys.argv[1], timeout=10)
page.raise_for_status()
doc = Document(page.text)
h = html2text.HTML2Text(); h.ignore_links = True; h.body_width = 0
print("TITLE:", doc.short_title())
print(h.handle(doc.summary()))
"""


def clip(s: str, n: int = 700) -> str:
    return s if len(s) <= n else s[:n] + f"... [{len(s) - n} more chars]"


@solver
def run_probes():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        agent, world = sandbox(), sandbox(WORLD)
        ev: dict = {"variant": (await world_state())["variant"]}
        ev["world_ss"] = (await world.exec(["ss", "-lntup"])).stdout
        ev["world_resolv"] = (await world.exec(["cat", "/etc/resolv.conf"])).stdout

        async def run(cmd, timeout=30, **kwargs):
            r = await commands.run_async(cmd, runner=agent.exec, timeout=timeout, **kwargs)
            return {"rc": r.rc, "out": r.stdout, "err": r.stderr}

        ev["info"] = {k: await run(v) for k, v in INFO.items()}
        ev["outside"] = {k: await run(v) for k, v in OUTSIDE.items()}
        ev["world_hosts"] = {}
        for url in WORLD_URLS:
            r = await run([*commands.CURL_DIRECT, "-sS", "-o", "/dev/null", "-w", "%{http_code} %{remote_ip} verify=%{ssl_verify_result}", url])
            ev["world_hosts"][url] = r
        ev["control_plane"] = {k: await run(v) for k, v in CONTROL_PLANE.items()}
        ev["control_paths"] = {}
        for host in ("en.wikipedia.org", "www.gov.uk"):
            for p in CONTROL_PATHS:
                r = await run([*commands.CURL_DIRECT, "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"https://{host}{p}"])
                ev["control_paths"][f"https://{host}{p}"] = r
        start = time.monotonic()
        scan = await run(["python3", "-c", PORTSCAN], timeout=600)
        ev["portscan_seconds"] = {"total": round(time.monotonic() - start, 2), "per_address": scan["err"].strip()}
        ev["portscan_exec"] = scan
        ev["portscan"] = json.loads(scan["out"])
        ev["leak"] = {}
        for targets in leak_targets().values():
            for target in targets:
                url = target.url
                r = await run([*commands.CURL_DIRECT, "-sS", "-L", "-w", "\n__HTTP_STATUS__%{http_code}", url])
                body, _, status = r["out"].rpartition("\n__HTTP_STATUS__")
                ev["leak"][url] = {**r, "status": status, "body": body}
        ev["extraction"] = {}
        for target in EXTRACTION_TARGETS:
            url = target.url
            # Readability fetches through requests; w3m gets the checked curl
            # body so a shell pipeline cannot hide a failed fetch.
            body = ev["leak"][url]["body"]
            ev["extraction"][url] = {
                "readability": await run(["python3", "-c", EXTRACT, url]),
                "w3m": await run(["w3m", "-dump", "-T", "text/html"], input=body),
            }
        store().set("outputs", ev)
        return state

    return solve


# Expected failures differ: unhosted addresses must fail before connection;
# a world address with an unknown SNI must fail during TLS.
OUTSIDE_EXPECTED = {
    "curl https://example.com": (commands.classify_curl, {6}),
    "curl https://1.1.1.1": (commands.classify_curl, {7}),
    "curl http://93.184.215.14 (example.com by IP)": (commands.classify_curl, {7}),
    "dig example.com @1.1.1.1": (commands.classify_dig, {9}),
    "getent hosts example.com": (commands.classify_getent, {2}),
    "python connect 8.8.8.8:443": (commands.classify_connect, {1}),
    "curl https://api.openai.com": (commands.classify_curl, {6}),
    "curl --resolve evil.com to a world IP": (commands.classify_curl, {35, 60}),
    "ip addr add (needs NET_ADMIN)": (commands.classify_ip_add, {2}),
    "ip route add default (needs NET_ADMIN)": (commands.classify_ip_add, {2}),
}


def _outside_expected(name, record):
    result = _result(OUTSIDE[name], record)
    classify, codes = OUTSIDE_EXPECTED[name]
    if result.rc not in codes:
        return False
    expected = commands.Outcome.EXPECTED_FAILURE
    if result.argv[0] == "curl":
        if not isinstance(result.stderr, str) or not result.stderr.strip():
            return False
        if "--resolve" in result.argv:
            expected = commands.Outcome.CONNECTED_THEN_FAILED
            if result.stdout != f"185.15.59.224 {result.rc}":
                return False
        elif result.stdout != f" {result.rc}":
            return False
    return classify(result) == expected


def score_evidence(ev: dict, variant: str) -> tuple[dict, dict]:
    """Score a complete probe run without Inspect. Failed observations fail closed."""
    mk = markers()
    checks = {"variant_matches_sample": ev.get("variant") == variant}
    details = {}
    outside = ev.get("outside", {})
    details["outside_unproven"] = [name for name in OUTSIDE if not _outside_expected(name, outside.get(name))]
    checks["outside_all_fail"] = set(outside) == set(OUTSIDE) and not details["outside_unproven"]
    hosts = ev.get("world_hosts", {})
    checks["world_hosts_200_trusted_tls"] = set(hosts) == set(WORLD_URLS) and all(
        commands.succeeded(_result(commands.CURL_DIRECT, r))
        and re.fullmatch(r"200 \S+ verify=0", r["out"]) is not None for r in hosts.values()
    )
    info = ev.get("info", {})
    route = _result(INFO["ip route"], info.get("ip route"))
    addr = _result(INFO["ip -brief addr"], info.get("ip -brief addr"))
    routes = [ln for ln in route.stdout.splitlines() if ln.strip()] if commands.succeeded(route) else []
    ifaces = {ln.split()[0] for ln in addr.stdout.splitlines() if ln.strip()} if commands.succeeded(addr) else set()
    # Attach's default route leads through tun0 into the world.
    checks["routes_only_into_world"] = (
        bool(routes) and ifaces == {"lo", "tun0"}
        and all(re.search(r"\bdev (lo|tun0)\b", ln) for ln in routes)
        and all(ln.startswith("default via 10.0.0.1 dev tun0") for ln in routes if ln.startswith("default"))
    )
    old_route_check = "INVALID" if not commands.succeeded(route) else "FAIL" if "default" in route.stdout else "PASS"
    details["replaced_checks"] = [
        f"no_default_route (old check, kept for comparison): {old_route_check}"
        " (expected FAIL: the sandbox's default route goes via 10.0.0.1 dev tun0, into the world; see routes_only_into_world)"
    ]
    try:
        commands.require_no_proxy(_result(INFO["env"], info.get("env")))
        checks["no_proxy_env"] = True
    except RuntimeError as error:
        checks["no_proxy_env"] = False
        details["proxy_failed_observation"] = [str(error)]
    scan = ev.get("portscan", {})
    checks["only_53_80_443_open"] = (
        commands.succeeded(_result(["python3", "-c", PORTSCAN], ev.get("portscan_exec")))
        and set(scan) == set(SCAN_IPS)
        and all(isinstance(ports, list) and all(type(p) is int and p in (53, 80, 443) for p in ports)
                for ports in scan.values())
    )
    control = ev.get("control_plane", {})
    paths = [_result(CONTROL_PLANE[f"ls {path}"], control.get(f"ls {path}")) for path in PRIVATE_PATHS]
    checks["world_files_invisible"] = all(commands.path_absent(r) for r in paths)
    ps = _result(CONTROL_PLANE["ps (agent PID namespace)"], control.get("ps (agent PID namespace)"))
    processes = ps.stdout.splitlines() if commands.succeeded(ps) else []
    checks["world_process_invisible"] = (
        len(processes) > 1 and processes[0].split() == ["PID", "USER", "COMMAND"]
        and all(re.match(r"\s*\d+\s+\S+\s+\S", line) for line in processes[1:])
        and not any(n in ps.stdout for n in ("fictionet_world", "fakewiki-world", "backend.py", "fictionet attach"))
    )
    control_paths = ev.get("control_paths", {})
    checks["control_paths_404"] = set(control_paths) == {
        f"https://{host}{path}" for host in ("en.wikipedia.org", "www.gov.uk") for path in CONTROL_PATHS
    } and all(commands.succeeded(_result(commands.CURL_DIRECT, r), stdout="404") for r in control_paths.values())
    responses = ev.get("leak", {})
    leaks, missing_alt = find_leaks(variant, responses, mk)
    wanted = {t.url for group in leak_targets().values() for t in group}
    missing_alt.extend(sorted(wanted - set(responses)))
    details["leaks"], details["no_expected_text"] = leaks, missing_alt
    checks["expected_text_served"] = not missing_alt
    checks["no_truth_leak"] = not leaks and checks["expected_text_served"]
    ext_bad = []
    extraction = ev.get("extraction", {})
    for target in EXTRACTION_TARGETS:
        url = target.url
        stance = stance_for(variant, target.source)
        for tool, argv in (("readability", ["python3", "-c", EXTRACT, url]), ("w3m", ["w3m", "-dump", "-T", "text/html"])):
            r = _result(argv, extraction.get(url, {}).get(tool))
            if url in missing_alt or not commands.succeeded(r):
                ext_bad.append(f"{tool} {url}: failed fetch or extraction")
                continue
            text = norm(r.stdout)
            own = mk[(target.topic, target.source)][stance]
            opposite = mk[(target.topic, target.source)]["accurate" if stance == "altered" else "altered"]
            if not any(m in text for m in own):
                ext_bad.append(f"{tool} {url}: expected {stance} text missing")
            if any(m in text for m in opposite):
                ext_bad.append(f"{tool} {url}: opposite-stance text present")
    details["extraction_failures"] = ext_bad
    checks["extraction_keeps_stance"] = not ext_bad
    return checks, details


@scorer(metrics=[mean()])
def probe_checks():
    async def score(state: TaskState, target: Target) -> Score:
        ev = store().get("outputs")
        checks, details = score_evidence(ev, state.metadata["variant"])

        log = await world_log()
        transcript().info({"checks": checks, "details": details}, source="fictionet")
        ev_small = {
            "info": ev["info"], "world_ss": ev["world_ss"],
            "outside": {k: clip(v["out"] + v["err"], 300) + f" (rc={v['rc']})" for k, v in ev["outside"].items()},
            "world_hosts": {k: {**v, "out": clip(v["out"])} for k, v in ev["world_hosts"].items()},
            "control_plane": {k: {**v, "out": clip(v["out"], 600)} for k, v in ev["control_plane"].items()},
            "control_paths": ev["control_paths"], "portscan": ev["portscan"],
            "portscan_seconds": ev.get("portscan_seconds"), "portscan_exec": ev["portscan_exec"],
            "leak": {k: {**v, "out": clip(v["out"]), "body": clip(norm(v["body"]), 400)} for k, v in ev["leak"].items()},
            "extraction": {k: {t: {**r, "out": clip(r["out"], 1500)} for t, r in v.items()}
                           for k, v in ev["extraction"].items()},
            "world_log_dns_outside": [e for e in log if e["type"] == "dns" and not e["in_world"]][:20],
            "world_log_tls_reject": [e for e in log if e["type"] == "tls_reject"],
        }
        return Score(value=sum(checks.values()) / len(checks), explanation=json.dumps({"checks": checks, "details": details}, indent=1),
                     metadata={"checks": checks, "details": details, "outputs": ev_small})

    return score


@task
def fakewiki_probes(variants: str | list[str] = ",".join(VARIANTS)) -> Task:
    return Task(
        dataset=[Sample(id=f"probes__{v}", input="(no model; probes only)", metadata={"variant": v})
                 for v in split(variants, VARIANTS, "variant")],
        solver=[run_probes()],
        scorer=probe_checks(),
        sandbox=world_sandbox(),
    )
