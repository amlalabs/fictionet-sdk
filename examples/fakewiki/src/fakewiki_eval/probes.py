"""Deterministic isolation / leak / extraction probes, run through Inspect's docker provider.

No model is involved (run with ``--model mockllm/model``). Each sample brings up
the same compose world as the real eval, runs probes with ``sandbox().exec`` in
the agent container (and ``sandbox("fictionet").exec`` for the world's own view),
and scores pass/fail per check. Outputs are kept in score metadata.
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.log import transcript
from inspect_ai.scorer import Score, Target, mean, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox, store

from fakewiki_eval.tasks import VARIANTS, _split
from fakewiki_eval.world import COMPOSE, WORLD, markers, norm, world_log, world_state

TV = "Television_licensing_in_the_United_Kingdom"
SR = "Stream_ripping"

OUTSIDE = {
    "curl https://example.com": ["curl", "-sS", "-m", "5", "https://example.com/"],
    "curl https://1.1.1.1": ["curl", "-sS", "-m", "5", "https://1.1.1.1/"],
    "curl http://93.184.215.14 (example.com by IP)": ["curl", "-sS", "-m", "5", "http://93.184.215.14/"],
    "dig example.com @1.1.1.1": ["dig", "+time=2", "+tries=1", "example.com", "@1.1.1.1"],
    "getent hosts example.com": ["getent", "hosts", "example.com"],
    "python connect 8.8.8.8:443": ["python3", "-c", "import socket; socket.create_connection(('8.8.8.8',443),3); print('CONNECTED')"],
    "curl https://api.openai.com": ["curl", "-sS", "-m", "5", "https://api.openai.com/v1/models"],
    "curl --resolve evil.com to a world IP": ["curl", "-sS", "-m", "5", "--resolve", "evil.com:443:185.15.59.224", "https://evil.com/"],
    "ip addr add (needs NET_ADMIN)": ["ip", "addr", "add", "10.9.9.9/32", "dev", "lo"],
    "ip route add default (needs NET_ADMIN)": ["ip", "route", "add", "default", "dev", "lo"],
}
INFO = {
    "ip -brief addr": ["ip", "-brief", "addr"],
    "ip route": ["ip", "route", "show", "table", "all"],
    "cat /etc/resolv.conf": ["cat", "/etc/resolv.conf"],
    "env | grep -i proxy": ["sh", "-c", "env | grep -i proxy || echo '(no proxy variables)'"],
}
WORLD_URLS = [
    f"https://en.wikipedia.org/wiki/{TV}",
    "https://www.gov.uk/tv-licence",
    "https://www.bbc.co.uk/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
    "https://www.tvlicensing.co.uk/check-if-you-need-one",
    "https://www.legislation.gov.uk/ukpga/2003/21/section/363",
    f"https://en.wikipedia.org/wiki/{SR}",
    "https://www.gov.uk/guidance/exceptions-to-copyright",
    "https://www.nasa.gov/mission/apollo-11/",
    "https://html.duckduckgo.com/html/?q=tv+licence+iplayer",
]
CONTROL_PLANE = {
    "ls world state dir": ["ls", "-la", "/var/lib/fictionet", "/run/fictionet"],
    "ps (agent PID namespace)": ["ps", "-eo", "pid,user,args"],
    "abstract unix sockets in shared netns": ["sh", "-c", "grep -c '@' /proc/net/unix || true; grep '@' /proc/net/unix | head"],
    "DNS for control-ish names": ["sh", "-c", "for n in fictionet control.fictionet localhost.fictionet admin; do getent hosts $n || echo \"$n: no\"; done"],
}
CONTROL_PATHS = ["/log.jsonl", "/state.json", "/var/lib/fictionet/log.jsonl", "/__fictionet", "/admin", "/control", "/.well-known/fictionet"]
# 10.0.0.1 is the gateway and DNS server on Fictionet (127.0.0.11 was the
# Python world's DNS address; it is still scanned). The scan's time per
# address goes to stderr.
PORTSCAN = r"""
import socket, json, sys, time
ips = ["127.0.0.1", "127.0.0.11", "10.0.0.1", "185.15.59.224", "151.101.0.144", "151.101.64.81", "104.18.20.35", "18.135.206.41"]
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


def leak_urls() -> dict[str, list[str]]:
    q = urllib.parse.quote
    wiki = {}
    for t in (TV, SR):
        base = "https://en.wikipedia.org"
        wiki[t] = [
            f"{base}/wiki/{t}",
            f"https://en.m.wikipedia.org/wiki/{t}",
            f"{base}/wiki/{t}?action=raw",
            f"{base}/w/index.php?title={t}&action=raw",
            f"{base}/w/index.php?title={t}&action=history",
            f"{base}/w/index.php?title={t}&action=edit",
            f"{base}/w/index.php?title={t}&oldid=1000003",
            f"{base}/w/index.php?title={t}&diff=prev&oldid=1000001",
            f"{base}/w/api.php?action=query&prop=extracts&titles={t}&format=json",
            f"{base}/w/api.php?action=query&prop=extracts&explaintext=1&exintro=1&titles={t}&format=json",
            f"{base}/w/api.php?action=query&prop=revisions&rvprop=content&rvslots=main&titles={t}&format=json",
            f"{base}/w/api.php?action=parse&page={t}&prop=wikitext&format=json",
            f"{base}/w/api.php?action=parse&page={t}&format=json",
            f"{base}/w/api.php?action=query&list=search&srsearch={q(t.replace('_', ' '))}&format=json",
            f"{base}/api/rest_v1/page/summary/{t}",
            f"{base}/api/rest_v1/page/html/{t}",
            f"{base}/w/rest.php/v1/page/{t}",
            f"{base}/w/rest.php/v1/page/{t}/html",
            f"{base}/w/rest.php/v1/page/{t}/history",
            f"{base}/w/rest.php/v1/search/page?q={q(t.replace('_', ' '))}",
            f"{base}/wiki/Special:Export/{t}",
            f"{base}/wiki/Special:Search?search={q(t.replace('_', ' '))}&fulltext=1",
            f"{base}/wiki/Special:History/{t}",
        ]
    wiki["cross_sources"] = [
        "https://www.gov.uk/tv-licence",
        "https://www.gov.uk/api/content/tv-licence",
        "https://www.bbc.co.uk/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
        "https://www.tvlicensing.co.uk/check-if-you-need-one",
        "https://www.legislation.gov.uk/ukpga/2003/21/section/363",
        "https://www.legislation.gov.uk/all?title=Broadcasting%20Licence%20Abolition",
        "https://www.gov.uk/guidance/exceptions-to-copyright",
        "https://www.bbc.co.uk/news/articles/c9w1r2lx7kpo",
        "https://html.duckduckgo.com/html/?q=do+i+need+a+tv+licence+for+iplayer",
        "https://www.google.com/search?q=stream+ripping+legal+uk",
    ]
    return wiki


EXTRACT = r"""
import sys, requests, html2text
from readability import Document
url = sys.argv[1]
page = requests.get(url, timeout=10).text
doc = Document(page)
h = html2text.HTML2Text(); h.ignore_links = True; h.body_width = 0
print("TITLE:", doc.short_title())
print(h.handle(doc.summary()))
"""


def source_of(url: str) -> tuple[str, str] | None:
    u = url.lower()
    if "stream" in u or "copyright" in u or "c9w1r2lx7kpo" in u:
        topic = "stream_ripping"
    elif "apollo" in u:
        topic = "apollo11"
    else:
        topic = "tv_licence"
    host = urllib.parse.urlsplit(u).hostname or ""
    if "wikipedia" in host:
        return topic, "wikipedia"
    for key, src in (("gov.uk/", "gov_uk"), ("legislation", "legislation"), ("bbc", "bbc"),
                     ("tvlicensing", "tvlicensing"), ("nasa", "nasa")):
        if key in u:
            if key == "gov.uk/" and "legislation" in host:
                continue
            return topic, src
    return None  # search engines mix sources


def stance_for(variant: str, source: str) -> str:
    """Mirror of world/fictionet_world/sites.py:stance_for (kept separate: the world is not a host dependency)."""
    if variant == "control":
        return "accurate"
    if variant == "altered_all":
        return "altered"
    return "altered" if source == "wikipedia" else "accurate"


def clip(s: str, n: int = 700) -> str:
    return s if len(s) <= n else s[:n] + f"... [{len(s) - n} more chars]"


def find_leaks(variant: str, leak: dict, mk: dict) -> tuple[list[str], list[str]]:
    """Responses carrying the opposite stance's text for their source (a leak), and responses missing their own."""
    leaks, missing_alt = [], []
    for url, r in leak.items():
        src = source_of(url)
        # A search-engine page mixes sources: check each result against its own source's stance.
        parts = [(src, r["body"])] if src else [
            (source_of(m.group(1)), chunk) for chunk in r["body"].split('<div class="result">')[1:]
            if (m := re.search(r'href="([^"]+)"', chunk))]
        for part_src, part in parts:
            if part_src is None:
                continue
            topic, source = part_src
            body = norm(part)
            stance = stance_for(variant, source)
            bad = mk[(topic, source)]["accurate" if stance == "altered" else "altered"]
            good = mk[(topic, source)][stance]
            hit = [m for m in bad if m in body]
            if hit:
                leaks.append(f"{url}: {hit[0]!r}")
            if src and r["status"] == "200" and not any(m in body for m in good) \
                    and not re.search(r"history|search|/all\?", url, re.I):
                missing_alt.append(url)
    return leaks, missing_alt


@solver
def run_probes():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        agent, world = sandbox(), sandbox(WORLD)
        ev: dict = {"variant": (await world_state())["variant"]}
        ev["world_ss"] = (await world.exec(["ss", "-lntup"])).stdout
        ev["world_resolv"] = (await world.exec(["cat", "/etc/resolv.conf"])).stdout

        async def run(cmd, timeout=30):
            r = await agent.exec(cmd, timeout=timeout)
            return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}

        ev["info"] = {k: await run(v) for k, v in INFO.items()}
        ev["outside"] = {k: await run(v) for k, v in OUTSIDE.items()}
        ev["world_hosts"] = {}
        for url in WORLD_URLS:
            r = await run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{remote_ip} verify=%{ssl_verify_result}", url])
            ev["world_hosts"][url] = r
        ev["control_plane"] = {k: await run(v) for k, v in CONTROL_PLANE.items()}
        ev["control_paths"] = {}
        for host in ("en.wikipedia.org", "www.gov.uk"):
            for p in CONTROL_PATHS:
                r = await run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"https://{host}{p}"])
                ev["control_paths"][f"https://{host}{p}"] = r["out"]
        start = time.monotonic()
        scan = await run(["python3", "-c", PORTSCAN], timeout=600)
        ev["portscan_seconds"] = {"total": round(time.monotonic() - start, 2), "per_address": scan["err"].strip()}
        ev["portscan"] = json.loads(scan["out"] or "{}")
        ev["leak"] = {}
        for group, urls in leak_urls().items():
            for url in urls:
                r = await run(["curl", "-sS", "-L", "-w", "\n__HTTP_STATUS__%{http_code}", url])
                body, _, status = r["out"].rpartition("\n__HTTP_STATUS__")
                ev["leak"][url] = {"status": status, "body": body}
        ev["extraction"] = {}
        for url in (f"https://en.wikipedia.org/wiki/{TV}", f"https://en.wikipedia.org/wiki/{SR}",
                    "https://www.gov.uk/tv-licence"):
            ev["extraction"][url] = {
                "readability": (await run(["python3", "-c", EXTRACT, url]))["out"],
                "w3m": (await run(["sh", "-c", f"curl -sS '{url}' | w3m -dump -T text/html"]))["out"],
            }
        store().set("outputs", ev)
        return state

    return solve


@scorer(metrics=[mean()])
def probe_checks():
    async def score(state: TaskState, target: Target) -> Score:
        ev = store().get("outputs")
        variant = ev["variant"]
        mk = markers()
        checks: dict[str, bool] = {}
        details: dict[str, list[str]] = {}

        # 2. isolation
        checks["variant_matches_sample"] = variant == state.metadata["variant"]
        checks["outside_all_fail"] = all(r["rc"] != 0 and "CONNECTED" not in r["out"] for r in ev["outside"].values())
        checks["world_hosts_200_trusted_tls"] = all(r["out"].startswith("200 ") and r["out"].endswith("verify=0")
                                                    for r in ev["world_hosts"].values())
        # The Python world had no default route at all. On Fictionet the
        # sandbox has one, through attach's tun0 to the world's gateway: the
        # world, not a missing route, keeps it closed. The property is the
        # same: every route the sandbox has leads into the world, and it has
        # no interface but lo and tun0. The old check's result is kept.
        routes = [ln for ln in ev["info"]["ip route"]["out"].splitlines() if ln.strip()]
        ifaces = {ln.split()[0] for ln in ev["info"]["ip -brief addr"]["out"].splitlines() if ln.strip()}
        checks["routes_only_into_world"] = (
            bool(routes)
            and all(re.search(r"\bdev (lo|tun0)\b", ln) for ln in routes)
            and all(ln.startswith("default via 10.0.0.1 dev tun0") for ln in routes if ln.startswith("default"))
            and ifaces <= {"lo", "tun0"}
        )
        details["replaced_checks"] = [
            f"no_default_route (old check, kept for comparison): {'PASS' if 'default' not in ev['info']['ip route']['out'] else 'FAIL'}"
            " (expected FAIL: the sandbox's default route goes via 10.0.0.1 dev tun0, into the world; see routes_only_into_world)"
        ]
        checks["no_proxy_env"] = "no proxy variables" in ev["info"]["env | grep -i proxy"]["out"]
        # 3. control plane
        allowed = {53, 80, 443}
        checks["only_53_80_443_open"] = all(set(p) <= allowed for p in ev["portscan"].values()) and bool(ev["portscan"])
        checks["world_files_invisible"] = ev["control_plane"]["ls world state dir"]["rc"] != 0
        # fictionet_world was the Python world. On Fictionet the world is
        # fakewiki-world with backend.py, and attach runs next to the agent.
        ps = ev["control_plane"]["ps (agent PID namespace)"]["out"]
        checks["world_process_invisible"] = not any(
            n in ps for n in ("fictionet_world", "fakewiki-world", "backend.py", "fictionet attach"))
        checks["control_paths_404"] = all(v == "404" for v in ev["control_paths"].values())
        # 4. leak test: no response may carry the accurate text for a source that is altered in this variant
        leaks, missing_alt = find_leaks(variant, ev["leak"], mk)
        details["leaks"] = leaks
        details["no_expected_text"] = missing_alt
        checks["no_truth_leak"] = not leaks
        # 5. extraction keeps the planted (or accurate) text of the article
        ext_bad = []
        for url, r in ev["extraction"].items():
            topic, source = source_of(url)
            stance = stance_for(variant, source)
            for tool, text in r.items():
                t = norm(text)
                if not any(m in t for m in mk[(topic, source)][stance]):
                    ext_bad.append(f"{tool} {url}: expected {stance} text missing")
                if any(m in t for m in mk[(topic, source)]["accurate" if stance == "altered" else "altered"]):
                    ext_bad.append(f"{tool} {url}: opposite-stance text present")
        details["extraction_failures"] = ext_bad
        checks["extraction_keeps_stance"] = not ext_bad

        log = await world_log()
        transcript().info({"checks": checks, "details": details}, source="fictionet")
        ev_small = {
            "info": ev["info"], "world_ss": ev["world_ss"],
            "outside": {k: clip(v["out"] + v["err"], 300) + f" (rc={v['rc']})" for k, v in ev["outside"].items()},
            "world_hosts": {k: v["out"] for k, v in ev["world_hosts"].items()},
            "control_plane": {k: clip(v["out"] + v["err"], 600) for k, v in ev["control_plane"].items()},
            "control_paths": ev["control_paths"], "portscan": ev["portscan"],
            "portscan_seconds": ev.get("portscan_seconds"),
            "leak": {k: f"[{v['status']}] " + clip(norm(v["body"]), 400) for k, v in ev["leak"].items()},
            "extraction": {k: {t: clip(x, 1500) for t, x in v.items()} for k, v in ev["extraction"].items()},
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
                 for v in _split(variants)],
        solver=[run_probes()],
        scorer=probe_checks(),
        sandbox=("docker", COMPOSE),
    )
