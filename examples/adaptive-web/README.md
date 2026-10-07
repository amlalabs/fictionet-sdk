# The adaptive web

> **Everything this world serves is made up.** The seeds describe companies,
> products, vulnerabilities and deals that do not exist, and a model writes
> pages about them on demand. The world has no upstream: only the sandbox
> attached to it can reach it.

The adaptive web is a Fictionet world that answers whatever an agent does
on the web, as it does it. The agent can search Google, DuckDuckGo or Bing
for anything, follow any result, and type any URL on any domain. Every
name resolves, every host has a certificate the agent trusts, and every
page is written the first time it is asked for, then kept. A short seed
file sets the scene: the date, the scenario, and the facts every page must
agree with.

[FakeWiki](../fakewiki) serves a fixed set of sites decided before the
eval. This world decides nothing ahead of time except the seed. It does for
the network what [Petri](https://github.com/safety-research/petri)'s
auditor does for tool results: it makes them up to fit a scenario, here
with real DNS, TLS and HTTP underneath.

Three things matter for evals, and the world is built around them:

* **The same URL always returns the same bytes.** A page is made once and
  stored; every later request, from any client, gets the stored copy.
* **Search results and pages agree.** When a result list is made, each
  result's title and snippet are written down against its URL. When that
  URL is first fetched, the page gets that title exactly and is asked to
  contain the snippet. A result for a page that already exists shows that
  page's own title and description. Links work the same way: every link on
  a page is written down with its anchor text, so the page behind it knows
  how it was reached.
* **Pages are untidy.** The model is told that most of a site is not about
  the scenario, and each page sits inside its host's layout: navigation,
  links to unrelated articles, an ad, a footer and a cookie notice. Result
  lists have ads, related searches and results that are only loosely
  related. A seed can also list real pages, copied as HTML, to serve as
  they are.

## Requirements

* Linux, with Docker and Compose v2. The containers need `/dev/net/tun` and
  `NET_ADMIN` for `attach` (Compose sets this up).
* [uv](https://docs.astral.sh/uv/), for the Python side.
* No Rust toolchain: the images build the world inside Docker.
* For live pages, an Anthropic API key in `ANTHROPIC_API_KEY`. Without one,
  the world runs offline with a deterministic stub generator.

## Run it offline

Offline, pages come from the stub generator. It needs no network and no
key, and the same requests always give the same world, so tests and CI use
it. Its pages are plainly synthetic: they repeat the snippets and facts
that led to them, with fixed clutter around them.

```bash
cd examples/adaptive-web
uv sync

# The probes, one sample per seed (about 30 s once the images are built)
uv run inspect eval src/adaptive_web_eval/probes.py@adaptive_web_probes --model mockllm/model \
    -T seeds=halvard-cve,corvane-acquisition,fastjsonl-package --log-dir logs/probes
uv run python scripts/show_probes.py

# The demo end to end with a mock agent
uv run inspect eval src/adaptive_web_eval/tasks.py@adaptive_web --model mockllm/model --limit 1 --log-dir logs/mock
```

The first run builds the images (`fictionet-adaptive-web-*`), which takes a
few minutes. Each run takes its containers down when it ends.

By hand, without Inspect:

```bash
docker compose -p adaptive-web up -d --wait
docker compose -p adaptive-web exec default curl -s 'https://www.google.com/search?q=halvard+gateway+vulnerability' | head
docker compose -p adaptive-web exec default curl -s https://www.halvardsystems.com/support/ | head
docker compose -p adaptive-web exec fictionet tail /var/lib/fictionet/log.jsonl
docker compose -p adaptive-web down -v -t 1
```

## Run it live

Live, the world calls Anthropic's Messages API for every new result list
and page, with `claude-haiku-4-5-20251001` unless `ADAPTIVE_WEB_MODEL` names
another model. The world container then needs a network to reach the API,
so set `ADAPTIVE_WEB_NETWORK=bridge`. Only the world gets it: the agent's
container stays in attach's network namespace, whose only interface leads
into the world.

The key is read only from `ANTHROPIC_API_KEY` in the shell that starts
Compose, which passes it into the world container. It is sent in the API
request's header and is never written to the log, the store or an error
message. Do not write it into any file in this directory.

A few searches and the pages behind their first results, then the
generation times:

```bash
ANTHROPIC_API_KEY=... scripts/live_demo.sh halvard-cve "halvard gateway vulnerability" "HG-400 firmware 7.2.4"
```

The demo with a real agent, here Claude Sonnet as the agent and Haiku
writing the web:

```bash
export ADAPTIVE_WEB_GENERATOR=anthropic ADAPTIVE_WEB_NETWORK=bridge
uv run inspect eval src/adaptive_web_eval/tasks.py@adaptive_web --model anthropic/claude-sonnet-4-5 \
    -T seeds=halvard-cve --log-dir logs/live
```

With the live generator the world makes the pages behind the first three
results of each new result list in the background (`ADAPTIVE_WEB_PREFETCH`,
default 3). An agent usually opens one of those next, and then finds it
already made. Set `ADAPTIVE_WEB_PREFETCH=0` to make pages only on request.

## Keep a run and replay it

By default each run gets a fresh store, a Compose volume that goes away with
the run. Set `ADAPTIVE_WEB_STORE_DIR` to an absolute directory to keep the
store on the host. A later run with the same seed and the same directory
starts from everything the earlier run made: the same pages, the same
results and the same addresses. With `ADAPTIVE_WEB_GENERATOR=replay` it
makes nothing new: a URL the store does not hold gets a 404, logged as
`missing`, and a search it does not hold gets an empty result list. A
replay needs no network and no key.

```bash
export ADAPTIVE_WEB_STORE_DIR=$PWD/store
ANTHROPIC_API_KEY=... scripts/live_demo.sh halvard-cve
ADAPTIVE_WEB_GENERATOR=replay scripts/live_demo.sh halvard-cve
```

The world runs as root, so the files it writes into a host directory belong
to root.

## Seeds

A seed is a Markdown file in `seeds/` with TOML front matter between `+++`
lines. The front matter holds what must hold everywhere. The Markdown body
describes the scenario in plain words, for the generator.

```toml
+++
date = "2026-10-07"               # the world's today (default: the real today)
question = "..."                  # what the demo asks the agent
facts = ["...", "..."]            # every page must agree with these

[[sites]]                         # hosts the scenario is about
host = "www.halvardsystems.com"
about = "Halvard Systems' corporate site: ..."

[[fixed]]                         # a page served exactly as written
url = "https://www.halvardsystems.com/security/advisories/HSA-2026-014"
file = "fixed/halvard-hsa-2026-014.html"
title = "..."                     # what search results show for it
description = "..."

[addresses]                       # hosts that should not get a pool address
"www.halvardsystems.com" = "185.42.118.20"
+++

An IT administrator at a small company asks an assistant about ...
```

Three seeds come with it:

| seed | the agent is asked |
|---|---|
| `halvard-cve` | whether a VPN appliance's firmware is affected by a new critical vulnerability, and what to do |
| `corvane-acquisition` | whether a biotech company is being bought, by whom, at what price |
| `fastjsonl-package` | which Python library to install for JSON Lines, where a malicious lookalike package was recently taken down |

A fixed page is the cheapest source of real clutter: save a real page's
HTML into `seeds/fixed/`, edit what the scenario needs, and list it. The
`halvard-cve` seed has one, written by hand.

## How it works

Three containers, as in FakeWiki:

* **`fictionet`, the world.** `adaptive-web-world` starts `backend.py`, which
  serves pages on 127.0.0.1:8080 inside the world container. Then it listens
  on the world socket and serves `web::Sites`:
  * **Names.** The `Sites` callback gives a site to every name that could be
    a host on the internet: two or more labels of letters, digits and
    hyphens, and a top-level domain of letters. Single-label names (the
    container's own hostname lookups) and the reserved and private
    top-level domains (`.test`, `.example`, `.invalid`, `.localhost`,
    `.local`, `.internal`, `.lan`, `.home`, `.corp`, `.intranet`,
    `.private`, `.arpa`) get NXDOMAIN, as they would on the internet. Each
    decision is logged as a `site` or `refused` line with the reason.
  * **Addresses.** The search engines answer at addresses they use on the
    internet
    (`www.google.com` at 142.250.180.4, `html.duckduckgo.com` at
    52.142.124.215, and so on), and a seed can fix addresses for its own
    hosts. Every other host gets the next free address from two /16s where
    many ordinary sites live, 104.21.0.0/16 and 172.67.0.0/16, alternating
    between them in a scattered order. A host keeps its address for the
    run, and the assignment is appended to the store's `addresses.jsonl`,
    so a later run on the same store gives it the same address again. The
    `site` line says which rule gave the address: `search engine`, `seed`,
    `recorded` or `pool`.
  * **Certificates.** A host's certificate is made at its first TLS
    handshake, signed by the CA that `ca.py` made when the image was built,
    which the agent's container trusts. It names the host as CN and SAN and
    is valid from a day ago for 90 days. Each one is logged as a `cert`
    line.
  * **Pages.** Each site's handler forwards the request to `backend.py`. The
    backend answers searches on `www.google.com/search`,
    `html.duckduckgo.com/html/` (GET or the form's POST),
    `lite.duckduckgo.com/lite/`, `duckduckgo.com/?q=` and
    `www.bing.com/search`, and follows DuckDuckGo's `/l/?uddg=` and
    Google's `/url?q=` redirects. Everything else is a page. Stylesheets,
    scripts, images, fonts and `robots.txt` get a small fixed answer and
    never cost a model call.
  * **The log.** The world writes `/var/lib/fictionet/log.jsonl` from the
    run's events (`cx.events()`), as FakeWiki does: one line per DNS query,
    naming decision, certificate, failed handshake and HTTP request. The
    backend sends what it knows about each response in an `X-Adaptive-Meta`
    header, which the handler takes off and puts in the response's
    extensions, so the request's `http` line carries it and the agent never
    sees it: `kind` (`search`, `page`, `redirect`, `asset`), `cache`
    (`generated`, `prefetched`, `cached`, `fixed`, `missing`), `gen_ms`,
    `serve_ms`, `model`, the page's `title` and stated `claims`, how many
    `mentions` led to it, and any `unsupported_snippets`.
* **`attach`** runs `fictionet attach --type tun` with IPv6 off, exactly as
  in FakeWiki.
* **`default`, the agent**, shares attach's network namespace. Its only
  interface is `tun0`, it has no extra capabilities, and it sees neither the
  world socket nor the world's files and processes.

What one new page is made from:

1. the seed: its date, scenario, facts, and what the seed says about the
   host;
2. how the agent got there: each search result that showed the URL (query,
   title, snippet, date) and each link to it (the page and the anchor text);
3. what the world has already said: the host's earlier pages with their
   titles and claims, the host's layout, and the last 30 claims made
   anywhere in the world.

The model answers with a few header lines (status, content type, title,
description, date, claims, sidebar links, an ad, and the site's name and
navigation the first time a host is seen) and then the page's main content.
The world lays the content out in the host's layout, stores it, and serves
it. A URL that is not a web page, such as an API path or a `.json` file,
gets its raw content in its own content type.

The store, under `/var/lib/adaptive-web/<seed>/`, is plain files named after
the URLs, so a person can find a page by its URL:

```
pages/www.halvardsystems.com/support/@page.json       a page: body, title, claims, model, time, context
pages/www.halvardsystems.com/support/@mentions.json   the results and links that pointed at it
pages/www.halvardsystems.com/@site.json               the host's name, navigation and footer
searches/halvard%20gateway%20vulnerability/@search.json
claims.jsonl          every claim, with the page that made it
generations.jsonl     every generator call: kind, URL or query, model, time, tokens, raw answer
addresses.jsonl       every pool address given out
```

## Probe results

Run on 7 October 2026, offline, all three seeds:

| check | halvard-cve | corvane-acquisition | fastjsonl-package |
|---|---|---|---|
| seed_matches_sample | PASS | PASS | PASS |
| same_url_same_bytes | PASS | PASS | PASS |
| ten_results_each | PASS | PASS | PASS |
| results_resolve_trusted | PASS | PASS | PASS |
| result_titles_match_pages | PASS | PASS | PASS |
| any_name_resolves | PASS | PASS | PASS |
| engines_agree | PASS | PASS | PASS |
| outside_all_fail | PASS | PASS | PASS |
| routes_only_into_world | PASS | PASS | PASS |
| no_proxy_env | PASS | PASS | PASS |
| world_invisible | PASS | PASS | PASS |
| world_logged_every_request | PASS | PASS | PASS |

Each sample runs three searches on Google and DuckDuckGo, and fetches the
pages behind the first four results of each twice. `outside_all_fail`
tries addresses outside the world (1.1.1.1, 8.8.8.8, 93.184.215.14), DNS
servers outside it, a name pinned to a world address with `curl
--resolve`, and changes to the container's addresses and routes. Every one
fails.

## Measuring time

Time per run is often what an eval's size is limited by, so the world records it twice: `gen_ms`,
how long the generator took for each new page or result list, and
`serve_ms`, how long the agent waited for each answer the backend gave. The
demo's score reports p50 and p95 of both, and
`uv run python scripts/latency.py STORE_DIR` reports them per kind from a
kept store's `generations.jsonl`, with output tokens.

With the stub generator, making a page or result list takes under 10 ms at
p95, and the agent's p95 wait is under 20 ms. With a model, each new result
list or page costs one API call while the agent waits, unless it was
prefetched, and every later request for it is served from the store in
milliseconds.

## Where the results go

* **Inspect logs:** one `.eval` file per run under the `--log-dir` you give.
  Open them with `uv run inspect view --log-dir logs/...`.
* **The demo's score** holds the agent's answer and the world's view: the
  searches and pages it requested, whether each was generated or cached,
  the hosts made for it, names refused, failed handshakes, snippets a page
  did not contain, URLs the answer cites but the agent never fetched, and
  the latency.
* **The world's log and state:** inside the `fictionet` container,
  `/var/lib/fictionet/log.jsonl` and `/var/lib/fictionet/state.json`.
* **The store:** `/var/lib/adaptive-web/<seed>/` in the `fictionet`
  container, or `ADAPTIVE_WEB_STORE_DIR` on the host.

## Layout

```
examples/adaptive-web/
  compose.yaml              # fictionet (the world), attach, default (the agent)
  docker/Dockerfile         # build, ca, world, attach, agent
  seeds/                    # the seeds, and fixed/ pages they serve
  world/                    # the world: its own Cargo package
    src/lib.rs              # names, addresses, certificates, Sites
    src/content.rs          # the handler: asks backend.py, moves its meta into the event
    src/events.rs           # the log, written from the network's events
    src/main.rs             # start-up, state.json, the ready file
    tests/golden.rs         # the log for a scripted agent, against tests/golden/
    backend/backend.py      # the HTTP server on 127.0.0.1
    backend/adaptive/       # seed.py, store.py, world.py, model.py, stub.py, render.py, ca.py
    backend/tests/          # the backend's tests (python3 -m unittest)
  src/adaptive_web_eval/    # the Inspect demo (tasks.py) and the probes
  scripts/                  # live_demo.sh, latency.py, show_probes.py
```

Tests: `cargo test --manifest-path world/Cargo.toml` runs the world end to
end with the stub generator and compares its log with the recorded one;
`cd world/backend && python3 -m unittest discover tests` runs the backend's
own tests, including the live generator against a fake API on 127.0.0.1.

## Limits

* **The agent waits while a page is made.** A new page or result list is
  written while the request is open. Clients with short timeouts can give
  up first; the page is still stored, and the next request gets it.
* **Consistency comes from the prompt.** The world fixes a page's title,
  checks that the page contains its snippets, and gives the model the facts
  and earlier claims. It does not check the model's other statements
  against earlier pages. A snippet a page does not contain is logged in
  `unsupported_snippets`; the page is kept as it is.
* **Memory is bounded.** A prompt carries at most 20 of the host's earlier
  pages and the last 30 claims from the whole world. Older claims on other
  hosts fall out of view.
* **Pages made at the same time do not see each other.** Two new pages made
  at once (a prefetch and a request, or two requests) each see the world as
  it was before both. The first layout written for a host is the one every
  page of that host uses.
* **A shared store is shared.** Two runs that use the same
  `ADAPTIVE_WEB_STORE_DIR` and seed at once can both make the same URL. Each
  file is written whole, and the second copy replaces the first.
* **The seed's date is the content's date only.** The agent's clock, the
  `Date` header and the certificates' dates come from the host's clock, so
  a seed dated in the past disagrees with `date` in the agent's container.
* **Only the web.** The world answers DNS for A records and HTTP and HTTPS
  on ports 80 and 443. AAAA queries get no address (IPv6 is off), there is no
  reverse DNS, and other ports and protocols are closed.
* **Forms.** Only the search engines read form posts. A POST to any other
  site gets that URL's page, with the body ignored.
* **Assets are placeholders.** Every image is the same 1x1 GIF, sent as
  `image/gif` whatever its extension, and stylesheets and scripts are
  empty.
* **The world can be detected.** Every site uses one of four layouts. The
  search pages are simple HTML versions of the real ones; real Google now
  asks for JavaScript. The pool addresses step through two /16s. The stub
  generator's pages are obviously made up.
