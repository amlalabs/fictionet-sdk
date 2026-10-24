# Search

Build the shared workstation image once on Linux with KVM, `qemu-system-x86_64`,
`qemu-img`, `curl` and `sha256sum` installed:

```sh
rustup run 1.99.0 cargo xtask search-image demos/downloads/cloudimage
```

The command verifies the pinned Ubuntu cloud disk, kernel and initrd and Cloud
Hypervisor, then installs Xfce, Firefox, Claude Code, Codex, Python and the guest
settings in a temporary VM. It writes `search-workstation.qcow2` atomically after
successful shutdown. Construction needs the internet; the resulting workstation
boots without downloading or installing software. Rebuilding replaces the image
for subsequent launches; running guests retain their existing image.

Run the demo with a host-held Claude token:

```sh
CLAUDE_CODE_OAUTH_TOKEN_FILE=/path/to/claude-oauth-token \
  rustup run 1.99.0 cargo run --release -p fictionet-search-demo --bin search -- \
  demos/downloads/cloudimage
```

The image contains no provider credentials, run CA, SSH identity or run clock.
A read-only settings disk applies the run's root certificate, fresh SSH public
key and placeholder Claude credential before SSH and the desktop start. The real
Claude token stays on the host. `claude` opens ready to work. Each launch writes
to a fresh disk overlay; the prepared image stays unchanged. All demo flows use
this workstation. The terminal uses ghostty-web and a persistent tmux session;
Screen shows Firefox. Terminal text starts at 19 px on a dark background in both
page themes; the text controls adjust its size and the expand control widens the
agent pane. Pass `preview` instead of the downloads folder to run without a VM.

On the workstation, a before-and-after run reached full readiness in 63.384 s
with boot-time installation and 7.213 s with the prepared image. Desktop readiness
was 63.088 s and 7.208 s. A subsequent warm boot reached full readiness in
5.890 s. The prepared boot recorded zero upstream attempts;
Firefox's start page was served inside the world. Corpus loading and indexing
were 0.468 s before and 0.532 s after, with no indexing changes. The image build
took 98 s using the existing verified Ubuntu downloads and produced a standalone
4.0 GiB disk. These are single-run wall-clock measurements, excluding compilation.

`preview` needs no downloads or API keys. It uses the world's corpus when
available, otherwise a small embedded sky.org capture. Its labeled client makes
real requests inside the world. Model calls appear when an agent uses the
gateway; preview does not invent provider traffic.

[app/src/main.rs](app/src/main.rs) assembles the workstation and its owned page.
[app/src/network.rs](app/src/network.rs) connects the model gateway and local
startup services. Search explicitly reports typed facts from its request and
tool handlers, its name resolver and the typed no-route callback on its network.

[app/src/page/](app/src/page/) projects those facts into the map, site details,
model calls and recent activity. Selecting a site or gateway keeps the map
above its details while the agent remains visible. The scrubber replays the
retained observation history; the agent stays live. The World menu chooses the page source or restarts world pages.
The last 1024 observations are kept for rewind. Observed internet destinations
and sign-in policy survive activity expiry and page restarts. Each launch writes its facts to a separate
`<downloads>/search/run-<uuid>.jsonl` with RFC 3339 wall-clock timestamps and
owner-only permissions. Preview records are under `demos/downloads/search-preview/`.
Request credentials are redacted before entering the observation channel; request
bodies are not retained. Header details show only values retained by recording.
The map draws internet
routes from upstream facts, including host page-writer calls, rather than from
model call activity. Local and rejected model requests therefore leave the
internet wire dark. The activity feed updates one row per upstream attempt;
the run record retains each transport phase.

Page and search request bodies are limited to one MiB, including chunked requests; larger
bodies receive 413 before routing. The observation queue holds at most 256 facts,
including one reserved failure notification. A burst or a fact larger than 256
KiB fails recording explicitly; the app stops instead of silently losing facts.

The page prints a loopback URL with its run token. Browser libraries are served
locally. Recorded page previews are inert and cannot run scripts or contact
sites. Capture dates are shown only when the archive records them.

## Page sources

- **Copied** replays WARC responses at their real URLs. A crawler builds one
  BM25 index from their titles and text. Google, Bing and DuckDuckGo render that
  index in their own layouts. Results rank by distinct query-term coverage,
  then BM25 score. A result must cover a majority of the terms; unrelated
  searches have no results. Counts come from the index before pagination.
  Missing URLs on captured hosts return 404. Uncaptured hosts return NXDOMAIN,
  apart from the caller's declared model and sign-in services.
- **Model-written** writes pages from a prose brief, prior mentions and stored
  claims. The app chooses the host-held Claude token first, then
  `OPENROUTER_API_KEY`, then `ANTHROPIC_API_KEY`. The page writer uses its own
  host-side model client; it does not send its credential through the guest.
  Failed calls do not invent fallback articles.
- **Live** uses `EXA_API_KEY` for [Exa search](https://github.com/exa-labs/openapi-spec/blob/master/exa-openapi-spec.yaml).
  Results retain their order, titles, URLs and snippets in each engine's skin.
  The World menu shows why a source is unavailable: missing captures, a page
  writer or a search key. Other sources remain usable.

Live downloads result pages and requisites, following navigation to depth five
within each result's site. Redirects and cross-host assets are retained at their
real URLs. Live search and capture use a separate host HTTP transport, outside
the guest model gateway; selecting Live permits public-web downloads. Search
queries and served pages are logged and displayed. The crawler ignores
robots.txt and limits requests per host. Unknown URLs do not start downloads.
The page reports the source that answered each request. Keep Copied selected
for the bounded security research and offline package flows.

The content audit applies to text the world writes. Replayed WARC responses carry
capture provenance and are outside that scope; their words are not allowlisted.

## Provider boundary

Every world-served HTTPS host uses the Zscaler look-alike chain from
`fictionet-extras`, with its root installed in the guest. The prepared image
contains the software; boot has no installation window or download forwarding.
Interactive provider sign-in, guest token refresh and API key creation stay
closed throughout the run. This app provides no Codex sign-in or tokenless
Claude sign-in flow.

The host reads `CLAUDE_CODE_OAUTH_TOKEN_FILE` at startup. The guest receives a
placeholder OAuth token; the gateway substitutes the real token only when
forwarding an admitted Anthropic request. The long-lived token does not refresh
inside the guest. Account provisioning and any refreshable credentials belong
on the host. Startup checks and host-token policy reads are answered locally.
The gateway restricts operational account, catalog and usage reads to specific
provider paths and methods; these exceptions are policy, not evidence that a
request occurred.

The world's observations report sign-in policy and upstream attempts, responses
and failures. An attempt means the request entered the host transport, not that
a connection succeeded. Model gateway and page-writer requests share this
observed provider transport. Local startup responses and rejected requests do
not produce an upstream attempt. Live's host search and capture transport is
separate from this provider boundary.

Provider URL image, document and file sources and unsupported server tools are
refused before web-tool splicing, including requests mixing allowed web tools
with unsupported features. Inline data and client tool arguments containing URLs
remain usable. Provider-native search and fetch become client functions answered
from the world's pages; they do not reach the provider as native web tools.

## Briefs

A file in [seeds/](seeds) has a world date and free-text instructions:

```toml
+++
date = "2026-10-21"
+++
```

Write the world's full brief after the closing marker: what is true, what the
sites contain and which sources matter. Optional `[[fixed]]` entries retain
`url`, `file`, `title`, `description` and `content_type`; their files are served
verbatim. For the VM demo, the brief's date is replaced by the run day. The guest
inherits the host clock; HTTP dates and certificates use the run clock. The
standalone world can still run against a brief's historical date.
Search ranking receives the prose without special treatment for named sites.
Eval questions live in the Python task's `QUESTIONS` mapping.

## Corpus

The default world is [security](seeds/security.md). Its `[corpus]` front matter
chooses the capture directory under `demos/downloads/` and the starting URLs.
The app opens that declaration; it does not choose a topic or URL list itself.
The capture contains MITRE ATT&CK techniques, CISA advisories, NIST guidance,
and researcher and vendor analyses of tj-actions, Shai-Hulud, SolarWinds,
XZ, 3CX, Codecov and PyTorch nightly. It is a bounded
collection; links beyond the captures have no public-web fallback.

WARCs are stored in `demos/downloads/security/`, outside git, with their wget
logs. Capture the URLs in the seed with:

```sh
wget --page-requisites --span-hosts --compression=auto --delete-after \
  --inet4-only --no-http-keep-alive --wait=0.3 --timeout=30 --tries=2 \
  --warc-file=<directory>/<name> <URLs>
```

Use a separate WARC name for each batch. Keep original URLs, redirects, HTTP
headers and response bodies; do not rewrite links or unpack the archives.
Microsoft's site required a browser User-Agent. Referenced NIST PDFs are also
captured. Some upstream optional images and fonts return errors in the original
sites and retain those errors in replay.

The downloaded-corpus acceptance test runs separately from the offline unit
tests, and fails if its captures are missing or sources cannot be replayed:

```sh
rustup run 1.99.0 cargo test -p web-world --test corpus -- --nocapture
```

Set `SEARCH_DOWNLOADS` to another downloads root when testing captures outside
this checkout. The test searches the real index, fetches citations through the
world, and checks empty results without booting a VM or opening the demo port.
The previous astronomy captures remain in `demos/downloads/astronomy/`.

### Packages

The corpus's `packages/` directory holds separate WARCs for PyPI indexes,
wheel metadata and distributions, and GitHub source archives. These sites
always replay locally, including in Model-written mode. There is no upstream
transport. Missing distributions return 404, and a missing project cannot
fall through to a generated page. Captured site 404 pages and their assets
also supply missing-page responses for the research sources.

Capture the research sources and packages with Python 3.12 and pip available
on the host:

```sh
rustup run 1.99.0 cargo xtask search-capture demos/downloads <python-with-pip>
```

The command retains existing captures, resolves research tools with pip,
and captures their dependency closure at the original PyPI URLs. It includes
requests, pandas, numpy, matplotlib, beautifulsoup4, scipy, networkx, pyyaml,
packaging, rich and pytest. The wheel selection targets the workstation's
Python 3.12 on Linux x86-64. Requests, NetworkX and Click source archives are
available at the tagged GitHub archive URLs declared in the capture command.
Other versions and platforms require their own captures.

The package acceptance test runs real pip through a loopback proxy backed by
the world's HTTP handler, with its CA trusted and no upstream transport. It
checks installation, package imports, plotting, and a GitHub archive download:

```sh
SEARCH_PYTHON=<python-with-pip> rustup run 1.99.0 cargo test -p web-world --test packages -- --nocapture
```

It uses a temporary installation directory and disables pip's cache. Set
`SEARCH_DOWNLOADS` to test another downloads root. Neither acceptance test
boots the VM or uses the demo's port.

## Code

The world's page modules separate routing, generation, listings, stored pages,
corrections and model tools. Prompt construction and answer parsing are separate.
The WARC reader, crawler, BM25 index, model gateway and credential transport live in
`fictionet-extras`. The shared demo kit supplies VM lifetime, prepared images
and SSH console sockets. Search owns its HTML, styles and JavaScript, including copies of the
terminal and screen pieces. ghostty-web 0.4.0 and noVNC 1.7.0, with their
licenses, live in `demos/kit/assets`.
