# Search

Build the shared workstation image once on Linux with KVM, `qemu-system-x86_64`,
`qemu-img`, `curl` and `sha256sum` installed:

```sh
rustup run 1.99.0 cargo xtask search-image demos/downloads/cloudimage
```

The command verifies the pinned Ubuntu cloud disk, kernel and initrd and Cloud
Hypervisor, then installs Xfce, Firefox, Claude Code, Codex, Python and the guest
settings in a private build VM. Ubuntu packages come from the fixed
`20261023T000000Z` [archive snapshot](https://snapshot.ubuntu.com/). Firefox's
Debian archive and the Claude and Codex releases are pinned and checksum-checked.

Before publishing, the candidate boots normally with upstream networking blocked.
The builder checks Xfce, the Firefox window, the terminal settings and a Python
virtual environment on a disposable overlay, then checks the compacted qcow2.
Each VM returns its own completion result on its attached disk; shared summary logs never authorize a
build. Partial downloads and progress logs belong to that build too.
`search-image-build.log` and `search-image-verify.log` retain the latest completed
stages for inspection.

Only a verified candidate atomically replaces `search-workstation.qcow2`.
Construction needs the internet; the resulting workstation boots without
downloading or installing software. Running guests retain their existing image.
Every invocation rebuilds from the verified Ubuntu base. To reproduce the tested
software, run the command twice and compare its printed `Installed package set`
digests; these cover every installed Debian package and version. Guest identities
and filesystem allocation can differ between builds.

Two overlapping clean builds completed in 199 s and 232 s and returned the same
installed-package digest:
`d8478626a1fc70965055f8ac2ff8f961310f01fb38cb0e65e457be830f0b0f28`.
Both passed the desktop boot check. A separate Search demo run reached readiness
in 7.312 s, searched for the XZ backdoor, followed a captured source, wrote a cited
file, ran Python and installed `requests` into a virtual environment. Its record
contained zero upstream attempts. Desktop and laptop screenshots showed both the
terminal and Firefox. These measurements exclude compilation; the two builds ran
concurrently and downloaded their packages from the fixed snapshot.

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

The page binds to localhost without authentication. Browser libraries are served
locally. Recorded previews cannot execute scripts or contact upstream sites.
Capture dates appear when the archive records them.

## Page sources

- **Copied** serves offline English Wikipedia, Python, Rust, MDN and GitHub documentation,
  and the captured security sources at their original URLs. A prepared Tantivy
  index ranks partial matches by BM25 with extra title weight. Google, Bing,
  DuckDuckGo and Claude's search tool share that index. Result counts come from
  the index before pagination. An unmatched query returns an empty list.
  Missing pages use captured site responses; unknown hosts return NXDOMAIN.
- **Model-written** writes pages for the requested subject from the prose brief,
  earlier mentions and stored claims. The host-held Claude token takes priority,
  followed by `OPENROUTER_API_KEY` and `ANTHROPIC_API_KEY`. The Anthropic writer is
  Claude Haiku 5.5, without thinking, with the API's 128K output maximum.
- **Live** is selected by default when `EXA_API_KEY` is present. Exa supplies search
  results, and the host copies any public URL the guest or Claude requests,
  including URLs that never appeared in search. Pages and static dependencies
  are retained at their original URLs. Separate downloads can progress together.
  Navigation links are fetched when opened. Actual host requests appear in the
  page's internet activity. Transport failures return a gateway error; upstream
  status codes, including real missing pages, are preserved.

The page source can change during a session. Copied mode has no public-web
fallback. Wikipedia reflects its June 2026 snapshot; documentation reflects its
capture date. Live supplies current material.

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

## Corpus

The default [brief](seeds/security.md) selects the security captures and the broad
reference web under the shared downloads directory. Prepare the reference web
once before starting the demo:

```sh
rustup run 1.99.0 cargo xtask search-web /path/to/demos/downloads
```

This downloads the English Wikipedia ZIM without images and captures complete
English documentation sites, then publishes an immutable disk index. Startup
loads the prepared index instead of parsing Wikipedia again. `--documents` runs
only capture; `--index` runs only indexing. Preparation leaves at least 60 GiB of
free disk space. Downloads and indexes stay outside git.

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

## Code

The world's page modules separate routing, generation, listings, stored pages,
corrections and model tools. Prompt construction and answer parsing are separate.
The WARC reader, crawler, BM25 index, model gateway and credential transport live in
`fictionet-extras`. The shared demo kit supplies VM lifetime, prepared images
and SSH console sockets. Search owns its HTML, styles and JavaScript, including copies of the
terminal and screen pieces. ghostty-web 0.4.0 and noVNC 1.7.0, with their
licenses, live in `demos/kit/assets`.
