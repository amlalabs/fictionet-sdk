# Search

Build the shared workstation image once on Linux with KVM, `qemu-system-x86_64`,
`qemu-img`, `curl` and `sha256sum` installed:

```sh
rustup run 1.99.0 cargo xtask-host search-image demos/downloads/cloudimage
```

The command verifies the pinned Ubuntu cloud disk, kernel and initrd and Cloud
Hypervisor, then installs Xfce, Firefox, Claude Code, Python and the guest
settings in a private build VM. Ubuntu packages come from the fixed
`20261023T000000Z` [archive snapshot](https://snapshot.ubuntu.com/). Firefox's
Debian archive and the Claude Code release are pinned and checksum-checked.

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

Or run it with an Anthropic API key in `ANTHROPIC_API_KEY` and no token file.
A hosted demo, whose workstation runs as a Nitro Sandbox on an EC2 parent,
offers Live-Depth only, since Live and Edited copy any URL the guest asks
for. The guest's Claude Code signs in the way the image was built: with an
API key when
`ANTHROPIC_API_KEY` is set and `CLAUDE_CODE_OAUTH_TOKEN_FILE` is not, and
otherwise with a subscription token. Build the image with the same variables
set as the demo; the build reads neither credential. Without the copied
corpus on disk, the demo starts without Copied.

The image build makes the workstation's root certificate, the key of its `ops`
admin account and a placeholder Claude credential once, bakes them into the
image, and keeps the private halves beside `search-workstation.qcow2`, readable
only by their owner. The host controls the workstation as `ops`; the user's
tmux session starts at boot, and the page terminal joins it. The workstation
takes its clock from network time. The real Claude token stays on the host. `claude` opens ready to work. Each launch writes
to a fresh disk overlay; the prepared image stays unchanged. All demo flows use
this workstation. The terminal uses ghostty-web and a persistent tmux session;
Screen shows Firefox. Terminal text starts at 15 px on a dark background in both
page themes, using the bundled JetBrains Mono font. The page source switch stays
visible. Choosing Copied, Live, Live-Depth or Edited starts a new session, with
a new run record and an empty activity view. Every mode switch boots a fresh
workstation from the prepared image on that mode's clock. The world starts
with no names, and the terminal opens with a fresh session once the clock is set.

On the workstation, a before-and-after run reached full readiness in 63.384 s
with boot-time installation and 7.213 s with the prepared image. Desktop readiness
was 63.088 s and 7.208 s. A subsequent warm boot reached full readiness in
5.890 s. The prepared boot recorded zero upstream attempts;
Firefox's start page was served inside the world. Corpus loading and indexing
were 0.468 s before and 0.532 s after, with no indexing changes. The image build
took 98 s using the existing verified Ubuntu downloads and produced a standalone
4.0 GiB disk. These are single-run wall-clock measurements, excluding compilation.

[app/src/main.rs](app/src/main.rs) assembles the workstation and its owned page.
[app/src/network.rs](app/src/network.rs) connects the model gateway and local
startup services. Search explicitly reports typed facts from its request and
tool handlers, its resolvers and the typed no-route callback on its network.

The world answers DNS itself. The gateway runs a resolver like Unbound whose
only data is a root zone of the world's own: the first time a name the
session serves is asked, the world places its site and the resolver answers
with its address. Copied serves the corpus's hosts, Live-Depth the hosts its
search results allow, and Live and Edited any host name. Every other name
does not exist.

Every page source models a corporate network. The workstation uses the gateway
resolver. The guest's outgoing TCP and UDP port 53 to any other address, and
port 853, are silently dropped, so `dig @8.8.8.8`, `dig +trace`, and DNS over
TLS time out. Public resolver addresses also block TCP and UDP port 443,
covering DoH and HTTP/3. Known public DoH names get NXDOMAIN with the Blocked
extended DNS error in every mode, and so do Live-Depth's unserved host names.

[app/src/page/](app/src/page/) projects those facts into the map, site details,
model calls and recent activity. Selecting a site or gateway keeps the map
above its details while the agent remains visible. The page always shows the
live run. Each session is a run of its own: the world forgets what it copied,
crawled, fetched and edited, the feed and map start empty, and its facts go to
a separate `<downloads>/search/run-<uuid>.jsonl` with RFC 3339 wall-clock timestamps and
owner-only permissions. Request credentials are redacted before entering the observation channel; request
bodies are not retained. Header details show only values retained by recording.
The map draws internet
routes from upstream facts, including the editor's model calls, rather than from
model call activity. Local and rejected model requests therefore leave the
internet wire dark. The activity feed updates one row per upstream attempt;
the run record retains each transport phase.

The page binds to localhost with no authentication. Browser libraries are served
locally. Recorded page previews are inert and cannot run scripts or contact
sites. Capture dates are shown only when the archive records them.

## Page sources

- **Copied** serves offline English Wikipedia, Python, Rust, MDN and GitHub documentation, recipes,
  and the captured security sources at their original URLs. A prepared Tantivy
  index ranks partial matches by BM25 with extra title weight and the same English
  word stemming for documents and queries. Google, Bing,
  DuckDuckGo and Claude's search tool share that index, each engine in its own
  layout. Result counts come from the index before pagination. An unmatched query
  returns an empty list. Missing pages use captured site responses. Every host the
  corpus serves resolves, and every other name does not exist.
- **Live** is selected by default when `EXA_API_KEY` is present. [Exa search](https://github.com/exa-labs/openapi-spec/blob/master/exa-openapi-spec.yaml)
  supplies results, which keep their order, titles and URLs in each engine's
  skin; snippets are Exa's highlights as plain text, and Exa's own pages are
  left out. The host copies any public URL the guest or Claude requests,
  including URLs that never appeared in search. Each page, stylesheet or image
  is copied when requested and retained at its original URL. A copied page also
  brings its stylesheets, CSS imports, fonts, images and scripts, including
  cross-host assets and redirects at their real URLs. Separate downloads
  can progress together. Actual host requests appear in the
  page's internet activity. Interrupted downloads retry until completion; upstream
  status codes, including real missing pages, are preserved. A host whose real
  certificate fails verification (expired, issued for other names, or from an
  untrusted issuer) presents a certificate that fails the same way. A copy is
  served dated when it is served.
  Signed HTTPS records keep their ECH configurations. Their public TLS names
  authenticate with the world's CA without accepting ECH, so Firefox retries
  with the site's ordinary name. Those fallback fronts serve no pages.
- **Live-Depth** answers searches as Live does and keeps an allowlist. Search
  results, from the engines and from Claude's search tool, are allowed at depth
  0. Nothing is fetched ahead of time: when the guest opens an allowed address,
  the host copies it as Live does, and its links, on any site, are allowed one
  deeper, up to depth 5, at the fewest links they were reached by. A PDF's
  links count as a page's. The files the page uses are allowed too and copied
  when asked for. An unlisted path on an allowed host gets the site's own 404.
  A host the session does not serve gets NXDOMAIN with the Blocked extended
  DNS error from the gateway.
  Direct queries to other DNS servers are blocked by the network. Neither
  unlisted pages nor blocked hosts are fetched. The site's
  404 is learned when the first page on it is copied, by asking it once for a
  random path made up for the session; before then the answer is nginx's 404.
  A blocked host resolves as soon as a link to it is allowed; the resolver
  does not cache policy blocks. Package downloads from pip, npm and Cargo
  registries, including captured packages, return HTTP 403 with "Package downloads are
  blocked by network policy." The feed shows each opened page's depth and
  refused addresses as rows; the map counts the allowed links.
- **Edited** serves the real web as Live does, with the changes a scenario calls
  for. The scenario is a short instruction set in the World menu, such as "The
  Fed raised rates by 0.5 points on Oct 22". A model reads each page or result
  list with the scenario, today's date and what readers have already been shown,
  and returns only edits: an exact passage and its replacement. The world makes
  them in the real bytes and serves everything else unchanged, then asks again
  until nothing is left to change. Text that names nothing the scenario is about
  is served without a model call. Real 404s, PDFs and other files stay real.
  The editor uses `OPENROUTER_API_KEY`, or else `ANTHROPIC_API_KEY`, never
  the guest's Claude token; it is Claude Haiku 5.5 and never sends its
  credential through the guest. The feed and the reading view mark each change;
  the guest sees none of this. With no scenario, Edited behaves like Live.

The source switch shows why a source is unavailable: missing captures, a model
key or a search key. Other sources remain usable. The page reports the source
that answered each request and search. Copied mode has no public-web fallback.
Its day is the day its newest page was copied: the workstation clock, HTTP
dates and the World menu are set back by as many whole days as have passed
since then, so no page is dated after the guest's clock. The workstation sets
its clock from Ubuntu's default time server, `ntp.ubuntu.com`, which the world
serves in every mode with the session's time. A stored copy goes
decoded to a client whose `Accept-Encoding` does not name its coding. Live supplies current
material. Live search and capture use a separate host HTTP transport, outside
the guest model gateway. Search queries and served pages are logged and
displayed. The crawler ignores robots.txt.

The content audit applies to text the world writes. Replayed WARC responses carry
capture provenance and are outside that scope; their words are not allowlisted.

## Provider boundary

Every world-served HTTPS host uses the Zscaler look-alike chain from
`fictionet-extras`, with its root installed in the guest. The prepared image
contains the software; boot has no installation window or download forwarding.
Interactive provider sign-in, guest token refresh and API key creation stay
closed throughout the run. This app provides no tokenless
Claude sign-in flow.

The host reads `CLAUDE_CODE_OAUTH_TOKEN_FILE`, or else `ANTHROPIC_API_KEY`, at
startup. The guest receives a placeholder of the same kind, approved in Claude
Code's settings; the gateway substitutes the real credential only when
forwarding an admitted Anthropic request. The long-lived token does not refresh
inside the guest. Account provisioning and any refreshable credentials belong
on the host. Startup checks and host-token policy reads are answered locally.
The gateway restricts operational account, catalog and usage reads to specific
provider paths and methods; these exceptions are policy, not evidence that a
request occurred.

The world's observations report upstream attempts, responses and failures. An attempt means the request entered the host transport, not that
a connection succeeded. Model gateway and editor requests share this
observed provider transport. Local startup responses and rejected requests do
not produce an upstream attempt. Live's host search and capture transport is
separate from this provider boundary.

Provider URL image, document and file sources and unsupported server tools are
refused before web-tool splicing, including requests mixing allowed web tools
with unsupported features. Inline data and client tool arguments containing URLs
remain usable. Provider-native search and fetch become client functions answered
from the world's pages; they do not reach the provider as native web tools.

## Corpus

The [seed](seeds/security.md) selects the security captures and the broad
reference web under the shared downloads directory. Prepare the reference web
once before starting the demo:

```sh
rustup run 1.99.0 cargo xtask-host search-web /path/to/demos/downloads
```

This downloads the English Wikipedia ZIM without images and crawls English
documentation and recipe sites, then publishes an immutable disk index. Startup
loads the prepared index and archive locations instead of parsing the sources again. `--documents` runs
only capture; `--index` runs only indexing. Preparation leaves at least 60 GiB of
free disk space. Downloads and indexes stay outside git.

WARCs are stored in `demos/downloads/security/`, outside git. Capture the seed
pages, references and their requisites with:

```sh
rustup run 1.99.0 cargo xtask-host search-capture /path/to/demos/downloads --research
```

Each batch gets a separate archive. Captures keep original URLs, redirects, HTTP
headers and response bodies.
Microsoft's site required a browser User-Agent. Referenced NIST PDFs are also
captured. Some upstream optional images and fonts return errors in the original
sites and retain those errors in replay.

Capture follows stylesheets, CSS imports, fonts, images and scripts across hosts.
Chromium refreshes page HTML and discovers dependencies requested by JavaScript
at a desktop viewport. Successful refreshed pages become new records; a failed
refresh retains a previous successful response and reports the upstream failure.
Its requests use the same host transport with the browser's request
headers; the browser itself has no Internet route.

Complete requisites for every page in an existing corpus with:

```sh
rustup run 1.99.0 cargo xtask-host search-requisites demos/downloads/security
```

Append URLs to that command to capture or repair individual pages. Cached pages
are traversed too. New WARC batches are flushed and linked into place atomically;
the original archives and URLs remain intact. Upstream HTTP errors are retained
at their original URLs, and transport failures are reported in the capture output.
Batches published after the offline index was prepared are served at startup
without reindexing.

The previous astronomy captures remain in `demos/downloads/astronomy/`.

### Packages

The corpus's `packages/` directory holds separate WARCs for PyPI indexes,
wheel metadata and distributions, and GitHub source archives. These sites
replay their captures in Copied, Live and Edited. Live-Depth blocks registry package
downloads with HTTP 403, including files present in the capture. In Live and
Edited, a file the capture lacks is copied from its real host when first asked for and kept for the session, so installs work for
any package; a package that does not exist stays a 404. In Copied, a file
the capture lacks gets the registry's own not-found answer and is never fetched. Captured site 404 pages and their assets
also supply missing-page responses for the research sources.

Capture the research sources and packages with Python 3.12 and pip available
on the host:

```sh
rustup run 1.99.0 cargo xtask-host search-capture demos/downloads <python-with-pip>
```

The command retains existing captures, resolves research tools with pip,
and captures their dependency closure at the original PyPI URLs. It includes
requests, pandas, numpy, matplotlib, beautifulsoup4, scipy, networkx, pyyaml,
packaging, rich and pytest. The wheel selection targets the workstation's
Python 3.12 on Linux x86-64. Requests, NetworkX and Click source archives are
available at the tagged GitHub archive URLs declared in the capture command.
Other versions and platforms require their own captures.

## Code

The world's page modules separate the copied web, Live copies, the editor and
the text it edits, listings and model tools.
The WARC reader, crawler, BM25 index, model gateway and credential transport live in
`fictionet-extras`. The shared demo kit supplies VM lifetime, prepared images
and SSH console sockets. Search owns its HTML, styles and JavaScript, including copies of the
terminal and screen pieces. Vendored upstream ghostty-web with wheel reporting
and noVNC 1.7.0, with their
licenses, live in `demos/kit/assets`.
