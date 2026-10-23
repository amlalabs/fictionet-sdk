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
Screen shows Firefox. Pass `preview` instead of the downloads folder to run
without a VM.

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
[app/src/network.rs](app/src/network.rs) connects the model gateway and inspected
provider sign-in. Search explicitly reports typed facts from its request and
tool handlers, its name resolver and the typed no-route callback on its network.

[app/src/page/](app/src/page/) projects those facts into the map, site details,
model calls and recent activity. Selecting a site or gateway expands the map
beside its details. The scrubber replays the retained observation history; the
agent stays live. The World menu chooses the page source or restarts world pages.
The last 1024 observations are kept for rewind. The app writes its typed facts to
`<downloads>/search/log.jsonl`.

The page prints a loopback URL with its run token. Browser libraries are served
locally. Recorded page previews are inert and cannot run scripts or contact
sites. Capture dates are shown only when the archive records them.

## Page sources

- **Copied** replays WARC responses at their real URLs. A crawler builds one
  BM25 index from their titles and text. Google, Bing and DuckDuckGo render that
  index in their own layouts. Each result covers every query term; unrelated
  searches have no results. Counts come from the index before pagination.
  Missing URLs on captured hosts return 404. Uncaptured hosts return NXDOMAIN,
  apart from the caller's declared model and sign-in services.
- **Model-written** uses `OPENROUTER_API_KEY` to write pages from a prose brief,
  prior mentions and stored claims. Failed calls do not invent fallback articles.
- **Live** uses `EXA_API_KEY` for [Exa search](https://github.com/exa-labs/openapi-spec/blob/master/exa-openapi-spec.yaml).
  Results retain their order, titles, URLs and snippets in each engine's skin.
  Without the key, the World menu identifies the missing configuration and the
  other sources remain usable.

Live downloads result pages and requisites, following navigation to depth five
within each result's site. Redirects and cross-host assets are retained at their
real URLs. Search queries and served pages are logged and displayed. The crawler ignores
robots.txt and limits requests per host. Unknown URLs do not start downloads.
The page reports the source that answered each request.

The content audit applies to text the world writes. Replayed WARC responses carry
capture provenance and are outside that scope; their words are not allowlisted.

## Provider boundary

Every world-served HTTPS host uses the Zscaler look-alike chain from
`fictionet-extras`, with its root installed in the guest. Sign-in hosts include
`claude.com`. Their HTTPS requests are inspected and forwarded only during
setup, including provider-hosted assets and hCaptcha. Its regional asset hosts
follow the [published hCaptcha domains](https://docs.hcaptcha.com/#content-security-policy-settings).
The first successful inference response closes interactive sign-in for
the rest of the run, including requests on existing connections. Only validated
refresh-token grants to the Claude and OpenAI token endpoints remain on these
hosts. Refresh requests are serialized from the validated fields before sending.
Account profile, policy, model-catalog and usage endpoints are restricted to
specific paths and methods; API key creation closes with sign-in.

The world's observations report sign-in state and every remaining exception,
and upstream attempts, responses and refusals. Interactive sign-in paths, query strings, headers
and bodies are omitted because they can contain credentials. An attempt means
the request entered the host transport, not that a connection succeeded. Local
startup responses and rejected requests do not produce an upstream attempt.

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
and SolarWinds and XZ analyses from researchers and vendors. It is a bounded
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

## Code

The world's page modules separate routing, generation, listings, stored pages,
corrections and model tools. Prompt construction and answer parsing are separate.
The WARC reader, crawler, BM25 index, model gateway and sign-in policy live in
`fictionet-extras`. The shared demo kit supplies VM lifetime, prepared images
and SSH console sockets. Search owns its HTML, styles and JavaScript, including copies of the
terminal and screen pieces. ghostty-web 0.4.0 and noVNC 1.7.0, with their
licenses, live in `demos/kit/assets`.
