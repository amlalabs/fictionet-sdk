# The web world

The [Search demo](../../demos/README.md#search) serves an astronomy corpus from
compressed WARC archives. Its World menu chooses **Pages: Copied**,
**Pages: Model-written** or **Pages: Live search, copied in**. Copied pages are the default; changing the menu affects
new requests without restarting the VM.

Run `cargo xtask demo corpus` to complete the retained NASA and ESA archive to
about 500 HTML pages through Wikimedia's Action API, with a descriptive User-Agent
and contact address. The copied article content sits in Wikipedia's real desktop
skin, with scripts removed for static replay and CSS, fonts and images captured
at their real URLs. Reruns complete missing assets without growing the article
count beyond the target. Archives stay in `demos/downloads/astronomy/`, outside
git. Capture errors fail the command; retained files still need browser checks.

Run `cargo xtask demo search` on Linux with KVM to start Firefox, Claude Code
and Codex. `cargo xtask demo search preview` uses an in-world client without a VM.
The Search demo has no check or bake mode.

The world scans each gzip member once to build an in-memory URL-to-record
index. Responses are served by seeking to a member and decompressing it, with
revisit references and redirects preserved. The reusable reader lives in
[`fictionet-extras`](../../extras/src/warc.rs). It never unpacks the archive.

At startup the search crawler follows links from the starting URLs through
the copied-site response handler. It stays within the captured URL set, extracts
page titles and text, and builds a BM25 inverted index. Startup prints scan and
crawl/index times and the number of indexed pages. Google, Bing and DuckDuckGo
use that one index and their existing layouts. Snippets are excerpts of matching
page text. Unknown URLs return 404; unmatched queries show no results.

Every public hostname resolves to an address assigned by the world. TLS
certificates are signed by its CA. Claude retains its own sign-in; its server
search and fetch tools are answered locally, with one search log entry recording
the source, query and returned results. The model request itself still goes to
the provider.

## Live search, copied in

Set `GOOGLE_SEARCH_API_KEY` and `GOOGLE_SEARCH_ENGINE_ID` in the host environment
before starting, then select the mode in the World menu. Browser engine searches
and intercepted Claude and Codex tools call Google's Programmable Search JSON API
on the host. Every outgoing query is visible in the Web pane and logs. Ordered
results appear in the selected engine's existing skin while downloads continue.

The host downloads result URLs and dependencies, and follows navigation links
on each result's hostname through depth five. It preserves redirects and can fetch
cross-host CSS, fonts, images and scripts named by the copied documents. It uses
an ordinary browser identity, robots.txt permissions and per-host delays. Unknown
URLs never trigger a download. Reached URLs can wait up to 45 seconds for their
copy; failures and timeouts get a normal not-found response. Requests generated
only by scripts, with no URL discovered in HTML or CSS, remain unavailable.

Copies use the same WARC writer and replay as the astronomy corpus. They remain
for the run, including mode changes, and are retained as
`demos/downloads/live-search-*.warc.gz`. `Pages::with_live_search` configures this
source for a host application; it never changes guest network forwarding.
The run log records `real_search`, `downloaded`, `copy_served` and `download_failed`.
The Web pane shows recent matching events, and the event log retains the history.
Host API credentials never enter guest pages or log messages.

## Model-written pages

Set `OPENROUTER_API_KEY` before starting the demo to enable the menu's
Model-written option. The existing model writer creates search results and
pages when requested, using the seed's date, facts, prior mentions and stored
claims. Its store remains in memory. Failed model calls return an error and do
not fall back to invented keyword pages.

The same writer is available to other worlds as `Pages::with_model`, and
`Pages::open` supports a persistent store for evaluation workloads. Store files
record pages, searches, model attempts and address assignments. Worlds sharing a
store coordinate writes with file locks. Replay mode serves only stored content.
The lightweight offline helper can preserve known metadata and mentions; it no
longer contains query catalogs or fabricated articles.

A seed in `seeds/` describes a date, question, sites and facts. Other evaluation
workloads can use the existing standalone world configuration and
[`inspect_fictionet.worlds.web`](../../python/inspect_fictionet/src/inspect_fictionet/worlds/web).
For example, `cargo xtask eval web --live '{"seed":"corvane-acquisition","generator":"openrouter"}'`
uses the OpenRouter writer. Anthropic generation continues to support
`ANTHROPIC_API_KEY`. These evaluation settings are separate from the Search
demo's menu.

## Validation

Unit fixtures exercise WARC member seeking, stored headers and bodies,
redirects, revisits, crawler boundaries and BM25 ranking. The model integration
fixture uses a local upstream to ensure that Claude's API-key and bearer-token
requests have their search and fetch tools answered from the same archive,
without external search requests, and log one search entry.

A real corpus additionally needs at least twenty Chromium page samples per
site, with every request recorded and zero failed stylesheet, font or image
requests. Unit fixtures do not establish that result. No complete corpus or
successful asset sample is committed here.
