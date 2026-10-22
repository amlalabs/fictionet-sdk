# Search

Run `cargo run --release -p fictionet-search-demo --bin search --
demos/downloads/cloudimage` on Linux with KVM, or pass `preview` instead of the
downloads folder to run without a VM. Agents sign in inside the guest. The terminal uses ghostty-web and a persistent
tmux session; Screen shows the Firefox desktop. Input starts off and can be
enabled beside the console.

`preview` needs no downloads or API keys. It uses the astronomy corpus when
available, otherwise a small embedded sky.org capture. Its labeled client makes
real requests inside the world. Model calls appear when an agent uses the
gateway; preview does not invent provider traffic.

[app/src/main.rs](app/src/main.rs) assembles the workstation and its owned page.
[app/src/network.rs](app/src/network.rs) connects the model gateway, sign-in relay
and package mirror. Search explicitly reports typed facts from its request and
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
  index in their own layouts. Missing URLs return 404.
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
verbatim. The date controls pages, HTTP dates and certificate validity.
Search ranking receives the prose without special treatment for named sites.
Eval questions live in the Python task's `QUESTIONS` mapping.

## Corpus

The NASA, ESA and Wikipedia captures are stored in `demos/downloads/astronomy/`.

## Code

The world's page modules separate routing, generation, listings, stored pages,
corrections and model tools. Prompt construction and answer parsing are separate.
The WARC reader, crawler, BM25 index, model gateway and sign-in relay live in
`fictionet-extras`. The shared demo kit supplies VM lifetime, SSH console sockets and the package
mirror. Search owns its HTML, styles and JavaScript, including copies of the
terminal and screen pieces. ghostty-web 0.4.0 and noVNC 1.7.0, with their
licenses, live in `demos/kit/assets`.
