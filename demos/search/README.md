# Search

Run `cargo xtask demo search` on Linux with KVM, or
`cargo xtask demo search preview` without a VM. Agents sign in inside the guest.
The terminal uses ghostty-web.

[app/src/main.rs](app/src/main.rs) assembles the workstation, copied web,
search observer and page. [app/src/network.rs](app/src/network.rs) connects the
model gateway, sign-in relay and package mirror. The web world supplies DNS,
certificates, page sources and engine layouts. Model calls retain the guest's
credentials; search and fetch tools use the same active page source as Firefox.
The gateway emits `model.tool` observations for Architecture.

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
real URLs. Every outgoing query is logged and displayed. The crawler ignores
robots.txt and limits requests per host. Unknown URLs do not start downloads.
The log records `real_search`, `downloaded`, `copy_served` and `download_failed`.

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

`cargo xtask demo corpus` completes the NASA, ESA and Wikipedia capture.
`cargo xtask demo corpus sites` captures the additional astronomy sources listed
in [corpus/new-sites.urls](corpus/new-sites.urls), with `wget -e robots=off
--page-requisites`, a browser identity and request delays. An optional URL limits
that command to one source. `cargo xtask demo corpus report` reports actual HTML
counts and index coverage. Captures are stored in `demos/downloads/astronomy/`.
Capture failures are reported rather than replaced with authored pages.

## Code

The world's page modules separate routing, generation, listings, stored pages,
corrections and model tools. Prompt construction and answer parsing are separate.
The WARC reader, crawler, BM25 index, model gateway and sign-in relay live in
`fictionet-extras`. The shared demo kit owns VM lifetime, the observation page,
terminal, screen and package cache. Browser libraries are fetched with
`cargo xtask demo libraries`.
