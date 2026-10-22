# Demo cleanup report

The code cleanup and layout changes are committed on `final-20261022`. Nothing was pushed and local main was not changed. The corpus acceptance work is incomplete: all eight requested sites have not supplied 30–60 usable pages, and the requested twenty-page-per-site replay check with zero failed CSS, font and image requests has not passed.

## What changed

Both requested branches were read and merged. The model gateway uses the guest's own credentials, answers supported search and fetch tools from the active page mode, and emits `model.tool` observations. The Ghostty terminal and the packet flow graph with its packet list remain.

Every example world is under its owning `demos/<name>/` folder. Interactive apps use `app/` and `world/`; the shared VM and page kit is `demos/kit/`. Portable world helpers, sign-in forwarding, capture, WARC and indexing belong to `fictionet-extras`. The Python starter is under `python/inspect_fictionet/demos/`; world fixtures and briefs point to the owning demo folders. Nuclear's viewer is a binary in its world crate.

Search's entry points are `demos/search/app/src/main.rs` and `network.rs`. DNS, certificates, copied pages, live captures, model transport, HTTP serving, result lists and model tool answers have separate modules. Empty advisory and cast helpers, identity conversion, unused maker arguments and stale offline-maker descriptions were removed. URL and display-name data are separate from code.

Seeds contain a date, optional fixed files and a prose brief. The brief is supplied to the page writer without structured facts or site fields. Evaluation questions are in the Python eval tasks. Live search calls Exa with `EXA_API_KEY`, preserves result order and uses each engine's existing rendering. The menu reports an absent key. Local HTTP integration coverage exercises the Exa request header, JSON, results, crawling, replay and observations; no real Exa account was used.

WARC replay marks content provenance. The content audit skips those captured responses before inspecting their text. Authored pages remain in scope. No word exception was added for captured pages. The crawler ignores robots and retains its per-host limit; a failed rate-limit regression exposed a deadline measured before the previous response arrived. The existing cooldown now starts after capture completion, with the test unchanged.

## Tests removed and kept

[The deletion list](test-deletions.md) gives each deleted test file or module and its reason. Regenerated output comparisons, copy and CSS assertions, helper tests, duplicate traffic scripts and coverage of the removed keyword maker were deleted. Unused fixtures and helpers were removed when no scorer or live regression used them.

Kept coverage includes protocol parsing on bytes, real HTTP and TLS connections, refused and logged traffic, guest API-key and bearer forwarding, WARC replay, index ranking, model retries and redaction, bounded state, persistence, concurrent request deduplication, browser transport behavior, physics and scoring from observed evidence. Passing these tests does not substitute for the unfinished corpus browser acceptance work.

## Layout and line counts

[The file inventory](demo-layout.md) lists every tracked demo file and the moved shared support files, with line counts and purposes. Generated downloads and WARC assets are not tracked source.

The baseline is the merged tree after both branches, before deletion and restructuring. The three old Search locations contained 25,030 newline bytes across 50 files. The final Search folder contains 20,462 newline bytes across 81 files, including tests, documentation, manifests and data. This is 4,568 fewer lines. The largest Search file is 606 lines. The limit reported here is for Search; the inventory also shows larger existing shared and other-world modules. These totals include more than the approximately 21,700 code lines quoted in the request; the comparison uses the same counting method on both trees.

The root source `examples/` tree and root Cargo aliases for demo binaries are gone. Build commands select each owning demo package. Remaining `examples/` text refers to the SDK web test fixture or the generic Inspect helper for external crates; there are no stale demo source paths. VM scripts belong to `demos/web/`, `demos/proxy/` and `demos/k8s/`, with shared setup in `demos/kit/guest/`.

## Validation commands

`CARGO_INCREMENTAL=0` was used for final Rust builds after disk space was exhausted by accumulated incremental artifacts. It does not change test assertions.

| Command | Result |
| --- | --- |
| `cargo fmt --all` and `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed, warnings denied. |
| `cargo test --workspace` | Passed, including retained integration tests and doctests. |
| `cargo doc --workspace --no-deps` | Passed. |
| `cargo check -p fictionet --no-default-features --lib` | Passed. |
| Owning-package target checks matching VM and container build commands | Passed; deployment images were not rebuilt in this pass. |
| `cargo xtask demo` | Lists the six interactive apps and three VM script demos. |
| `cargo check --workspace --all-targets` | Passed after moves and module extraction. |
| `cargo check -p web-world --all-targets` | Passed after declaring the native runtime features in extras. |
| `cargo check -p wasm-world --target wasm32-unknown-unknown` | Passed. The SDK reports its existing unused `sent` method warning on this target. |
| `node --test $(rg --files -g '*.test.mjs')` | 480 passed, zero failed, zero skipped. |
| `PATH=/tmp/linux-amd64:$PATH uv run --project python/inspect_fictionet pytest python/inspect_fictionet/tests demos/hosted/tests` | 1,006 passed. |
| `cargo run -p fictionet-search-demo --bin search -- preview` | Served real scripted requests through Google, Bing and DuckDuckGo, copied Wikipedia and NASA pages, and refused `wiki.corp`. Exit zero after Ctrl-C, with the content audit drained. |
| Headless Chromium on the preview, with `--password-store=basic --use-mock-keychain` | Screenshot showed nine completed web requests in Architecture. The initial capture exposed the dropped-history bug; the corrected capture showed all nine. This was a no-VM preview, not a full guest run. |
| `git diff --check` | Passed. |
| `git grep -n 'examples/'` | Remaining matches are the SDK fixture and generic Cargo example build outputs; no stale demo source location. |
| `gzip -t` on the new EarthSky and Space.com captures | Passed. This validates archive compression, not page completeness. |
| `cargo xtask demo corpus report` | Loaded captures and built the shared index. After unverified additions were staged aside, the active corpus indexed 386 pages from its original 500 HTML pages. |

The final clippy and documentation commands also report Cargo's existing future-incompatibility notice for `russh v0.54.5`.

## Failures encountered and disposition

| Command or stage | Failure | Disposition |
| --- | --- | --- |
| Initial merged Rust check and test build | Stale `adaptive_web_world`, removed page-maker calls, old argument counts and missing model constructors. | Updated callers and actual event sources; deleted only coverage of removed functionality. |
| Initial merged Search tests | Old tests expected invented keyword-maker pages and ten synthetic results. | Listed individually in the deletion log. Copied corpus and real transport regressions remain. |
| Search snapshot bound regression | `5299356` versus `5299417`. | Corrected the serialized size bound after removing structured seed fields; retained the exact regression. |
| Initial Node run | Missing Ghostty library and an obsolete New pages menu expectation. | Downloaded the required Ghostty asset; removed obsolete menu coverage and copy assertions, with reasons recorded. |
| Initial Python invocation | `No module named pytest`. | Used the project environment. |
| Python environment preparation | Missing optional Kubernetes support and Helm. | Installed the package's Kubernetes extra and used Helm from `/tmp/linux-amd64`; tests then passed. |
| Inspect starter move | Test looked for nonexistent `demos/search_eval.py`. | Moved the existing `web_eval.py` and corrected its path. |
| Context snapshot during a download | A transient downloaded file disappeared while being copied. | Excluded downloads from generated Cargo build contexts; retained the real rebuild test. |
| Rust and Python builds at disk exhaustion | `No space left on device`. | Used `cargo clean --profile dev`, then disabled incremental compilation for this worktree's builds and reran the suites. |
| Clippy after snapshot removal | `unused variable: here`. | Removed obsolete snapshot setup. |
| A Rust run during a folder move | `could not execute process ... No such file or directory`. | Reran after the moved target was rebuilt. |
| Standalone Search check | `could not find tokio in fictionet` and `no associated function ... new_multi_thread`. | Declared the native runtime features in extras rather than relying on workspace feature unification. |
| Clippy after certificate extraction | `fields issuer and start of struct tls::Ca are private`. | Preserved the previous crate-internal field visibility. Assertions were unchanged. |
| Capture rate regression | `times[1].duration_since(times[0]) >= Duration::from_millis(500)`. | Moved the existing cooldown deadline to capture completion; no test limit was relaxed and no test sleep was added. |
| First documentation build | Duplicate `web_world` target output, redundant links and unresolved `fictionet_observe` link. | Kept quick-start API documentation in extras, disabled duplicate binary docs and corrected links. |
| One-off Chromium network-log inspection | `TypeError` comparing a string with an integer. | Restricted numeric error comparisons to integer values and inspected the log. |
| In-app browser | `Browser is not available: iab`. | Used installed headless Chromium for the preview. |
| Space.com Wget capture | `wget exit status: 8`, including `ERROR 404: Not Found`. | Capture retained locally; not declared asset-complete. |
| EarthSky capture | `wget exit status: 3` during disk exhaustion. | Archive compression is readable, but capture is incomplete. |

## Corpus acceptance remains open

`cargo xtask demo corpus sites` and the single-site form use browser identity, `wget -e robots=off --page-requisites`, bounded bandwidth and per-request waiting. The final command also follows asset hosts and writes into a capture directory before publishing a Wget-successful WARC. Wget success alone is not browser acceptance. The first long-running invocation predates that publication change; its partial captures must not be treated as verified.

Observed discovery responses:

| Site | Observed response or capture |
| --- | --- |
| Astronomy Stack Exchange | HTTP 403. Popular questions and answers were not captured. |
| Space.com | Correct astronomy root returned 200; 40 requested pages, Wget exit 8. |
| EarthSky | Root returned 200; 36 requested pages, Wget exit 3 when disk filled. |
| Sky & Telescope | Curl root returned 200; the first discovery client returned 403, while Wget returned 200. Discovery now uses Wget. A capture that selected navigation links was stopped; a corrected capture prioritizing main content is still running and is not accepted. |
| HubbleSite | HTTP 301 from the requested news-release root. |
| ESO | HTTP 503. |
| Universe Today | 40 requested pages, Wget exit zero. |
| Planetary Society | 40 requested pages; Wget exit 8, including HTTP 429 Too Many Requests. |

Before staging the unverified data aside, a scan found 288 Wikipedia HTML pages, 212 NASA/ESA HTML pages, 25 EarthSky pages, 39 Space.com pages, 38 Universe Today pages and 38 Planetary pages across two hosts. It indexed 526 pages from 7,353 URL records in 657,347,721 compressed WARC bytes. These are raw capture counts, not acceptance counts. Some early discovered pages were navigation or account pages, not astronomy articles. Discovery now prioritizes article and main content links. The failed or unverified captures are retained under `demos/downloads/astronomy/.unverified/` or their `.capture-` directories. The active original corpus has 500 HTML pages, 6,600 URL records and 386 indexed pages in 381,013,296 compressed WARC bytes. No new site has passed the requested browser acceptance check. The original WARC files remain active; unverified additions are not counted as completed work.

One live Space.com page was loaded in headless Chromium with the requested keychain flags. Its network log contained a font error and an image error. Twenty replayed pages per new site have not been verified, and zero failed CSS, font or image requests has not been established. No captures have been silently replaced with model-written pages to meet that requirement.

The corrected Sky & Telescope download is still running at report time, with its archive staged under `.capture-skyandtelescope.org-2050583`. It has not been accepted. The task keeps completed unverified captures outside the active corpus. A new `cargo xtask demo corpus browser` checker was proposed for real replay verification. Approval is pending because the supplied AGENTS.md explicitly requires asking before adding a checker; no checker was added.


## Commits

These are the worktree's first-parent implementation commits after local main, in order. The documentation commit contains this report and inventory.

- `9411825b4` Merge demo architecture and guest credential forwarding
- `04f96fe6a` Merge copied web modes with observed demo architecture
- `2b9e7651e` Connect Search page modes to the guest credential gateway
- `a426f5d79` Delete copy assertions and coverage of removed page modes
- `7c779f416` Remove source parsing tests that pin obsolete viewer counts
- `314c29958` Remove unused generator arguments and update merged test callers
- `4a5fbe3c5` Remove remaining coverage of invented offline pages
- `fe1aece0e` Use renamed web observations and an authored search fixture
- `cc98d01f6` Move worlds and demo apps into their own folders
- `6d79b8293` Give the small demos their own crates
- `d1ac1c301` Delete palette assertions and tests of test helpers
- `b05a6e9f2` Remove constant-only protocol and driver tests
- `4e38057e5` Delete redundant formatting and command constant assertions
- `54dae7b5a` Replace demo snapshots with the existing real traffic assertions
- `fee8bf60a` Keep completed world requests visible in Architecture
- `673776e40` Keep the Inspect starter with the demo files
- `57f213f26` Remove snapshot setup left behind in the request test
- `a1d5718f6` Share sign in forwarding and use one guest credential gateway
- `c060777df` Organize Search around page modes and free text briefs
- `06a53bcaf` Delete identifier constants and regenerated page comparisons
- `6bc4c2a56` Consolidate shared world support in fictionet extras
- `d1b515a80` Describe the active Search architecture at its entry point
- `73cbdd2df` Keep VM scripts with their demos and shared guest setup in the kit
- `114252d40` Delete unrendered page styling and duplicate determinism tests
- `a82f807af` Capture varied astronomy sites with page requisites and robots disabled
- `51f6b09c5` Give demo documentation distinct targets and valid links
- `08b8f8723` Delete empty page maker paths and name test modules by behavior
- `349ec5b8b` Declare native runtime features where shared world support uses them
- `622412dfd` Make the Nuclear viewer a binary in its world crate
- `cc08be652` Start the host cooldown after a capture completes
- `1d8cff6af` Keep DNS admission and certificate issuance in their own modules
- `1527c6f1f` Preserve certificate state visibility within the world crate
- `8aa51d9b3` Use wget for site discovery as well as page capture
- `95222e550` Count each corpus page once during discovery
- `ba844f614` Delete the regenerated client report and redundant source comparison
- `35b52be68` Delete compose constant assertions for obsolete generator configurations
- `862cd00f1` Keep SBE byte comparisons and delete the generated source snapshot
- `78be11e50` Remove unused test dependencies and describe retained scoring fixtures
- `317b7f68c` Prefer article and main content links when selecting corpus pages
- `d2a05ab11` Build demo binaries from their owning crates without root aliases
- `4c6cf25ec` Delete display name assertions and retired argument cases
- `ebb1d21d3` Keep the cloud init filesystem roundtrip and delete copied guest settings

### Source branch commits inspected

`fix-rushed-20261021`:

- `fd0bda899` Share coding agent installers and add nmap
- `c1126a62e` Finish the packet graph and Ghostty terminal
- `bd445eab0` Forward guest credentials through model search interception
- `90fd34871` Restore plain web Search and its coverage
- `6c4702b22` Remove environment settings and regenerate goldens through xtask
- `788061a27` Replace demo checks with observed architecture and packet inspection
- `e56bda9ff` Describe concrete network and memory boundaries
- `d53d9cba6` Keep guest sign-in and declare each app world architecture

`canned-web-20261021`:

- `637b455eb` Format Rust sources and remove redundant bindings
- `240d40ac5` Restore dashboard consoles and packet view
- `7e00062d9` Write prepared pages for three research tasks
- `6402d00f6` Serve prepared pages and observe local model searches
- `08ce413d4` Revert "Restore dashboard consoles and packet view"
- `8ff5824cf` Rename the web world and its integrations
- `e3ed0c61d` Add direct WARC replay and a crawling text index
- `8da0e7c2c` Serve Search from WARC pages with a live model mode
- `40ad78d6b` Prefer specific matching passages in search snippets
- `29514c147` Complete the bounded astronomy archive through Wikimedia
- `369746437` Copy live search results into the world
- `ffc6576ee` Exercise host searches across every engine
- `e10024f0c` Preserve copied article bodies and dependent assets

