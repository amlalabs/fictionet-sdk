# Site captures

Captured on October 20, 2026 with Chromium 153.0.8010.52 through Playwright and the
Chrome DevTools Protocol, at 1440 × 1000, English, signed out. The one-time
capture and trimming tools live outside this repository.

- www.google.com: https://www.google.com/search?q=rust+programming&hl=en
- www.bing.com: https://www.bing.com/search?q=rust+programming&setlang=en-US
- en.wikipedia.org: https://en.wikipedia.org/wiki/Rust_(programming_language)
- www.bbc.com: https://www.bbc.com/news/articles/c6j9kwmkd7gwo
- www.bbc.com (sport): https://www.bbc.com/sport/football
- github.com: https://github.com/rust-lang/rust
- doc.rust-lang.org: https://doc.rust-lang.org/std/vec/struct.Vec.html
- docs.python.org: https://docs.python.org/3/library/json.html
- pypi.org: https://pypi.org/project/requests/
- www.theregister.com: https://www.theregister.com/os-platforms/2026/10/20/openeuler-brings-chinas-enterprise-linux-ambitions-to-the-desktop/5304145

The DOM is the rendered page with scripts, script attributes, frames, trackers,
preloads, and large editorial images removed. Linked and inline stylesheets
are local files; inline sheets retain their document order. Fonts and small
images fetched by the page are local assets. Asset URLs are rewritten to
/_assets/ on the same host. Unavailable image and font URLs are cleared.
Unused rules were removed using Chromium CSS coverage on the saved desktop
DOM. Empty sheets and unreferenced assets were removed. Python's selected
language and version were saved from its rendered controls.

Google returned results before an asynchronous CAPTCHA overlay. The saved
DOM retains those results and omits the overlay; no challenge was completed.
DuckDuckGo returned HTTP 202 challenges at both its HTML and main endpoints.
Stack Overflow and Medium returned HTTP 403 challenges. Reddit returned a
JavaScript challenge. These hosts have no capture and keep the existing layout.
The result captures contain no sponsored block; sponsored results use the
existing renderer until a sponsored block is available in a capture.

Google extraction uses #rso, .tF2Cxc.asEBEc inside .MjjYud, h3, and .VwiC3b.
Bing uses #b_results, li.b_algo, h2 a, and .b_caption p. DuckDuckGo's
HTML adapter expects #links and .web-result. Sponsored selectors are .uEierd,
.b_ad, and .result--ad respectively; these remain unverified on live ads.
Missing required elements report the host and selector and use the built-in
layout. The bundled files are embedded in the world binary.
