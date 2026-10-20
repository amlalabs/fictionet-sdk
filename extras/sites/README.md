# Site captures

Captured on October 20, 2026 with Chromium 153.0.8010.52 through Playwright
and the Chrome DevTools Protocol, at 1440 × 1000, English, signed out.
The one-time tools and raw responses stay outside this repository.

| Host | Source URL |
|---|---|
| www.google.com | https://www.google.com/search?q=rust+programming&hl=en |
| www.bing.com | https://www.bing.com/search?q=rust+programming&setlang=en-US |
| html.duckduckgo.com | https://html.duckduckgo.com/html/?q=rust+programming&kl=us-en |
| en.wikipedia.org | https://en.wikipedia.org/wiki/Rust_(programming_language) |
| www.bbc.com | https://www.bbc.com/news/articles/c6j9kwmkd7gwo |
| www.bbc.com, sport | https://www.bbc.com/sport/football |
| github.com | https://github.com/rust-lang/rust |
| doc.rust-lang.org | https://doc.rust-lang.org/std/vec/struct.Vec.html |
| docs.python.org | https://docs.python.org/3/library/json.html |
| pypi.org | https://pypi.org/project/requests/ |
| www.theregister.com | https://www.theregister.com/os-platforms/2026/10/20/openeuler-brings-chinas-enterprise-linux-ambitions-to-the-desktop/5304145 |

The HTML retains layout containers, navigation, headers, footers, stylesheets
and local assets. Scripts, tracking attributes, comments, frames, source
metadata, editorial images and page content were removed. The skins contain
empty title, breadcrumb, contents and date slots. The renderer fills them from
the served page; publication dates are capped at the caller's world date.
The main container retains empty heading and paragraph elements to show a
writer the site's content classes. Article language counts, repository counts,
package details, author names, related articles and source timestamps are not
part of a skin. Copyright years come from the world date.

Fonts and small images are local assets under `/_assets/` on each host.
Stylesheet order is preserved. The original desktop captures were trimmed
with Chromium CSS coverage, which dropped the rules for narrower windows.
Wikipedia's `narrow.css` and the shared search stylesheet put back the ones
a window under about 1,100 px needs: Wikipedia folds its side columns and
Google hides its wide logo. Unreferenced assets were removed. DuckDuckGo's
HTML capture retains its full stylesheets. Python's language and version
controls are static; the version label is Python 3.

Each blocked host was retried once on October 20, 2026 using Chromium with an
Xvfb display. No challenge was completed and no account was used:

- DuckDuckGo's HTML endpoint returned results, now included above.
- https://stackoverflow.com/questions/59632632/what-is-the-difference-between-string-and-str-in-rust
  returned HTTP 403 and a challenge.
- https://medium.com/@Medium/what-were-reading-how-to-make-the-most-of-medium-703459bc2110
  returned HTTP 200 with a page-not-found screen, not an article.
- https://old.reddit.com/r/rust/ returned HTTP 200 requiring sign-in.
- The single ads query, https://www.google.com/search?q=buy+car+insurance&hl=en,
  returned an unusual-traffic challenge and no sponsored result. Google ads
  therefore retain the built-in markup with explicit scoped styling. It is
  not captured ad markup.

The original Google results loaded before an asynchronous challenge overlay;
the saved results omit that overlay. Search adapters require the result list,
result heading, snippet and query field to match. A missing or changed layout
uses the built-in search page. Site lookup or rendering returns `None` for a
missing or mismatched skin so a caller can use its own fallback.
