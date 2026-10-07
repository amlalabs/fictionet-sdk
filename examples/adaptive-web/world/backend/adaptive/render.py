"""HTML for search engines and for every generated page.

The generator writes what a page says. The parts every site has (header,
navigation, sidebar links, an ad, footer, cookie notice) are laid out here
from the host's profile, which is written once per host and kept, so every
page of a host looks like the same site. A host's layout follows its kind
(news, company, forum, ...), and its details follow the profile's `style`,
the order in which hosts were first seen.
"""
from __future__ import annotations

from html import escape
from urllib.parse import quote, quote_plus, urlsplit


def e(s: object) -> str:
    return escape(str(s or ""), quote=True)


def display_url(url: str) -> str:
    u = urlsplit(url)
    parts = [p for p in u.path.split("/") if p]
    shown = (u.hostname or "") + ("".join(f" › {p}" for p in parts[:3]))
    return shown


def result_count(results: list[dict], query: str) -> str:
    """A believable count from the query's length. Not a statistic."""
    words = max(1, len(query.split()))
    n = 48_300_000 // (words * words) + 1_270 * len(query)
    return f"{n:,}"


# The Server header each engine sends.
ENGINE_SERVERS = {"google": "gws", "duckduckgo": "nginx", "bing": "Microsoft-IIS/10.0"}

# The Server header of other sites, by layout style: the web's common ones.
SERVERS = ["cloudflare", "nginx", "Apache", "cloudflare", "AmazonS3", "nginx/1.24.0", "Microsoft-IIS/10.0",
           "cloudflare", "openresty", "Apache/2.4.58 (Ubuntu)"]


def server_of(profile: dict | None) -> str:
    return SERVERS[int((profile or {}).get("style", 1)) % len(SERVERS)]


# --- Google -------------------------------------------------------------

def google(query: str, record: dict, start: int = 0) -> str:
    q = e(query)
    out = [f"""<!DOCTYPE html><html lang="en-GB"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{q} - Google Search</title><style>body{{font-family:arial,sans-serif;margin:0}}#res{{margin-left:150px;max-width:652px}}.g{{margin:0 0 30px}}h3{{font-size:20px;font-weight:normal;margin:0}}cite{{color:#202124;font-style:normal;font-size:14px}}.VwiC3b{{color:#4d5156;font-size:14px}}.LEwnzc{{color:#70757a}}</style></head>
<body><div id="gb"><a href="https://mail.google.com/mail/">Gmail</a> <a href="https://www.google.com/imghp">Images</a> <a href="https://accounts.google.com/ServiceLogin">Sign in</a></div>
<header><a href="/" id="logo">Google</a><form action="/search" method="GET" role="search"><input name="q" value="{q}" aria-label="Search" type="text"><input type="submit" value="Search"></form>
<div id="hdtb"><a href="/search?q={quote_plus(query)}">All</a> <a href="/search?q={quote_plus(query)}&amp;tbm=nws">News</a> <a href="/search?q={quote_plus(query)}&amp;tbm=isch">Images</a> <a href="/search?q={quote_plus(query)}&amp;tbm=vid">Videos</a> <a href="https://maps.google.com/maps?q={quote_plus(query)}">Maps</a> <span>More</span> <span>Tools</span></div></header>
<div id="main"><div id="result-stats">About {result_count(record['results'], query)} results <nobr>(0.{31 + len(query) % 60} seconds)</nobr></div><div id="res"><div id="search">"""]
    if start == 0:
        for ad in record.get("ads", [])[:2]:
            out.append(f"""<div class="uEierd"><span class="U3A9Ac">Sponsored</span><a href="{e(ad['url'])}"><div role="heading">{e(ad['title'])}</div><span>{e(display_url(ad['url']))}</span></a><div class="MUxGbd">{e(ad.get('text'))}</div></div>""")
    for r in record["results"]:
        date = f'<span class="LEwnzc">{e(r["date"])} — </span>' if r.get("date") else ""
        out.append(f"""<div class="g"><div class="yuRUbf"><a href="{e(r['url'])}"><h3>{e(r['title'])}</h3><br><cite>{e(display_url(r['url']))}</cite></a></div><div class="VwiC3b">{date}<span>{e(r['snippet'])}</span></div></div>""")
    if record.get("questions"):
        out.append('<div class="related-question-pair"><h2>People also ask</h2>')
        for question in record["questions"][:4]:
            out.append(f'<div class="wQiwMc"><a href="/search?q={quote_plus(question)}">{e(question)}</a></div>')
        out.append("</div>")
    out.append('</div></div><div id="bres"><h2>Related searches</h2>')
    for rel in record.get("related", [])[:8]:
        out.append(f'<a href="/search?q={quote_plus(rel)}">{e(rel)}</a><br>')
    nxt = start + 10
    out.append(f"""</div><div id="foot"><table><tr><td><a href="/search?q={quote_plus(query)}&amp;start={nxt}">Next</a></td></tr></table></div></div>
<footer><span>United Kingdom</span> · <a href="https://support.google.com/websearch">Help</a> · <a href="https://www.google.com/tools/feedback">Send feedback</a> · <a href="https://policies.google.com/privacy">Privacy</a> · <a href="https://policies.google.com/terms">Terms</a></footer></body></html>""")
    return "\n".join(out)


def google_home() -> str:
    return """<!DOCTYPE html><html lang="en-GB"><head><meta charset="UTF-8"><title>Google</title></head>
<body><div id="gb"><a href="https://mail.google.com/mail/">Gmail</a> <a href="https://www.google.com/imghp">Images</a> <a href="https://accounts.google.com/ServiceLogin">Sign in</a></div>
<center><h1>Google</h1><form action="/search" method="GET"><input name="q" title="Search" size="57"><br><input type="submit" value="Google Search"> <input type="submit" name="btnI" value="I'm Feeling Lucky"></form>
<p>Google offered in: <a href="/setprefs?hl=cy">Cymraeg</a> <a href="/setprefs?hl=gd">Gàidhlig</a></p></center>
<footer><a href="/intl/en_uk/ads/">Advertising</a> · <a href="/services/">Business</a> · <a href="/intl/en_uk/about.html">About Google</a> · <a href="https://policies.google.com/privacy">Privacy</a> · <a href="https://policies.google.com/terms">Terms</a></footer></body></html>"""


# --- DuckDuckGo (html.duckduckgo.com/html/) -----------------------------

def ddg_link(url: str) -> str:
    return "//duckduckgo.com/l/?uddg=" + quote(url, safe="")


def duckduckgo(query: str, record: dict, start: int = 0) -> str:
    q = e(query)
    out = [f"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head><meta http-equiv="content-type" content="text/html; charset=UTF-8" /><meta name="referrer" content="origin" />
<title>{q} at DuckDuckGo</title><link rel="stylesheet" href="/dist/h.css" type="text/css" /></head>
<body class="body--html"><div class="header"><form id="search_form" name="x" action="/html/" method="post"><input type="text" name="q" class="search__input" value="{q}" /><input type="submit" class="search__button" value="S" /><select class="frm__select" name="kl"><option value="">All Regions</option><option value="uk-en">United Kingdom</option><option value="us-en">US (English)</option></select></form></div>
<div class="serp__results"><div id="links" class="results">"""]
    for ad in record.get("ads", [])[:1]:
        out.append(f"""<div class="result results_links results_links_deep result--ad"><div class="links_main links_deep result__body"><h2 class="result__title"><a rel="nofollow" class="result__a" href="{e(ddg_link(ad['url']))}">{e(ad['title'])}</a></h2><a class="result__url" href="{e(ddg_link(ad['url']))}">{e(urlsplit(ad['url']).hostname)}</a><a class="result__snippet" href="{e(ddg_link(ad['url']))}">{e(ad.get('text'))}</a><div class="badge--ad">Ad</div></div></div>""")
    for r in record["results"]:
        link = e(ddg_link(r["url"]))
        host = urlsplit(r["url"]).hostname or ""
        date = f'<span class="result__timestamp">{e(r["date"])}</span>' if r.get("date") else ""
        out.append(f"""<div class="result results_links results_links_deep web-result"><div class="links_main links_deep result__body"><h2 class="result__title"><a rel="nofollow" class="result__a" href="{link}">{e(r['title'])}</a></h2><div class="result__extras"><div class="result__extras__url"><span class="result__icon"><a rel="nofollow" href="{link}"><img class="result__icon__img" width="16" height="16" alt="" src="//external-content.duckduckgo.com/ip3/{e(host)}.ico" name="i15" /></a></span><a class="result__url" href="{link}">{e(display_url(r['url']).replace(' › ', '/'))}</a>{date}</div></div><a class="result__snippet" href="{link}">{e(r['snippet'])}</a><div class="clear"></div></div></div>""")
    out.append(f"""<div class="nav-link"><form action="/html/" method="post"><input type="submit" class="btn btn--alt" value="Next" /><input type="hidden" name="q" value="{q}" /><input type="hidden" name="s" value="10" /><input type="hidden" name="dc" value="11" /></form></div>
</div></div><div class="feedback-btn"><a rel="nofollow" href="//duckduckgo.com/feedback.html">Feedback</a></div></body></html>""")
    return "\n".join(out)


def duckduckgo_home() -> str:
    return """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>DuckDuckGo</title></head>
<body><form action="/html/" method="post"><input type="text" name="q" autofocus /><input type="submit" value="Search" /></form></body></html>"""


# --- Bing ----------------------------------------------------------------

def bing(query: str, record: dict, start: int = 0) -> str:
    q = e(query)
    out = [f"""<!DOCTYPE html><html lang="en" dir="ltr"><head><meta charset="utf-8"><title>{q} - Search</title></head>
<body><header id="b_header"><form action="/search" id="sb_form"><input id="sb_form_q" name="q" type="search" value="{q}"></form>
<nav><ul><li><a href="/search?q={quote_plus(query)}">All</a></li><li><a href="/images/search?q={quote_plus(query)}">Images</a></li><li><a href="/videos/search?q={quote_plus(query)}">Videos</a></li><li><a href="/news/search?q={quote_plus(query)}">News</a></li><li><a href="/maps?q={quote_plus(query)}">Maps</a></li></ul></nav></header>
<main><span class="sb_count">About {result_count(record['results'], query)} results</span><ol id="b_results">"""]
    for ad in record.get("ads", [])[:1]:
        out.append(f"""<li class="b_ad"><h2><a href="{e(ad['url'])}">{e(ad['title'])}</a></h2><p>{e(ad.get('text'))}</p><span>Ad</span></li>""")
    for r in record["results"]:
        date = f'<span class="news_dt">{e(r["date"])}</span> · ' if r.get("date") else ""
        out.append(f"""<li class="b_algo"><h2><a href="{e(r['url'])}">{e(r['title'])}</a></h2><div class="b_caption"><cite>{e(r['url'])}</cite><p>{date}{e(r['snippet'])}</p></div></li>""")
    out.append('</ol><div id="b_context"><h2>Related searches</h2><ul>')
    for rel in record.get("related", [])[:8]:
        out.append(f'<li><a href="/search?q={quote_plus(rel)}">{e(rel)}</a></li>')
    out.append("""</ul></div></main><footer id="b_footer"><a href="https://go.microsoft.com/fwlink/?LinkId=521839">Privacy and Cookies</a> · <a href="https://go.microsoft.com/fwlink/?LinkID=246338">Legal</a> · <a href="https://www.bing.com/account/general">Settings</a> · © 2026 Microsoft</footer></body></html>""")
    return "\n".join(out)


# --- every other site ----------------------------------------------------

def _nav(items: list[str], base_class: str) -> str:
    links = []
    for item in items:
        label, _, href = item.partition("|")
        href = href.strip() or "/" + "-".join(label.lower().split())
        links.append(f'<li><a href="{e(href)}">{e(label.strip())}</a></li>')
    return f'<ul class="{base_class}">' + "".join(links) + "</ul>"


LAYOUTS = {"news": "news", "blog": "news", "company": "company", "government": "company", "shop": "company",
           "forum": "docs", "docs": "docs", "wiki": "docs", "qa": "docs", "package": "docs"}
RAIL = ["Most read", "Popular", "Trending", "Latest"]
NO_COOKIE_BANNER = {"government", "wiki", "docs", "package"}


def _copyright(name: str, year: str, style: int) -> str:
    return [f"© {year} {name}. All rights reserved.", f"Copyright © {year} {name}", f"© {name} {year}"][style % 3]


def page(host: str, profile: dict, record: dict, year: str) -> str:
    """A generated page inside its host's layout. The layout follows the
    site's kind (news, company, forum, ...); the profile's `style` varies
    the details, so two sites of one kind do not look the same."""
    name = profile.get("name") or host
    kind = profile.get("kind", "")
    style = int(profile.get("style", 0))
    layout = LAYOUTS.get(kind, "plain")
    nav = _nav(profile.get("nav", []), "nav")
    footer = _nav(profile.get("footer", []), "footer-links")
    sidebar = "".join(f'<li><a href="{e(href)}">{e(label)}</a></li>' for label, href in record.get("sidebar", []))
    ad = record.get("ad") or ""
    title = record.get("title") or name
    head = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(record.get('description'))}">
<meta property="og:site_name" content="{e(name)}">
<meta property="og:title" content="{e(title)}">
<link rel="stylesheet" href="/static/css/main.css">
<link rel="icon" href="/favicon.ico">
</head>"""
    body = record.get("body") or ""
    tagline = f'<span class="tagline">{e(profile.get("tagline"))}</span>' if profile.get("tagline") else ""
    if layout == "news":
        newsletter = ("""<section class="newsletter"><h2>Newsletter</h2><form action="/newsletter" method="post">"""
                      """<input type="email" name="email" placeholder="Email address"><button>Sign up</button></form></section>"""
                      if style % 2 == 0 else "")
        main = f"""<body class="site">
<header class="masthead"><div class="brand"><a href="/">{e(name)}</a>{tagline}</div>
<nav aria-label="Main">{nav}</nav></header>
<div class="layout"><main id="content"><article>
{body}
</article>{newsletter}</main>
<aside class="rail"><h2>{RAIL[style % len(RAIL)]}</h2><ol>{sidebar}</ol>{f'<div class="ad-slot"><span class="ad-label">Advertisement</span><p>{e(ad)}</p></div>' if ad else ''}</aside></div>"""
    elif layout == "company":
        topbar = '<div class="topbar"><a href="/contact">Contact</a> <a href="/support">Support</a> <a href="/login">Log in</a></div>\n' if style % 2 else ""
        main = f"""<body>
{topbar}<header class="site-header"><a class="logo" href="/">{e(name)}</a><nav>{nav}</nav></header>
<div class="breadcrumb"><a href="/">Home</a> › {e(title)}</div>
<main id="main">
{body}
</main>
<aside class="related"><h3>{["Related", "See also", "Explore"][style % 3]}</h3><ul>{sidebar}</ul></aside>
{f'<div class="promo-banner"><p>{e(ad)}</p></div>' if ad else ''}"""
    elif layout == "docs":
        main = f"""<body class="docs">
<header><a class="home" href="/">{e(name)}</a><form action="/search" class="search"><input name="q" placeholder="Search"></form><a href="/login">Sign in</a></header>
<div class="columns"><nav class="sidebar">{nav}<h4>{["See also", "Related", "More"][style % 3]}</h4><ul>{sidebar}</ul></nav>
<main>
{body}
</main></div>
{f'<div class="sponsor">Sponsored: {e(ad)}</div>' if ad else ''}"""
    else:
        main = f"""<body>
<header><h2 class="site-title"><a href="/">{e(name)}</a></h2>{nav}</header>
<main>
{body}
</main>
<section class="more"><h3>More from {e(name)}</h3><ul>{sidebar}</ul></section>
{f'<p class="ad">{e(ad)}</p>' if ad else ''}"""
    cookies = ("""<div class="cookie-banner" role="dialog" aria-label="Cookies"><p>We use cookies to improve your experience and for analytics. <a href="/privacy">Privacy policy</a></p><button>Accept</button> <button>Reject non-essential</button></div>\n"""
               if kind not in NO_COOKIE_BANNER and style % 3 != 2 else "")
    tail = f"""
<footer class="site-footer">{footer}<p>{e(_copyright(name, year, style))}</p></footer>
{cookies}<script src="/static/js/main.js" defer></script>
</body>
</html>
"""
    return head + "\n" + main + tail


def not_found(host: str, profile: dict | None, target: str, year: str) -> str:
    profile = profile or {"name": host, "nav": ["Home|/"], "footer": [], "style": 2}
    record = {"title": "Page not found", "description": "",
              "body": f"<h1>Page not found</h1><p>Sorry, we couldn't find <code>{e(target)}</code>. It may have moved or been removed.</p><p><a href=\"/\">Go to the home page</a></p>"}
    return page(host, profile, record, year)
