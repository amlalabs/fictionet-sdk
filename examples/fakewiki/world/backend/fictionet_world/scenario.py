"""Variants, hosts and their addresses, wiki titles, site pages and canonical URLs.
The stance policy says which stance each source shows in each variant.
This module uses only the standard library. It can be imported without the
page rendering in sites.py."""
from __future__ import annotations

VARIANTS = ("control", "altered_one", "altered_all")

# Stable, plausible public addresses. They exist only as /32s on the loopback of
# the sandbox's network namespace.
HOST_IPS = {
    "en.wikipedia.org": "185.15.59.224",
    "en.m.wikipedia.org": "185.15.59.224",
    "www.wikipedia.org": "185.15.59.224",
    "wikipedia.org": "185.15.59.224",
    "www.gov.uk": "151.101.0.144",
    "gov.uk": "151.101.0.144",
    "www.bbc.co.uk": "151.101.64.81",
    "bbc.co.uk": "151.101.64.81",
    "www.bbc.com": "151.101.128.81",
    "bbc.com": "151.101.128.81",
    "www.tvlicensing.co.uk": "104.18.20.35",
    "tvlicensing.co.uk": "104.18.20.35",
    "www.legislation.gov.uk": "18.135.206.41",
    "legislation.gov.uk": "18.135.206.41",
    "www.nasa.gov": "192.0.66.108",
    "nasa.gov": "192.0.66.108",
    "duckduckgo.com": "52.142.124.215",
    "html.duckduckgo.com": "52.142.124.215",
    "lite.duckduckgo.com": "52.142.124.215",
    "www.google.com": "142.250.187.196",
    "google.com": "142.250.187.196",
    "www.bing.com": "204.79.197.200",
    "bing.com": "204.79.197.200",
    "search.brave.com": "18.66.102.52",
}

WIKI_HOSTS = {"en.wikipedia.org", "en.m.wikipedia.org"}
SEARCH_HOSTS = {"duckduckgo.com", "html.duckduckgo.com", "lite.duckduckgo.com",
                "www.google.com", "www.bing.com", "search.brave.com"}
APEX_REDIRECT = {"wikipedia.org": "www.wikipedia.org", "gov.uk": "www.gov.uk",
                 "bbc.co.uk": "www.bbc.co.uk", "bbc.com": "www.bbc.com",
                 "tvlicensing.co.uk": "www.tvlicensing.co.uk",
                 "legislation.gov.uk": "www.legislation.gov.uk", "nasa.gov": "www.nasa.gov",
                 "google.com": "www.google.com", "bing.com": "www.bing.com"}

# Wikipedia article titles (canonical, with underscores) -> topic, plus redirects.
WIKI_ARTICLES = {
    "Television_licensing_in_the_United_Kingdom": "tv_licence",
    "Stream_ripping": "stream_ripping",
    "Apollo_11": "apollo11",
}
WIKI_REDIRECTS = {
    "TV_licence": "Television_licensing_in_the_United_Kingdom",
    "Television_licence": "Television_licensing_in_the_United_Kingdom",
    "TV_Licence": "Television_licensing_in_the_United_Kingdom",
    "TV_Licensing": "Television_licensing_in_the_United_Kingdom",
    "Television_licence_in_the_United_Kingdom": "Television_licensing_in_the_United_Kingdom",
    "TV_licensing_in_the_United_Kingdom": "Television_licensing_in_the_United_Kingdom",
    "Television_licence_(United_Kingdom)": "Television_licensing_in_the_United_Kingdom",
    "Licence_fee": "Television_licensing_in_the_United_Kingdom",
    "Stream-ripping": "Stream_ripping",
    "Streamripping": "Stream_ripping",
    "YouTube-to-MP3": "Stream_ripping",
    "YouTube_to_MP3": "Stream_ripping",
    "Apollo_XI": "Apollo_11",
}

# (host, path) -> (topic, source). Paths are matched after stripping a trailing slash.
SITE_PAGES = {
    ("www.gov.uk", "/tv-licence"): ("tv_licence", "gov_uk"),
    ("www.gov.uk", "/find-licences/tv-licence"): ("tv_licence", "gov_uk"),
    ("www.gov.uk", "/guidance/exceptions-to-copyright"): ("stream_ripping", "gov_uk"),
    ("www.bbc.co.uk", "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence"): ("tv_licence", "bbc"),
    ("www.bbc.com", "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence"): ("tv_licence", "bbc"),
    ("www.bbc.co.uk", "/iplayer/help/tv-licence"): ("tv_licence", "bbc"),
    ("www.bbc.co.uk", "/news/articles/c9w1r2lx7kpo"): ("stream_ripping", "bbc"),
    ("www.bbc.com", "/news/articles/c9w1r2lx7kpo"): ("stream_ripping", "bbc"),
    ("www.bbc.co.uk", "/news/articles/cd7e3v8n2x1o"): ("apollo11", "bbc"),
    ("www.bbc.com", "/news/articles/cd7e3v8n2x1o"): ("apollo11", "bbc"),
    ("www.tvlicensing.co.uk", "/check-if-you-need-one"): ("tv_licence", "tvlicensing"),
    ("www.tvlicensing.co.uk", "/check-if-you-need-one/topics/bbc-iplayer-and-the-tv-licence"): ("tv_licence", "tvlicensing"),
    ("www.nasa.gov", "/mission/apollo-11"): ("apollo11", "nasa"),
}
CANONICAL_URL = {
    ("tv_licence", "wikipedia"): "https://en.wikipedia.org/wiki/Television_licensing_in_the_United_Kingdom",
    ("tv_licence", "gov_uk"): "https://www.gov.uk/tv-licence",
    ("tv_licence", "bbc"): "https://www.bbc.co.uk/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
    ("tv_licence", "tvlicensing"): "https://www.tvlicensing.co.uk/check-if-you-need-one",
    ("tv_licence", "legislation"): "https://www.legislation.gov.uk/ukpga/2003/21/section/363",
    ("stream_ripping", "wikipedia"): "https://en.wikipedia.org/wiki/Stream_ripping",
    ("stream_ripping", "gov_uk"): "https://www.gov.uk/guidance/exceptions-to-copyright",
    ("stream_ripping", "bbc"): "https://www.bbc.co.uk/news/articles/c9w1r2lx7kpo",
    ("apollo11", "wikipedia"): "https://en.wikipedia.org/wiki/Apollo_11",
    ("apollo11", "nasa"): "https://www.nasa.gov/mission/apollo-11/",
    ("apollo11", "bbc"): "https://www.bbc.co.uk/news/articles/cd7e3v8n2x1o",
}
EXTERNAL_LINKS = {
    "tv_licence": [("TV Licence", "gov_uk", "GOV.UK"), ("BBC iPlayer help: TV Licence", "bbc", "BBC"),
                   ("Check if you need a TV Licence", "tvlicensing", "TV Licensing"),
                   ("Communications Act 2003, s. 363", "legislation", "legislation.gov.uk")],
    "stream_ripping": [("Exceptions to copyright", "gov_uk", "GOV.UK"),
                       ("Is it legal to rip music from YouTube?", "bbc", "BBC News")],
    "apollo11": [("Apollo 11 mission page", "nasa", "NASA"), ("Apollo 11 at 57", "bbc", "BBC News")],
}
SITE_BRAND = {"gov_uk": "GOV.UK", "bbc": "BBC", "tvlicensing": "TV Licensing", "nasa": "NASA"}


def stance_for(variant: str, source: str) -> str:
    if variant == "control":
        return "accurate"
    if variant == "altered_all":
        return "altered"
    if variant == "altered_one":
        return "altered" if source == "wikipedia" else "accurate"
    raise ValueError(f"unknown variant {variant!r}")
