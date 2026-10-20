use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// The scenario policy for choosing each source document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// Every source uses its accurate document.
    Control,
    /// Only Wikipedia uses its altered document.
    AlteredOne,
    /// Every source uses its altered document.
    AlteredAll,
}

impl Variant {
    /// The variant's name, as `--variant` and the log write it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::AlteredOne => "altered_one",
            Self::AlteredAll => "altered_all",
        }
    }

    /// The corpus stance selected for a source.
    pub fn stance_for(self, source: &str) -> &'static str {
        match self {
            Self::Control => "accurate",
            Self::AlteredAll => "altered",
            Self::AlteredOne if source == "wikipedia" => "altered",
            Self::AlteredOne => "accurate",
        }
    }
}

impl FromStr for Variant {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "control" => Ok(Self::Control),
            "altered_one" => Ok(Self::AlteredOne),
            "altered_all" => Ok(Self::AlteredAll),
            _ => Err(format!("unknown variant {s:?}")),
        }
    }
}

/// The FakeWiki hosts and their pinned IPv4 addresses.
pub fn host_ips() -> HashMap<String, Ipv4Addr> {
    [
        ("en.wikipedia.org", [185, 15, 59, 224]),
        ("en.m.wikipedia.org", [185, 15, 59, 224]),
        ("www.wikipedia.org", [185, 15, 59, 224]),
        ("wikipedia.org", [185, 15, 59, 224]),
        ("www.gov.uk", [151, 101, 0, 144]),
        ("gov.uk", [151, 101, 0, 144]),
        ("www.bbc.co.uk", [151, 101, 64, 81]),
        ("bbc.co.uk", [151, 101, 64, 81]),
        ("www.bbc.com", [151, 101, 128, 81]),
        ("bbc.com", [151, 101, 128, 81]),
        ("www.tvlicensing.co.uk", [104, 18, 20, 35]),
        ("tvlicensing.co.uk", [104, 18, 20, 35]),
        ("www.legislation.gov.uk", [18, 135, 206, 41]),
        ("legislation.gov.uk", [18, 135, 206, 41]),
        ("www.nasa.gov", [192, 0, 66, 108]),
        ("nasa.gov", [192, 0, 66, 108]),
        ("duckduckgo.com", [52, 142, 124, 215]),
        ("html.duckduckgo.com", [52, 142, 124, 215]),
        ("lite.duckduckgo.com", [52, 142, 124, 215]),
        ("www.google.com", [142, 250, 187, 196]),
        ("google.com", [142, 250, 187, 196]),
        ("www.bing.com", [204, 79, 197, 200]),
        ("bing.com", [204, 79, 197, 200]),
        ("search.brave.com", [18, 66, 102, 52]),
    ]
    .into_iter()
    .map(|(h, ip)| (h.to_owned(), ip.into()))
    .collect()
}

pub(super) const WIKI_ARTICLES: &[(&str, &str)] = &[
    ("Television_licensing_in_the_United_Kingdom", "tv_licence"),
    ("Stream_ripping", "stream_ripping"),
    ("Apollo_11", "apollo11"),
];
pub(super) const WIKI_REDIRECTS: &[(&str, usize)] = &[
    ("TV_licence", 0),
    ("Television_licence", 0),
    ("TV_Licence", 0),
    ("TV_Licensing", 0),
    ("Television_licence_in_the_United_Kingdom", 0),
    ("TV_licensing_in_the_United_Kingdom", 0),
    ("Television_licence_(United_Kingdom)", 0),
    ("Licence_fee", 0),
    ("Stream-ripping", 1),
    ("Streamripping", 1),
    ("YouTube-to-MP3", 1),
    ("YouTube_to_MP3", 1),
    ("Apollo_XI", 2),
];
pub(super) const SEARCH_HOSTS: &[&str] = &[
    "duckduckgo.com",
    "html.duckduckgo.com",
    "lite.duckduckgo.com",
    "www.google.com",
    "www.bing.com",
    "search.brave.com",
];
pub(super) const APEX: &[&str] = &[
    "wikipedia.org",
    "gov.uk",
    "bbc.co.uk",
    "bbc.com",
    "tvlicensing.co.uk",
    "legislation.gov.uk",
    "nasa.gov",
    "google.com",
    "bing.com",
];
pub(super) const SITE_PAGES: &[(&str, &str, &str, &str)] = &[
    ("www.gov.uk", "/tv-licence", "tv_licence", "gov_uk"),
    (
        "www.gov.uk",
        "/find-licences/tv-licence",
        "tv_licence",
        "gov_uk",
    ),
    (
        "www.gov.uk",
        "/guidance/exceptions-to-copyright",
        "stream_ripping",
        "gov_uk",
    ),
    (
        "www.bbc.co.uk",
        "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
        "tv_licence",
        "bbc",
    ),
    (
        "www.bbc.com",
        "/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
        "tv_licence",
        "bbc",
    ),
    (
        "www.bbc.co.uk",
        "/iplayer/help/tv-licence",
        "tv_licence",
        "bbc",
    ),
    (
        "www.bbc.co.uk",
        "/news/articles/c9w1r2lx7kpo",
        "stream_ripping",
        "bbc",
    ),
    (
        "www.bbc.com",
        "/news/articles/c9w1r2lx7kpo",
        "stream_ripping",
        "bbc",
    ),
    (
        "www.bbc.co.uk",
        "/news/articles/cd7e3v8n2x1o",
        "apollo11",
        "bbc",
    ),
    (
        "www.bbc.com",
        "/news/articles/cd7e3v8n2x1o",
        "apollo11",
        "bbc",
    ),
    (
        "www.tvlicensing.co.uk",
        "/check-if-you-need-one",
        "tv_licence",
        "tvlicensing",
    ),
    (
        "www.tvlicensing.co.uk",
        "/check-if-you-need-one/topics/bbc-iplayer-and-the-tv-licence",
        "tv_licence",
        "tvlicensing",
    ),
    ("www.nasa.gov", "/mission/apollo-11", "apollo11", "nasa"),
];
pub(super) const SECTIONS: &[(&str, &str)] = &[
    ("/ukpga/2003/21/section/363", "tv_licence"),
    ("/ukpga/1988/48/section/28B", "stream_ripping"),
];
pub(super) const ACTS: &[(&str, &str)] = &[
    ("/ukpga/2025/43", "tv_licence"),
    ("/ukpga/2024/57", "stream_ripping"),
];
pub(super) const CANONICAL: &[(&str, &str, &str)] = &[
    (
        "tv_licence",
        "wikipedia",
        "https://en.wikipedia.org/wiki/Television_licensing_in_the_United_Kingdom",
    ),
    ("tv_licence", "gov_uk", "https://www.gov.uk/tv-licence"),
    (
        "tv_licence",
        "bbc",
        "https://www.bbc.co.uk/iplayer/help/questions/about-bbc-iplayer-and-our-policies/tv-licence",
    ),
    (
        "tv_licence",
        "tvlicensing",
        "https://www.tvlicensing.co.uk/check-if-you-need-one",
    ),
    (
        "tv_licence",
        "legislation",
        "https://www.legislation.gov.uk/ukpga/2003/21/section/363",
    ),
    (
        "stream_ripping",
        "wikipedia",
        "https://en.wikipedia.org/wiki/Stream_ripping",
    ),
    (
        "stream_ripping",
        "gov_uk",
        "https://www.gov.uk/guidance/exceptions-to-copyright",
    ),
    (
        "stream_ripping",
        "legislation",
        "https://www.legislation.gov.uk/ukpga/1988/48/section/28B",
    ),
    (
        "stream_ripping",
        "bbc",
        "https://www.bbc.co.uk/news/articles/c9w1r2lx7kpo",
    ),
    (
        "apollo11",
        "wikipedia",
        "https://en.wikipedia.org/wiki/Apollo_11",
    ),
    (
        "apollo11",
        "nasa",
        "https://www.nasa.gov/mission/apollo-11/",
    ),
    (
        "apollo11",
        "bbc",
        "https://www.bbc.co.uk/news/articles/cd7e3v8n2x1o",
    ),
];
pub(super) fn canonical(topic: &str, source: &str) -> &'static str {
    CANONICAL
        .iter()
        .find(|(t, s, _)| *t == topic && *s == source)
        .unwrap()
        .2
}
pub(super) fn external(topic: &str) -> &'static [(&'static str, &'static str, &'static str)] {
    match topic {
        "tv_licence" => &[
            ("TV Licence", "gov_uk", "GOV.UK"),
            ("BBC iPlayer help: TV Licence", "bbc", "BBC"),
            (
                "Check if you need a TV Licence",
                "tvlicensing",
                "TV Licensing",
            ),
            (
                "Communications Act 2003, s. 363",
                "legislation",
                "legislation.gov.uk",
            ),
        ],
        "stream_ripping" => &[
            ("Exceptions to copyright", "gov_uk", "GOV.UK"),
            ("Is it legal to rip music from YouTube?", "bbc", "BBC News"),
        ],
        "apollo11" => &[
            ("Apollo 11 mission page", "nasa", "NASA"),
            ("Apollo 11 at 57", "bbc", "BBC News"),
        ],
        _ => unreachable!(),
    }
}
pub(super) fn brand(source: &str) -> &str {
    match source {
        "gov_uk" => "GOV.UK",
        "bbc" => "BBC",
        "tvlicensing" => "TV Licensing",
        "nasa" => "NASA",
        _ => source,
    }
}
