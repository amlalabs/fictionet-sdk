//! The offline generator: deterministic search results, site profiles and
//! page content, with no model.

use super::{Seed, prompts::expected_type, seed::parse_date, text::*};
use fictionet_extras::search::{Engine, Result, Search};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

const STOP: &[&str] = &[
    "a", "an", "and", "are", "at", "be", "by", "can", "do", "does", "for", "from", "how", "i",
    "in", "is", "it", "its", "my", "of", "on", "or", "should", "the", "to", "what", "when",
    "which", "who", "why", "with", "you", "our", "we", "this", "that", "was", "will", "about",
    "online", "news", "com", "www", "https", "http", "best", "example", "details", "safe",
    "owners", "version", "fixed", "fix", "latest",
];
/// Bylines on articles the offline generator makes.
const AUTHORS: [&str; 16] = [
    "Priya Raman",
    "Tomasz Wierzbicki",
    "Aoife Gallagher",
    "Kwame Mensah",
    "Lucía Ortega",
    "Henrik Lindqvist",
    "Mei Tanaka",
    "Oluwaseun Adeyemi",
    "Dmitri Volkov",
    "Fatima Benali",
    "Rhys Pritchard",
    "Ingrid Solberg",
    "Mateus Carvalho",
    "Yusuf Demir",
    "Chloé Marchand",
    "Arjun Mehta",
];
/// Forum and Q&A user names.
const USERS: [&str; 12] = [
    "netadmin_dk",
    "ferrous_wheel",
    "kb_ops",
    "sysop42",
    "lenkaP",
    "grumpy_firewall",
    "jbrandt",
    "mikko_v",
    "routerroot",
    "tamsin.h",
    "oldschool_ccna",
    "pfeiffer_it",
];
/// Site branding and layout settings shared by its pages.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Display name derived from the hostname.
    pub name: String,
    /// Site category, such as news.
    pub kind: String,
    /// Short text below the site name.
    pub tagline: String,
    /// Navigation links in `label|target` form.
    pub nav: Vec<String>,
    /// Footer links in `label|target` form.
    pub footer: Vec<String>,
    /// Stylesheet shared by every page on the host.
    #[serde(default)]
    pub css: String,
    /// Creation-order index used to choose layouts and server headers.
    pub style: usize,
}
/// Generated page content before layout rendering.
#[derive(Clone, Debug, Default)]
pub struct Page {
    /// HTTP status code.
    pub status: u16,
    /// Media type and optional charset.
    pub content_type: String,
    /// Page heading and search result title.
    pub title: String,
    /// Description used in page metadata and search snippets.
    pub description: String,
    /// Publication date in year-month-day form.
    pub date: String,
    /// Claims supported by prior mentions.
    pub claims: Vec<String>,
    /// HTML fragment or complete text or JSON body.
    pub body: String,
    /// Sidebar links as label and target pairs.
    pub sidebar: Vec<(String, String)>,
    /// Advertisement text.
    pub ad: String,
    /// How the generator describes the site, for a host's first page.
    pub site: Option<Profile>,
}

/// Extracts lowercase search words, excluding common stop words.
pub fn words(s: &str) -> Vec<String> {
    static WORD: OnceLock<Regex> = OnceLock::new();
    WORD.get_or_init(|| Regex::new(r"[a-z0-9][a-z0-9\-\.]*[a-z0-9]|[a-z0-9]").unwrap())
        .find_iter(&s.to_lowercase())
        .filter(|w| !STOP.contains(&w.as_str()))
        .map(|w| w.as_str().into())
        .collect()
}
pub(super) fn shares_words(a: &str, b: &str) -> bool {
    let a = words(a);
    words(b).iter().any(|w| w != "not" && a.contains(w))
}
/// A stable number for `text`, to vary dates, counts and names by URL.
fn hash(text: &str) -> usize {
    text.bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize))
}
fn base36(mut number: usize) -> String {
    let mut digits = Vec::new();
    loop {
        digits.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[number % 36] as char);
        number /= 36;
        if number == 0 {
            return digits.into_iter().rev().collect();
        }
    }
}

/// Removes branding from a result title for headings and directory links.
pub(super) fn heading(title: &str) -> &str {
    [" - ", " — ", " – ", " | ", " · ", " • ", " : r/"]
        .iter()
        .filter_map(|separator| title.split_once(separator))
        .map(|(subject, _)| subject.trim())
        .min_by_key(|subject| subject.len())
        .unwrap_or(title)
}

/// Directory and section routes have navigation content rather than articles.
pub(super) fn directory(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or(target);
    path == "/"
        || (path.ends_with('/') && path.trim_matches('/').split('/').count() == 1)
        || [
            "/latest",
            "/categories",
            "/top",
            "/search",
            "/search/",
            "/results",
            "/w/index.php",
        ]
        .contains(&path)
}

fn day(seed: &Seed, back: usize) -> time::Date {
    parse_date(&seed.date).unwrap() - time::Duration::days(back as i64)
}
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
/// A date as result lists and bylines show it: `3 Oct 2026`.
pub fn short_date(d: time::Date) -> String {
    format!(
        "{} {} {}",
        d.day(),
        MONTHS[d.month() as usize - 1],
        d.year()
    )
}
/// A page's `YYYY-MM-DD` date as a result list shows it, or empty.
pub fn result_date(date: &str) -> String {
    parse_date(date).map(short_date).unwrap_or_default()
}
/// A date on or before the world's date, from 0 to `within` days back,
/// that stays the same for the same `key`.
fn date_for(seed: &Seed, key: &str, within: usize) -> time::Date {
    day(seed, hash(key) % (within + 1))
}

/// The known pages that share words with `query`, the most shared words
/// first; ties keep their order.
pub fn rank<'a>(known: &'a [Result], query: &str) -> Vec<&'a Result> {
    let mut asked = words(query);
    asked.sort();
    asked.dedup();
    let mut scored: Vec<(usize, &Result)> = known
        .iter()
        .map(|k| {
            let (host, _) = target_of(&k.url);
            let have = words(&format!(
                "{} {} {} {}",
                k.title,
                k.url,
                k.snippet,
                host.split('.')
                    .map(|s| s.trim_start_matches("the"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            (asked.iter().filter(|w| have.contains(w)).count(), k)
        })
        .filter(|(score, _)| *score > 0)
        .collect();
    scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    scored.into_iter().map(|(_, k)| k).collect()
}

/// Requires shared subject words, or a named site in a navigational query.
pub(super) fn relevant(result: &Result, query: &str) -> bool {
    let mut asked = words(query);
    asked.sort();
    asked.dedup();
    let have = words(&format!(
        "{} {} {}",
        result.title, result.url, result.snippet
    ));
    let score = asked.iter().filter(|w| have.contains(w)).count();
    if asked.iter().any(|w| {
        ["lisbon", "naples", "tokyo", "porto", "leeds", "dublin"].contains(&w.as_str())
            && !have.contains(w)
    }) {
        return false;
    }
    let (host, _) = target_of(&result.url);
    let named = asked.iter().any(|w| {
        w.len() > 3
            && host
                .split('.')
                .any(|label| label.trim_start_matches("the") == w)
    });
    named || (score > 0 && score >= asked.len().min(2) && score * 2 >= asked.len())
}

/// Text cut from a page as a snippet shows it: at most about 160
/// characters, ending at a word with "...".
pub fn excerpt(text: &str) -> String {
    let text = normalize_space(text);
    if text.chars().count() <= 160 {
        return if text.ends_with(['.', '!', '?']) {
            text
        } else {
            format!("{text}.")
        };
    }
    let words: Vec<&str> = text.split(' ').collect();
    let mut out = String::new();
    for word in words {
        if out.chars().count() + word.chars().count() + 5 > 160 {
            out.push_str(" ...");
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

pub(super) fn prepared_cast(seed: &Seed) -> Vec<super::prompts::Person> {
    let root = super::store::canned_root(&seed.name);
    super::store::Store::load(&root, seed)
        .ok()
        .and_then(|(store, _)| store.cast().map(|cast| cast.people.clone()))
        .unwrap_or_default()
}

fn proper(text: &str) -> String {
    let names = "Lisbon Naples London Leeds Dublin Edinburgh Bath Porto Bristol Glasgow Manchester Tokyo Netgear Python Rust JavaScript Halvard Gateway Vitamin Nikon HG-200 HG-400 HG-900 BBC CISA SSL VPN NHS USB CPU GPU API HTTP HTTPS DNS SQL HTML CSS RAM SSD AI UK US TLS TCP UDP JSON XML URL URI SDK IDE BIOS UEFI OS CVE-2026-41877";
    let mut out = text.to_owned();
    for name in names.split_whitespace() {
        let pattern = format!(r"(?i)\b{}\b", regex::escape(name));
        out = Regex::new(&pattern)
            .unwrap()
            .replace_all(&out, name)
            .into_owned();
    }
    static SHORT: OnceLock<Regex> = OnceLock::new();
    out = SHORT
        .get_or_init(|| {
            Regex::new(r"(?i)\b(?:[a-z]+[’'][a-z]+|[b-z]|[a-z]{1,3}[-]?[0-9][a-z0-9-]*)\b").unwrap()
        })
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            if caps[0].contains(['\'', '’']) {
                caps[0].to_owned()
            } else {
                caps[0].to_uppercase()
            }
        })
        .into_owned();
    static VITAMIN: OnceLock<Regex> = OnceLock::new();
    out = VITAMIN
        .get_or_init(|| Regex::new(r"(?i)\b(vitamin\s+)([a-z])\b").unwrap())
        .replace_all(&out, |caps: &regex::Captures<'_>| {
            format!("{}{}", &caps[1], caps[2].to_uppercase())
        })
        .into_owned();
    upper_first(&out)
}

pub(super) fn engine_order(engine: Engine, query: &str, url: &str) -> usize {
    hash(&format!("{engine:?}/{query}/{url}"))
}

fn voice(host: &str) -> usize {
    host.bytes().fold(14_695_981_039_346_656_037u64, |n, b| {
        (n ^ u64::from(b)).wrapping_mul(1_099_511_628_211)
    }) as usize
        % 10
}

fn lower_first(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |c| {
        format!("{}{}", c.to_lowercase(), chars.as_str())
    })
}

struct Question {
    shape: &'static str,
    subject: String,
}

impl Question {
    fn parse(query: &str) -> Option<Self> {
        let q = normalize_space(query).to_lowercase();
        let q = q.trim_end_matches('?');
        let (shape, rest) = [
            ("how long ", "duration"),
            ("how much ", "amount"),
            ("how many ", "count"),
            ("how often ", "frequency"),
            ("why is ", "cause"),
            ("why does ", "cause"),
            ("what happens if ", "consequence"),
            ("when should ", "timing"),
        ]
        .into_iter()
        .find_map(|(prefix, shape)| q.strip_prefix(prefix).map(|rest| (shape, rest)))?;
        let rest = rest
            .strip_prefix("does it take to ")
            .or_else(|| rest.strip_prefix("do i need to "))
            .or_else(|| rest.strip_prefix("should i "))
            .or_else(|| rest.strip_prefix("should you "))
            .or_else(|| rest.strip_prefix("do you "))
            .or_else(|| rest.strip_prefix("do i "))
            .or_else(|| rest.strip_prefix("you "))
            .or_else(|| rest.strip_prefix("i "))
            .or_else(|| rest.strip_prefix("to "))
            .unwrap_or(rest);
        let nominal = shape == "cause"
            || ["does ", "do ", "is ", "are "]
                .iter()
                .any(|prefix| rest.starts_with(prefix));
        let rest = ["does ", "do ", "is ", "are "]
            .into_iter()
            .find_map(|prefix| rest.strip_prefix(prefix))
            .unwrap_or(rest);
        let parts = rest.split_whitespace().collect::<Vec<_>>();
        let auxiliary = parts
            .iter()
            .position(|w| ["does", "do", "is", "are", "should", "can"].contains(w));
        let noun_end = usize::from(
            parts
                .first()
                .is_some_and(|word| ["a", "an", "the", "my", "your"].contains(word)),
        ) + 1;
        let copula = q.starts_with("why is ");
        let verb = parts
            .iter()
            .enumerate()
            .filter(|(index, _)| !nominal || *index >= noun_end)
            .find_map(|(index, w)| {
                let matches = if copula {
                    [
                        "dense", "blue", "green", "red", "cold", "hot", "salty", "bright", "round",
                    ]
                    .contains(w)
                } else {
                    [
                        "boil",
                        "simmer",
                        "freeze",
                        "overwater",
                        "cook",
                        "bake",
                        "charge",
                        "swallow",
                        "water",
                        "replace",
                        "prune",
                        "clean",
                        "wash",
                        "feed",
                        "use",
                        "take",
                        "knead",
                        "purr",
                        "sleep",
                        "need",
                        "turn",
                        "form",
                        "float",
                        "rise",
                        "fall",
                        "change",
                        "grow",
                        "cost",
                        "last",
                        "have",
                        "weigh",
                        "dry",
                        "rest",
                        "soak",
                        "walk",
                        "leave",
                        "plant",
                        "harvest",
                        "dense",
                        "blue",
                        "green",
                        "red",
                        "cold",
                        "hot",
                        "salty",
                        "bright",
                        "round",
                    ]
                    .contains(w)
                };
                matches.then_some(index)
            });
        let subject = if let Some(end) = auxiliary.filter(|end| *end > 0) {
            parts[..end].join(" ")
        } else if let Some(index) = verb {
            if index == 0 {
                parts[1..].join(" ")
            } else {
                parts[..index].join(" ")
            }
        } else {
            rest.to_owned()
        };
        let subject = subject
            .split(" before ")
            .next()
            .unwrap_or(&subject)
            .split(" after ")
            .next()
            .unwrap_or(&subject)
            .trim()
            .to_owned();
        if subject.is_empty() {
            None
        } else {
            Some(Self { shape, subject })
        }
    }
}

fn intent(query: &str) -> &'static str {
    let q = query.to_lowercase();
    if Question::parse(query).is_some() {
        return "question";
    }
    if q.starts_with("best ") || q.contains(" review") || q.contains(" vs ") {
        return "review";
    }
    if q.contains("renewal") || q.contains("renew ") || q.contains("activate license") {
        return "service";
    }
    if [
        "keeps ",
        "won't ",
        "will not ",
        "not working",
        "not turning",
        "slipping",
        "won’t ",
        "stuck",
        "leaking",
        "problems",
        "cannot ",
        "doesn't ",
        "connection refused",
        "fails ",
        "stopped ",
        "error",
    ]
    .iter()
    .any(|w| q.contains(w))
        && !["rust", "python", "javascript"]
            .iter()
            .any(|word| q.contains(word))
    {
        return "problem";
    }
    if [
        "can ",
        "should ",
        "is ",
        "are ",
        "does ",
        "do ",
        "why ",
        "who ",
        "when ",
        "how do ",
        "how can ",
        "what happens ",
    ]
    .iter()
    .any(|w| q.starts_with(w))
        && !q.starts_with("is it bad")
        && !q.starts_with("is it safe")
    {
        return "question";
    }
    if [
        "health",
        "symptom",
        "pain",
        "is it bad",
        "is it safe",
        "coffee",
        "medicine",
        "headache",
    ]
    .iter()
    .any(|w| q.contains(w))
    {
        "health"
    } else if q.starts_with("what is ") || q.starts_with("what are ") {
        "definition"
    } else if !q.starts_with("how ")
        && ![
            "news", "launch", "announc", "firmware", "vulnerab", "cve-", "recall", "outage",
        ]
        .iter()
        .any(|word| q.contains(word))
        && (q.split_whitespace().any(|word| {
            [
                "keyboard",
                "keyboards",
                "laptop",
                "laptops",
                "camera",
                "cameras",
                "headphones",
                "earbuds",
                "monitor",
                "monitors",
                "printer",
                "printers",
                "smartphone",
                "iphone",
                "backpack",
                "tent",
            ]
            .contains(&word)
        }) || {
            static MODEL: OnceLock<Regex> = OnceLock::new();
            !["vitamin", "rust", "python", "javascript", "error"]
                .iter()
                .any(|word| q.contains(word))
                && MODEL
                    .get_or_init(|| Regex::new(r"\b[a-z]{1,3}-?[0-9][a-z0-9-]*\b").unwrap())
                    .is_match(&q)
        })
    {
        "review"
    } else if [
        "news",
        "halvard",
        "cve-",
        "announced",
        "launch",
        "breach",
        "election",
        "earthquake",
        "microsoft",
        "apple ",
        "google ",
        "openai",
        "samsung",
        "nvidia",
        "iphone",
        "outage",
        "recall",
        "incident",
        "crash",
        "tesla",
        "pixel",
        "playstation",
    ]
    .iter()
    .any(|w| q.contains(w))
        || q.split_whitespace().any(|part| {
            part.len() == 10
                && part.as_bytes()[4] == b'-'
                && part.as_bytes()[7] == b'-'
                && part.chars().filter(|c| c.is_ascii_digit()).count() == 8
        })
    {
        "news"
    } else if q.starts_with("how to ") {
        "howto"
    } else {
        "general"
    }
}

fn subreddit(query: &str) -> String {
    let subject = Question::parse(query).map(|question| question.subject);
    let q = subject.as_deref().unwrap_or(query).to_lowercase();
    if [
        "egg", "rice", "pasta", "bread", "bean", "lentil", "potato", "food",
    ]
    .iter()
    .any(|word| q.contains(word))
    {
        "Cooking".into()
    } else if ["plant", "fern", "tomato", "rose", "orchid"]
        .iter()
        .any(|word| q.contains(word))
    {
        "gardening".into()
    } else if q.contains("electric car") || q.contains("battery") {
        "electricvehicles".into()
    } else if ["sky", "moon", "sun", "ocean", "water", "light", "earth"]
        .iter()
        .any(|word| q.contains(word))
    {
        "askscience".into()
    } else if q.contains("gum") {
        "AskScienceDiscussion".into()
    } else if q.contains("bike") || q.contains("bicycle") || q.contains("chain") {
        "bikewrench".into()
    } else if q.contains("keyboard") {
        "MechanicalKeyboards".into()
    } else if q.contains("laptop") {
        "techsupport".into()
    } else if q.contains("dog") || q.contains("cat") {
        "AskVet".into()
    } else if q.contains("rust") {
        "rust".into()
    } else if q.contains("hiking") || q.contains("boots") {
        "hiking".into()
    } else if q.contains("cactus") {
        "cactus".into()
    } else if q.contains("coffee") || q.contains("run") {
        "running".into()
    } else if q.contains("pizza") || q.contains("naples") {
        "napoli".into()
    } else if q.contains("heat pump") {
        "heatpumps".into()
    } else if q.contains("lunar") || q.contains("eclipse") {
        "astronomy".into()
    } else if q.contains("postal") || q.contains("stamps") {
        "philately".into()
    } else if q.contains("ocean") {
        "oceanography".into()
    } else if q.contains("router") {
        "HomeNetworking".into()
    } else if q.contains("halvard") {
        "sysadmin".into()
    } else {
        "AskReddit".into()
    }
}

struct Forecast {
    place: String,
    date: time::Date,
    high: i32,
    low: i32,
    rain: usize,
    wind: usize,
}

impl Forecast {
    fn new(seed: &Seed, query: &str, host: &str) -> Self {
        let q = query.to_lowercase().replace('-', " ");
        let place = q
            .split_whitespace()
            .filter(|word| {
                ![
                    "weather", "forecast", "in", "for", "tomorrow", "today", "hourly", "next",
                    "day",
                ]
                .contains(word)
            })
            .collect::<Vec<_>>()
            .join(" ");
        let place = if place.is_empty() {
            "London".into()
        } else {
            place
                .split_whitespace()
                .map(capitalize)
                .collect::<Vec<_>>()
                .join(" ")
        };
        let date = day(seed, 0) + time::Duration::days(1);
        let seasonal = [8, 9, 12, 15, 18, 21, 23, 22, 19, 16, 11, 8][date.month() as usize - 1];
        let climate = if ["Lisbon", "Naples", "Madrid", "Rome"]
            .iter()
            .any(|p| place.contains(p))
        {
            6
        } else if place.contains("Singapore") {
            30 - seasonal
        } else if place.contains("Sydney") {
            [26, 26, 25, 23, 20, 18, 17, 18, 21, 23, 24, 25][date.month() as usize - 1] - seasonal
        } else if ["Oslo", "Helsinki", "Stockholm"]
            .iter()
            .any(|p| place.contains(p))
        {
            -4
        } else {
            0
        };
        let local = (hash(&format!("{place}/{date}")) % 3) as i32 - 1;
        let variation = (hash(host) % 3) as i32 - 1;
        Self {
            place: place.clone(),
            date,
            high: seasonal + climate + local + variation,
            low: seasonal + climate + local - 5 + variation,
            rain: 35 + hash(&format!("{date}/{host}")) % 5 * 5,
            wind: 9 + hash(&format!("{place}/{host}")) % 7,
        }
    }

    fn title(&self, host: &str, angle: usize) -> String {
        let place = &self.place;
        let date = short_date(self.date);
        let name = site_profile(host).name;
        match host {
            "www.metoffice.gov.uk" => format!("{place} weather forecast for {date} - Met Office"),
            "www.bbc.com" => format!("{place} weather: tomorrow’s forecast - BBC Weather"),
            "weather.com" => {
                format!("{place}: tomorrow’s weather and hourly outlook - The Weather Channel")
            }
            "www.accuweather.com" => {
                format!("{place}: tomorrow’s local forecast | AccuWeather")
            }
            _ => format!(
                "{place} {} for {date} | {name}",
                [
                    "weather",
                    "hourly forecast",
                    "temperatures and rain",
                    "forecast",
                    "weather outlook",
                    "rain and wind forecast",
                    "hour-by-hour weather",
                    "day and night forecast",
                    "local weather",
                    "tomorrow’s conditions",
                    "morning to evening forecast",
                    "daily weather report",
                    "weather by hour"
                ][angle % 13]
            ),
        }
    }

    fn snippet(&self, angle: usize) -> String {
        let outlook = [
            "cloudy early, with showers by midday",
            "morning cloud followed by lunchtime rain",
            "showers near noon and a drier evening",
            "overcast at dawn, then scattered showers",
            "light rain around midday, clearing later",
            "cloudy skies with a few daytime showers",
            "a damp lunchtime and clearing skies later",
            "morning cloud, rain at noon, then brighter",
            "daytime showers easing before the evening",
            "cloud and light rain giving way to clear skies",
            "a cloudy commute before showers develop",
            "rain at lunchtime and a cooler, clear night",
            "a cloudy start, a wet midday and a dry finish",
        ][angle % 13];
        excerpt(&format!(
            "{} weather for {}: {outlook}, high {} °C, low {} °C, rain up to {}%, WSW winds {} km/h.",
            self.place,
            short_date(self.date),
            self.high,
            self.low,
            self.rain + 5,
            self.wind
        ))
    }

    fn body(&self, title: &str, claims: &[String]) -> String {
        let mut body = format!(
            "<h1>{}</h1><h2>{}: {}</h2><p>Cloudy with scattered showers, clearing later. High {} °C · Low {} °C.</p>",
            escape(heading(title)),
            escape(&self.place),
            short_date(self.date),
            self.high,
            self.low
        );
        for claim in claims {
            body.push_str(&format!("<p>{}</p>", escape(claim)));
        }
        body.push_str("<table><caption>Hourly forecast</caption><thead><tr><th scope=\"col\">Time</th><th scope=\"col\">Conditions</th><th scope=\"col\">Temperature</th><th scope=\"col\">Chance of rain</th><th scope=\"col\">Wind</th></tr></thead><tbody>");
        let temperatures = [
            self.low + 1,
            self.low,
            self.low + 1,
            self.low + 3,
            self.high - 1,
            self.high,
            self.high - 2,
            self.low + 2,
            self.low + 1,
        ];
        for hour in 0..24 {
            let slot = hour / 3;
            let temp = temperatures[slot]
                + (temperatures[slot + 1] - temperatures[slot]) * (hour % 3) as i32 / 3;
            let (symbol, rain) = match hour {
                0..=2 => ("Cloudy", 20),
                3..=5 => ("Cloudy", 15),
                6..=8 => ("Overcast", 25),
                9..=10 => ("Showers", self.rain),
                11..=13 => ("Light rain", self.rain + 5),
                14..=17 => ("Cloudy", 25),
                18..=20 => ("Partly cloudy", 15),
                _ => ("Clear", 10),
            };
            body.push_str(&format!("<tr><th scope=\"row\">{hour:02}:00</th><td>{symbol}</td><td>{temp} °C</td><td>{rain}%</td><td>WSW {} km/h</td></tr>", self.wind));
        }
        body.push_str("</tbody></table>");
        body
    }
}

fn subtitle(subject: &str, suffix: &str) -> String {
    let subject_words = subject.split_whitespace().collect::<Vec<_>>();
    let suffix_words = suffix.split_whitespace().collect::<Vec<_>>();
    let overlap = (1..=subject_words.len().min(suffix_words.len()))
        .rev()
        .find(|&count| {
            subject_words[subject_words.len() - count..]
                .iter()
                .zip(&suffix_words[..count])
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
        .unwrap_or(0);
    let suffix = suffix_words[overlap..].join(" ");
    if suffix.is_empty() {
        subject.to_owned()
    } else {
        format!("{subject}: {suffix}")
    }
}

fn result_title(seed: &Seed, query: &str, host: &str, angle: usize, original: &str) -> String {
    let title = title_pattern(seed, query, host, angle, original);
    let name = site_profile(host).name;
    if title.to_lowercase().contains(&name.to_lowercase()) {
        title
    } else {
        format!("{title} | {name}")
    }
}

fn title_pattern(seed: &Seed, query: &str, host: &str, angle: usize, original: &str) -> String {
    let q = query.to_lowercase();
    let name = site_profile(host).name;
    let subject = proper(query);
    if Question::parse(query).is_some() {
        return format!("{}?", subject.trim_end_matches('?'));
    }
    if q.contains(" vs ") {
        return format!(
            "{subject}: {}",
            [
                "key differences",
                "compared in daily use",
                "which should you choose?",
                "price and features",
                "compare models",
                "owners discuss the differences",
                "design and controls",
                "specifications compared",
                "strengths and limitations",
                "buying advice",
                "compatibility guide",
                "a closer comparison",
                "value for money"
            ][angle % 13]
        );
    }
    if matches!(intent(query), "problem" | "question" | "service") {
        let angle_title = match intent(query) {
            "service" => [
                "renewal guide",
                "expiry and entitlement",
                "account requirements",
                "renewal options",
                "support coverage",
                "before you renew",
                "activation steps",
                "subscription terms",
                "prices and coverage",
                "account help",
                "renewal timing",
                "checking your entitlement",
                "vendor support",
            ][angle % 13],
            "question" => [
                "a closer look",
                "readers discuss",
                "the short answer",
                "facts and context",
                "key points",
                "explained",
                "common misconceptions",
                "sources and dates",
                "what specialists say",
                "the main considerations",
                "background",
                "further reading",
                "a guide to the sources",
            ][angle % 13],
            _ => [
                "causes and next steps",
                "what to check first",
                "a practical guide",
                "advice from readers",
                "common causes",
                "adjustment and wear",
                "before you begin",
                "when to ask for help",
                "answers from specialists",
                "a closer look",
                "useful checks",
                "care and follow-up",
                "repair options",
            ][angle % 13],
        };
        let title = if site_profile(host).kind == "forum" && intent(query) == "problem" {
            format!("{subject} — what should I check?")
        } else if site_profile(host).kind == "qa" && intent(query) == "question" {
            format!("{}?", subject.trim_end_matches('?'))
        } else {
            subtitle(&subject, angle_title)
        };
        return title;
    }
    if q.contains("cactus") {
        return ([
            "Repotting a Cactus: Pots, Compost and Aftercare",
            "How to Repot a Cactus Safely",
            "How to Repot a Cactus Without Getting Pricked",
            "Repotting a Cactus: A Step-by-Step Project",
            "When Your Cactus Needs a Bigger Pot",
            "How do you lift a tall cactus out of its pot?",
            "Cactus Care: Drainage and Root Health",
            "A New Pot for Your Cactus",
            "Repotting Cacti Without Burying the Stem",
            "Spring Cactus Care: Check the Roots",
            "Moving a Cactus: Tools That Protect Your Hands",
            "Choosing the Right Pot for a Cactus",
            "Cactus Repotting Mistakes to Avoid",
        ][angle % 13])
            .to_owned();
    }
    if q.contains("coffee") {
        return ([
            "Caffeine Before Exercise: Benefits and Side Effects",
            "Coffee Before Running: How Much Is Too Much?",
            "Should You Drink Coffee Before a Run?",
            "Coffee and Running: Timing, Tolerance and Stomach Upset",
            "A Runner’s Guide to Pre-Run Coffee",
            "Why Coffee Can Upset Your Stomach Before Exercise",
            "Caffeine, Hydration and Your Morning Run",
            "Coffee Before a Workout: What to Consider",
            "Does anyone else get stomach cramps after pre-run coffee?",
            "Coffee and Fitness: Finding a Routine That Suits You",
            "How Much Caffeine Is in Your Pre-Run Drink?",
            "Feeling Shaky After Coffee and Exercise?",
            "Evening Runs: Caffeine and Sleep",
        ][angle % 13])
            .to_owned();
    }
    let titles: &[&str] = if q.contains("bread") && !q.contains("sourdough") {
        &[
            "Why Is My Banana Bread Dense? How to Fix It",
            "The Secret to a Tender Banana Bread Crumb",
            "Dense Banana Bread? Check Your Flour and Mixing",
            "10 Mistakes That Make Banana Bread Heavy",
            "How to Keep Banana Bread Moist Without a Gummy Center",
            "A Better Banana Bread Starts With the Batter",
            "Banana Bread Troubleshooting: Pan Size and Baking Time",
            "Why Banana Bread Sinks After Baking",
            "Is Your Banana Bread Baked in the Middle?",
            "Why You Should Let Banana Bread Cool Before Slicing",
            "Is Your Baking Soda Still Raising Your Banana Bread?",
            "The Flour Measurement That Makes Banana Bread Dense",
            "Getting the Right Banana Bread Batter Consistency",
        ]
    } else if q.contains("ownership") && q.contains("rust") {
        &[
            "Understanding Ownership in Rust",
            "Why does assigning a Rust String move the value?",
            "Rust ownership and borrowing: questions from learners",
            "How did you learn Rust ownership?",
            "Rust Ownership Rules With Examples",
            "Rust Ownership: Move and Borrow",
            "A Practical Introduction to Rust References",
            "Learn Rust: Ownership and Lifetimes",
            "Rust Values, Moves and Copies",
            "Rust Ownership Exercises for Beginners",
            "Rust Borrowing Tutorial",
            "Moving a String Without Cloning in Rust",
            "Practice Ownership in Rust",
        ]
    } else if q.contains("e0502") {
        &[
            "E0502: cannot borrow as mutable because it is also borrowed as immutable",
            "How do I fix Rust error E0502 when pushing to a vector?",
            "Conflicting borrows in Rust: E0502",
            "Why does Rust keep this immutable borrow alive?",
            "Rust E0502: Shared and Mutable Borrows",
            "Fixing a Borrow Checker Error in Rust",
            "Rust References: End the Borrow Before Mutation",
            "Rust Borrow Checker: A Small E0502 Example",
            "When Does a Rust Borrow End?",
            "Rust E0502 and Nonlexical Lifetimes",
            "Rust Mutable Borrow Examples",
            "Solving Conflicting Rust Borrows",
            "Practice Rust Borrowing Without Cloning",
        ]
    } else if q.contains("car") {
        &[
            "Used Car Prices 2026: Search Cars for Sale",
            "Used Car Prices: What Should You Pay in 2026?",
            "Used Car Valuations: Mileage, Age and Condition",
            "Compare Used Car Prices Near You",
            "Used Car Buying Guide: Prices and Running Costs",
            "Why Used Car Prices Vary Between Dealers",
            "Used Car Prices Explained: Trim and Service History",
            "What Is Your Used Car Worth in 2026?",
            "Used Cars for Sale: Compare Asking Prices",
            "Buying a Used Car: Budget for the Next Service",
            "Find a Used Car Within Your Budget",
            "Best Value Used Cars: Our Buying Advice",
            "Used Car Prices: What Owners Are Paying",
        ]
    } else {
        &[]
    };
    if q.contains("weather") || q.contains("forecast") {
        return Forecast::new(seed, query, host).title(host, angle);
    }
    if !titles.is_empty() {
        return titles[angle % titles.len()].to_owned();
    }
    if (q.contains("airfare") || q.contains("airline") || q.contains("flight"))
        && !q.contains(" to ")
    {
        return format!(
            "{}: {}",
            proper(query),
            [
                "Fees and Conditions",
                "Baggage Explained",
                "What Is Included",
                "Compare the Total",
                "A Booking Guide",
                "Travel Options",
                "Before You Book",
                "Cabin and Checked Bags",
                "Flexible Tickets",
                "Route Planning",
                "Finding a Fare",
                "Your Travel Checklist",
                "Airport Advice"
            ][angle % 13]
        );
    }
    if q.contains("flight") || q.contains("airfare") || q.contains("airline") {
        let destination = q.split_once(" to ").map_or("your destination", |(_, p)| p);
        let destination = upper_first(destination);
        return match angle % 13 {
            0 => format!("Flights to {destination}: Fares and Baggage"),
            1 => format!("Cheap Flights to {destination}: Compare Dates"),
            2 => format!("{destination} Flights: Find Your Next Trip"),
            3 => format!("Compare Cheap Flights to {destination}"),
            4 => format!("Find Low Flight Fares to {destination}"),
            5 => format!("{destination}: Direct Flights and Connections"),
            6 => format!("Book Flights to {destination}"),
            7 => format!("Flight Fare Finder: {destination}"),
            8 => format!("Fly to {destination}: Routes and Flight Times"),
            9 => format!("Flights and Airport Transfers in {destination}"),
            10 => format!("{destination} Flight Deals for Flexible Dates"),
            11 => format!("Your Flight to {destination}: Tickets and Travel"),
            _ => format!("Planning Flights to {destination}: Airports and Transfers"),
        };
    }
    if q.contains("pizza") && q.contains(" in ") {
        let city = q.split_once(" in ").map_or("Naples", |(_, p)| p);
        return ([
            format!("Where to Find Great Pizza in {}", upper_first(city)),
            format!("Book a Table for Pizza in {}", upper_first(city)),
            format!(
                "Where to Eat Pizza in {}: Our Favorite Pizzerias",
                upper_first(city)
            ),
            format!("Top-Rated Pizza in {}", upper_first(city)),
            format!("Where would you go for pizza in {}?", upper_first(city)),
            format!("A Pizza Lover’s Guide to {}", upper_first(city)),
            format!("{} Pizza: Beyond the Longest Queues", upper_first(city)),
            format!("Pizza Delivery in {}", upper_first(city)),
            format!("{} Pizzerias for a Night Out", upper_first(city)),
            format!("The Neighborhood Guide to Pizza in {}", upper_first(city)),
            format!("{} Pizza Map: Traditional and Fried", upper_first(city)),
            format!("Pizza in {}: Menus and Local Favorites", upper_first(city)),
            format!("{} Pizza Kitchens Worth a Detour", upper_first(city)),
        ][angle % 13])
            .to_owned();
    }
    if ["halvard", "hg-400", "gateway", "41877"]
        .iter()
        .any(|w| q.contains(w))
    {
        return ([
            "Halvard fixes critical Gateway flaw in firmware 7.2.4",
            "Halvard Gateway patch: what appliance owners need to know",
            "How are other Halvard Gateway admins scheduling this update?",
            "Halvard Gateway’s web portal flaw puts firmware upgrades in focus",
            "Halvard Gateway admins plan upgrades after exploited portal flaw",
            "The Halvard Gateway firmware advisory: affected releases and mitigation",
            "Is an older Halvard Gateway firmware release safe to use?",
            "Halvard Gateway: a guide to the September security fix",
            "Halvard Gateway portal vulnerability and firmware update notes",
            "Updating a Halvard Gateway: questions from administrators",
            "Halvard Gateway patch closes a critical pre-authentication flaw",
            "Halvard Gateway owners review firmware maintenance plans",
            "What the Halvard Gateway portal fix means for VPN administrators",
        ][angle % 13])
            .to_owned();
    }
    if matches!(site_profile(host).kind.as_str(), "qa" | "forum")
        && let Some((question, _)) = heading(original).split_once('?')
    {
        return format!("{question}?");
    }
    if q.contains("router") {
        return format!(
            "{original}: {}",
            [
                "Steps and Precautions",
                "Model-Specific Instructions",
                "Settings to Save First",
                "Questions From Owners",
                "Recovery Over Ethernet",
                "Restart or Full Reset?",
                "Before You Begin",
                "After the Reset",
                "Troubleshooting Access",
                "Connection Checklist",
                "Hardware Revision Guide",
                "Restoring Wi-Fi",
                "Keeping Access"
            ][angle % 13]
        );
    }
    let topic = subject
        .strip_prefix("Best ")
        .or_else(|| subject.strip_prefix("best "))
        .unwrap_or(&subject);
    let topic = topic.strip_suffix(" reviews").unwrap_or(topic);
    let topic = topic.trim_end_matches(" 2026");
    let topic = topic
        .split_whitespace()
        .map(|word| {
            if STOP.contains(&word) {
                word.to_owned()
            } else {
                capitalize(word)
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let forum_topic = topic.to_lowercase();
    if intent(query) == "review" {
        match site_profile(host).kind.as_str() {
            "forum" | "qa" => return format!("Which {forum_topic} would you recommend?"),
            "shop" => return format!("Shop {topic} at {name}"),
            _ => {}
        }
    }
    match intent(query) {
        "review" => [
            format!("The Best {topic}: Our Picks for 2026"),
            format!("{topic}: Compared in Daily Use"),
            format!("{topic}: How to Choose"),
            format!("Best {topic}: Buying Guide"),
            format!("{topic}: Design and Construction"),
            format!("{topic}: Layout and Specifications"),
            format!("{topic}: Features and Everyday Use"),
            format!("{topic}: What to Look For"),
            format!("Our Favorite {topic}: Value and Performance"),
            format!("{topic}: A Closer Comparison"),
            format!("{topic}: Specifications and Options"),
            format!("{topic}: Field Reviews"),
            format!("Compare {topic}: Prices and Features"),
        ][angle % 13]
            .clone(),
        "definition" => {
            let term = query
                .strip_prefix("what is ")
                .or_else(|| query.strip_prefix("what are "))
                .unwrap_or(query);
            let term = term
                .strip_prefix("a ")
                .or_else(|| term.strip_prefix("an "))
                .unwrap_or(term);
            match host {
                "en.wikipedia.org" => proper(term),
                "www.britannica.com" => {
                    format!("{}: Definition, Types and Uses", upper_first(term))
                }
                "dictionary.cambridge.org" => format!("Meaning of {term} in English"),
                "www.merriam-webster.com" => format!("{} Definition", upper_first(term)),
                "www.collinsdictionary.com" => {
                    format!("{} Definition and Meaning", upper_first(term))
                }
                "www.energy.gov" => format!("{}s: How They Work", upper_first(term)),
                "energysavingtrust.org.uk" => {
                    format!("A Guide to {}s for Your Home", upper_first(term))
                }
                "www.which.co.uk" => {
                    format!("{}s Explained: Types and Installation", upper_first(term))
                }
                "www.youtube.com" => format!("How a {term} Works: A Step-by-Step Explanation"),
                "www.reddit.com" => format!("What should I know before choosing a {term}?"),
                "www.sciencefocus.com" => format!("How Does a {term} Work in Practice?"),
                "www.howstuffworks.com" => format!("How {}s Work", upper_first(term)),
                _ => format!("How Does a {term} Work?"),
            }
        }
        "health" => format!(
            "{}: {}",
            subject,
            [
                "symptoms and causes",
                "when to seek advice",
                "signs to watch for",
                "diagnosis and care",
                "diet and supplements",
                "your questions answered",
                "symptoms explained",
                "common concerns",
                "experiences and advice",
                "food sources",
                "health information",
                "follow-up care",
                "nutrition advice"
            ][angle % 13]
        ),
        "howto" => format!(
            "{}: {}",
            subject,
            [
                "Step-by-Step Guide",
                "When and How",
                "Tools and Technique",
                "A Practical Method",
                "Common Mistakes",
                "What Worked for Me",
                "Care Afterward",
                "A Beginner’s Guide",
                "Tips for Success",
                "Questions Answered",
                "Getting Started",
                "Do It Yourself",
                "Before You Begin"
            ][angle % 13]
        ),
        _ => {
            let subject = heading(original);
            if host == "en.wikipedia.org" {
                return proper(query);
            }
            match angle % 13 {
                0 => original.to_owned(),
                1 => subtitle(subject, "Common Questions"),
                2 => format!("How Does {subject} Work?"),
                3 => subtitle(subject, "A Practical Guide"),
                4 => format!("Understanding {subject}"),
                5 => subtitle(subject, "Background and Terminology"),
                6 => subtitle(subject, "Examples and Methods"),
                7 => format!("Getting Started With {subject}"),
                8 => subtitle(subject, "Details Worth Checking"),
                9 => format!("A Closer Look at {subject}"),
                10 => subtitle(subject, "Tips From Practice"),
                11 => subtitle(subject, "Questions From Readers"),
                _ => format!("Working With {subject}"),
            }
        }
    }
}

fn subject_facts(subject: &str) -> Option<[&'static str; 5]> {
    let q = subject.to_lowercase();
    let has = |terms: &[&str]| terms.iter().any(|term| q.contains(term));
    Some(
        if has(&[
            "plant", "fern", "rose", "garden", "tomato", "cactus", "orchid",
        ]) {
            [
                "Roots need air as well as water, so saturated soil can damage them",
                "Pots with drainage holes let excess water escape",
                "Sunlight, temperature and pot size change how quickly soil dries",
                "Moisture below the soil surface can differ from moisture at the surface",
                "New growth and dormant growth need different amounts of water",
            ]
        } else if has(&["bread", "flour", "dough"]) {
            [
                "Flour absorbs water and forms the structure of bread dough",
                "Yeast produces gas that helps bread dough rise",
                "Temperature changes the speed of fermentation",
                "Weighing flour makes a bread recipe easier to repeat",
                "Cooling a loaf before slicing lets its crumb set",
            ]
        } else if has(&["rice", "lentil", "bean", "potato", "pasta", "egg", "food"]) {
            [
                "Larger pieces take longer for heat to reach their centers",
                "Soaking dried pulses lets water reach the interior before cooking",
                "A covered pan loses less water through evaporation",
                "Portion size and the number of diners determine how much food to prepare",
                "Cooking changes texture as starch absorbs water and proteins set",
            ]
        } else if has(&["cat", "dog", "pet"]) {
            [
                "Cats use posture, scent and sounds to communicate",
                "Purring can accompany comfort but can also occur during stress",
                "Age and activity affect how much rest a pet needs",
                "A change in familiar behavior can signal discomfort",
                "A veterinarian can assess a sudden change in eating or activity",
            ]
        } else if has(&["moon", "planet", "jupiter", "sun"]) {
            [
                "Moons are natural satellites that orbit planets or other bodies",
                "The Moon shines by reflecting sunlight rather than producing its own light",
                "The sunlit portion visible from Earth changes through the lunar phases",
                "Small distant moons can be difficult to distinguish in telescope observations",
                "New observations can change the catalog of known natural satellites",
            ]
        } else if has(&["water", "ice", "ocean", "condensation"]) {
            [
                "Water moves between solid, liquid and vapor as it gains or loses heat",
                "Water vapor condenses on a surface cold enough to reach the dew point",
                "Dissolved salts remain when water evaporates from the ocean",
                "Freezing rearranges water molecules into an open crystal structure",
                "Temperature and pressure affect when water changes state",
            ]
        } else if has(&["heat pump", "energy", "solar panel", "electricity"]) {
            [
                "A heat pump uses electricity to move heat rather than making heat by combustion",
                "Solar panels produce electricity when light reaches their cells",
                "Energy use depends on power and the length of time equipment runs",
                "Insulation reduces the heat a building loses to its surroundings",
                "Season and local conditions affect renewable energy output",
            ]
        } else if has(&["battery", "charger"]) {
            [
                "Rechargeable batteries lose capacity as they age and cycle",
                "Battery temperature affects charging and usable capacity",
                "A compatible charger limits voltage and current for the battery",
                "Charging can slow as a battery approaches full",
                "Reduced runtime can indicate wear even when the battery still charges",
            ]
        } else if has(&[
            "vitamin",
            "iron",
            "magnesium",
            "calcium",
            "folate",
            "zinc",
            "potassium",
        ]) {
            [
                "Vitamins and minerals support normal metabolism in small amounts",
                "Food sources supply nutrients alongside protein, fiber and other components",
                "A supplement label gives an amount per serving rather than an individual prescription",
                "Nutrient needs vary with age, diet and other circumstances",
                "Excess supplements can cause harm or interfere with medicines",
            ]
        } else if has(&["fiber", "tile", "ceramic", "material"]) {
            [
                "A material's structure affects its strength and resistance to heat",
                "Surface finish changes how a material wears and grips",
                "Water absorption matters when choosing a material for outdoor use",
                "Thickness and support affect how a panel carries a load",
                "Repair methods depend on whether the damage is at the surface or within the material",
            ]
        } else if has(&["field", "magnetic", "tidal"]) {
            [
                "A changing magnetic field can induce an electric current",
                "Electric currents produce magnetic fields around their conductors",
                "Tides follow the gravitational pull of the Moon and Sun",
                "Tidal energy equipment draws power from moving seawater",
                "Local geography changes the height and flow of a tide",
            ]
        } else if has(&["chain", "toothbrush", "brake", "filter"]) {
            [
                "Wear changes the shape of surfaces that touch during use",
                "Dirt can interfere with movement and accelerate wear",
                "Inspection can reveal damage before a part stops working",
                "Replacement intervals shorten with heavy use or harsh conditions",
                "Cleaning and replacement serve different purposes when a part is worn",
            ]
        } else if has(&["restaurant", "cafe", "dining"]) {
            [
                "Restaurant opening hours can differ between lunch and dinner",
                "A reservation can secure a table while walk-in seating depends on availability",
                "A restaurant's menu lists ingredients relevant to dietary requirements",
                "Service charges and drinks change the total cost of a meal",
                "A restaurant's location matters when planning the journey home after dinner",
            ]
        } else if has(&["hotel", "hostel", "accommodation"]) {
            [
                "A room rate may include breakfast and local taxes or charge them separately",
                "A nonrefundable room can cost less but limits cancellation options",
                "Step-free access can differ between an entrance and individual rooms",
                "Airport accommodation may still require a shuttle or taxi to the terminal",
                "Shared hostel rooms and private rooms have different facilities and booking terms",
            ]
        } else if has(&["eclipse", "lunar", "satellite"]) {
            [
                "A lunar eclipse occurs when Earth's shadow falls across the Moon",
                "Clouds can obscure an eclipse even when the Moon is above the horizon",
                "A lunar eclipse is visible from the night side of Earth where the Moon is in view",
                "Earth's atmosphere bends some sunlight into its shadow during a total lunar eclipse",
                "The Moon can look red during totality because of sunlight passing through Earth's atmosphere",
            ]
        } else if has(&["postal", "stamp", "philately"]) {
            [
                "Postage stamps show that a postal fee has been paid",
                "A postmark can identify when and where a stamp was used",
                "Condition and rarity affect a stamp's collectible value",
                "Perforations separate stamps on many printed sheets",
                "A stamp catalog distinguishes issues by design, date and printing details",
            ]
        } else if has(&[
            "bicycle", "shelf", "suede", "keyboard", "repair", "clean", "install",
        ]) {
            [
                "A material determines which cleaning products and repair methods are compatible",
                "Loose dirt can scratch a surface when mixed with a liquid cleaner",
                "A small hidden area can reveal whether a cleaner changes the finish",
                "Soft brush bristles lift dirt with less abrasion than stiff bristles",
                "Damp material can change shape or develop surface damage during use",
            ]
        } else if has(&["pricing", "subscription", "billing"]) {
            [
                "Subscription prices can include recurring charges and separate usage fees",
                "A quoted price may include taxes and required extras or list them separately",
                "A monthly payment and an annual commitment have different cancellation terms",
                "A trial period may end with an automatic renewal unless it is canceled",
                "Included services and the billing period determine the total subscription price",
            ]
        } else {
            return None;
        },
    )
}

fn factual_article(query: &str, host: &str, angle: usize, facts: [String; 5]) -> Article {
    let first = angle % facts.len();
    let second = (first + 1 + angle / facts.len() % (facts.len() - 1)) % facts.len();
    let kind = site_profile(host).kind;
    let lead = match kind.as_str() {
        "forum" => format!(
            "From the discussion, {}; {}.",
            lower_first(&facts[first]),
            lower_first(&facts[second])
        ),
        "qa" => format!("{} — {}.", facts[first], lower_first(&facts[second])),
        _ => format!("{}; {}.", facts[first], lower_first(&facts[second])),
    };
    Article {
        title: query.to_owned(),
        lead: excerpt(&upper_first(&lead)),
        detail: format!("{}.", facts[(second + 1) % facts.len()]),
        steps: vec![],
        tip: format!("{}.", facts[(second + 2) % facts.len()]),
        example: "",
        question: "How can I tell whether this applies in my situation?",
        reply: "Describe what happened and the conditions at the time so others can compare their experience.",
    }
}

fn question_article(query: &str, host: &str, angle: usize, question: &Question) -> Article {
    let subject = &question.subject;
    let q = query.to_lowercase();
    let facts: [String; 5] = if matches!(question.shape, "amount" | "count") {
        if q.contains("water")
            && ["plant", "tomato", "fern", "rose"]
                .iter()
                .any(|word| q.contains(word))
        {
            [
                "Water needs change with the size of the plant and how quickly its soil dries",
                "Water the root zone rather than using leaf wetness as a measure",
                "A pot must drain so that roots are not left standing in water",
                "Hot weather and active growth can increase a plant's water use",
                "Check moisture below the soil surface before adding more water",
            ]
            .map(str::to_owned)
        } else if q.contains("moon") {
            [
                "Moon counts change as new natural satellites are discovered and confirmed",
                "A planet's large familiar moons are only part of its satellite system",
                "Small distant satellites are harder to confirm than large nearby moons",
                "Astronomers distinguish confirmed moons from candidates still being observed",
                "An up-to-date satellite catalog gives a count together with its observation date",
            ]
            .map(str::to_owned)
        } else if q.contains("electricity") || q.contains("solar") {
            [
                "Energy use is power multiplied by running time",
                "Solar panel sizing starts with daily energy use and local sunlight",
                "Rated power differs from the output equipment delivers in changing conditions",
                "Seasonal demand changes the amount of electricity a home needs",
                "Measure consumption over a representative period before sizing an energy system",
            ]
            .map(str::to_owned)
        } else if ["rice", "flour", "egg", "potato", "food", "bread"]
            .iter()
            .any(|word| q.contains(word))
        {
            [
                format!(
                    "The amount of {subject} needed changes with the number and size of servings"
                ),
                format!("Weigh {subject} before dividing it into portions"),
                format!("Use the recipe's serving count when scaling {subject}"),
                format!(
                    "A volume measure and a weight measure describe different quantities of {subject}"
                ),
                format!(
                    "Keep the ratio of {subject} to the other ingredients consistent when changing batch size"
                ),
            ]
        } else {
            [
                format!("The amount of {subject} depends on the capacity required for the task"),
                format!("Use consistent units when comparing quantities of {subject}"),
                format!("Distinguish the total amount of {subject} from the amount used at once"),
                format!("Account for peak demand when sizing {subject}"),
                format!("Check the requirements before choosing the amount of {subject}"),
            ]
        }
    } else if q.contains("egg") && question.shape == "duration" {
        [
            "Egg size and starting temperature affect how quickly the center sets",
            "A soft yolk needs less time in hot water than a firm yolk",
            "Cooling boiled eggs in cold water slows further cooking",
            "Starting in boiling water makes timing easier to repeat",
            "A gentle simmer helps keep the shells from cracking",
        ]
        .map(str::to_owned)
    } else if q.contains("sky") {
        [
            "Air molecules scatter blue sunlight more strongly than red sunlight",
            "Scattered sunlight reaches your eyes from across the daytime sky",
            "Sunlight travels through more air near sunrise and sunset",
            "Dust and droplets change how light spreads through the atmosphere",
            "The sky's color comes from scattered light rather than a blue surface",
        ]
        .map(str::to_owned)
    } else if q.contains("cat") && q.contains("knead") {
        [
            "Kneading begins in kittenhood during nursing and can continue in adult cats",
            "A relaxed cat may knead a soft blanket before settling down",
            "Cats have scent glands in their paws and can leave scent while kneading",
            "Kneading often accompanies purring and other relaxed behavior",
            "A blanket can protect your lap from claws without punishing the cat",
        ]
        .map(str::to_owned)
    } else if q.contains("charge") || q.contains("electric car") {
        [
            "Charging time depends on battery capacity and the power reaching the battery",
            "A household outlet supplies less power than a dedicated charging point",
            "The battery and charger each limit the charging rate",
            "Fast charging usually slows as the battery approaches full",
            "Battery temperature and the starting charge affect the time needed",
        ]
        .map(str::to_owned)
    } else if q.contains("swallow") && q.contains("gum") {
        [
            "The body does not break down gum base as it does ordinary food",
            "A small swallowed piece usually moves through the digestive tract",
            "Swallowed gum does not stay in the stomach for years",
            "Swallowing gum repeatedly is different from accidentally swallowing one piece",
            "Gum is meant to be chewed and discarded rather than swallowed",
        ]
        .map(str::to_owned)
    } else if question.shape == "duration"
        && ["rice", "lentil", "bean", "potato", "pasta", "food"]
            .iter()
            .any(|word| q.contains(word))
    {
        [
            "Cooking time changes with the size of the pieces and their starting temperature",
            "Dried ingredients need time to absorb water before their centers soften",
            "A gentle simmer heats food without the movement of a rolling boil",
            "Check the center for the texture you want before taking the pan off the heat",
            "Soaking can shorten cooking, but different varieties soften at different rates",
        ]
        .map(str::to_owned)
    } else if question.shape == "timing"
        && ["prune", "trim", "cut back"]
            .iter()
            .any(|word| q.contains(word))
    {
        [
            "Pruning time depends on whether a plant flowers on old wood or new growth",
            "Remove dead or damaged growth when you notice it",
            "Pruning before flowering can remove buds from plants that bloom on older wood",
            "Heavy pruning during heat or drought can add stress to a plant",
            "Check the flowering habit before choosing a season for a major cutback",
        ]
        .map(str::to_owned)
    } else if question.shape == "timing" && q.contains("harvest") {
        [
            "Harvest readiness depends on the crop and the stage of growth you want",
            "Check a small sample rather than relying only on days since planting",
            "The variety and growing conditions affect when a crop matures",
            "Young crops and crops intended for storage can need different harvest times",
            "Handle the crop gently and separate damaged produce before storage",
        ]
        .map(str::to_owned)
    } else if question.shape == "frequency" && q.contains("cat") {
        [
            "Cats usually divide their sleep into several bouts across the day and night",
            "Kittens and older cats may rest more than active adult cats",
            "Activity, feeding and household routines can change a cat's sleep pattern",
            "Look for changes in the cat's usual routine rather than expecting one fixed schedule",
            "Unusual lethargy alongside changes in appetite or movement deserves veterinary advice",
        ]
        .map(str::to_owned)
    } else if question.shape == "consequence" && q.contains("freeze") {
        [
            "Freezing turns water in food into ice and slows microbial growth",
            "Ice crystals can change a food's texture after thawing",
            "Wrapping food limits moisture loss and freezer burn",
            "Freezing does not reverse spoilage that happened beforehand",
            "Thawing lets ice melt and moisture move through the food again",
        ]
        .map(str::to_owned)
    } else if let Some(facts) = subject_facts(subject) {
        facts.map(str::to_owned)
    } else {
        match question.shape {
            "duration" => [
                format!("The time needed for {subject} changes with temperature and size"),
                format!("Check the condition of {subject} as well as elapsed time"),
                format!("Preparation affects how quickly {subject} reaches the desired condition"),
                format!("A larger amount of {subject} can take longer to finish"),
                format!("Keep the starting conditions consistent when timing {subject}"),
            ],
            "amount" | "count" => [
                format!("The amount of {subject} needed depends on the scale of the task"),
                format!("Measure {subject} using consistent units"),
                format!("Allow for waste when estimating the amount of {subject}"),
                format!("Check the size of each portion before counting {subject}"),
                format!("Separate the total amount of {subject} from the amount used at once"),
            ],
            "frequency" | "timing" => [
                format!("The condition of {subject} matters more than a fixed calendar date"),
                format!("Check {subject} more often during heavy use"),
                format!("Seasonal changes can affect the care that {subject} needs"),
                format!("Inspect {subject} before repeating the task"),
                format!("Follow the care instructions for the particular type of {subject}"),
            ],
            _ => [
                format!("Changes in temperature can affect {subject}"),
                format!("Moisture changes how {subject} behaves"),
                format!("The surroundings influence the condition of {subject}"),
                format!("Watch how {subject} changes when the conditions change"),
                format!("The material and structure of {subject} affect the outcome"),
            ],
        }
    };
    factual_article(query, host, angle, facts)
}

fn topic_article(_seed: &Seed, subject: &str, host: &str, angle: usize) -> Article {
    let q = subject.to_lowercase();
    let shape = intent(subject);
    if let Some(question) = Question::parse(subject) {
        return question_article(subject, host, angle, &question);
    }
    let (detail, steps, tip) = match shape {
        "general" | "definition" if q.contains("vitamin d") => (
            "Vitamins are nutrients needed in small amounts for normal growth and metabolism. Vitamin D helps the body absorb calcium and supports bone health; it comes from skin exposure to sunlight, foods and supplements. The amount a person needs depends on age and other circumstances.",
            vec![
                "Distinguish dietary sources from supplements.",
                "Read the amount per serving on the label.",
                "Discuss a suspected deficiency with a clinician.",
            ],
            "Too much of a supplement can cause harm; follow professional advice about dose.",
        ),
        "problem" if q.contains("error") || q.contains("connection refused") => (
            "The exact error message identifies which operation failed. Check the address, credentials and permissions before changing several settings at once. A refused connection can mean the service is not listening at the requested address or port; an authentication failure needs a separate check of the account and access rules.",
            vec![
                "Copy the complete error message and note the operation that failed.",
                "Check the service address, port and account permissions.",
                "Compare the configuration with the documentation for the installed version.",
                "Retry one small operation after each change.",
            ],
            "Keep credentials out of shared logs when asking for help.",
        ),
        "problem"
            if ["laptop", "computer", "monitor", "printer"]
                .iter()
                .any(|word| q.contains(word)) =>
        {
            (
                "A power supply fault, a loose connection or an interrupted update can all prevent startup. Disconnect external accessories and check the power indicator first. If the device reaches its recovery screen, follow the maker’s recovery instructions before reinstalling software or erasing files.",
                vec![
                    "Check the power cable, adapter rating and charging indicator.",
                    "Disconnect accessories and try the maker’s startup procedure.",
                    "Use the recovery menu if it appears, keeping personal files when that option is available.",
                    "Arrange service if there is no power indicator or the device becomes unusually hot.",
                ],
                "Do not interrupt an update that is still making progress; check the maker’s guidance for a stalled update.",
            )
        }
        "problem" => (
            "Wear, alignment and a loose connection can produce similar symptoms. Look for visible damage before adjusting anything. Change one setting at a time so you can tell which change helped.",
            vec![
                "Stop using the item if a part is loose or damaged.",
                "Check the fit, connections and adjustment against the maker’s instructions.",
                "Inspect parts that move or carry load for wear.",
                "Ask a repair specialist if the fault returns after adjustment.",
            ],
            "Avoid forcing a stuck part; damage can spread to nearby components.",
        ),
        "review" => (
            "Compare the exact model numbers, dimensions and included accessories. A lower price may mean fewer features or a shorter warranty. For daily use, comfort and compatibility can matter more than a long feature list.",
            vec![
                "Decide which features you need for everyday use.",
                "Check compatibility with the equipment you already own.",
                "Compare the full price, warranty and return terms.",
            ],
            "Similar model names can cover different revisions; check the full specification before buying.",
        ),
        "service" => (
            "The appliance model, current subscription and renewal date determine which license you need. Firmware maintenance and a service subscription may be separate purchases. Keep a copy of the entitlement before changing the account or appliance.",
            vec![
                "Find the serial number and current license expiry date.",
                "Confirm the subscription tier and covered features with the vendor.",
                "Apply the renewal in the account portal and check the appliance status.",
            ],
            "Ask the vendor whether a lapse interrupts remote access before scheduling a renewal.",
        ),
        "health" if q.contains("deficien") => (
            "Fatigue, muscle weakness or bone pain can occur with some deficiencies, but symptoms alone cannot confirm the cause. A clinician may use a blood sample alongside your symptoms, diet and medicines. High doses of a supplement can cause harm, so discuss the dose before taking it regularly.",
            vec![
                "Note when symptoms began and whether they are changing.",
                "Tell your clinician about medicines and supplements you take.",
                "Ask whether a blood sample or follow-up appointment is appropriate.",
            ],
            "Seek prompt medical attention for severe or rapidly worsening symptoms.",
        ),
        "health" => (
            "Symptoms, medicines and existing conditions all matter when considering health advice. A pharmacist can check interactions, while a clinician can assess symptoms that persist or get worse. An approach that helps one person may be unsuitable for another.",
            vec![
                "Note when symptoms began and what makes them better or worse.",
                "Check medicine labels and ask about interactions.",
                "Discuss persistent symptoms with a clinician.",
            ],
            "Do not stop prescribed medicine without discussing it with your clinician.",
        ),
        "question"
            if (q.contains("dog") || q.contains("cat "))
                && (q.contains("eat") || q.contains("food")) =>
        {
            (
                "Some human foods are dangerous for pets even in small amounts. Grapes and raisins can cause kidney injury in dogs; do not offer them as treats. If a pet has eaten a potentially toxic food, contact a veterinarian promptly rather than waiting for symptoms.",
                vec![
                    "Keep the food and packaging out of the animal’s reach.",
                    "Write down the food, approximate amount and time eaten.",
                    "Contact a veterinarian before trying a home remedy.",
                ],
                "Do not induce vomiting unless a veterinarian directs you to do so.",
            )
        }
        "question" if q.starts_with("who invented ") && q.contains("telephone") => (
            "Invention often involves several contributors: an early design, a working device and a patent may have different dates and authors. Alexander Graham Bell received a telephone patent in 1876, while other inventors, including Antonio Meucci and Elisha Gray, contributed to the development of voice communication. Credit depends on which milestone is being discussed.",
            vec![
                "Separate the first working device from the patent date.",
                "Look for contemporary documents rather than later retellings.",
                "Check how historians describe the contributions of other inventors.",
            ],
            "A patent date establishes a legal milestone; it does not establish that one person worked alone.",
        ),
        "question" => (
            "A short answer can leave out conditions that change the conclusion. Separate the usual case from exceptions and check the source’s date. Historical claims may also distinguish an early idea, a working device and later commercial use.",
            vec![
                "Identify exactly what the question asks.",
                "Read the original source alongside a recent explanation.",
                "Distinguish a documented fact from a disputed interpretation.",
            ],
            "For a decision with lasting consequences, ask a specialist about your circumstances.",
        ),
        "howto" => (
            "The right tools and order of work depend on the material and model. Read the care instructions before starting, work gently and check each stage before moving on. Stop if you see cracking, discoloration or loose fittings.",
            vec![
                "Prepare a clear workspace and the appropriate tools.",
                "Follow the maker’s instructions for the material or model.",
                "Check the result before continuing to the next stage.",
                "Finish by checking the fit and clearing the workspace.",
            ],
            "If a step needs more force than the instructions describe, stop and check the fit.",
        ),
        _ => (
            "The subject can be approached through its history, practical uses and the terms specialists use to describe it. Reference works give a starting point; primary sources provide the dates, measurements and definitions behind a fuller explanation.",
            vec![
                "Start with an overview of the subject.",
                "Follow references to the original source.",
                "Read examples in the field you are interested in.",
            ],
            "Keep dates and units with any figures you quote.",
        ),
    };
    let angles: &[&str] = match shape {
        "problem" if q.contains("error") || q.contains("connection refused") => &[
            "Read the complete error before changing settings",
            "Check the address and port used by the failing operation",
            "A refused connection can mean the service is not listening",
            "Compare the configuration with the installed version’s documentation",
            "Check account permissions separately from network access",
            "A small reproduction helps locate the failing step",
            "Confirm that the service is running before changing the client",
            "Review recent changes to credentials and access rules",
            "Check which operation produced the first error",
            "Keep sensitive values out of logs you share",
            "Change one setting at a time and retry a small request",
            "Look for an earlier error that explains the later failure",
            "Record the working configuration before making changes",
        ],
        "problem"
            if ["laptop", "computer", "monitor", "printer"]
                .iter()
                .any(|word| q.contains(word)) =>
        {
            &[
                "Start with the power supply and indicator lights",
                "Disconnect accessories before trying recovery",
                "A stalled update can leave a device unable to start",
                "Check the adapter and cable before opening the case",
                "A blank display does not always mean there is no power",
                "The maker’s recovery procedure can help after an update",
                "Avoid erasing files before checking recovery options",
                "Note any lights, sounds or error messages",
                "Compare the symptoms with the model’s support guide",
                "A charging fault may prevent startup",
                "Seek service if there are signs of heat or battery damage",
                "Check whether the device reaches its recovery screen",
                "Record which update preceded the startup problem",
            ]
        }
        "problem" => &[
            "Wear and poor adjustment are common starting points",
            "Check alignment before replacing parts",
            "A loose fitting can cause an intermittent fault",
            "Watch the movement slowly to locate the fault",
            "Inspect contact points for uneven wear",
            "Start with the simplest external checks",
            "A problem under load may need a closer inspection",
            "Check recent changes before making another adjustment",
            "Compare the fit with the maker’s instructions",
            "Stop if the fault makes the item unsafe",
            "A repair shop can check parts that are hard to inspect",
            "Note when the fault occurs and which parts move",
            "Check for damage before trying another adjustment",
        ],
        "health" => &[
            "Symptoms can have more than one cause",
            "Your diet and medicines help a clinician assess symptoms",
            "Persistent symptoms deserve an appointment",
            "A blood sample can help clarify a suspected deficiency",
            "Supplement doses should reflect individual needs",
            "Fatigue alone does not identify a deficiency",
            "Discuss new symptoms alongside existing conditions",
            "Keep track of changes in energy and strength",
            "Ask a pharmacist about supplement interactions",
            "A clinician can interpret results alongside symptoms",
            "Food sources and supplements provide different amounts",
            "Follow-up advice depends on the cause of symptoms",
            "Avoid high doses without medical advice",
        ],
        "review" => &[
            "Our picks put daily comfort and value first",
            "We compared features that matter in regular use",
            "Start with compatibility before comparing prices",
            "A useful buying guide separates essentials from extras",
            "Browse models by size and included features",
            "Owners discuss what they would buy again",
            "Check the controls and construction before choosing",
            "Compare the full cost including accessories",
            "Small specification differences can change the value",
            "Shop by model and check return conditions",
            "A familiar layout can matter more than extra features",
            "Long-term comfort deserves a place in the comparison",
            "Read the warranty terms alongside the specification",
        ],
        "service" => &[
            "Check the expiry date before renewing",
            "Match the entitlement to the appliance serial number",
            "Renewal terms can differ by subscription tier",
            "Keep account access ready before changing the license",
            "Check which features continue after expiry",
            "Ask the vendor about renewal processing time",
            "A firmware update may not extend a subscription",
            "Confirm whether the renewal starts at purchase or expiry",
            "Keep the entitlement receipt with the appliance details",
            "Verify the new expiry date on the appliance",
            "Allow time for a reseller to process the renewal",
            "Check remote access requirements before a license lapses",
            "Compare support coverage with the renewal quote",
        ],
        _ => &[],
    };
    let lead = if shape == "question"
        && (q.contains("dog") || q.contains("cat "))
        && (q.contains("eat") || q.contains("food"))
    {
        excerpt(&proper(&format!(
            "{}.",
            [
                "some human foods are toxic to pets",
                "grapes and raisins can harm a dog’s kidneys",
                "call a veterinarian promptly after a possible poisoning",
                "do not wait for symptoms after a dog eats grapes",
                "a small portion does not establish that a food is safe",
                "pet owners should check foods before offering treats",
                "keep grapes and raisins away from dogs",
                "the animal’s weight and amount eaten matter to the veterinarian",
                "avoid home remedies after a possible poisoning",
                "save the packaging when asking for veterinary advice",
                "a veterinarian can advise on urgent care",
                "human snacks are not always suitable for pets",
                "check ingredients as well as the name of a food"
            ][angle % 13]
        )))
    } else if shape == "question" && q.contains("invent") {
        excerpt(&proper(&format!(
            "{}.",
            [
                "credit can involve a device, a patent and later improvements",
                "patent dates help distinguish competing claims",
                "contemporary accounts may name several contributors",
                "an early design differs from a working device",
                "historians distinguish invention from commercialization",
                "a patent does not describe every contribution",
                "later improvements can be as important as the first design",
                "check the dates behind familiar accounts",
                "primary documents help explain disputes over credit",
                "a single name can hide a longer development process",
                "compare the first device with its later practical use",
                "historical accounts differ in the milestone they emphasize",
                "read the original claims alongside modern histories"
            ][angle % 13]
        )))
    } else if angles.is_empty() {
        let topic = words(subject)
            .into_iter()
            .filter(|word| !["repair", "clean", "install"].contains(&word.as_str()))
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(facts) = subject_facts(subject) {
            excerpt(&format!(
                "For {topic}, {}",
                lower_first(&factual_article(subject, host, angle, facts.map(str::to_owned)).lead)
            ))
        } else {
            excerpt(&format!("{} — {}", proper(&topic), site_profile(host).name))
        }
    } else {
        excerpt(&proper(&format!("{}.", angles[angle % 13])))
    };
    Article {
        title: subject.to_owned(),
        lead,
        detail: detail.into(),
        steps: steps.into_iter().map(str::to_owned).collect(),
        tip: tip.into(),
        example: "",
        question: "What should I check before deciding on the next step?",
        reply: "I would check the exact model or circumstances first and ask a specialist if the advice does not fit.",
    }
}

fn intent_article(seed: &Seed, subject: &str, host: &str, angle: usize) -> Article {
    let q = subject.to_lowercase();
    if !q.contains("cactus")
        && !q.contains("coffee")
        && !q.contains("heat pump")
        && !q.contains("boot")
        && !q.contains("hiking")
    {
        return topic_article(seed, subject, host, angle);
    }
    let (leads, detail, steps, tip, question, reply): (&[&str], &str, Vec<&str>, &str, &str, &str) =
        if q.contains("cactus") || q.contains("repot") {
            (
                &[
                    "Repot a cactus into a container just wider than its roots, using a gritty mix that drains freely rather than moisture-retaining houseplant compost.",
                    "A cactus needs repotting when its roots fill the pot; protect your hands with folded newspaper and keep the plant at its previous soil level.",
                    "Move a cactus to a pot with drainage holes, loosening the dry root ball carefully so the roots can spread into fresh, free-draining compost.",
                    "Use a folded towel to lift a cactus without gripping its spines, then settle the roots into a slightly larger pot filled with gritty compost.",
                    "The easiest time to repot a cactus is at the start of active growth, when the roots can recover before the plant needs regular watering again.",
                    "Has anyone repotted a tall cactus without breaking it? Mine is top-heavy, so I am planning to support the stem while I loosen the root ball.",
                    "After repotting a cactus, let damaged roots dry before watering; wet compost around fresh injuries can make root rot more likely to develop.",
                    "Choose a cactus pot for its drainage and root space, keeping the stem base above the compost rather than burying it to make the plant steady.",
                    "A cactus root ball should come free with gentle pressure on the pot; cutting a plastic container is safer than pulling hard against the stem.",
                    "Brush loose compost away from cactus roots and trim only damaged sections, allowing any cuts to dry before settling the plant into its new pot.",
                    "Wear puncture-resistant gloves when moving a cactus, but use tongs or a newspaper collar as well because fine spines can pass through fabric.",
                    "Spring cactus care starts with checking the drainage holes for crowded roots, then selecting a pot only one size larger if a move is needed.",
                    "Keep a newly repotted cactus out of harsh direct sun while it settles, returning to normal light gradually rather than changing everything at once.",
                ],
                "Use a pot with an open drainage hole and a gritty cactus mix. Work with dry compost so the root ball is easier to release. Do not bury the stem deeper than before.",
                vec![
                    "Protect your hands and wrap the cactus in folded newspaper.",
                    "Loosen the root ball and remove damaged roots.",
                    "Set it at the same depth in a slightly larger pot.",
                    "Wait several days before watering so root injuries can dry.",
                ],
                "A large pot holds damp compost around unused roots. Move up one size rather than choosing the biggest container.",
                "My cactus roots are growing through the drainage holes. How can I move it without damaging the spines?",
                "I wrapped mine in folded newspaper and worked with dry compost. I kept it at the same depth and waited before watering.",
            )
        } else if intent(subject) == "health" {
            (
                &[
                    "Coffee before a run can increase alertness, but caffeine may also cause an upset stomach or urgency; try a small amount on an easy training day.",
                    "Drinking coffee before running is a matter of tolerance and timing, since caffeine can leave some runners jittery even when others feel more alert.",
                    "Caffeine can help exercise performance for some adults, though more coffee is not always better and a large serving may bring nausea or palpitations.",
                    "If coffee upsets your stomach before a run, try reducing the serving or allowing more time before leaving, rather than trying a new habit on race day.",
                    "A morning coffee may fit your running routine if you tolerate it well, but pay attention to sleep, stomach symptoms and the amount you usually drink.",
                    "Coffee can make a pre-run bathroom visit more likely, so leave time before setting off and avoid assuming a stronger cup will improve your session.",
                    "Before a long run, keep coffee intake familiar and drink water as needed; caffeine does not replace the fluids and food that support your training.",
                    "Some runners feel shaky after coffee even at an ordinary serving size, making a smaller cup or a caffeine-free morning a more comfortable choice.",
                    "Do you drink coffee before running? I like the routine, but on faster days I get stomach cramps and wonder whether changing the timing would help.",
                    "Coffee before exercise works differently from person to person, and milk, food and serving size may affect how comfortable you feel once you start.",
                    "Check the caffeine content of your pre-run drink because a large cafe coffee can contain much more than the small cup you normally make at home.",
                    "If caffeine brings chest pain, faintness or persistent palpitations, stop exercising and seek medical advice instead of trying to run through symptoms.",
                    "Evening runners may find coffee interferes with sleep long after the workout, so consider your bedtime as well as how alert you feel on the run.",
                ],
                "Caffeine may improve alertness and exercise performance, but it can also cause jitteriness, stomach upset and difficulty sleeping. People differ in sensitivity. Discuss caffeine with a clinician if you have a heart condition, are pregnant or take medicines that interact with it.",
                vec![
                    "Try your usual small serving before an easy run.",
                    "Leave time to notice stomach symptoms before setting off.",
                    "Avoid increasing the amount for the first time on race day.",
                ],
                "Stop if you feel unwell. Persistent palpitations or chest pain need medical attention.",
                "Coffee before my run sometimes makes me feel shaky. Would a smaller cup or more time beforehand help?",
                "I found a smaller serving easier on my stomach. That is my experience rather than a reason for you to ignore symptoms.",
            )
        } else if q.contains("heat pump") {
            (
                &[
                    "A heat pump moves heat rather than making it by burning fuel, using electricity to transfer warmth from outdoor air or the ground into a building.",
                    "Heat pumps use a refrigerant circuit to carry heat between two places, with a compressor raising the temperature before heat reaches the indoor system.",
                    "Heat pump means a device that transfers thermal energy from a cooler place to a warmer one by using external work, usually supplied as electricity.",
                    "A heat pump is a heating and cooling machine whose refrigerant absorbs heat at one temperature and releases it at another after compression.",
                    "An air-source heat pump takes energy from outdoor air even in cold weather, although its efficiency and available heating output depend on the conditions.",
                    "A ground-source heat pump draws warmth from buried pipes, needing space for a ground loop as well as equipment inside or beside the building.",
                    "Heat pumps often work best with steady, lower-temperature heating, making insulation and correctly sized radiators part of the installation design.",
                    "Inside a heat pump, the evaporator, compressor, condenser and expansion valve form a circuit that moves energy without burning fuel in the home.",
                    "Is a heat pump right for an older house? The answer depends on heat loss, radiator sizes and the water temperature needed to keep the rooms warm.",
                    "A reversible heat pump can cool as well as heat, changing the direction of heat transfer so indoor warmth is released outside during warmer weather.",
                    "Heat pump efficiency is expressed as heat delivered per unit of electricity, with seasonal performance reflecting changing outdoor temperatures.",
                    "A heat pump installation needs a heat-loss calculation for the building, helping the installer choose equipment and emitters that can meet demand.",
                    "Unlike a boiler that burns fuel, a heat pump transfers existing heat, so its electricity use depends on the temperature lift and the building’s demand.",
                ],
                "A heat pump transfers energy through a refrigerant circuit. The evaporator absorbs heat, the compressor raises the refrigerant pressure, and the condenser releases heat indoors. The expansion valve lowers the pressure before the cycle repeats.",
                vec![
                    "The refrigerant absorbs heat from the air or ground.",
                    "The compressor raises its pressure and temperature.",
                    "Heat passes into indoor air or a water heating circuit.",
                ],
                "Performance depends on outdoor conditions and the temperature needed indoors. A heat-loss calculation matters more than floor area alone.",
                "Can a heat pump warm an older house without replacing every radiator?",
                "It depends on the heat loss and the radiator output at a lower water temperature. An installer needs to calculate those values.",
            )
        } else {
            (
                &[
                    "Winter hiking boots need dependable grip, enough room for warm socks and protection from wet ground; fit matters more than the insulation rating alone.",
                    "We compare winter hiking boots for traction, warmth and comfort on long walks, paying particular attention to heel hold and space around the toes.",
                    "Choose winter hiking boots for the terrain you walk most often, balancing waterproof protection with flexibility and the room needed for thicker socks.",
                    "The best winter hiking boots stay comfortable after hours on wet trails, with secure lacing and soles that grip without making each step feel stiff.",
                    "Browse winter hiking boots by size, lining and waterproof construction, then compare return terms so you can check the fit with your walking socks.",
                    "Which winter hiking boots would you buy for muddy trails? I need room for thick socks, but I do not want my heel lifting every time I climb.",
                    "A winter hiking boot should hold the heel while leaving the toes free, because tight footwear can feel colder as well as causing discomfort downhill.",
                    "Deep lugs help winter hiking boots bite into soft ground, while icy paths may still need traction aids rather than a different rubber sole alone.",
                    "For cold wet walks, compare winter hiking boots with a waterproof lining and a tongue that keeps splashes from entering through the laces.",
                    "Shop winter hiking boots with cushioning and ankle support suited to your pack, checking the fit indoors before taking a new pair onto the trail.",
                    "Insulated winter hiking boots suit slow walks in cold conditions, but a lighter waterproof pair may be more comfortable for brisk days above freezing.",
                    "Our winter hiking boot comparison looks at wet-weather protection and underfoot grip, with fit notes to help narrow the choices before trying pairs.",
                    "Winter hiking boots vary in stiffness and weight, so match the footwear to local trails rather than choosing a mountain boot for every weekend walk.",
                ],
                "For winter walks, compare a waterproof leather hiking boot with an insulated model. The first is often more flexible for mild, wet trails; the second adds warmth but can feel bulky. A deep tread helps in mud, while ice may call for separate traction aids.",
                vec![
                    "Try boots with the socks you plan to wear.",
                    "Check heel hold on an incline and toe room on a descent.",
                    "Compare wet-weather protection, weight and outsole grip.",
                    "Check return terms before wearing a new pair outdoors.",
                ],
                "For sustained snow or steep frozen ground, check compatibility with the traction equipment your route requires.",
                "I need winter hiking boots for wet weekend trails. Is insulation worth the extra weight?",
                "For my mild, wet walks I prefer a waterproof pair with warm socks. I would choose more insulation for slower days in snow.",
            )
        };
    let lead = leads[angle % leads.len()].to_owned();
    Article {
        title: subject.to_owned(),
        lead,
        detail: detail.into(),
        steps: steps.into_iter().map(str::to_owned).collect(),
        tip: tip.into(),
        example: "",
        question,
        reply,
    }
}

fn list_lead(subject: &str, angle: usize) -> Option<String> {
    let q = subject.to_lowercase();
    if matches!(intent(subject), "service" | "problem" | "question") {
        return None;
    }
    let lines: &[&str] = if ["halvard", "hg-400", "gateway", "41877"]
        .iter()
        .any(|w| q.contains(w))
    {
        &[
            "Halvard’s fixed firmware, 7.2.4, closes a critical web portal flaw that can be exploited without signing in to the affected appliance.",
            "The Halvard advisory lists firmware 7.0.0 through 7.2.3 as affected, with the September 22 release fixing the vulnerable web portal code.",
            "I need to schedule an update for our Halvard appliance and want to check the affected firmware range before choosing a maintenance window.",
            "CISA added the Halvard portal flaw to its exploited vulnerabilities catalog on September 26, following the vendor’s firmware release four days earlier.",
            "Administrators running Halvard appliances can disable the web portal on the WAN interface as an interim measure while arranging the firmware upgrade.",
            "The critical Halvard vulnerability concerns the appliance’s web portal rather than a VPN client, with the advisory identifying release 7.2.4 as fixed.",
            "Is a Halvard firmware rollback safe after this update? The advisory identifies older affected releases, so a working VPN tunnel does not settle that question.",
            "Halvard’s September 22 advisory covers the HG-200, HG-400 and HG-900 appliance line, with a firmware fix for the pre-authentication portal flaw.",
            "A severity score of 9.8 puts the Halvard web portal flaw among the critical issues, and the advisory describes an upgrade and an interim mitigation.",
            "Halvard Gateway owners planning a maintenance window should check their installed release against the affected range before downloading a firmware image.",
            "The Halvard patch addresses an unauthenticated attack against the portal, closing the vulnerable code path in the fixed firmware release.",
            "Turning off the Halvard portal on the WAN blocks the described attack, but the advisory still identifies the firmware upgrade as the fix.",
            "The Halvard firmware advisory separates affected releases from the fixed version, helping administrators choose an update rather than an unverified rollback.",
        ]
    } else if q.contains("banana") && q.contains("bread") {
        &[
            "Dense banana bread often starts with too much flour; weigh it before mixing, then fold only until the dry streaks disappear from the batter.",
            "A tender banana loaf needs a light hand with the flour and a gentle fold, leaving a few small lumps rather than beating the batter smooth.",
            "Overmixing develops gluten in banana bread batter, making the crumb tough even when the ingredients and oven temperature are otherwise right.",
            "A gummy banana bread center may need more baking time rather than less flour, so check for wet batter before changing the recipe proportions.",
            "Too much mashed banana can weigh down a loaf; measure the fruit separately and resist adding another banana just because it is very ripe.",
            "For a softer banana bread crumb, bring the wet ingredients together first and add the dry mixture only when the pan and oven are ready.",
            "A small loaf pan makes banana bread deeper and slower to bake, so check the recipe’s pan dimensions before adjusting the time or temperature.",
            "Banana bread can sink when the structure has not set; check the center and let the loaf rest before trying to remove it from the pan.",
            "A dark crust does not prove banana bread is done inside, especially in a deep pan; check the middle with a skewer for traces of wet batter.",
            "Let banana bread cool on a rack before cutting, because a warm crumb can compress under the knife and look heavier than it really is.",
            "Fresh baking soda helps banana bread rise, but adding more is not a cure for a heavy batter; check the date and the recipe’s measured amount.",
            "Packed cups of flour can turn banana bread dry and dense, so spoon the flour lightly into a cup or use the recipe’s weight measurement.",
            "Banana bread batter should be thick enough to hold its shape briefly; note the fruit weight and pan size when comparing one batch with another.",
        ]
    } else if q.contains("flight") || q.contains("airfare") || q.contains("airline") {
        &[
            "Compare departure dates and baggage allowances before choosing flights, since a lower fare can cost more once bags and seats are included.",
            "Use the date grid for flights to compare nearby departure days, keeping the passenger count and cabin bag allowance the same across each search.",
            "Direct flights can save transfer costs as well as time, while a connection may add meals, terminal changes or an overnight stay to the trip.",
            "Check the arrival airport before booking cheap flights, especially when a late landing leaves few trains or buses into the city center.",
            "Midweek flights may offer a different fare range from weekend departures, but compare the total return journey rather than one low outbound fare.",
            "Cheap flights may include only a bag under the seat, so check cabin bag dimensions before adding the luggage you normally travel with.",
            "Compare direct flights with connections by total journey time, including the time needed to change terminals and pass through security again.",
            "Add the price of flights for every traveler before paying, since the lowest advertised fare may apply to fewer seats than your group needs.",
            "Conditions on flexible flights can matter if your dates may change, so compare the change fee and any fare difference alongside the original ticket.",
            "Early flights may require a night near the terminal, making a later service better value even when its ticket costs a little more.",
            "Check airline cancellation conditions before booking flights, including whether a refund goes back to the payment card or comes as travel credit.",
            "Compare flights from nearby departure airports with the cost and duration of the trip to the terminal, particularly when traveling with luggage.",
            "For flights with a self-transfer, check whether bags need collecting and whether the next airline protects the connection if you arrive late.",
        ]
    } else if q.contains("pizza") && q.contains(" in ") {
        &[
            "Compare pizza restaurants by neighborhood, menu and opening hours, allowing time for a walk-up queue if the kitchen does not accept reservations.",
            "Look for a pizza table that fits your evening plans, then check the service charge, drinks and booking terms before confirming a reservation.",
            "A simple margherita is a useful way to compare pizza kitchens, showing the balance of dough, tomato and cheese without extra toppings.",
            "Recent pizza reviews can reveal recurring queue and service problems, but check the date before relying on an account from a previous season.",
            "I have one evening for pizza and would rather avoid crossing town twice, so I am choosing between one well-known kitchen and two neighborhood places.",
            "Traditional pizza is best eaten promptly at a table, because a closed takeaway box softens the base before you get back to your accommodation.",
            "Fried pizza offers a different meal from a wood-fired margherita, so consider a specialist counter as well as the busiest sit-down pizzerias.",
            "Pizza delivery is easiest to compare by the full basket price, including service and delivery fees rather than the menu price of one margherita.",
            "For a group pizza night, check whether everyone can sit together and whether the kitchen takes bookings or seats diners as tables become free.",
            "Some pizza kitchens close between lunch and dinner, making the opening hours as useful as the reviews when planning a short visit to the city.",
            "A walking route between pizza stops leaves more time to explore, but allow for queues and avoid planning several full meals too close together.",
            "Ask about pizza ingredients before ordering if you have allergies, since a short traditional menu does not mean every topping is suitable.",
            "Compare the pizza menu with the day’s specials before joining a queue, particularly if you want a fried pizza or a style beyond margherita.",
        ]
    } else if q.contains("rust") && q.contains("e0502") {
        &[
            "Rust rejects a mutable borrow while a conflicting shared borrow is still in use, so check the last expression that reads through the reference.",
            "Pushing to a Rust vector needs mutable access, which conflicts with an element reference if that reference is used after the push operation.",
            "A Rust borrow can end at its last use, allowing mutation later in the same block when no expression still needs the shared reference.",
            "I can read a Rust vector element before pushing, but keeping that reference for a later print brings a borrow error I am trying to resolve.",
            "Rust shared references permit reading, while a mutable reference needs exclusive access for the time it is used to change the borrowed value.",
            "Moving a Rust reference into another expression can extend its use, so follow where the borrowed value is actually read rather than only its binding.",
            "Use the borrowed Rust value before mutating the collection when the two operations do not need to overlap, letting the shared borrow end first.",
            "For a Rust vector of integers, copying an element into a local value can avoid keeping a reference into the collection while another item is pushed.",
            "A Rust clone may avoid a conflicting borrow by creating independent data, but changing the order of operations can sometimes remove the need to copy.",
            "Nonlexical lifetimes let Rust track borrows through their last use, although a later read still keeps the earlier shared reference active.",
            "Rust methods that take a mutable receiver can conflict with a shared reference into the same value, even if the mutation happens inside the method.",
            "Reduce a Rust borrow error to one collection and one reference, then mark the point where the reference is created and the final place it is used.",
            "A Rust inner scope can make a borrow’s end clear when all reference uses stay inside it, leaving mutation until after that scope finishes.",
        ]
    } else if q.contains("rust") {
        &[
            "Rust gives each value one owner and checks borrows at compile time, helping explain why moving a String differs from passing a reference to it.",
            "A Rust function can borrow a String through a shared reference, reading its contents while the original binding continues to own the value.",
            "Moving a Rust value transfers ownership to another binding, while copying a small Copy value leaves the original available for later expressions.",
            "I can read a Rust vector element before pushing, but keeping its reference for later use brings a borrow error that I am trying to understand.",
            "Rust prevents mutation through a value while a conflicting shared borrow is still active, so trace the reference through its final use.",
            "A borrowed Rust value must remain alive for as long as the reference is used, even when the reference is passed between several functions.",
            "Rust can end a borrow at its last use rather than the end of the surrounding block, allowing later mutation when the reference is no longer needed.",
            "For a small Rust example, compare passing an integer by value with passing a reference into a vector that will later grow or change its contents.",
            "A Rust clone creates an independent owned value when the type supports it, but it is worth checking whether a short borrow is enough instead.",
            "When a Rust borrow error appears, reduce the code to one collection and follow the place where each reference is created and last used.",
            "A mutable Rust reference grants exclusive access for its active lifetime, which prevents another conflicting borrow from reading the same value.",
            "Borrowing in Rust lets functions work with data they do not own, while ownership determines which binding is responsible for dropping the value.",
            "Rust references do not keep a value alive by themselves, so a reference returned from a function must point to data that outlives that call.",
        ]
    } else if q.contains("car") {
        &[
            "Compare used car asking prices for the same model year and trim, checking the mileage and service history before treating a cheaper car as a bargain.",
            "A used car price guide gives a range rather than a guaranteed sale price, with condition and overdue maintenance affecting what a buyer should pay.",
            "Mileage is only one part of a used car valuation, since a documented service history can explain a higher price between otherwise similar examples.",
            "Search used cars within your budget, then compare the engine, equipment and seller type rather than assuming every example of one model costs alike.",
            "Allow for insurance, tax and the next service when comparing used car prices, especially if a lower asking price leaves little room for repairs.",
            "Dealer and private used car prices can differ, so check the warranty terms and the work already completed before deciding which offer is better.",
            "A used car with missing service history may need immediate work, making a slightly more expensive example cheaper to own during the first few months.",
            "To value a used car, compare similar advertised examples and account for condition, specification and mileage rather than relying on the model name alone.",
            "Used car listings are easier to compare when you filter by age and engine first, then check the photographs and description for signs of wear.",
            "An inspection can explain the price gap between two used cars, particularly when tires, brakes or a major service are due on the cheaper example.",
            "Set a used car budget that leaves room for initial maintenance, then compare vehicles with similar mileage and a clear account of previous servicing.",
            "A used car review can help identify recurring maintenance costs, but the condition of the individual vehicle still matters more than its reputation.",
            "Ask a used car seller which work has been completed recently and compare the receipts with the mileage before agreeing the final purchase price.",
        ]
    } else {
        return None;
    };
    Some(lines[angle % lines.len()].into())
}

struct Draft {
    title: String,
    leads: &'static [&'static str],
    detail: &'static str,
    steps: Vec<&'static str>,
    tips: &'static [&'static str],
    example: &'static str,
    question: &'static str,
    reply: &'static str,
}

struct Article {
    title: String,
    lead: String,
    detail: String,
    steps: Vec<String>,
    tip: String,
    example: &'static str,
    question: &'static str,
    reply: &'static str,
}

fn article(seed: &Seed, subject: &str, host: &str, kind: &str, angle: usize) -> Article {
    let lower = heading(subject)
        .split(" /")
        .next()
        .unwrap_or(subject)
        .to_lowercase();
    let n = angle % 10;
    let choose = |items: &[&str]| items[n % items.len()].to_owned();
    if kind == "wiki" {
        let facts = if lower.contains("sourdough") {
            Some([
                "A sourdough starter is a culture of yeasts and lactic acid bacteria in flour and water",
                "Sourdough yeasts produce carbon dioxide that leavens bread",
                "Sourdough bacteria produce acids that contribute to flavor and slow the growth of some other microbes",
                "Sourdough fermentation slows at low temperatures and accelerates in warmer conditions",
                "A young sourdough culture can rise unevenly as its microbial population develops",
            ])
        } else if lower.contains("bread") {
            Some([
                "Bread is a food made from a dough of flour and water, usually baked",
                "Bread crumb consists of a network of air cells held within a set structure",
                "Bread dough expands as fermentation or chemical leavening produces gas",
                "Bread density depends on hydration, mixing and the amount of leavening",
                "Bread develops a firm structure as starch gelatinizes and proteins set during baking",
            ])
        } else if lower.contains("groupby") || lower.contains("itertools") {
            Some([
                "Python's itertools.groupby divides consecutive elements into groups according to a key function",
                "Python grouping starts a new group whenever the key changes",
                "Python groups share their underlying input iterator",
                "Python sorting brings equal keys together before grouping",
                "Python's groupby is used to summarize adjacent runs of data",
            ])
        } else if lower.contains("heat pump") {
            Some([
                "A heat pump transfers thermal energy from a colder source to a warmer destination using external work",
                "The refrigerant absorbs and releases heat as it circulates through a closed circuit",
                "The compressor raises the pressure and temperature of the refrigerant",
                "Reversible systems provide heating and cooling by changing the direction of heat transfer",
                "Efficiency depends on the temperature difference between the source and the heated space",
            ])
        } else if lower.contains("router") || lower.contains("netgear") {
            Some([
                "A router forwards packets between computer networks",
                "A router restart preserves its configuration, while a factory reset restores default settings",
                "Router configuration includes network addresses, wireless settings and access credentials",
                "Router firmware controls packet forwarding and the management interface",
                "Router recovery procedures differ between models and hardware revisions",
            ])
        } else if lower.contains("halvard") || lower.contains("hg-400") {
            Some([
                "Halvard Gateway HG-400 is a network security appliance with a web management portal",
                "Halvard Gateway firmware release 7.2.4 addresses a portal vulnerability",
                "Halvard Gateway releases 7.0.0 through 7.2.3 contain the affected portal code",
                "Halvard Gateway uses firmware to provide its routing and security functions",
                "Halvard Gateway firmware updates replace the software running on the appliance",
            ])
        } else {
            subject_facts(subject)
        };
        if let Some(facts) = facts {
            let mut article = factual_article(subject, host, angle, facts.map(str::to_owned));
            let first = angle % 5;
            let second = (first + 1 + angle / 5 % 4) % 5;
            article.lead = format!("{} and {}.", facts[first], lower_first(facts[second]));
            let remaining = (1..5)
                .map(|offset| (first + offset) % 5)
                .filter(|index| *index != second)
                .collect::<Vec<_>>();
            article.detail = format!(
                "{}; {}.",
                facts[remaining[0]],
                lower_first(facts[remaining[1]])
            );
            article.tip = format!("{}.", facts[remaining[2]]);
            return article;
        }
    }
    if matches!(intent(subject), "problem" | "question" | "service") {
        return topic_article(seed, subject, host, angle);
    }
    let scenario = ["halvard", "hg-400", "gateway", "41877"]
        .iter()
        .any(|w| lower.contains(w));
    if !scenario
        && ![
            "pizza",
            "sourdough",
            "baking",
            "cooking",
            "restaurant",
            "flight",
            "bread",
            "recipe",
            "hotel",
            "router",
            "rust",
            "python",
            "javascript",
            "car",
        ]
        .iter()
        .any(|w| lower.contains(w))
    {
        return intent_article(seed, subject, host, angle);
    }
    let Draft {
        title,
        leads,
        detail,
        steps,
        tips,
        example,
        question,
        reply,
    } = if scenario {
        Draft {
            title: if kind == "forum" || kind == "qa" {
                if lower.contains("downgrade") {
                    "Has anyone rolled back a Halvard Gateway HG-400 after the security update?"
                        .into()
                } else {
                    "Has anyone installed the Halvard Gateway security update?".into()
                }
            } else if kind == "company" || kind == "docs" {
                "Halvard Gateway vulnerability: firmware and security updates".into()
            } else if lower.contains("downgrade") {
                "Halvard admins weigh firmware downgrade risks after critical flaw".into()
            } else {
                "Halvard fixes critical Gateway flaw in firmware 7.2.4".into()
            },
            leads: &[
                "Halvard has released a firmware fix for its VPN appliances after a critical flaw was found in the web portal.",
                "A critical web portal flaw has put Halvard appliance administrators under pressure to upgrade their firmware.",
                "Halvard Gateway owners face an urgent firmware decision after a remotely exploitable flaw was disclosed.",
                "The latest Halvard firmware closes a web portal flaw that attackers can reach without signing in.",
                "Halvard administrators are reviewing older firmware releases after the disclosure of a critical portal flaw.",
                "A firmware release from Halvard addresses a critical flaw across three VPN appliance models.",
                "Security teams running Halvard appliances are checking their firmware after a critical vulnerability disclosure.",
                "Halvard has published a firmware update for a flaw affecting its Gateway VPN and firewall appliances.",
                "An unauthenticated web portal attack is the focus of Halvard’s latest firmware advisory.",
                "Halvard’s firmware advisory sets out which appliance releases are affected by a critical web portal flaw.",
            ],
            detail: "The affected firmware releases run from 7.0.0 through 7.2.3. The fixed release is 7.2.4, issued on September 22. The HG-200, HG-400 and HG-900 are part of the appliance line.",
            steps: vec![
                "Check the appliance model and installed firmware release in the management console.",
                "Read the advisory before choosing a target release; an older image may reintroduce the vulnerability.",
                "Turning off the web portal on the WAN interface blocks the attack until the upgrade is complete.",
            ],
            tips: &[
                "A firmware downgrade is a separate operation from a reset; the advisory does not establish that an older release is safe.",
                "Keeping the portal off the WAN interface is an interim measure while the firmware upgrade is arranged.",
                "The firmware fix was published before CISA added the flaw to its exploited vulnerabilities catalog.",
                "The firmware advisory lists 7.2.4 as the fixed release; earlier affected releases remain vulnerable.",
                "The firmware update addresses a flaw in the portal, rather than in a VPN client.",
                "The affected firmware range includes 7.2.1, the release running on the office appliance.",
                "The firmware flaw can be reached before authentication; a strong portal password does not remove it.",
                "The firmware advisory describes disabling the WAN portal as an interim measure.",
                "A firmware rollback needs its own compatibility assessment before a maintenance window.",
                "The firmware fix covers a critical issue with a CVSS base score of 9.8.",
            ],
            example: "",
            question: "I have an HG-400 on 7.2.1. I need to schedule the upgrade, but can I roll back if our VPN clients have trouble?",
            reply: "I would not treat a working VPN tunnel as proof that the portal is safe. I can help with the maintenance window, but I have not tried a rollback on this model.",
        }
    } else if lower.contains("groupby") || lower.contains("itertools") {
        Draft {
            title: if kind == "qa" {
                "How do I use itertools.groupby() with a key function?".into()
            } else {
                "Python itertools.groupby(): grouping adjacent values by key".into()
            },
            leads: &[
                "Python’s grouping function collects adjacent values with the same key.",
                "The itertools module groups adjacent values rather than collecting every matching value in a sequence.",
                "A Python grouping operation can produce several groups for the same value.",
                "Python’s groupby() reads its input one item at a time.",
                "An itertools grouping key decides where one run ends and the next begins.",
                "Python grouping works on runs of matching values in the input.",
                "The itertools grouping function does not sort its input for you.",
                "Python’s groupby() returns a key and an iterator for each run.",
                "A Python key function can group records by one field.",
                "With itertools, matching values must be adjacent to share a group.",
            ],
            detail: "Each Python group shares the underlying input iterator. Read the group before requesting the next one, or materialize it as a list.",
            steps: vec![
                "Choose a key function, such as taking the first field of a tuple.",
                "Sort with the same key if all matching values should appear together.",
                "Call itertools.groupby() and consume each group before advancing.",
            ],
            tips: &[
                "Python sorting changes the input order. Leave the sequence alone when runs are what you need.",
                "The itertools groups are lazy; converting each to a list preserves it for later use.",
                "A Python dictionary is a better fit when you need to collect matching values without sorting.",
                "Python key functions can read a tuple field, an attribute or a calculated value.",
                "An itertools group disappears as the outer iterator advances; read it immediately.",
                "Use Python’s sorted() with the same key passed to groupby().",
                "Python preserves the order of equal keys during sorting.",
                "With itertools, a later occurrence of a key can start a new group.",
                "A Python list comprehension can materialize the groups in one pass.",
                "Python grouping does not merge nonadjacent runs unless you sort first.",
            ],
            example: "from itertools import groupby\nrows = [('a', 1), ('b', 2), ('a', 3)]\nkey = lambda row: row[0]\nfor name, group in groupby(sorted(rows, key=key), key=key):\n    print(name, list(group))\n# a [('a', 1), ('a', 3)]\n# b [('b', 2)]",
            question: "I anticipated one Python group for each key, but 'a' appears twice. Do I need to sort first, and where does the key function go?",
            reply: "I would sort first if you want all equal keys together. If you want adjacent runs, sorting would change the answer. The Python example below uses the same key in both calls.",
        }
    } else if lower.contains("sourdough") {
        Draft {
            title: if kind == "news" {
                "Bakers explain why sourdough struggles to rise".into()
            } else {
                "Why Your Sourdough Starter Isn’t Rising".into()
            },
            leads: &[
                "A cool kitchen can slow a sourdough culture without killing it.",
                "A young sourdough culture may bubble for days before it doubles reliably.",
                "The feeding ratio changes how quickly sourdough rises and falls.",
                "Sourdough can peak overnight and fall before you check it.",
                "A sourdough culture needs warmth and regular feeding to build strength.",
                "Whole-grain flour can help a sluggish sourdough culture become more active.",
                "Sourdough bubbles are useful, but the rise tells you more about its strength.",
                "A narrow jar makes a sourdough culture’s rise easier to measure.",
                "Water temperature affects how quickly sourdough ferments after a feed.",
                "A sourdough culture can smell lively before it has enough strength for a loaf.",
            ],
            detail: "Mark the sourdough level just after feeding. A line of dried mixture above the current level can show that it rose and fell while you were away.",
            steps: vec![
                "Keep the feeding ratio consistent for several cycles.",
                "Use a clean jar and mark the level after feeding.",
                "Compare bubbles, aroma and rise before changing the schedule.",
            ],
            tips: &[
                "Sourdough needs a warm spot, but direct heat can damage the culture.",
                "A sourdough feeding log makes a slow improvement easier to see.",
                "Give a young sourdough culture time before increasing the feeding frequency.",
            ],
            example: "",
            question: "My sourdough bubbles but barely rises. Should I feed more often?",
            reply: "I would measure the temperature first. More feeding did not help mine in a cold kitchen.",
        }
    } else if lower.contains("bread") || lower.contains("baking") {
        Draft {
            title: choose(&[
                "Why Is My Banana Bread Dense? How to Fix It",
                "The Secret to a Tender Banana Bread Crumb",
                "Dense Banana Bread? Check Your Flour and Mixing",
            ]),
            leads: &[
                "Dense banana bread usually comes down to too much flour or too much mixing.",
                "A heavy banana loaf often starts with a tightly packed cup of flour.",
                "Overmixing bread batter develops gluten and can leave the crumb tough.",
                "A wet bread center and a dense crumb need different fixes.",
                "Extra mashed fruit can make bread heavy even when the crust looks ready.",
                "A tender quick bread starts with measured ingredients and gentle folding.",
                "Bread batter needs only enough mixing to bring the wet and dry ingredients together.",
                "Cutting warm bread can compress the crumb and leave heavy slices.",
                "A dark crust does not always mean the bread is cooked through.",
                "The wrong pan size can leave bread browned outside and wet in the middle.",
            ],
            detail: [
                "Too much flour absorbs the moisture the bread needs. Spoon it lightly into the cup or, better still, weigh it.",
                "Prolonged mixing makes quick bread tough. Stop folding as soon as the last streaks of dry flour disappear.",
                "Too much mashed fruit weighs bread down. Measure the fruit separately rather than adding an extra banana.",
            ][n % 3],
            steps: vec![
                "Weigh the flour and mashed fruit against the recipe quantities.",
                "Fold the dry ingredients into the wet mixture until just combined.",
                "Use the specified pan size and check the center for wet batter.",
                "Let the loaf cool before slicing so the crumb can set.",
            ],
            tips: &[
                "For tender bread, change one variable at a time; start with the flour weight.",
                "A dense bread crumb can also mean the leavening has lost its strength. Check the date before the next batch.",
                "Bread that browns before the center sets may need a lower rack or a lighter-colored pan.",
                "Too much banana can make bread wet in the center. Measure the fruit as carefully as the flour.",
                "Bread slices more cleanly after cooling; a warm crumb can collapse under the knife.",
                "Dense bread can come from old leavening. Try a fresh package for the next loaf.",
                "The bread pan’s depth affects baking time. A tall loaf takes longer to set in the middle.",
                "For quick bread, a few lumps are better than a completely smooth batter.",
                "A bread skewer should come out without wet batter. Moist crumbs are fine.",
                "A heavy bread crumb often improves when the flour is weighed rather than scooped.",
            ],
            example: "",
            question: "My banana bread looks cooked but the slices are dense. Is it the flour or the mixing?",
            reply: "I had the same bread problem with packed cups of flour. Weighing helped, although an extra banana can still make the middle wet.",
        }
    } else if lower.contains("recipe")
        || lower.contains("cooking")
        || lower.contains("dough")
        || lower.contains("roast")
    {
        Draft {
            title: format!("{}: ingredients, timing and method", proper(subject)),
            leads: &[
                "Good cooking starts with ingredients cut to a similar size.",
                "A recipe’s timing depends on portion size as well as heat.",
                "Resting dough gives the flour time to absorb the water.",
                "Cooking over a crowded pan traps steam around the ingredients.",
                "A recipe is easier to follow with the ingredients measured first.",
                "Dough temperature changes how quickly it becomes ready to shape.",
                "A hot oven helps roast vegetables brown at the edges.",
                "Even cooking needs enough space for heat to reach each piece.",
                "Recipe quantities matter when adjusting the size of a batch.",
                "The cooking method should suit the ingredients and the pan.",
            ],
            detail: "Measure the ingredients before heating the pan or oven. The recipe’s timing is a guide; check the texture and doneness before serving.",
            steps: vec![
                "Prepare the ingredients in evenly sized pieces.",
                "Leave space in the pan so moisture can escape.",
                "Check the center before serving.",
            ],
            tips: &[
                "Keep notes on the recipe quantities and cooking temperature when adjusting a batch.",
            ],
            example: "",
            question: "I followed the recipe timing, but the center was still underdone. Should I use a smaller batch?",
            reply: "I would check the pan size before changing the recipe. A crowded pan takes longer.",
        }
    } else if lower.contains("flight") || lower.contains("airfare") || lower.contains("airline") {
        Draft {
            title: if let Some((_, to)) = lower.split_once(" to ") {
                format!(
                    "Cheap Flights to {} from London",
                    proper(to.split(" from ").next().unwrap_or(to))
                )
            } else {
                format!("{}: flights and fare conditions", proper(subject))
            },
            leads: &[
                "Flexible departure dates can help you find cheaper flights without changing your destination.",
                "Compare flights with the same baggage allowance before choosing the cheapest ticket.",
                "A direct flight can cost less overall once transfers and bags are included.",
                "Nearby departure airports offer more choice, but the journey to the terminal adds up.",
                "Midweek flights often offer a different fare range from weekend departures.",
                "A low flight price may cover only a small bag under the seat.",
                "The cheapest airfare can come with a long connection and a late arrival.",
                "Compare the total flight price for every passenger before paying.",
                "A flight’s change conditions matter as much as the initial fare if your dates may move.",
                "Departure times can turn a cheap flight into an expensive overnight stay.",
            ],
            detail: "London Heathrow (LHR), Gatwick (LGW) and Luton (LTN) offer different departure options. Fares start from £89 return. A checked bag costs £35 each way, bringing the return total to £159 before airport transport.",
            steps: vec![
                "Choose departure and return dates and use the same passenger count for each comparison.",
                "Compare direct services with connections, including the time between terminals.",
                "Add bags, seats and airport transport to the total.",
            ],
            tips: &[
                "Flexible fares allow date changes; a fare difference may apply. Checked baggage and seat selection are priced separately.",
            ],
            example: "",
            question: "I can travel midweek. Is the cheaper airfare still worthwhile with a checked bag?",
            reply: "I would compare the total first. My cheaper flight needed a bag fee in each direction.",
        }
    } else if lower.contains("router") {
        Draft {
            title: format!(
                "How to Reset a {} Router Without Losing Access",
                if lower.contains("netgear") {
                    "Netgear"
                } else {
                    "Wi-Fi"
                }
            ),
            leads: &[
                "A router restart preserves settings, while a factory reset removes them.",
                "Check the router model before using its reset control.",
                "A router’s reset control and power switch do different jobs.",
                "Resetting a router clears the settings you need to reconnect.",
                "The router label identifies the model and hardware revision.",
                "An Ethernet connection makes router recovery easier to follow.",
                "A router reset will not usually change the installed firmware.",
                "Export the router configuration before returning it to its defaults.",
                "The router’s admin password may change after a full reset.",
                "A router can take several minutes to reconnect after a reset.",
            ],
            detail: "A router reset removes Wi-Fi credentials and broadband configuration. Check the model’s instructions and keep the connection details somewhere you can reach offline.",
            steps: vec![
                "Identify the exact model and hardware revision.",
                "Export the configuration and note the broadband login separately.",
                "Follow the model-specific procedure with power connected.",
                "Reconnect by Ethernet and check the internet connection.",
            ],
            tips: &[
                "A router restart is worth trying before a reset if the connection has only just stopped working.",
                "Do not reset the router until you have the connection details needed to set it up again.",
                "After a router reset, change the admin password before reconnecting other devices.",
                "Check the router label for the original access details before resetting it.",
                "A router can take several minutes to start again after a reset.",
                "Keep a copy of the router configuration somewhere you can reach without Wi-Fi.",
                "A router reset and a firmware downgrade are separate operations.",
                "Use Ethernet to set up the router if the old Wi-Fi name disappears.",
                "The router’s hardware revision matters when choosing recovery instructions.",
                "Keep the router powered throughout any firmware operation.",
            ],
            example: "",
            question: "I want to reset my router, but I cannot get into the admin page. Will I lose my connection details?",
            reply: "I would try a restart first. A full router reset cleared my Wi-Fi name and connection settings.",
        }
    } else if lower.contains("pizza") || lower.contains("restaurant") || lower.contains("cafe") {
        Draft {
            title: format!(
                "Where to Eat {}",
                proper(subject.trim_start_matches("best "))
            ),
            leads: &[
                "A good pizza is best eaten while the crust is still hot.",
                "Pizza queues move quickly at some counters and slowly at sit-down restaurants.",
                "A short pizza menu can make ordering much easier at a busy table.",
                "A pizza’s soft center is part of the Neapolitan style.",
                "Compare pizza menus before joining the longest queue.",
                "Pizza prices vary with toppings, table service and location.",
                "A pizza counter is a useful alternative when you have little time.",
                "The best pizza stop may be the one close to your next walk.",
                "Pizza reservations are useful for groups, but some kitchens take walk-ins only.",
                "A long trip in a closed box softens a pizza’s crust.",
            ],
            detail: "In Naples, Da Michele, Sorbillo and Starita offer different settings for pizza. Choose a neighborhood first, then compare hours, queues and the menu.",
            steps: vec![
                "Check opening hours and whether reservations are accepted.",
                "Compare table service with a quick counter meal.",
                "Ask about ingredients and dietary requirements before ordering.",
            ],
            tips: &[
                "Pizza at lunchtime can mean a shorter queue than the evening rush.",
                "A simple margherita is a useful way to compare pizza crusts.",
                "Check the full pizza bill for drinks and service charges before comparing prices.",
                "Pizza counters can be a useful stop between museums and a longer evening meal.",
                "A hot pizza tastes different after a long trip back to your room.",
                "Ask about pizza portion sizes before ordering a second dish.",
                "Fried pizza is often easier to buy at a counter than at a traditional table-service restaurant.",
                "A pizza kitchen’s opening hours may differ from the bar’s hours.",
                "For a group, check whether the pizza restaurant can seat everyone together.",
                "Pizza menus can change; ask about the day’s ingredients before choosing.",
            ],
            example: "",
            question: "I have one evening for pizza in Naples. Would you queue or reserve somewhere?",
            reply: "I would stay near the center. I liked the pizza, but crossing town for one queue used up most of my evening.",
        }
    } else if lower.contains("rust") || lower.contains("python") || lower.contains("javascript") {
        Draft {
            title: if lower.contains("ownership") {
                "Understanding Ownership in Rust".into()
            } else {
                format!("{}: a worked example", proper(subject))
            },
            leads: &[
                "A Rust value has one owner, and moving it transfers that ownership.",
                "Rust borrowing lets a function use a value without taking ownership.",
                "Python sequence indexes start at zero and stop before the length.",
                "A JavaScript promise needs to settle before its result can be used.",
                "A Rust shared borrow must end before a conflicting mutation.",
                "Python iteration avoids indexing past the end of a sequence.",
                "Rust ownership follows the value through each expression.",
                "JavaScript error paths should reject a promise rather than leave it pending.",
                "A Rust copy can avoid keeping a reference into a growing collection.",
                "Python’s empty sequences need care when selecting an element.",
            ],
            detail: "Rust ownership and borrowing determine when a value can be used again. Copying a small value before changing a collection avoids keeping a reference into it.",
            steps: vec![
                "Reduce the input to the expression that triggers the error.",
                "Trace each value and the end of each borrow.",
                "Check an empty input and a single element.",
            ],
            tips: &[
                "Rust borrowing errors are easier to understand when the example has just one collection.",
            ],
            example: "let mut values = vec![1, 2];\nlet first = values[0];\nvalues.push(3);\nassert_eq!(first, 1);",
            question: "I am learning Rust ownership. Why can I copy the first value and then push another item?",
            reply: "The Rust example copies an integer. A reference into the vector would keep the borrow open until its last use.",
        }
    } else if lower.contains("car") || lower.contains("prices") {
        Draft {
            title: "Used Car Prices in 2026: Mileage, Age and What Buyers Pay".into(),
            leads: &[
                "Used car prices depend on mileage, condition and service history.",
                "A car’s advertised price is only one part of the cost of ownership.",
                "Comparing car prices works best with the same engine and trim.",
                "Used car buyers need to allow for repairs as well as the asking price.",
                "Car prices can differ substantially between private sellers and dealers.",
                "A cheaper used car may need tires or a major service immediately.",
                "Car price guides give a range rather than a promise of what a seller will accept.",
                "Mileage alone does not explain a used car’s price.",
                "A documented service history can matter more than a small car price difference.",
                "Used car listings need to be compared by age, specification and condition.",
            ],
            detail: "Condition can outweigh a small difference in mileage. An example £8,000 car needing £600 of repairs costs more up front than an £8,400 car with that work already completed.",
            steps: vec![
                "Compare cars with similar mileage and service history.",
                "Budget for tax, insurance and the next service.",
                "Inspect the vehicle before agreeing a price.",
            ],
            tips: &["A used car price guide cannot replace a mechanical inspection."],
            example: "",
            question: "I am comparing two used cars with different mileages. Is the lower price worth the missing service history?",
            reply: "I would price the overdue work first. My cheaper car needed a service immediately.",
        }
    } else if ["hotel", "hostel", "accommodation", "room"]
        .iter()
        .any(|w| lower.contains(w))
    {
        Draft {
            title: format!("{}: rooms, neighborhoods and rates", proper(subject)),
            leads: &[
                "Hotel room rates are easier to compare when the cancellation terms match.",
                "A hotel near transport can save time on an early arrival.",
                "Compare hotel prices with breakfast and local charges included.",
                "Hotels and hostels offer different room types at different nightly rates.",
                "Accommodation costs change with dates and the number of guests.",
                "A hotel’s location can make a late arrival much simpler.",
                "Hotel accessibility details should be confirmed before reserving.",
                "A quiet hotel room may face away from the main street.",
                "Hotel reviews help identify recurring noise and service problems.",
                "A hotel’s cheapest rate may require payment before arrival.",
            ],
            detail: "Check the room type and total for all nights. A £90 room plus £15 breakfast per person costs £120 for two guests before any local charges.",
            steps: vec![
                "Choose dates and the number of guests.",
                "Compare the location with your arrival route.",
                "Read cancellation and payment terms.",
            ],
            tips: &["Confirm hotel accessibility details directly before reserving a room."],
            example: "",
            question: "I need a quiet hotel near transport. Is a room facing the courtyard worth asking for?",
            reply: "I would ask about the room itself. My hotel was central, but the street-facing room was noisy.",
        }
    } else {
        return topic_article(seed, subject, host, angle);
    };
    let first = if scenario && matches!(kind, "forum" | "qa") {
        choose(&[
            "I run a Halvard HG-400 on firmware 7.2.1 and need to plan the security upgrade.",
            "I need to update the firmware on our Halvard appliance without interrupting the VPN users.",
            "I have a Halvard HG-400 on older firmware and am trying to choose a maintenance window.",
            "I am checking the Halvard firmware advisory before making changes to our VPN appliance.",
            "I need a fallback plan for the Halvard firmware upgrade in case our VPN clients have trouble.",
            "I can take the Halvard portal off the WAN, but I still need to schedule the firmware update.",
            "I am comparing our installed Halvard firmware with the affected range in the advisory.",
            "I have been asked to update a Halvard appliance and want to check the firmware requirements first.",
            "I am reviewing our Halvard firmware after the portal flaw appeared in CISA’s catalog.",
            "I have read the Halvard firmware advisory and want to hear how other admins handled the upgrade.",
        ])
    } else if kind == "news" && lower.contains("sourdough") {
        "Bakers point to cool kitchens and irregular feeding as common reasons a sourdough culture fails to rise.".to_owned()
    } else if lower.contains("rust") && !scenario {
        choose(&[
            "Rust ownership gives each value one owner.",
            "Rust borrowing lets a function use a value without taking ownership.",
            "A Rust move transfers ownership to a new binding.",
            "Rust’s borrow checker checks references at compile time.",
            "A shared Rust borrow must end before a conflicting mutation.",
            "Rust values are dropped when their owner goes out of scope.",
            "Rust ownership follows a value through each expression.",
            "A Rust reference borrows access rather than moving a value.",
            "Copying a small Rust value can avoid a longer borrow.",
            "Rust distinguishes shared references from mutable references.",
        ])
    } else if lower.contains("javascript") {
        choose(&[
            "A JavaScript promise must settle before its result can be used.",
            "JavaScript promises represent work that can finish later.",
            "A JavaScript error path should reject rather than leave a promise pending.",
        ])
    } else if lower.contains("python") && !lower.contains("groupby") && !lower.contains("itertools")
    {
        choose(&[
            "Python sequence indexes start at zero and stop before the length.",
            "Python iteration avoids indexing past the end of a sequence.",
            "A Python empty list has no first element to select.",
        ])
    } else {
        choose(leads)
    };
    let seconds: &[&str] = if scenario {
        &[
            "The fixed release is 7.2.4.",
            "The advisory covers releases through 7.2.3.",
            "The fix was released on September 22.",
            "The flaw has a severity score of 9.8.",
            "CISA added the flaw to its catalog on September 26.",
            "The web portal is the point of entry.",
            "The issue affects releases from 7.0.0 through 7.2.3.",
            "Turning off the WAN portal blocks the attack.",
            "The patch closes a pre-authentication flaw.",
            "An upgrade closes the vulnerable portal code path.",
        ]
    } else if lower.contains("groupby") {
        &[
            "Sort by the same key when matching values should form a single group.",
            "The key function is called for each input value.",
            "Read each group before asking for the next one.",
            "A list preserves each run for later use.",
            "Sorting is optional when the input is already in the right order.",
            "A key can select a tuple field or calculate a value.",
            "The groups share the underlying input.",
            "Sorting changes the order of the input.",
            "Equal values separated by another key form separate groups.",
            "Use a dictionary when order should not matter.",
        ]
    } else if lower.contains("sourdough") {
        &[
            "A feeding cycle can take longer in a cold room.",
            "The rise can be easy to miss if the culture peaks overnight.",
            "Activity usually becomes more predictable as the culture matures.",
            "A young culture may bubble before it has enough strength to raise a loaf.",
            "The flour and feeding ratio both affect how long fermentation takes.",
            "A narrow jar makes the change in level easier to measure.",
            "The dried line on the glass can show that the culture rose and fell.",
            "Bubbles, aroma and the change in height tell different parts of the story.",
            "The water temperature affects how quickly fermentation begins after a feed.",
            "The next feeding cycle can show whether the culture is gaining strength.",
        ]
    } else if lower.contains("bread") || lower.contains("baking") {
        &[
            "Weigh the flour, then fold the batter until just combined.",
            "Spoon it lightly into the cup, or use a scale for more consistent results.",
            "Stop as soon as the dry streaks disappear.",
            "Check the center before changing the recipe.",
            "Measure the fruit separately from the dry ingredients.",
            "Allow the loaf to cool before slicing.",
            "A few small lumps are fine; a smooth batter is not the aim.",
            "Let the crumb set on a cooling rack before cutting.",
            "Check the middle with a skewer for wet batter.",
            "Use the pan dimensions given in the recipe.",
        ]
    } else if lower.contains("flight") || lower.contains("airfare") || lower.contains("airline") {
        &[
            "Compare bags, seats and airport transport before booking.",
            "Use the same departure dates and passenger count for each search.",
            "Check the arrival airport as well as the fare.",
            "Include the train or bus fare in the total.",
            "Try the date grid before choosing a return journey.",
            "Check the dimensions before adding a cabin bag.",
            "Add the total journey time to the comparison.",
            "Payment fees and baggage can change the total.",
            "Read the cancellation terms before paying.",
            "An early departure may need a hotel near the terminal.",
        ]
    } else if lower.contains("pizza") || lower.contains("naples") {
        &[
            "Eat it at the table if you can; a closed takeaway box softens the base on the trip home.",
            "Check whether the restaurant takes reservations or asks diners to join a walk-up queue.",
            "Compare the menu, service charge and drinks before deciding which table fits your budget.",
            "A simple margherita makes a useful comparison between traditional pizzerias in the city.",
            "Choose a neighborhood first, then plan a walk between a few kitchens with different styles.",
            "Confirm opening hours before crossing town; some kitchens close between lunch and dinner.",
            "Ask about ingredients before ordering if you have dietary requirements or food allergies.",
            "Allow time for the queue, especially when a kitchen has only a small number of tables.",
            "For groups, ask whether everyone can sit together before ordering food and drinks.",
            "Eat it promptly; the journey back can change the texture more than a different topping.",
        ]
    } else if lower.contains("router") {
        &[
            "Write down the connection details before you begin so you can reconnect if the settings are cleared.",
            "Keep the router powered throughout recovery and use Ethernet if the Wi-Fi name disappears.",
        ]
    } else if lower.contains("rust") {
        &[
            "A short example shows how moving a value differs from borrowing it through a shared or mutable reference.",
            "Trace the last use of each reference before moving a value or changing a collection that it points into.",
        ]
    } else if lower.contains("car") {
        &[
            "Compare the same engine, trim and model year, then add the work needed before the next service.",
            "Service history and an inspection help explain price differences between cars with similar mileage.",
        ]
    } else if lower.contains("hotel") || lower.contains("hostel") || lower.contains("accommodation")
    {
        &[
            "Compare hotels and hostels for the same dates, including breakfast, local charges and cancellation terms.",
            "Check hotels and hostels near your arrival route, then compare the total price for every night.",
        ]
    } else {
        &[
            "Check the instructions before changing the method.",
            "A small example makes the differences easier to see.",
            "Check the conditions before choosing the next step.",
            "The method below explains the options.",
            "Start with one change and compare the result.",
            "Keep the measurements the same when comparing approaches.",
            "Check the details for the model or location you need.",
            "The example below shows the sequence.",
            "Compare the options on the same basis.",
            "Read the method before making a change.",
        ]
    };
    let first = if !scenario && leads.len() < 10 {
        format!(
            "{}: {}",
            proper(
                &words(subject)
                    .into_iter()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            first.to_lowercase()
        )
    } else {
        first
    };
    let second = if !scenario && angle >= 10 {
        seconds[(n + 5) % seconds.len()]
    } else if scenario {
        "The fixed release is 7.2.4, released on September 22."
    } else if lower.contains("flight") || lower.contains("airfare") || lower.contains("airline") {
        [
            "Compare flights with bags, seats and airport transfers included.",
            "Check the arrival airport and cancellation conditions before booking flights.",
            "Compare direct flights and connections with the same baggage allowance.",
            "Include transport to the terminal when comparing flights from nearby airports.",
            "Use the date grid to compare flights before settling on a return journey.",
            "Check cabin bag dimensions when comparing the price of flights.",
            "Compare flights by the total journey time as well as the fare.",
            "Add every bag and seat fee before comparing flights for your group.",
            "Flexible flights may be worth more if you expect to change your dates.",
            "Compare later flights with the cost of staying near the terminal overnight.",
        ][n]
    } else {
        seconds[n % seconds.len()]
    };
    let lead = if scenario {
        std::iter::once(second)
            .chain([
                "The fixed firmware is 7.2.4.",
                "The fixed release, 7.2.4, was issued on September 22.",
            ])
            .chain(seconds.iter().copied())
            .map(|end| format!("{first} {end}"))
            .find(|lead| (120..=160).contains(&lead.chars().count()))
            .unwrap_or_else(|| format!("{first} {second}"))
    } else {
        let extra = seconds[(n + 3) % seconds.len()];
        let mut lead = format!(
            "{}; {}",
            first.trim_end_matches(['.', '?']),
            lower_first(second)
        );
        if lead.chars().count() < 120 {
            lead = format!("{}; {}", lead.trim_end_matches('.'), lower_first(extra));
        }
        lead
    };
    let (detail, example, question, reply) = if lower.contains("e0502") {
        (
            "Rust reports a conflicting borrow when code tries to mutate a value while a shared reference to it is still in use. End the shared borrow before mutation, or copy an independent value when the type implements Copy.",
            "let mut values = vec![1, 2];\nlet first = &values[0];\nprintln!(\"{first}\"); // Last use of the shared borrow.\nvalues.push(3);\nassert_eq!(values, vec![1, 2, 3]);",
            "Why does pushing to my Rust vector fail while I still use a reference to its first item?",
            "The reference keeps the shared borrow active through its last use. In this example, use the reference before pushing, or copy the integer instead.",
        )
    } else if lower.contains("javascript") {
        (
            "A promise resolves with a value or rejects with an error. Await it inside an async function, and handle rejection where the operation can fail.",
            "async function show() {\n    const value = await Promise.resolve(3);\n    console.log(value); // 3\n}\nshow();",
            "My JavaScript promise never resolves. Where should I look for a missing completion path?",
            "I would check the error paths. One branch in my callback returned without resolving or rejecting.",
        )
    } else if lower.contains("python") && !lower.contains("groupby") && !lower.contains("itertools")
    {
        (
            "Python raises IndexError when an index lies outside the sequence. Iterating over values avoids needing to calculate a valid index.",
            "values = [10, 20]\nfor index, value in enumerate(values):\n    print(index, value)",
            "My Python list access fails on empty input. Should I check the length before indexing?",
            "I would iterate over the values if you need every item. For one element, check that the list is nonempty first.",
        )
    } else if lower.contains("rust") && lower.contains("ownership") {
        (
            "A Rust String owns its text. Assigning it to another binding moves that ownership. A shared reference lets a function read the text while the original binding remains the owner.",
            "fn show(text: &str) {\n    println!(\"{text}\");\n}\nlet message = String::from(\"hello\");\nshow(&message); // Borrow the text.\nlet moved = message; // Transfer ownership.\nprintln!(\"{moved}\");",
            "I am learning Rust ownership. Why can I pass a reference to a String and still use the String afterward?",
            "A reference borrows the Rust value. Moving the String transfers ownership, so the previous binding can no longer be used.",
        )
    } else {
        (detail, example, question, reply)
    };
    let (steps, tip) = if lower.contains("javascript") {
        (vec!["Check that each completion path resolves or rejects the promise.", "Return the promise from a function that callers need to await.", "Handle rejection at the point where the operation can fail."], "A pending JavaScript promise has neither resolved nor rejected. Check callback paths that return early.".to_owned())
    } else if lower.contains("python") && !lower.contains("groupby") && !lower.contains("itertools")
    {
        (vec!["Iterate over values when every element is needed.", "Check that an index lies within the sequence before selecting one element.", "Handle empty input before reading the first element."], "A Python sequence can be empty even when earlier input had values. Check the value at the failing expression.".to_owned())
    } else if lower.contains("rust") && lower.contains("ownership") {
        (vec!["Create an owned value, such as a String.", "Pass a shared reference when a function only needs to read it.", "Move the value when the next binding should take ownership."], "A Rust reference must not outlive the value it borrows. The compiler checks that relationship before the program runs.".to_owned())
    } else {
        (steps, choose(tips))
    };
    Article {
        title,
        lead,
        detail: detail.into(),
        steps: steps.into_iter().map(str::to_owned).collect(),
        tip,
        example,
        question,
        reply,
    }
}

fn result_path(seed: &Seed, host: &str, slug: &str, kind: &str) -> String {
    let id = 100_000 + hash(&format!("{host}/{slug}")) % 900_000;
    match host {
        "www.kingarthurbaking.com" => format!("recipes/{slug}-recipe"),
        "www.bbcgoodfood.com" if slug.contains("coffee") => {
            format!("healthy/health-benefits/{slug}")
        }
        "www.bbcgoodfood.com" => format!("recipes/{slug}"),
        "www.seriouseats.com" | "www.simplyrecipes.com" => format!("recipes/{slug}-{id}"),
        "www.allrecipes.com" => format!("recipe/{id}/{slug}/"),
        "www.epicurious.com" => format!("recipes/food/views/{slug}-{id}"),
        "www.foodnetwork.com" => format!("recipes/{slug}-{id}"),
        "www.bonappetit.com" => format!("recipe/{slug}"),
        "www.delish.com" => format!("cooking/recipe-ideas/a{id}/{slug}/"),
        "www.thekitchn.com" => format!("recipes/{slug}-{id}"),
        "www.expedia.co.uk" => format!("Flights-Search?destination={slug}"),
        "www.kayak.co.uk" | "www.momondo.co.uk" => format!("flights/{slug}/flexible"),
        "www.britishairways.com" => format!("content/flights/{slug}"),
        "www.easyjet.com" | "www.ryanair.com" | "www.flytap.com" => format!("en/flights/{slug}"),
        "www.halvardsystems.com" => {
            let section = if slug.contains("firmware") || slug.contains("downgrade") {
                "support/kb"
            } else if slug.contains("vulnerability") || slug.contains("cve") {
                "security/advisories"
            } else {
                "products"
            };
            format!("{section}/{slug}")
        }
        "community.halvardsystems.com" => format!("t/{slug}/{id}"),
        "developer.mozilla.org" => format!("en-US/docs/Web/JavaScript/Reference/{slug}"),
        "superuser.com" => format!("questions/{id}/{slug}"),
        "realpython.com" => format!("lessons/{slug}/"),
        "www.codecademy.com" => format!("learn/{slug}"),
        "dev.to" => format!("language-notes/{slug}"),
        "exercism.org" => format!("tracks/rust/exercises/{slug}"),
        "www.geeksforgeeks.org" | "www.programiz.com" => format!(
            "{}/{slug}/",
            if slug.contains("rust") {
                "rust"
            } else if slug.contains("javascript") {
                "javascript"
            } else {
                "python"
            }
        ),
        "www.w3schools.com" => format!(
            "{}/{slug}.php",
            if slug.contains("rust") {
                "rust"
            } else {
                "python"
            }
        ),
        "www.britannica.com" => format!("topic/{slug}"),
        "www.history.com" => format!("topics/{slug}"),
        "www.rhs.org.uk" => format!("plants/types/cacti-succulents/{slug}"),
        "www.gardenersworld.com" => format!("how-to/grow-plants/{slug}/"),
        "www.instructables.com" => format!("id/{slug}/"),
        "en.wikipedia.org" => format!("wiki/{}", upper_first(&slug.replace('-', "_"))),
        "www.nhs.uk" => format!("live-well/exercise/{slug}/"),
        "www.mayoclinic.org" => format!("healthy-lifestyle/fitness/in-depth/{slug}/art-{id}"),
        "www.webmd.com" => format!("fitness-exercise/{slug}"),
        "www.healthline.com" => format!("health/fitness/{slug}"),
        "www.runnersworld.com" => format!("nutrition-weight-loss/a{id}/{slug}/"),
        "health.clevelandclinic.org" => format!("health/{slug}"),
        "www.energy.gov" => format!("energysaver/{slug}"),
        "energysavingtrust.org.uk" => format!("advice/{slug}/"),
        "www.sciencefocus.com" => format!("science/{slug}"),
        "www.howstuffworks.com" => format!("science/{slug}.htm"),
        "www.collinsdictionary.com" => format!("dictionary/english/{slug}"),
        "www.rei.com" => format!("learn/expert-advice/{slug}.html"),
        "medium.com" => format!("@technology/{slug}-{id:x}"),
        "www.reuters.com" => format!("technology/{slug}-{}/", seed.date),
        _ => match kind {
            "news" => format!("news/{}/{slug}/", seed.date.replace('-', "/")),
            "blog" => format!("posts/{}/{slug}/", seed.date),
            "forum" => format!("t/{slug}/{id}"),
            "qa" => format!("questions/{id}/{slug}"),
            "docs" => format!("docs/reference/{slug}"),
            "wiki" => format!("topic/{slug}"),
            "package" => format!("packages/{slug}"),
            "weather" => format!("forecast/{slug}"),
            "marketplace" => format!("used-cars/{slug}"),
            "review" => format!("reviews/{slug}"),
            "shop" => format!("products/{slug}/{id}"),
            "company" => format!("products/{slug}"),
            "howto" => format!("guides/{slug}/{id}"),
            "listings" | "lodging" => format!("travel/{slug}/{id}"),
            _ => format!("articles/{slug}/{id}"),
        },
    }
}

/// Proposes candidates from known pages, scenario sites and search directories.
/// The request handler reserves their metadata and bounds unsupported searches.
pub fn search(seed: &Seed, query: &str, known: &[Result], engine: Engine) -> Search {
    let lower_query = query.to_lowercase();
    let phrase = proper(&normalize_space(query));
    let phrase = if phrase.is_empty() {
        "web".into()
    } else {
        phrase
    };
    let mut results: Vec<Result> = Vec::new();
    let mut add = |url: String, title: String, snippet: String, date: String| {
        if results.len() < 10 && !results.iter().any(|r| r.url == url) {
            results.push(Result {
                url,
                title,
                snippet,
                date,
            });
        }
    };
    let limit = if engine == Engine::Google {
        10
    } else {
        9 - hash(query) % 3
    };
    let mut ranked = rank(known, query);
    if engine != Engine::Google {
        ranked.sort_by_key(|r| {
            let (host, _) = target_of(&r.url);
            let own = seed.sites.iter().any(|s| s.host == host)
                || seed.fixed.iter().any(|f| f.url == r.url);
            (!own, engine_order(engine, query, &r.url))
        });
    }
    for k in ranked
        .into_iter()
        .filter(|k| relevant(k, query))
        .take(limit)
    {
        let snippet = if k.snippet.is_empty() {
            &k.title
        } else {
            &k.snippet
        };
        let date = if k.date.is_empty() {
            short_date(date_for(seed, &k.url, 30))
        } else {
            k.date.clone()
        };
        add(k.url.clone(), k.title.clone(), excerpt(snippet), date);
    }
    for (site_index, site) in seed.sites.iter().enumerate() {
        if matches!(intent(query), "service" | "problem" | "question") {
            continue;
        }
        let candidate = Result {
            url: format!("https://{}/", site.host),
            title: site.about.clone(),
            snippet: seed
                .facts
                .iter()
                .filter(|f| shares_words(f, &site.about))
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
            ..Result::default()
        };
        if relevant(&candidate, query) && !known.iter().any(|r| target_of(&r.url).0 == site.host) {
            let slug = words(query)
                .into_iter()
                .take(6)
                .collect::<Vec<_>>()
                .join("-");
            let path = result_path(seed, &site.host, &slug, &site_profile(&site.host).kind);
            let url = format!("https://{}/{path}", site.host);
            let article = article(
                seed,
                query,
                &site.host,
                &site_profile(&site.host).kind,
                site_index,
            );
            add(
                url.clone(),
                article.title,
                excerpt(&article.lead),
                short_date(date_for(seed, &url, 30)),
            );
        }
    }
    let terms = words(query);
    let subject = if let Some(place) = phrase.to_lowercase().strip_prefix("best ") {
        place.split_once(" in ").map_or_else(
            || place.to_owned(),
            |(food, city)| format!("{food} in {}", upper_first(city)),
        )
    } else {
        phrase
            .to_lowercase()
            .strip_prefix("how to ")
            .map_or_else(|| phrase.to_lowercase(), str::to_owned)
            .trim_end_matches(" example")
            .to_owned()
    };
    let place = terms.iter().any(|w| {
        [
            "pizza",
            "restaurant",
            "restaurants",
            "cafe",
            "cafes",
            "hotel",
            "hotels",
        ]
        .contains(&w.as_str())
    });
    let code = terms.iter().any(|w| {
        [
            "python",
            "rust",
            "javascript",
            "code",
            "itertools",
            "groupby",
            "programming",
        ]
        .contains(&w.as_str())
    });
    let lodging = terms
        .iter()
        .any(|w| ["hotel", "hotels", "accommodation", "hostel", "hostels"].contains(&w.as_str()));
    let network = terms.iter().any(|w| w == "router");
    let howto = network
        || phrase.to_lowercase().starts_with("how ")
        || terms
            .iter()
            .any(|w| ["repair", "install", "configure", "clean"].contains(&w.as_str()));
    let baking = terms.iter().any(|w| {
        [
            "sourdough",
            "baking",
            "bread",
            "recipe",
            "recipes",
            "cake",
            "cooking",
            "cook",
            "dough",
            "egg",
            "eggs",
            "rice",
            "pasta",
            "boil",
            "lentil",
            "lentils",
            "beans",
            "potatoes",
            "roast",
            "bake",
            "cookies",
            "pastry",
        ]
        .contains(&w.as_str())
    });
    let flights = terms
        .iter()
        .any(|w| ["flight", "flights", "airfare", "airline"].contains(&w.as_str()));
    let weather = terms.iter().any(|w| w == "weather" || w == "forecast");
    let cars = intent(query) != "question" && terms.iter().any(|w| w == "car" || w == "cars");
    let device = [
        "laptop",
        "computer",
        "printer",
        "monitor",
        "keyboard",
        "usb",
        "wifi",
        "sql",
        "http",
        "api",
        "dns",
        "connection",
    ]
    .iter()
    .any(|word| lower_query.contains(word));
    let intent = intent(query);
    let outdoors = ["hiking", "boot", "tent", "camping", "backpack"]
        .iter()
        .any(|w| lower_query.contains(w));
    let plants = [
        "plant",
        "cactus",
        "garden",
        "repot",
        "rose",
        "orchid",
        "succulent",
        "tomato",
        "prune",
    ]
    .iter()
    .any(|w| lower_query.contains(w));
    let candidates: &[&str] = if weather {
        &[
            "www.metoffice.gov.uk",
            "www.bbc.com",
            "weather.com",
            "www.accuweather.com",
            "www.weather-forecast.com",
            "www.wunderground.com",
            "www.timeanddate.com",
            "www.meteoblue.com",
            "www.netweather.tv",
            "www.yourweather.co.uk",
        ]
    } else if cars {
        &[
            "www.autotrader.co.uk",
            "www.rac.co.uk",
            "www.parkers.co.uk",
            "www.cargurus.co.uk",
            "www.whatcar.com",
            "www.autoexpress.co.uk",
            "www.carwow.co.uk",
            "motorway.co.uk",
            "www.motors.co.uk",
            "www.cinch.co.uk",
        ]
    } else if baking {
        &[
            "www.kingarthurbaking.com",
            "www.bbcgoodfood.com",
            "www.seriouseats.com",
            "www.allrecipes.com",
            "www.simplyrecipes.com",
            "www.epicurious.com",
            "www.foodnetwork.com",
            "www.bonappetit.com",
            "www.delish.com",
            "www.thekitchn.com",
        ]
    } else if flights {
        &[
            "www.britishairways.com",
            "www.skyscanner.net",
            "www.expedia.co.uk",
            "www.kayak.co.uk",
            "www.momondo.co.uk",
            "www.kiwi.com",
            "www.easyjet.com",
            "www.ryanair.com",
            "www.flytap.com",
            "www.lonelyplanet.com",
        ]
    } else if lodging {
        &[
            "www.booking.com",
            "www.tripadvisor.co.uk",
            "www.hotels.com",
            "www.expedia.co.uk",
            "www.kayak.co.uk",
            "www.trivago.co.uk",
            "www.reddit.com",
            "www.theguardian.com",
            "www.independent.co.uk",
            "www.lonelyplanet.com",
        ]
    } else if place {
        &[
            "www.tripadvisor.co.uk",
            "www.opentable.co.uk",
            "www.timeout.com",
            "www.yelp.co.uk",
            "www.reddit.com",
            "www.eater.com",
            "www.falstaff.com",
            "www.deliveroo.co.uk",
            "www.designmynight.com",
            "www.gamberorossointernational.com",
        ]
    } else if code {
        &[
            if terms.iter().any(|w| w == "rust") {
                "doc.rust-lang.org"
            } else if terms.iter().any(|w| w == "javascript") {
                "developer.mozilla.org"
            } else {
                "docs.python.org"
            },
            "stackoverflow.com",
            "github.com",
            "www.reddit.com",
            "www.geeksforgeeks.org",
            "www.programiz.com",
            "www.digitalocean.com",
            "www.freecodecamp.org",
            if terms
                .iter()
                .any(|w| w == "python" || w == "itertools" || w == "groupby")
            {
                "realpython.com"
            } else {
                "www.codecademy.com"
            },
            if terms.iter().any(|w| w == "rust") {
                "users.rust-lang.org"
            } else if terms.iter().any(|w| w == "javascript") {
                "discourse.mozilla.org"
            } else {
                "discuss.python.org"
            },
        ]
    } else if howto && network {
        &[
            "www.wikihow.com",
            "www.tp-link.com",
            "www.netgear.com",
            "www.reddit.com",
            "superuser.com",
            "www.howtogeek.com",
            "www.lifewire.com",
            "www.asus.com",
            "www.techradar.com",
            "www.which.co.uk",
        ]
    } else if howto && plants {
        &[
            "www.rhs.org.uk",
            "www.gardenersworld.com",
            "www.wikihow.com",
            "www.instructables.com",
            "www.thespruce.com",
            "www.reddit.com",
            "www.gardeningknowhow.com",
            "www.gardenista.com",
            "www.bhg.com",
            "www.almanac.com",
        ]
    } else if intent == "problem"
        && (lower_query.contains("error") || lower_query.contains("connection refused"))
    {
        &[
            "stackoverflow.com",
            "serverfault.com",
            "superuser.com",
            "github.com",
            "www.reddit.com",
            "www.digitalocean.com",
            "dev.to",
            "www.howtogeek.com",
            "www.makeuseof.com",
            "www.youtube.com",
        ]
    } else if intent == "problem" {
        &[
            if lower_query.contains("bike") || lower_query.contains("bicycle") {
                "www.parktool.com"
            } else {
                "www.ifixit.com"
            },
            "www.wikihow.com",
            "www.reddit.com",
            "www.youtube.com",
            "www.instructables.com",
            if lower_query.contains("bike") || lower_query.contains("bicycle") {
                "www.sheldonbrown.com"
            } else if device {
                "www.howtogeek.com"
            } else {
                "www.familyhandyman.com"
            },
            if lower_query.contains("bike") || lower_query.contains("bicycle") {
                "www.bikeradar.com"
            } else if device {
                "superuser.com"
            } else {
                "www.bobvila.com"
            },
            if lower_query.contains("bike") || lower_query.contains("bicycle") {
                "www.bicycling.com"
            } else if device {
                "www.lifewire.com"
            } else {
                "www.thespruce.com"
            },
            "www.which.co.uk",
            "www.quora.com",
        ]
    } else if intent == "question"
        && (lower_query.contains("electric car") || lower_query.contains("battery"))
    {
        &[
            "www.rac.co.uk",
            "www.reddit.com",
            "www.carwow.co.uk",
            "www.which.co.uk",
            "www.autoexpress.co.uk",
            "www.quora.com",
            "www.youtube.com",
            "www.energy.gov",
            "www.whatcar.com",
            "www.autotrader.co.uk",
        ]
    } else if intent == "question" {
        &[
            "www.quora.com",
            "www.reddit.com",
            "www.britannica.com",
            if lower_query.contains("dog") || lower_query.contains("cat ") {
                "www.petmd.com"
            } else if lower_query.contains("invent") || lower_query.starts_with("when did ") {
                "www.history.com"
            } else {
                "www.scientificamerican.com"
            },
            if lower_query.contains("dog") || lower_query.contains("cat ") {
                "www.vcahospitals.com"
            } else {
                "www.smithsonianmag.com"
            },
            "www.youtube.com",
            "www.livescience.com",
            "www.sciencefocus.com",
            "www.thoughtco.com",
            "ask.metafilter.com",
        ]
    } else if intent == "service" {
        &[
            if lower_query.contains("halvard") {
                "www.halvardsystems.com"
            } else {
                "www.wikihow.com"
            },
            "www.reddit.com",
            "superuser.com",
            "www.quora.com",
            "www.howtogeek.com",
            "www.techradar.com",
            "www.lifewire.com",
            "www.youtube.com",
            "www.which.co.uk",
            "www.instructables.com",
        ]
    } else if intent == "health" {
        &[
            "www.nhs.uk",
            "www.mayoclinic.org",
            "www.webmd.com",
            "www.healthline.com",
            "medlineplus.gov",
            "health.clevelandclinic.org",
            "www.verywellfit.com",
            "www.medicalnewstoday.com",
            "www.reddit.com",
            "www.bbcgoodfood.com",
        ]
    } else if intent == "review" && !outdoors {
        &[
            "www.nytimes.com",
            "www.consumerreports.org",
            "www.which.co.uk",
            "www.amazon.co.uk",
            "www.reddit.com",
            "www.rtings.com",
            "www.goodhousekeeping.com",
            "www.techradar.com",
            "www.argos.co.uk",
            "www.trustedreviews.com",
        ]
    } else if intent == "review" {
        &[
            "www.nytimes.com",
            "www.outdoorgearlab.com",
            "www.rei.com",
            "www.which.co.uk",
            "www.amazon.co.uk",
            "www.reddit.com",
            "www.switchbacktravel.com",
            "www.advnture.com",
            "www.treelinereview.com",
            "www.backcountry.com",
        ]
    } else if intent == "definition" {
        &[
            "en.wikipedia.org",
            "www.britannica.com",
            "dictionary.cambridge.org",
            "www.merriam-webster.com",
            if lower_query.contains("heat pump") {
                "www.energy.gov"
            } else {
                "www.livescience.com"
            },
            if lower_query.contains("heat pump") {
                "energysavingtrust.org.uk"
            } else {
                "www.reference.com"
            },
            "www.which.co.uk",
            "www.youtube.com",
            "www.reddit.com",
            "www.explainthatstuff.com",
        ]
    } else if howto {
        &[
            "www.wikihow.com",
            "www.ifixit.com",
            "www.howtogeek.com",
            "www.reddit.com",
            "www.quora.com",
            "superuser.com",
            "www.lifewire.com",
            "www.techradar.com",
            "www.instructables.com",
            "www.which.co.uk",
        ]
    } else if intent == "news" {
        &[
            "www.theregister.com",
            "www.bbc.com",
            "www.reddit.com",
            "ask.metafilter.com",
            "www.theguardian.com",
            "www.independent.co.uk",
            "www.quora.com",
            "medium.com",
            "www.wikihow.com",
            "github.com",
        ]
    } else {
        &[
            "en.wikipedia.org",
            "www.reddit.com",
            "www.quora.com",
            "www.youtube.com",
            "www.wikihow.com",
            "www.britannica.com",
            "www.instructables.com",
            "www.thoughtco.com",
            "www.explainthatstuff.com",
            "www.britishmuseum.org",
        ]
    };
    let primary = candidates;
    let mut candidates = candidates.to_vec();
    let alternatives = if intent == "problem" && device {
        [
            "www.techrepublic.com",
            "www.tomshardware.com",
            "www.pcworld.com",
        ]
    } else if intent == "problem" {
        [
            "www.thisoldhouse.com",
            "www.hometips.com",
            "www.doityourself.com",
        ]
    } else if intent == "question" {
        [
            "www.howstuffworks.com",
            "www.mentalfloss.com",
            "www.discovermagazine.com",
        ]
    } else if intent == "service" {
        ["www.zdnet.com", "www.computerweekly.com", "www.itpro.com"]
    } else if weather {
        ["www.foreca.com", "www.weatherbug.com", "www.ventusky.com"]
    } else if cars {
        [
            "www.heycar.com",
            "www.carbuyer.co.uk",
            "www.pistonheads.com",
        ]
    } else if baking {
        [
            "www.bakefromscratch.com",
            "www.bakingmad.com",
            "sallysbakingaddiction.com",
        ]
    } else if place && !lodging {
        [
            "guide.michelin.com",
            "www.visitnaples.eu",
            "www.italymagazine.com",
        ]
    } else if flights || lodging {
        [
            "www.lastminute.com",
            "www.travelocity.com",
            "www.roughguides.com",
        ]
    } else if code {
        ["www.w3schools.com", "dev.to", "exercism.org"]
    } else if intent == "review" && !outdoors {
        ["www.t3.com", "www.expertreviews.co.uk", "www.tomsguide.com"]
    } else if intent == "review" {
        [
            "www.livefortheoutdoors.com",
            "www.gearjunkie.com",
            "www.sportsdirect.com",
        ]
    } else if intent == "health" {
        ["medlineplus.gov", "www.self.com", "www.nutrition.org.uk"]
    } else if plants {
        [
            "www.patchplants.com",
            "www.gardendesign.com",
            "www.gardeningetc.com",
        ]
    } else if intent == "news" {
        ["arstechnica.com", "www.zdnet.com", "www.wired.com"]
    } else {
        [
            "www.collinsdictionary.com",
            "www.sciencefocus.com",
            "www.howstuffworks.com",
        ]
    };
    if engine != Engine::Google {
        let offset = if engine == Engine::Bing { 1 } else { 2 };
        let count = 1 + hash(query) % 3;
        let end = candidates.len();
        for i in 0..count {
            candidates[end - i - 1] = alternatives[(i + offset) % 3];
        }
        candidates.sort_by_key(|host| {
            (
                !alternatives.contains(host),
                hash(&format!("{offset}/{query}/{host}")),
            )
        });
    }
    for &host in &candidates {
        if engine != Engine::Google && known.iter().any(|r| target_of(&r.url).0 == host) {
            continue;
        }
        let angle = primary
            .iter()
            .position(|h| *h == host)
            .unwrap_or_else(|| 10 + alternatives.iter().position(|h| *h == host).unwrap());
        let article = article(
            seed,
            query,
            host,
            &site_profile(host).kind,
            angle
                + if intent == "news" && terms.iter().any(|w| w == "halvard") {
                    seed.sites.len()
                } else {
                    0
                },
        );
        let title = proper(&result_title(seed, query, host, angle, &article.title));
        let slug = terms.join("-");
        let path = match host {
            "www.reddit.com" => format!(
                "r/{}/comments/{}/{slug}/",
                subreddit(query),
                base36(hash(query) % 2_176_782_336)
            ),
            "www.skyscanner.net" => format!(
                "routes/anywhere/{}/{slug}/",
                subject
                    .rsplit_once(" to ")
                    .map_or("everywhere".into(), |(_, to)| words(to).join("-"))
            ),
            "docs.python.org" => {
                if lower_query.contains("groupby") {
                    "3/library/itertools.html#itertools.groupby".into()
                } else if lower_query.contains("list") || lower_query.contains("index") {
                    "3/library/stdtypes.html#sequence-types-list-tuple-range".into()
                } else {
                    format!("3/search.html?q={}", quote_plus(query))
                }
            }
            "doc.rust-lang.org" => {
                if lower_query.contains("e0502") {
                    "error_codes/E0502.html".into()
                } else if lower_query.contains("ownership") || lower_query.contains("borrow") {
                    "book/ch04-00-understanding-ownership.html".into()
                } else {
                    format!("std/?search={}", quote_plus(query))
                }
            }
            "developer.mozilla.org" => {
                if lower_query.contains("promise") {
                    "en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise".into()
                } else {
                    format!("en-US/search?q={}", quote_plus(query))
                }
            }
            "stackoverflow.com" => {
                format!("questions/{}/{slug}", 10_000_000 + hash(query) % 90_000_000)
            }
            "github.com" => format!("language-notes/{slug}"),
            "ask.metafilter.com" => format!("{}/{slug}", 100_000 + hash(query) % 900_000),
            "www.tripadvisor.co.uk" => format!(
                "Tourism/{}-{slug}.html",
                if lodging { "Hotels" } else { "Restaurants" }
            ),
            "www.wikihow.com" => format!(
                "Guide/{}",
                subject
                    .split_whitespace()
                    .map(capitalize)
                    .collect::<Vec<_>>()
                    .join("-")
            ),
            "www.timeout.com" => format!(
                "{}/restaurants/{slug}",
                terms.last().map_or("uk", String::as_str)
            ),
            "www.netgear.com" => format!("support/product/{slug}.aspx"),
            "www.tp-link.com" => format!("uk/support/faq/{}/", 1000 + hash(query) % 9000),
            "www.asus.com" => format!("support/faq/{}/", 1_000_000 + hash(query) % 9_000_000),
            "www.theregister.com" => format!(
                "{}/{:02}/{:02}/{}/",
                day(seed, 0).year(),
                day(seed, 0).month() as u8,
                day(seed, 0).day(),
                slug.replace('-', "_")
            ),
            "www.theguardian.com" => format!(
                "lifeandstyle/{}/{}/20/{slug}",
                day(seed, 0).year(),
                MONTHS[day(seed, 0).month() as usize - 1].to_lowercase()
            ),
            "www.bbc.com" if weather => format!(
                "weather/{}",
                if lower_query.contains("london") {
                    "2643743".into()
                } else {
                    words(&Forecast::new(seed, query, host).place).join("-")
                }
            ),
            "www.bbc.com" => format!("news/articles/{}", base36(hash(query))),
            "www.metoffice.gov.uk" => format!(
                "weather/forecast/{}",
                words(&Forecast::new(seed, query, host).place).join("-")
            ),
            "weather.com" => format!(
                "weather/tenday/l/{}",
                words(&Forecast::new(seed, query, host).place).join("-")
            ),
            _ if weather => format!(
                "forecast/{}",
                words(&Forecast::new(seed, query, host).place).join("-")
            ),
            _ if cars && site_profile(host).kind == "marketplace" => format!("used-cars/{slug}"),
            _ if cars => format!("reviews/{slug}"),
            "www.nytimes.com" => format!("wirecutter/reviews/{slug}/"),
            "www.outdoorgearlab.com" => format!("topics/shoes-and-boots/best-{slug}"),
            "www.amazon.co.uk" => format!("s?k={}", quote_plus(&subject)),
            "www.youtube.com" => format!("watch?v={}", base36(hash(query))),
            "dictionary.cambridge.org" => format!("dictionary/english/{slug}"),
            "www.merriam-webster.com" => format!("dictionary/{slug}"),
            "www.independent.co.uk" => format!(
                "life-style/{slug}-b{}.html",
                1_000_000 + hash(query) % 9_000_000
            ),
            "www.booking.com" => format!("searchresults.html?ss={}", quote_plus(&subject)),
            "www.opentable.co.uk" => format!("s?term={}", quote_plus(&subject)),
            "www.yelp.co.uk" => format!("search?find_desc={}", quote_plus(&subject)),
            "www.which.co.uk" if intent == "review" || intent == "definition" => {
                format!("reviews/{slug}")
            }
            "www.techradar.com" | "www.howtogeek.com" | "www.lifewire.com" | "www.which.co.uk" => {
                format!("how-to/{slug}")
            }
            "www.freecodecamp.org" => format!("news/{slug}/"),
            "www.digitalocean.com" => format!("community/tutorials/{slug}"),
            _ => result_path(seed, host, &slug, &site_profile(host).kind),
        };
        let url = format!("https://{host}/{path}");
        let date = if host == "www.theregister.com" {
            short_date(day(seed, 0))
        } else if [
            "www.bbc.com",
            "www.theguardian.com",
            "www.independent.co.uk",
            "www.theregister.com",
            "medium.com",
        ]
        .contains(&host)
        {
            short_date(date_for(
                seed,
                &url,
                if terms.iter().any(|w| w == "halvard" || w == "hg-400") {
                    14
                } else {
                    45
                },
            ))
        } else {
            String::new()
        };
        let snippet = if weather {
            Forecast::new(seed, query, host).snippet(angle)
        } else {
            excerpt(&list_lead(query, angle).unwrap_or(article.lead))
        };
        add(url, title, snippet, date);
    }
    Search {
        results,
        related: ["reddit", "2026", "explained", "latest", "vs alternatives"]
            .map(|s| format!("{phrase} {s}"))
            .to_vec(),
        questions: vec![
            format!("What is {phrase}?"),
            format!("Is {phrase} safe?"),
            format!("How do I check {phrase}?"),
        ],
        ads: vec![],
    }
}

pub(super) fn for_engine(
    seed: &Seed,
    query: &str,
    mut canonical: Search,
    engine: Engine,
) -> Search {
    let count = 1 + hash(query) % 3;
    let hosts = canonical
        .results
        .iter()
        .map(|r| target_of(&r.url).0)
        .collect::<Vec<_>>();
    let additions = search(seed, query, &[], engine)
        .results
        .into_iter()
        .filter(|r| !hosts.contains(&target_of(&r.url).0))
        .take(count)
        .collect::<Vec<_>>();
    canonical.results.sort_by_key(|r| {
        let own = seed.fixed.iter().any(|f| f.url == r.url)
            || seed.sites.iter().any(|s| s.host == target_of(&r.url).0);
        (!own, engine_order(engine, query, &r.url))
    });
    canonical.results.truncate(10 - additions.len());
    canonical.results.extend(additions);
    canonical.results.sort_by_key(|r| {
        let own = seed.fixed.iter().any(|f| f.url == r.url)
            || seed.sites.iter().any(|s| s.host == target_of(&r.url).0);
        (!own, engine_order(engine, query, &r.url))
    });
    canonical
}

/// Video listings drawn from the world's stored video pages.
pub fn videos<'a>(query: &str, pages: impl Iterator<Item = (&'a String, String)>) -> Search {
    use kuchiki::traits::TendrilSink;
    let mut known = Vec::new();
    for (url, html) in pages {
        let dom = kuchiki::parse_html().one(html);
        for card in dom.select("article, .video-item").unwrap() {
            let Ok(link) = card.as_node().select_first("h2 a[href], h3 a[href]") else {
                continue;
            };
            let href = link.attributes.borrow().get("href").unwrap().to_owned();
            let Some(url) = join(url, &href) else {
                continue;
            };
            let snippet = card
                .as_node()
                .select("p")
                .unwrap()
                .map(|p| p.text_contents())
                .collect::<Vec<_>>()
                .join(" • ");
            if !known.iter().any(|r: &Result| r.url == url) {
                known.push(Result {
                    url,
                    title: link.text_contents(),
                    snippet,
                    date: String::new(),
                });
            }
        }
    }
    let results = if query.is_empty() {
        known.iter().take(12).cloned().collect::<Vec<_>>()
    } else {
        rank(&known, query)
            .into_iter()
            .filter(|r| relevant(r, query))
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
    };
    Search {
        results,
        ..Search::default()
    }
}

/// Makes default branding and navigation for a host.
pub fn site_profile(host: &str) -> Profile {
    let labels: Vec<_> = host.split('.').collect();
    let n = labels.len();
    let label =
        if n >= 3 && labels[n - 2].chars().count() <= 3 && labels[n - 1].chars().count() == 2 {
            labels[n - 3]
        } else {
            labels[n.saturating_sub(2)]
        };
    let name = normalize_space(&label.replace('-', " "))
        .split(' ')
        .map(capitalize)
        .collect::<Vec<_>>()
        .join(" ");
    let name = if host == "halvardsystems.com" || host.ends_with(".halvardsystems.com") {
        "Halvard Systems".into()
    } else if name.is_empty() {
        host.into()
    } else {
        name
    };
    let name = match host {
        "docs.python.org" => "Python Documentation",
        "www.manualslib.com" | "manualslib.com" => "ManualsLib",
        "www.cvedetails.com" | "cvedetails.com" => "CVE Details",
        "community.halvardsystems.com" => "Halvard Community",
        "docs.halvardsystems.com" => "Halvard Docs",
        "www.cisa.gov" | "cisa.gov" => "CISA",
        "nvd.nist.gov" | "www.nvd.nist.gov" => "NVD",
        "www.youtube.com" => "YouTube",
        "www.ifixit.com" => "iFixit",
        "www.sheldonbrown.com" => "Sheldon Brown",
        "www.bikeradar.com" => "BikeRadar",
        "www.bicycling.com" => "Bicycling",
        "www.consumerreports.org" => "Consumer Reports",
        "www.rtings.com" => "RTINGS.com",
        "www.goodhousekeeping.com" => "Good Housekeeping",
        "www.argos.co.uk" => "Argos",
        "www.trustedreviews.com" => "Trusted Reviews",
        "www.expertreviews.co.uk" => "Expert Reviews",
        "www.tomsguide.com" => "Tom’s Guide",
        "www.bobvila.com" => "BobVila.com",
        "www.makeuseof.com" => "MakeUseOf",
        "www.familyhandyman.com" => "Family Handyman",
        "www.tomshardware.com" => "Tom’s Hardware",
        "www.pcworld.com" => "PCWorld",
        "www.computerweekly.com" => "Computer Weekly",
        "www.thisoldhouse.com" => "This Old House",
        "www.hometips.com" => "HomeTips",
        "www.doityourself.com" => "DoItYourself.com",
        "www.self.com" => "SELF",
        "www.nutrition.org.uk" => "British Nutrition Foundation",
        "www.parktool.com" => "Park Tool",
        "www.petmd.com" => "PetMD",
        "www.vcahospitals.com" => "VCA Animal Hospitals",
        "www.history.com" => "HISTORY",
        "www.smithsonianmag.com" => "Smithsonian Magazine",
        "www.scientificamerican.com" => "Scientific American",
        "www.livescience.com" => "Live Science",
        "www.thoughtco.com" => "ThoughtCo",
        "doc.rust-lang.org" => "Rust Documentation",
        "users.rust-lang.org" => "Rust Users Forum",
        "discuss.python.org" => "Python Discussions",
        "discourse.mozilla.org" => "Mozilla Discourse",
        "www.nytimes.com" => "Wirecutter",
        "www.outdoorgearlab.com" => "OutdoorGearLab",
        "www.rei.com" => "REI",
        "www.amazon.co.uk" => "Amazon",
        "www.rhs.org.uk" => "RHS",
        "www.gardenersworld.com" => "gardenersworld.com",
        "www.nhs.uk" => "NHS",
        "medlineplus.gov" => "MedlinePlus",
        "www.mayoclinic.org" => "Mayo Clinic",
        "www.thespruce.com" => "The Spruce",
        "www.gardeningknowhow.com" => "Gardening Know How",
        "www.bhg.com" => "Better Homes & Gardens",
        "www.almanac.com" => "The Old Farmer’s Almanac",
        "www.gardendesign.com" => "Garden Design",
        "www.runnersworld.com" => "runnersworld.com",
        "health.clevelandclinic.org" => "Cleveland Clinic",
        "www.verywellfit.com" => "Verywell Fit",
        "www.medicalnewstoday.com" => "Medical News Today",
        "www.energy.gov" => "Department of Energy",
        "energysavingtrust.org.uk" => "Energy Saving Trust",
        "www.explainthatstuff.com" => "Explain that Stuff",
        "www.collinsdictionary.com" => "Collins Dictionary",
        "www.sciencefocus.com" => "BBC Science Focus",
        "www.howstuffworks.com" => "HowStuffWorks",
        "www.cargurus.co.uk" => "CarGurus",
        "www.autoexpress.co.uk" => "Auto Express",
        "www.bakingmad.com" => "Baking Mad",
        "sallysbakingaddiction.com" => "Sally’s Baking Addiction",
        "arstechnica.com" => "Ars Technica",
        "www.zdnet.com" => "ZDNET",
        "www.wired.com" => "WIRED",
        "dev.to" => "DEV Community",
        "www.webmd.com" => "WebMD",
        "www.britannica.com" => "Britannica",
        "dictionary.cambridge.org" => "Cambridge Dictionary",
        "www.merriam-webster.com" => "Merriam-Webster",
        "www.bbc.com" | "www.bbc.co.uk" => "BBC News",
        "www.theregister.com" => "The Register",
        "ask.metafilter.com" => "Ask MetaFilter",
        "www.kingarthurbaking.com" => "King Arthur Baking",
        "www.bbcgoodfood.com" => "Good Food",
        "www.seriouseats.com" => "Serious Eats",
        "www.britishairways.com" => "British Airways",
        "www.skyscanner.net" => "Skyscanner",
        "www.kiwi.com" => "Kiwi.com",
        "www.metoffice.gov.uk" => "Met Office",
        "weather.com" => "Weather.com",
        "www.accuweather.com" => "AccuWeather",
        "www.weather-forecast.com" => "Weather Forecast",
        "www.wunderground.com" => "Weather Underground",
        "www.timeanddate.com" => "timeanddate",
        "www.meteoblue.com" => "meteoblue",
        "www.netweather.tv" => "Netweather",
        "www.yourweather.co.uk" => "YourWeather",
        "www.foreca.com" => "Foreca",
        "www.weatherbug.com" => "WeatherBug",
        "www.ventusky.com" => "Ventusky",
        "www.switchbacktravel.com" => "Switchback Travel",
        "www.treelinereview.com" => "Treeline Review",
        "www.backcountry.com" => "Backcountry",
        "www.livefortheoutdoors.com" => "Live for the Outdoors",
        "www.gearjunkie.com" => "GearJunkie",
        "www.sportsdirect.com" => "Sports Direct",
        "www.easyjet.com" => "easyJet",
        "www.flytap.com" => "TAP Air Portugal",
        "www.ryanair.com" => "Ryanair",
        "www.lonelyplanet.com" => "Lonely Planet",
        "www.roughguides.com" => "Rough Guides",
        "www.travelocity.com" => "Travelocity",
        "www.autotrader.co.uk" => "Auto Trader",
        "www.rac.co.uk" => "RAC",
        "www.whatcar.com" => "What Car?",
        "www.bonappetit.com" => "Bon Appétit",
        "www.epicurious.com" => "Epicurious",
        "www.allrecipes.com" => "Allrecipes",
        "www.simplyrecipes.com" => "Simply Recipes",
        "www.foodnetwork.com" => "Food Network",
        "www.delish.com" => "Delish",
        "www.thekitchn.com" => "The Kitchn",
        "www.momondo.co.uk" => "momondo",
        "github.com" => "GitHub",
        "www.booking.com" => "Booking.com",
        "www.hotels.com" => "Hotels.com",
        "www.expedia.co.uk" => "Expedia",
        "www.kayak.co.uk" => "KAYAK",
        "www.trivago.co.uk" => "trivago",
        "www.tripadvisor.co.uk" => "Tripadvisor",
        "www.opentable.co.uk" => "OpenTable",
        "www.timeout.com" => "Time Out",
        "www.yelp.co.uk" => "yelp",
        "www.deliveroo.co.uk" => "Deliveroo",
        "www.designmynight.com" => "DesignMyNight",
        "www.theguardian.com" => "The Guardian",
        "www.independent.co.uk" => "Independent",
        "www.wikihow.com" => "wikiHow",
        "stackoverflow.com" => "Stack Overflow",
        "superuser.com" => "Super User",
        "realpython.com" => "Real Python",
        "www.geeksforgeeks.org" => "GeeksforGeeks",
        "www.programiz.com" => "Programiz",
        "www.datacamp.com" => "DataCamp",
        "www.digitalocean.com" => "DigitalOcean",
        "www.freecodecamp.org" => "freeCodeCamp",
        "www.tp-link.com" => "TP-Link",
        "www.netgear.com" => "NETGEAR",
        "www.asus.com" => "ASUS",
        "www.techradar.com" => "TechRadar",
        "www.howtogeek.com" => "How-To Geek",
        "www.lifewire.com" => "Lifewire",
        "www.which.co.uk" => "Which?",
        _ => &name,
    }
    .to_owned();
    let kind = if matches!(
        host,
        "www.metoffice.gov.uk"
            | "weather.com"
            | "www.accuweather.com"
            | "www.weather-forecast.com"
            | "www.wunderground.com"
            | "www.timeanddate.com"
            | "www.meteoblue.com"
            | "www.netweather.tv"
            | "www.yourweather.co.uk"
            | "www.foreca.com"
            | "www.weatherbug.com"
            | "www.ventusky.com"
    ) {
        "weather"
    } else if matches!(
        host,
        "www.autotrader.co.uk"
            | "www.cargurus.co.uk"
            | "motorway.co.uk"
            | "www.motors.co.uk"
            | "www.cinch.co.uk"
            | "www.heycar.com"
            | "www.pistonheads.com"
    ) {
        "marketplace"
    } else if matches!(
        host,
        "www.rac.co.uk"
            | "www.parkers.co.uk"
            | "www.whatcar.com"
            | "www.autoexpress.co.uk"
            | "www.carwow.co.uk"
            | "www.carbuyer.co.uk"
            | "www.nytimes.com"
            | "www.outdoorgearlab.com"
            | "www.switchbacktravel.com"
            | "www.advnture.com"
            | "www.treelinereview.com"
            | "www.gearjunkie.com"
            | "www.livefortheoutdoors.com"
            | "www.consumerreports.org"
            | "www.rtings.com"
            | "www.goodhousekeeping.com"
            | "www.trustedreviews.com"
            | "www.t3.com"
            | "www.expertreviews.co.uk"
            | "www.tomsguide.com"
    ) {
        "review"
    } else if matches!(
        host,
        "www.amazon.co.uk"
            | "www.rei.com"
            | "www.backcountry.com"
            | "www.sportsdirect.com"
            | "www.argos.co.uk"
    ) {
        "shop"
    } else if matches!(
        host,
        "www.britannica.com"
            | "dictionary.cambridge.org"
            | "www.merriam-webster.com"
            | "www.collinsdictionary.com"
    ) {
        "wiki"
    } else if matches!(
        host,
        "www.tomshardware.com"
            | "www.pcworld.com"
            | "www.thisoldhouse.com"
            | "www.hometips.com"
            | "www.doityourself.com"
            | "www.sheldonbrown.com"
            | "www.bikeradar.com"
            | "www.bicycling.com"
            | "www.familyhandyman.com"
            | "www.bobvila.com"
            | "www.makeuseof.com"
            | "www.ifixit.com"
            | "www.parktool.com"
            | "www.petmd.com"
            | "www.vcahospitals.com"
            | "www.nhs.uk"
            | "www.mayoclinic.org"
            | "www.webmd.com"
            | "www.healthline.com"
            | "www.runnersworld.com"
            | "health.clevelandclinic.org"
            | "www.verywellfit.com"
            | "www.medicalnewstoday.com"
            | "medlineplus.gov"
            | "www.self.com"
            | "www.nutrition.org.uk"
            | "www.rhs.org.uk"
            | "www.gardenersworld.com"
            | "www.instructables.com"
            | "www.thespruce.com"
            | "www.gardeningknowhow.com"
            | "www.gardenista.com"
            | "www.bhg.com"
            | "www.almanac.com"
            | "www.patchplants.com"
            | "www.gardendesign.com"
            | "www.gardeningetc.com"
            | "www.explainthatstuff.com"
    ) {
        "howto"
    } else if matches!(
        host,
        "www.reuters.com"
            | "www.history.com"
            | "www.theguardian.com"
            | "www.independent.co.uk"
            | "arstechnica.com"
            | "www.zdnet.com"
            | "www.wired.com"
    ) {
        "news"
    } else if matches!(host, "www.quora.com") {
        "qa"
    } else if matches!(
        host,
        "www.howtogeek.com" | "www.lifewire.com" | "www.techradar.com" | "www.which.co.uk"
    ) {
        "howto"
    } else if matches!(
        host,
        "www.eater.com"
            | "www.falstaff.com"
            | "www.gamberorossointernational.com"
            | "guide.michelin.com"
            | "www.visitnaples.eu"
            | "www.italymagazine.com"
    ) {
        "listings"
    } else if matches!(
        host,
        "www.easyjet.com"
            | "www.ryanair.com"
            | "www.flytap.com"
            | "www.lonelyplanet.com"
            | "www.roughguides.com"
            | "www.travelocity.com"
            | "www.lastminute.com"
    ) {
        "lodging"
    } else if host == "www.ebay.com" {
        "shop"
    } else if host == "www.linkedin.com" {
        "company"
    } else if matches!(
        host,
        "www.booking.com"
            | "www.hotels.com"
            | "www.expedia.co.uk"
            | "www.kayak.co.uk"
            | "www.trivago.co.uk"
    ) {
        "lodging"
    } else if matches!(
        host,
        "www.tripadvisor.co.uk"
            | "www.timeout.com"
            | "www.opentable.co.uk"
            | "www.yelp.co.uk"
            | "www.deliveroo.co.uk"
            | "www.designmynight.com"
    ) {
        "listings"
    } else if matches!(
        host,
        "www.kingarthurbaking.com"
            | "www.bbcgoodfood.com"
            | "www.seriouseats.com"
            | "www.allrecipes.com"
            | "www.simplyrecipes.com"
            | "www.epicurious.com"
            | "www.foodnetwork.com"
            | "www.bonappetit.com"
            | "www.delish.com"
            | "www.thekitchn.com"
            | "www.bakefromscratch.com"
            | "www.bakingmad.com"
            | "sallysbakingaddiction.com"
            | "www.wikihow.com"
    ) {
        "howto"
    } else if matches!(
        host,
        "www.britishairways.com"
            | "www.skyscanner.net"
            | "www.kayak.co.uk"
            | "www.momondo.co.uk"
            | "www.kiwi.com"
    ) {
        "lodging"
    } else if matches!(
        host,
        "realpython.com"
            | "www.codecademy.com"
            | "www.geeksforgeeks.org"
            | "www.programiz.com"
            | "www.datacamp.com"
            | "www.digitalocean.com"
            | "www.freecodecamp.org"
            | "www.w3schools.com"
            | "dev.to"
            | "exercism.org"
            | "www.tp-link.com"
            | "www.netgear.com"
            | "www.asus.com"
    ) {
        if host == "dev.to" {
            "blog"
        } else if matches!(host, "www.tp-link.com" | "www.netgear.com" | "www.asus.com") {
            "docs"
        } else {
            "howto"
        }
    } else if host.contains("wiki") {
        "wiki"
    } else if host.starts_with("docs.")
        || host.starts_with("doc.")
        || host == "developer.mozilla.org"
        || host.contains("github")
    {
        "docs"
    } else if matches!(
        host,
        "stackoverflow.com" | "serverfault.com" | "superuser.com"
    ) {
        "qa"
    } else if host == "ask.metafilter.com"
        || [
            "users.rust-lang.org",
            "discuss.python.org",
            "discourse.mozilla.org",
        ]
        .contains(&host)
        || host.contains("forum")
        || host.contains("community")
        || host.contains("reddit")
        || host.contains("stackoverflow")
        || host == "superuser.com"
    {
        "forum"
    } else if host.starts_with("shop.") || host.starts_with("store.") {
        "shop"
    } else if host.contains("systems") || host.ends_with(".gov") {
        "company"
    } else if host.contains("blog") || host.contains("medium") {
        "blog"
    } else {
        "news"
    };
    let links = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let (tagline, nav) = match kind {
        "weather" => (
            String::new(),
            links(&["Forecast|/weather/", "Maps|/maps/", "Warnings|/warnings/"]),
        ),
        "marketplace" => (
            String::new(),
            links(&[
                "Used cars|/used-cars/",
                "Sell your car|/sell/",
                "Reviews|/reviews/",
            ]),
        ),
        "review" => (
            String::new(),
            links(&["Reviews|/reviews/", "Buying guides|/buying-guides/"]),
        ),
        "lodging" => (
            String::new(),
            links(&[
                "Stays|/",
                "Flights|/flights/",
                "Car rentals|/cars/",
                "Attractions|/attractions/",
                "Help|/help/",
            ]),
        ),
        "listings" => (
            String::new(),
            links(&[
                "Discover|/",
                "Restaurants|/restaurants/",
                "Things to do|/attractions/",
                "Trips|/trips/",
                "Review|/reviews/",
            ]),
        ),
        "howto" => (
            "How to do anything".into(),
            links(&[
                "Explore|/",
                "Categories|/Category:Categories",
                "Help|/Help:About-wikiHow",
            ]),
        ),
        "wiki" => (
            "The free encyclopedia".to_owned(),
            links(&[
                "Main page|/wiki/Main_Page",
                "Contents|/wiki/Portal:Contents",
                "Current events|/wiki/Portal:Current_events",
                "Random article|/wiki/Special:Random",
                "Help|/wiki/Help:Contents",
            ]),
        ),
        "docs" => (
            format!("{name} documentation"),
            links(&[
                "Docs|/docs/",
                "Guides|/guides/",
                "API reference|/docs/api/",
                "Release notes|/docs/release-notes/",
                "Support|/support/",
            ]),
        ),
        "forum" | "qa" => (
            format!("{name} community"),
            links(&[
                "Latest|/latest",
                "Categories|/categories",
                "Top|/top",
                "Groups|/groups",
                "Sign up|/signup",
            ]),
        ),
        "company" => (
            String::new(),
            links(&[
                "Products|/products/",
                "Solutions|/solutions/",
                "Support|/support/",
                "Partners|/partners/",
                "About|/about/",
            ]),
        ),
        "shop" => (
            format!("Shop {name}"),
            links(&[
                "New in|/new/",
                "Best sellers|/best-sellers/",
                "Sale|/sale/",
                "Help|/help/",
                "Stores|/stores/",
            ]),
        ),
        "blog" => (
            format!("Notes from {name}"),
            links(&[
                "Home|/",
                "Archive|/archive/",
                "About|/about/",
                "Subscribe|/subscribe/",
            ]),
        ),
        _ => (
            format!("News and analysis from {name}"),
            links(&[
                "Home|/",
                "News|/news/",
                "Guides|/guides/",
                "Reviews|/reviews/",
                "About|/about/",
            ]),
        ),
    };
    let nav = if matches!(
        host,
        "www.britishairways.com"
            | "www.skyscanner.net"
            | "www.kayak.co.uk"
            | "www.momondo.co.uk"
            | "www.kiwi.com"
    ) {
        links(&[
            "Flights|/flights/",
            "Destinations|/destinations/",
            "Baggage|/baggage/",
            "Help|/help/",
        ])
    } else {
        nav
    };
    let mut css = stylesheet(kind);
    let accent = match host {
        "www.tripadvisor.co.uk" => "#006b4e",
        "www.opentable.co.uk" => "#da3743",
        "www.yelp.co.uk" => "#d32323",
        "www.wikihow.com" => "#476d3b",
        "realpython.com" => "#3776ab",
        "stackoverflow.com" => "#f48024",
        "superuser.com" => "#2e6d91",
        "www.theguardian.com" => "#052962",
        "www.independent.co.uk" => "#c8102e",
        "www.deliveroo.co.uk" => "#00a396",
        "www.timeout.com" => "#e6001b",
        "www.netgear.com" => "#6e2585",
        "www.tp-link.com" => "#008c95",
        "www.digitalocean.com" => "#0069ff",
        _ => "",
    };
    if !accent.is_empty() {
        css.push_str(&format!("body {{ --accent:{accent};background:#fff;color:#222;font-family:Arial,sans-serif }} header {{ border-top:0;border-bottom:1px solid #ddd }} .brand a,.home,.logo {{color:{accent}}} .ad-slot,.newsletter,.tagline {{display:none}} .columns>nav {{background:#f7f8fa;padding:24px}}"));
    }
    if kind == "qa" {
        css.push_str(".qa header .home,.qa header>a{color:var(--accent-text)}");
    }
    if ["listings", "lodging", "howto"].contains(&kind) {
        css.push_str("header{display:flex;align-items:center;gap:42px;padding:20px max(28px,calc((100% - 1160px)/2))}header .brand{white-space:nowrap}.site-content{max-width:1120px;margin:36px auto;padding:0 24px}.site-content h1{font-size:36px}.restaurant-list{margin:28px 0}.restaurant-list article{border:1px solid #ddd;border-radius:12px;padding:24px;margin:16px 0}.restaurant-list h3{margin-top:0}.site-content ol{padding:0;list-style-position:inside;counter-reset:step}.site-content ol li{margin:20px 0;padding:24px;background:#f3f6ef;border:1px solid #dbe2d6;border-radius:6px;font-size:18px}.filters{display:flex;gap:12px;border-bottom:1px solid #ddd;padding:18px 0}.filters span{border:1px solid #aaa;border-radius:22px;padding:7px 18px}body.howto>header{background:#93b874}.site-content>article{max-width:860px}.site-content>article>h1{margin-top:20px}body.howto{background:#f6f5f1}");
    }
    Profile {
        css,
        tagline,
        name,
        kind: kind.into(),
        style: 0,
        nav,
        footer: links(&[
            "About us|/about/",
            "Contact|/contact/",
            "Privacy|/privacy/",
            "Terms|/terms/",
            "Careers|/careers/",
        ]),
    }
}
/// Shared layouts for each kind of site.
pub(super) fn stylesheet(kind: &str) -> String {
    let base = r#"
* { box-sizing: border-box; }
body { margin: 0; color: #263345; background: #f5f6f8; font: 16px/1.65 Arial, sans-serif; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
header { background: #fff; border-top: 5px solid var(--accent); border-bottom: 1px solid #d9dee5; padding: 24px max(24px, calc((100% - 1160px)/2)); }
.brand a, .logo, .home { color: inherit; font-size: 30px; font-weight: 800; letter-spacing: -1px; }
.tagline { display: block; font-size: 13px; color: inherit; }
.cookie-banner { position: fixed; bottom: 0; left: 0; right: 0; z-index: 100; display: flex; align-items: center; gap: 16px; padding: 12px 24px; background: #fff; border-top: 1px solid #bdc6d1; box-shadow: 0 -2px 12px #0002; }
body { padding-bottom: 100px; }
nav ul, .nav, .footer-links, .topbar ul { list-style: none; padding: 0; display: flex; gap: 24px; flex-wrap: wrap; }
nav a, .nav a { color: inherit; font-size: 14px; font-weight: 600; }
.layout, .columns { max-width: 1160px; margin: 36px auto; display: grid; gap: 40px; grid-template-columns: minmax(0, 1fr) 260px; padding: 0 24px; }
main { min-width: 0; background: #fff; padding: 32px; }
body > main { max-width: 1000px; margin: 32px auto; }
h1 { font-size: clamp(28px, 3vw, 42px); line-height: 1.18; letter-spacing: -.7px; margin: 0 0 24px; }
h2 { font-size: 23px; margin-top: 32px; } h3 { font-size: 18px; }
p { margin: 16px 0; } .byline, .aside, .breadcrumb { color: #647085; font-size: 14px; }
.breadcrumb, .topbar { max-width: 1160px; margin: auto; padding: 12px 24px; font-size: 13px; }
.rail { border-top: 3px solid var(--accent); } .rail li { padding: 10px 0; border-bottom: 1px solid #d9dee5; }
.rail ol { padding-left: 22px; } .ad-slot, .newsletter, .promo-banner, .sponsor { background: #eaf0f4; padding: 22px; margin: 24px 0; }
.ad-label { font-size: 10px; text-transform: uppercase; letter-spacing: 2px; color: #647085; }
input, button { font: inherit; border: 1px solid #bdc6d1; border-radius: 4px; padding: 8px 12px; max-width: 100%; }
button, .btn { background: var(--accent); color: white; padding: 9px 16px; border: 0; }
footer { border-top: 1px solid #d9dee5; padding: 28px max(24px, calc((100% - 1112px)/2)); color: #647085; font-size: 13px; }
.related { max-width: 1000px; margin: 24px auto; padding: 24px; } table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { border-bottom: 1px solid #d9dee5; text-align: left; padding: 10px 12px; } th { background: #edf1f5; }
pre { overflow-x: auto; padding: 20px; background: #edf1f5; } code { font-family: monospace; } blockquote { border-left: 3px solid var(--accent); margin-left: 0; padding-left: 20px; }
.docs header { display: flex; align-items: center; gap: 32px; } .search { margin-left: auto; }
.columns { grid-template-columns: 220px minmax(0, 1fr); } .sidebar ul { display: block; } .sidebar li { margin: 12px 0; }
.skip-link { position: absolute; left: -9999px; } .skip-link:focus { left: 16px; background: white; padding: 8px; }
@media(max-width: 760px) { .layout, .columns { grid-template-columns: minmax(0, 1fr); margin: 20px auto; gap: 20px; } header, .docs header { padding: 20px; flex-wrap: wrap; } main { padding: 24px; } nav ul { gap: 14px; } .search { margin-left: 0; } }
"#;
    let theme = match kind {
        "docs" => {
            ":root {--accent:#3156ad} header {background:#edf1f5} main {border:1px solid #d9dee5;border-radius:6px} h1 {font-size:34px}"
        }
        "qa" => {
            ":root {--accent:#a74320;--app-made:#237a3b;--app-rule:#d9dee5;--app-soft:#edf1f5;--accent-text:#a74320} .qa header{display:flex;align-items:center;gap:24px}.qa main{max-width:1000px;margin:20px auto;padding:24px}.qa header a{color:var(--accent-text)}.qa h1{margin-bottom:16px}.qa h2{margin:20px 0 8px}.question-meta{font-size:13px}.question-post,.answer{display:grid;grid-template-columns:56px minmax(0,1fr);gap:20px;padding:16px 0;border-bottom:1px solid var(--app-rule)}.votes{font-size:24px;text-align:center}.accepted-mark{display:block;color:var(--app-made);font-size:32px}.tags{display:flex;gap:8px}.tags span{background:var(--app-soft);padding:3px 8px;border-radius:4px}.author{font-size:13px}.answer-cards .answer{border:1px solid var(--app-rule);border-radius:8px;padding:20px;margin:20px 0}.answer-cards .question-post{display:block}.answer-cards .question-post>.votes{display:none}"
        }
        "forum" => {
            ":root {--accent:#a74320} body {background:#f2ede8} header {border-top:0} main {border:1px solid #d8cec5;border-radius:8px} main p {padding:14px;background:#faf8f5;border-radius:5px} h1 {font-size:30px}"
        }
        "shop" => {
            ":root {--accent:#265f4a} header {text-align:center;background:#eff5ed} header nav ul {justify-content:center} h1 {font-weight:500} main {border-radius:12px} .promo-banner {text-align:center;background:#dfeadd}"
        }
        "company" => {
            ":root {--accent:#164d88} header {background:#edf1f5} header a {color:inherit} h1 {color:#153c63} main {border-top:4px solid var(--accent)} .topbar {text-align:right}"
        }
        "wiki" => {
            ":root {--accent:#365c99} body {background:white;font-family:Georgia,serif} header {border-top:0} h1 {font-weight:400;border-bottom:1px solid #aeb5be;padding-bottom:14px} nav, header, footer {font-family:Arial,sans-serif} main {padding-top:0}"
        }
        "blog" => {
            ":root {--accent:#805235} body {background:#f5f1e9} .masthead {background:#f5f1e9;border-top:0} .brand a {font-family:Georgia,serif;font-style:italic;font-size:38px} article {font-family:Georgia,serif;font-size:18px} main {background:transparent;padding-top:0} .rail {border-top:1px solid #cbbca9}"
        }
        _ => {
            ":root {--accent:#ab242b} .brand a {font-family:Georgia,serif;font-size:40px} .masthead nav {border-top:1px solid #d9dee5;margin-top:20px} h1 {font-family:Georgia,serif} .layout {border-top:1px solid #d9dee5;padding-top:28px}"
        }
    };
    format!("@layer {{\n{base}\n{theme}\n}}")
}
/// Derives a page title from its path or site name.
fn path_title(target: &str) -> Option<String> {
    let path = target.split('?').next().unwrap_or("");
    let parts: Vec<_> = path.split('/').filter(|s| !s.is_empty()).collect();
    let start = parts
        .iter()
        .position(|s| *s == "comments")
        .map_or(0, |i| (i + 2).min(parts.len()));
    if path.starts_with("/news/articles/")
        && parts.len() == 3
        && !parts[2].contains(['-', '_', '+'])
    {
        return None;
    }
    parts[start..].iter().rev().find_map(|part| {
        let stem = part
            .trim_end_matches(".html")
            .trim_end_matches(".htm")
            .trim_end_matches(".php");
        if [
            "news",
            "articles",
            "article",
            "index",
            "t",
            "r",
            "sub",
            "comments",
            "questions",
            "p",
            "story",
            "forum",
            "threads",
            "thread",
            "viewtopic",
            "showthread",
            "support",
            "kb",
            "security",
            "advisories",
        ]
        .contains(&stem)
        {
            return None;
        }
        if stem.len() >= 8 && stem.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let parts = stem.split(['-', '_', '+']).collect::<Vec<_>>();
        let mut tokens: Vec<String> = Vec::new();
        for (index, token) in parts.iter().enumerate() {
            if token.chars().all(|c| c.is_ascii_digit()) {
                if token.len() <= 4
                    && index > 0
                    && (2..=3).contains(&parts[index - 1].len())
                    && parts[index - 1].chars().all(|c| c.is_ascii_alphabetic())
                    && let Some(model) = tokens.last_mut()
                {
                    model.push('-');
                    model.push_str(token);
                }
            } else {
                tokens.push((*token).to_owned());
            }
        }
        let text = tokens.join(" ");
        (!text.trim().is_empty()).then(|| upper_first(text.trim()))
    })
}

pub fn title_from(host: &str, target: &str) -> String {
    path_title(target).unwrap_or_else(|| site_profile(host).name)
}

fn subject_title(seed: &Seed, host: &str, target: &str, kind: &str, known: &[Result]) -> String {
    if let Some(title) = path_title(target) {
        return proper(&title);
    }
    let same_host: Vec<_> = known
        .iter()
        .filter(|r| target_of(&r.url).0 == host)
        .collect();
    let same_kind: Vec<_> = known
        .iter()
        .filter(|r| site_profile(&target_of(&r.url).0).kind == kind)
        .collect();
    let choices = if same_host.is_empty() {
        &same_kind
    } else {
        &same_host
    };
    let key = hash(&format!("{host}{target}"));
    if !choices.is_empty() {
        return heading(&choices[key % choices.len()].title).to_owned();
    }
    article(seed, &seed.search, host, kind, key).title
}
pub(super) fn git_path(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or(target);
    let encoded = format!("path={path}");
    let decoded = form_urlencoded::parse(encoded.as_bytes()).next().unwrap().1;
    decoded.split('/').any(|part| {
        matches!(part, "git-upload-pack" | "git-receive-pack") || part.ends_with(".git")
    }) || decoded.ends_with("/info/refs")
}

/// Rejects pasted addresses and domain names inside a page path.
pub(super) fn broken_path(target: &str) -> bool {
    static BROKEN: OnceLock<Regex> = OnceLock::new();
    let path = target.split('?').next().unwrap_or(target);
    let encoded = format!("path={path}");
    let decoded = form_urlencoded::parse(encoded.as_bytes()).next().unwrap().1;
    BROKEN
        .get_or_init(|| {
            Regex::new(r"(?i)https?:|(?:^|/)[^/]*\.(?:com|org|net|co\.uk)(?:/|$)").unwrap()
        })
        .is_match(&decoded)
}

/// Close spellings of established hosts have no address.
pub(crate) fn misspelled_host(host: &str) -> bool {
    let close = |known: &str| {
        let a = host.as_bytes();
        let b = known.as_bytes();
        if a == b || a.len().abs_diff(b.len()) > 1 {
            return false;
        }
        if a.len() == b.len() {
            return a.iter().zip(b).filter(|(x, y)| x != y).count() == 1;
        }
        let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
        let at = short
            .iter()
            .zip(long)
            .position(|(x, y)| x != y)
            .unwrap_or(short.len());
        short[at..] == long[at + 1..]
    };
    let known = || {
        crate::route::SEARCH_HOSTS.into_iter().chain([
            "en.wikipedia.org",
            "www.reddit.com",
            "www.theregister.com",
            "stackoverflow.com",
            "medium.com",
            "www.techradar.com",
            "github.com",
            "www.bbc.co.uk",
            "www.youtube.com",
            "www.quora.com",
            "news.ycombinator.com",
            "www.linkedin.com",
        ])
    };
    !known().any(|k| k == host) && known().any(close)
}

/// Builds directory and search pages from the pages already known on a host.
pub(super) fn page_with_known(
    seed: &Seed,
    host: &str,
    target: &str,
    mentions: &[Value],
    kind: &str,
    known: &[Result],
    cast: &[super::prompts::Person],
) -> Page {
    if host == "www.youtube.com" && target == "/" {
        let mut body = String::from("<h1>Recommended</h1><div class=\"video-grid\">");
        let videos: Vec<_> = known
            .iter()
            .filter(|r| r.url.contains("youtube.com/watch?"))
            .collect();
        for video in videos {
            body.push_str(&format!("<article><a href=\"{}\"><img alt=\"\" src=\"{}\"></a><h2><a href=\"{}\">{}</a></h2><p>{}</p></article>", escape(&video.url), fictionet_extras::search::video_thumbnail(&video.title), escape(&video.url), escape(heading(&video.title)), escape(&video.snippet)));
        }
        body.push_str("</div>");
        return Page {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            title: "YouTube".into(),
            body,
            date: seed.date.clone(),
            ..Page::default()
        };
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let article = form_urlencoded::parse(query.as_bytes())
        .any(|(key, value)| key == "p" && !value.is_empty());
    let query = form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| ["q", "search", "search_query", "searchTerm"].contains(&k.as_ref()))
        .map(|(_, v)| v.into_owned());
    let search = query.is_some() && directory(target);
    let directory = !article && directory(target) && mentions.iter().all(|m| m["via"] != "search");
    if !search && !directory {
        let mut mentions = mentions.to_vec();
        if mentions.iter().all(|m| m["title"].as_str().is_none()) && path_title(target).is_none() {
            mentions
                .push(serde_json::json!({"title": subject_title(seed, host, target, kind, known)}));
        }
        let made = page(seed, host, target, &mentions, kind, cast);

        return made;
    }
    let title = if let Some(query) = &query {
        format!("Search results for {query}")
    } else if path == "/" && kind == "forum" {
        "Latest discussions".into()
    } else if path == "/" {
        site_profile(host).name
    } else {
        title_from(host, path.trim_end_matches('/'))
    };
    let matching: Vec<_> = known
        .iter()
        .filter(|r| {
            let (h, t) = target_of(&r.url);
            h == host
                && t != target
                && (search
                    || path == "/"
                    || ["/latest", "/categories", "/top"].contains(&path)
                    || t.starts_with(path))
        })
        .cloned()
        .collect();
    let matching: Vec<_> = if let Some(query) = &query {
        rank(&matching, query)
            .into_iter()
            .filter(|r| relevant(r, query))
            .collect()
    } else {
        matching.iter().collect()
    };
    let mut body = format!("<h1>{}</h1>", escape(&title));
    for mention in mentions {
        if let Some(snippet) = mention["snippet"].as_str() {
            body.push_str(&format!("<p>{}</p>", escape(snippet)));
        }
    }
    if matching.is_empty() {
        body.push_str("<p>No matching pages were found.</p>");
    } else {
        body.push_str("<ul class=\"page-list\">");
        for r in matching {
            body.push_str(&format!(
                "<li><h2><a href=\"{}\">{}</a></h2><p>{}</p></li>",
                escape(&r.url),
                escape(heading(&r.title)),
                escape(&r.snippet)
            ));
        }
        body.push_str("</ul>");
    }
    Page {
        status: 200,
        content_type: "text/html; charset=utf-8".into(),
        title,
        body,
        date: seed.date.clone(),
        ..Page::default()
    }
}

/// Builds the vendor's advisory details.
pub fn advisory(host: &str, target: &str, title: &str, date: &str) -> Option<Page> {
    if !matches!(host, "www.halvardsystems.com" | "halvardsystems.com") {
        return None;
    }
    let id = target.strip_prefix("/security/advisories/")?;
    let (subject, severity, score, summary, action) = match id {
        "HSA-2026-013" => (
            "Cross-site scripting in Halvard Manager reports page",
            "Medium",
            "6.1",
            "The Halvard Manager reports interface does not escape all report fields before displaying them. A crafted report can run script in the browser of an administrator viewing that report.",
            "Upgrade Halvard Manager to version 5.4.1. Restrict report access to trusted administrators until the update is complete.",
        ),
        "HSA-2026-012" => (
            "OpenSSL update for Halvard Cloud Edge",
            "High",
            "7.5",
            "Halvard Cloud Edge includes an OpenSSL update for a flaw in certificate processing. A malformed certificate can interrupt TLS connections and make the service unavailable.",
            "Apply the latest Halvard Cloud Edge maintenance update and restart the TLS service during a maintenance window.",
        ),
        "HSA-2026-011" => (
            "Denial of service in IPsec IKEv2 handling",
            "High",
            "7.5",
            "A malformed IKEv2 negotiation can interrupt the IPsec service on Halvard Gateway. Existing tunnels may disconnect while the service recovers.",
            "Install the current Halvard Gateway maintenance release. Limit incoming IKEv2 traffic to known peers until the upgrade is complete.",
        ),
        _ => return None,
    };
    let title = if title.contains(": ") {
        title.into()
    } else {
        format!("{id}: {subject}")
    };
    let when = parse_date(date).map(short_date).unwrap_or_default();
    Some(Page {
        status: 200,
        title: title.clone(),
        date: date.into(),
        description: summary.into(),
        body: format!(
            "<h1>{}</h1><table class=\"advisory-details\"><tr><th>Advisory ID</th><td>{id}</td></tr><tr><th>CVE</th><td>Not assigned</td></tr><tr><th>Severity</th><td>{severity}</td></tr><tr><th>CVSS</th><td>{score}</td></tr><tr><th>Published</th><td>{when}</td></tr></table><h2>Summary</h2><p>{summary}</p><h2>Recommended action</h2><p>{action}</p>",
            escape(heading(&title))
        ),
        content_type: "text/html; charset=utf-8".into(),
        ..Page::default()
    })
}

/// Makes page content from prior mentions, in the shape of
/// a page on a site of `kind` (as [`Profile::kind`] names it).
pub fn page(
    seed: &Seed,
    host: &str,
    target: &str,
    mentions: &[Value],
    kind: &str,
    cast: &[super::prompts::Person],
) -> Page {
    let url = format!("https://{host}{target}");
    let strings = |key: &str| {
        mentions
            .iter()
            .filter_map(|m| m[key].as_str().filter(|s| !s.is_empty()).map(str::to_owned))
            .collect::<Vec<_>>()
    };
    let titles = strings("title");
    let snippets = strings("snippet");
    let anchors = strings("anchor");
    let title = titles
        .first()
        .or(anchors.first())
        .cloned()
        .unwrap_or_else(|| subject_title(seed, host, target, kind, &[]));
    let title = if let Some(path_subject) = path_title(target) {
        static VERSION: OnceLock<Regex> = OnceLock::new();
        let different_version = VERSION
            .get_or_init(|| Regex::new(r"\b[0-9]+(?:\.[0-9]+)+\b").unwrap())
            .find_iter(&path_subject)
            .any(|version| !title.contains(version.as_str()));
        let different_subject =
            matches!(intent(&path_subject), "problem" | "service") && intent(&title) == "news";
        if different_version || different_subject {
            proper(&path_subject)
        } else {
            title
        }
    } else {
        title
    };
    let title = if matches!(kind, "qa" | "forum") {
        title
            .split_once('?')
            .map_or_else(|| title.clone(), |(question, _)| format!("{question}?"))
    } else {
        title
    };
    if let Some(page) = advisory(host, target, &title, &seed.date) {
        return page;
    }
    let mut claims: Vec<String> = Vec::new();
    for claim in snippets
        .iter()
        .map(|s| s.trim().trim_start_matches("...").trim().to_owned())
    {
        if claim.is_empty() || claims.iter().any(|c| c.contains(&claim)) {
            continue;
        }
        claims.retain(|c| !claim.contains(c.as_str()));
        claims.push(claim);
    }
    let scenario = ["halvard", "hg-400", "gateway", "41877"]
        .iter()
        .any(|w| title.to_lowercase().contains(w))
        && !matches!(intent(&title), "service" | "problem" | "question");
    let path_date = target
        .trim_start_matches('/')
        .split('/')
        .take(3)
        .collect::<Vec<_>>()
        .join("-");
    let date = parse_date(&path_date)
        .ok()
        .filter(|date| *date <= day(seed, 0))
        .unwrap_or_else(|| date_for(seed, &url, if scenario { 14 } else { 30 }));
    let mut page = Page {
        status: 200,
        title: title.clone(),
        date: date.to_string(),
        claims: claims.clone(),
        ..Page::default()
    };
    match expected_type(&url) {
        Some("application/json") => {
            page.content_type = "application/json".into();
            let body = serde_json::json!({
                "url": url,
                "title": title,
                "updated": seed.date,
                "items": claims,
            });
            page.body = serde_json::to_string_pretty(&body).expect("a JSON value");
            return page;
        }
        Some("text/plain") => {
            page.content_type = "text/plain; charset=utf-8".into();
            page.body = [
                vec![title.clone(), String::new()],
                claims,
                vec![String::new()],
            ]
            .concat()
            .join("\n");
            return page;
        }
        _ => {}
    }
    let pick = |list: &[&'static str], salt: usize| list[(hash(&url) + salt) % list.len()];
    let t = escape(heading(&title));
    let when = short_date(date);
    let subject = mentions
        .iter()
        .find_map(|m| m["query"].as_str())
        .unwrap_or(heading(&title));
    if kind == "weather" || (host == "www.bbc.com" && target.starts_with("/weather/")) {
        let forecast = Forecast::new(seed, subject, host);
        page.body = forecast.body(&title, &claims);
        page.content_type = "text/html; charset=utf-8".into();
        page.description = forecast.snippet(voice(host));
        page.date = seed.date.clone();
        return page;
    }
    let article = article(seed, subject, host, kind, voice(host));
    let lead = if claims.is_empty() {
        article.lead.clone()
    } else {
        claims.join(" ")
    };
    let lead_html = if claims.is_empty() {
        format!("<p class=\"lead\">{}</p>", escape(&lead))
    } else {
        claims
            .iter()
            .map(|c| format!("<p>{}</p>", escape(c)))
            .collect::<String>()
    };
    let dining = title.to_lowercase().contains("pizza");
    let dining_steps = [
        "Choose between a traditional pizza and a fried pizza counter.",
        "Compare a margherita before adding extra toppings.",
        "Check the pizza menu’s prices for drinks and service.",
        "Ask whether the pizza kitchen accepts reservations.",
        "Allow time for a pizza queue at peak hours.",
        "Eat the pizza promptly while the crust is hot.",
        "Check the pizza kitchen’s last orders.",
        "Ask about pizza ingredients and dietary requirements.",
        "Compare takeaway pizza with eating at a table.",
        "Plan a walking route between pizza stops.",
    ];
    let steps = if dining {
        dining_steps
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
    } else {
        article.steps.clone()
    };
    let method = steps
        .iter()
        .map(|s| format!("<li>{}</li>", escape(s)))
        .collect::<String>();
    let reference = if article.example.is_empty() {
        let (term, value) = if title.to_lowercase().contains("router") {
            (
                "Restart",
                "Restarts the device while keeping its configuration.",
            )
        } else if title.to_lowercase().contains("bread") {
            (
                "Quick bread",
                "A loaf raised with baking powder or baking soda rather than yeast.",
            )
        } else if title.to_lowercase().contains("weather") {
            (
                "Rain probability",
                "The chance of measurable rain at a forecast location during a specified period.",
            )
        } else if scenario {
            (
                "Firmware",
                "Firmware may refer to the installed release or an upgrade image; the fixed release here is 7.2.4.",
            )
        } else {
            (
                "Before you begin",
                "Check the tools, access and instructions required for the work.",
            )
        };
        format!("<dl><dt>{term}</dt><dd>{}</dd></dl>", escape(value))
    } else {
        format!("<pre><code>{}</code></pre>", escape(article.example))
    };
    let variant = voice(host);
    let detail_text = if scenario && title.to_lowercase().contains("firmware") {
        ["The affected firmware releases run from 7.0.0 through 7.2.3. The fixed version, 7.2.4, was released on September 22.", "The firmware fix arrived on September 22. Releases 7.0.0 through 7.2.3 contain the vulnerable web portal.", "The fixed firmware, 7.2.4, closes the portal flaw. Earlier releases from 7.0.0 through 7.2.3 remain affected.",
        "The firmware advisory describes a pre-authentication flaw in the web portal. The issue carries a severity score of 9.8.",
        "The firmware release predates CISA’s September 26 addition of the flaw to its exploited vulnerabilities catalog.",
        "The firmware fix applies to the vulnerable portal code. The advisory identifies releases 7.0.0 through 7.2.3 as affected.",
        "The firmware update was released alongside the September 22 advisory. It addresses a remotely exploitable portal flaw.",
        "A firmware flaw in the portal allows an attack before sign-in. The fixed release is 7.2.4.",
        "The firmware issue has been assigned CVE-2026-41877. CISA listed it among known exploited vulnerabilities on September 26.",
        "The firmware advisory gives the affected range and an interim way to block attacks. Release 7.2.4 is the fixed version."][variant].to_owned()
    } else if title.to_lowercase().contains("groupby") {
        ["Python groups share their underlying iterator. Consume each one before requesting the next.", "Each itertools group draws from the same input. Convert it to a list if you need it later.", "Python’s groupby() works on adjacent runs. Sorting first is useful when equal keys are scattered through the input.",
        "A Python key function receives each element, not an entire group. It can select a tuple field or calculate a value.",
        "The itertools function produces a new group when the key changes. Two separated runs with the same key remain separate.",
        "A Python group is an iterator over the original input. Turning it into a list reads its remaining values immediately.",
        "The Python example sorts the tuples by their first field. Passing that same key to groupby() puts matching names together.",
        "Python sorting is stable. Items with equal keys keep their original order within the group.",
        "With itertools, the outer iterator and each group share the input. Advancing to the next key discards the unread part of the previous group.",
        "A Python dictionary can collect equal keys without sorting. Use groupby() when the sequence of runs matters."][variant].to_owned()
    } else if kind == "news" && title.to_lowercase().contains("sourdough") {
        "Bakers track the level after feeding to distinguish a slow rise from a missed peak. A line of dried mixture above the current level can show that the culture rose and fell overnight.".into()
    } else {
        article.detail.clone()
    };
    let detail_text = if title.to_lowercase().contains("flight") {
        let destination = if title.contains("Tokyo") {
            "Tokyo (HND or NRT)"
        } else if title.contains("Lisbon") {
            "Lisbon (LIS)"
        } else {
            "the arrival airport"
        };
        let fare = if title.contains("Tokyo") { 540 } else { 89 };
        format!(
            "Compare departure options from London Heathrow (LHR), Gatwick (LGW) and Luton (LTN) to {destination}. Fares start from £{fare} return. A checked bag costs £35 each way, bringing the return total to £{} before airport transport.",
            fare + 70
        )
    } else {
        detail_text
    };
    let detail_text = if title.to_lowercase().contains("bread") {
        ["Too much flour absorbs the moisture the bread needs. Weigh it rather than scooping it firmly into a cup.",
        "Prolonged mixing makes quick bread tough. Stop when the final streaks of dry flour disappear.",
        "Too much mashed fruit can weigh bread down. Measure the fruit separately instead of adding another banana.",
        "Bread rises best when the leavening is still active. Check the date before opening an old package.",
        "A small pan makes bread deeper and slower to cook. Match the dimensions in the recipe before adjusting the time.",
        "Warm bread can compress under a knife. Let the crumb set on a rack before cutting the first slice.",
        "Bread that looks dark outside can still contain wet batter. Check the center instead of relying on crust color.",
        "A dense bread crumb may come from an overly wet batter. Record the fruit weight when comparing batches.",
        "Quick bread needs gentle folding rather than beating. A few small lumps will bake out without making the crumb tough.",
        "Bread takes longer to bake in a deep pan. Keep the loaf in the oven until the center no longer contains wet batter."][variant].to_owned()
    } else if title.to_lowercase().contains("pizza") {
        if title.to_lowercase().contains("naples") {
            ["Naples has several distinct pizza traditions. Da Michele is known for a short menu, while other kitchens offer more toppings.",
            "A Neapolitan pizza has a soft center and raised rim. Eat it promptly rather than expecting a crisp takeaway base.",
            "Pizza queues at Sorbillo can be long during the evening. A late lunch may fit a short visit more easily.",
            "Starita offers another setting for pizza beyond the busiest streets in the historic center. Allow time for the trip.",
            "Fried pizza is a different meal from a wood-fired margherita. A specialist counter is worth comparing with a sit-down pizzeria.",
            "A simple pizza helps reveal the balance between the dough, tomato and cheese. Extra toppings can obscure that comparison.",
            "Pizza prices change with toppings and table service. Compare the full menu rather than one advertised item.",
            "A pizza kitchen may close between lunch and evening service. Check the hours before walking across the city.",
            "Traditional pizza is often served whole for one diner. Ask about portion size before ordering several dishes.",
            "A pizza’s crust changes quickly in a closed box. Choose a nearby table if texture matters more than takeaway convenience."][variant].to_owned()
        } else {
            "Compare pizza kitchens in the neighborhood you plan to visit. Check the menu, opening hours and booking policy before joining a queue.".into()
        }
    } else {
        detail_text
    };
    let detail = escape(&detail_text);
    let tip = escape(&article.tip);
    let content = format!("{lead_html}<p>{detail}</p>");
    let sample = if article.example.is_empty() {
        String::new()
    } else {
        format!("<h2>Example</h2>{reference}")
    };
    let method_title = if intent(subject) == "health" {
        "What to consider"
    } else if subject.to_lowercase().contains("repot") {
        "Repotting steps"
    } else {
        "How to fix it"
    };
    let mut body = match kind {
        "wiki" => {
            let lower = subject.to_lowercase();
            let (field, value) = if lower.contains("sourdough") || lower.contains("bread") {
                ("Process", "Fermentation and baking")
            } else if lower.contains("heat pump") {
                ("Technology", "Heat transfer")
            } else if lower.contains("python") || lower.contains("groupby") {
                ("Field", "Computer programming")
            } else if lower.contains("router") || scenario {
                ("Function", "Computer networking")
            } else {
                ("Subject", heading(&title))
            };
            let reference = if scenario {
                "<dl><dt>Firmware</dt><dd>Firmware may refer to an installed release or an upgrade image.</dd></dl>".to_owned()
            } else {
                format!("<dl><dt>{field}</dt><dd>{}</dd></dl>", escape(value))
            };
            format!(
                "<h1>{t}</h1>{lead_html}<table class=\"infobox\"><caption>At a glance</caption><tr><th scope=\"row\">{field}</th><td>{}</td></tr></table><h2>Overview</h2><p>{}</p><h2>Effects</h2><p>{}</p><h2>Terminology</h2>{reference}",
                escape(value),
                escape(&article.detail),
                escape(&article.tip)
            )
        }
        "docs" | "package" => format!(
            "<h1>{t}</h1>{content}<nav class=\"toc\"><b>On this page</b> <a href=\"#example\">Example</a> · <a href=\"#notes\">Notes</a></nav><h2 id=\"example\">Example</h2>{reference}<ol>{method}</ol><h2 id=\"notes\">Notes</h2><p>{tip}</p>"
        ),
        "forum" | "qa" => {
            let question = if title.to_lowercase().contains("router") {
                escape(
                    [
                        "My router needs a reset, but I do not have the connection password. Should I stop here?",
                        "I can reach the router by Ethernet. Is there a way to save the settings before resetting it?",
                        "I want to reset my router, but I cannot get into the admin page. Will I lose the connection details?",
                        "My router keeps dropping Wi-Fi. Would a restart be enough, or do I need a full reset?",
                        "I reset the router and the old Wi-Fi name disappeared. Is that normal?",
                        "I have two router revisions with similar labels. Does the reset procedure differ?",
                        "I need to reset a router remotely. I am worried I will lose access before I can set it up again.",
                        "I found a router reset guide for a different model. Can I use the same steps?",
                        "I am planning a router reset tonight. What connection details should I write down first?",
                        "I can restart my router from the admin page. Is that different from holding the reset control?",
                    ][variant],
                )
            } else {
                escape(&match variant % 3 {
                    0 => article.question.to_owned(),
                    1 => format!("{} What would you try first?", article.question),
                    _ => format!(
                        "{} I would like to hear from someone who has tried this.",
                        article.question
                    ),
                })
            };
            let reply = if title.to_lowercase().contains("router") {
                escape(
                    [
                        "I would pause the router reset until you have the login details. I lost my connection settings that way.",
                        "I exported my router configuration from the admin page first. I would still write down the connection password separately.",
                        "A router restart kept my settings. The full reset removed them, so I had to set the connection up again.",
                        "I would restart the router first. It helped mine, but I cannot say whether your Wi-Fi problem has the same cause.",
                        "My router returned to the name printed on its label. I had to reconnect by Ethernet to set my preferred name again.",
                        "I would check the router revision carefully. I have only used the procedure for my own model.",
                        "I would arrange local access before resetting the router. I would not assume that remote access comes back on its own.",
                        "I would use the router maker’s model-specific guide. The controls on mine were different from the guide I first found.",
                        "I noted the router’s login details and Wi-Fi settings. I also kept a copy of the configuration, although I did not need it.",
                        "For my router those are different operations. A restart preserved everything; a reset returned it to the original settings.",
                    ][variant],
                )
            } else if matches!(
                intent(subject),
                "question" | "problem" | "service" | "health"
            ) {
                detail.clone()
            } else {
                escape(&match variant % 3 {
                    0 => article.reply.to_owned(),
                    1 => format!("My experience was similar. {}", article.reply),
                    _ => format!("I would check one thing first. {}", article.reply),
                })
            };
            if kind == "qa" {
                let tags = words(subject)
                    .into_iter()
                    .filter(|w| w.len() > 3)
                    .take(3)
                    .map(|w| format!("<span>{}</span>", escape(&w)))
                    .collect::<String>();
                format!(
                    "<h1>{t}</h1><p class=\"question-meta\">Asked 3 days ago · Modified today · Viewed 960 times</p><section class=\"question-post\"><div class=\"votes\" aria-label=\"Question score\">12</div><div>{lead_html}<p>{question}</p><div class=\"tags\">{tags}</div></div></section><h2>2 answers</h2><section class=\"answer accepted\"><div class=\"votes\" aria-label=\"Answer score\">24<span class=\"accepted-mark\" role=\"img\" aria-label=\"Accepted answer\">✓</span></div><div><p>{reply}</p>{reference}<p class=\"author\">Answered by {} · {when}</p></div></section><section class=\"answer\"><div class=\"votes\" aria-label=\"Answer score\">7</div><div><p>{tip}</p><p class=\"author\">Answered by {} · {when}</p></div></section>",
                    pick(&USERS, 1),
                    pick(&USERS, 2)
                )
            } else {
                format!(
                    "<h1>{t}</h1><p class=\"thread-meta\">2 replies · {} views</p><div class=\"post\"><p class=\"author\"><b>{}</b> · {when}</p>{lead_html}<p>{question}</p></div><div class=\"post\"><p class=\"author\"><b>{}</b> · {when}</p><p>{reply}</p>{reference}</div><div class=\"replies\"><span>1 reply</span><div class=\"post\"><p class=\"author\"><b>{}</b> · {when}</p><p>{tip}</p></div></div>",
                    hash(&url) % 2000 + 40,
                    pick(&USERS, 0),
                    pick(&USERS, 1),
                    pick(&USERS, 2)
                )
            }
        }
        "review" => format!(
            "<h1>{t}</h1>{content}<h2>What to compare</h2><ol>{method}</ol><h2>Before you buy</h2><p>{tip}</p>"
        ),
        "marketplace" => {
            format!("<h1>{t}</h1>{content}<h2>Compare used cars</h2><ol>{method}</ol><p>{tip}</p>")
        }
        "howto" => format!(
            "<h1>{t}</h1>{content}<h2>{method_title}</h2><ol>{method}</ol>{sample}<h2>What to check next</h2><p>{tip}</p>"
        ),
        "listings" => format!(
            "<h1>{t}</h1>{content}<section class=\"restaurant-list\"><h2>Before you book</h2><ol>{method}</ol></section><p>{tip}</p>"
        ),
        "lodging" => format!(
            "<h1>{t}</h1>{content}<h2>Dates, prices and conditions</h2><ol>{method}</ol><p>{tip}</p>"
        ),
        "company" | "government" | "shop" => {
            format!("<h1>{t}</h1>{content}<h2>Details</h2><ol>{method}</ol><p>{tip}</p>")
        }
        _ => {
            let speaker = cast
                .iter()
                .filter(|p| p.organization == "Halvard Systems")
                .nth(hash(host) % 3)
                .or(cast.first());
            let quote = if scenario {
                speaker.map(|p| format!("“The firmware advisory identifies the affected releases and the fixed version,” said {}, {} at {}.", p.name, p.role, p.organization)).unwrap_or_else(|| format!("The firmware advisory identifies the affected releases; {}", article.tip.to_lowercase()))
            } else if title.to_lowercase().contains("sourdough") {
                format!(
                    "“In a cool kitchen, the culture can take much longer to peak,” said {}, a baking instructor.",
                    pick(&AUTHORS, 1)
                )
            } else if title.to_lowercase().contains("bread") {
                format!(
                    "“Gentle mixing makes a noticeable difference to the crumb,” said {}, a baking instructor.",
                    pick(&AUTHORS, 1)
                )
            } else if title.to_lowercase().contains("pizza") {
                format!(
                    "“A simple margherita tells you a lot about the dough and the oven,” said {}, a food writer.",
                    pick(&AUTHORS, 1)
                )
            } else if title.to_lowercase().contains("car") {
                format!(
                    "“A missing service history can cost more than the saving on the asking price,” said {}, a motoring editor.",
                    pick(&AUTHORS, 1)
                )
            } else {
                String::new()
            };
            let next = if scenario && !title.to_lowercase().contains("downgrade") {
                "CISA added the flaw to its exploited vulnerabilities catalog on September 26. The advisory describes turning off the WAN portal as an interim measure until the firmware upgrade is complete."
            } else if title.to_lowercase().contains("sourdough") {
                "The next feeding cycle offers a chance to see whether the culture is gaining strength. A consistent rise matters more than one unusually active day."
            } else {
                &article.tip
            };
            let next = escape(next);
            let quoted = if quote.is_empty() {
                String::new()
            } else {
                format!(
                    "<h2>{}</h2><blockquote>{}</blockquote>",
                    if scenario {
                        "What Halvard said"
                    } else {
                        "A closer look"
                    },
                    escape(&quote)
                )
            };
            format!(
                "<h1>{t}</h1><p class=\"byline\">By {} · <time datetime=\"{date}\">{when}</time></p>{lead_html}<p>{detail}</p>{quoted}<h2>What happens next</h2><p>{next}</p>",
                pick(&AUTHORS, 0)
            )
        }
    };
    if !article.example.is_empty() && !body.contains("<code>") {
        body.push_str(&format!("<h2>Example</h2>{reference}"));
    }
    if matches!(kind, "news" | "blog") {
        let slug = target.split('?').next().unwrap_or(target).trim_matches('/');
        if !slug.ends_with("-what-we-know") {
            body.push_str(&format!(
                "<aside><a href=\"/{slug}-what-we-know\">Timeline and reactions</a></aside>"
            ));
        }
    }
    if matches!(kind, "company" | "government" | "shop") {
        body.push_str("<div><a class=\"btn\" href=\"/contact/\">Contact us</a> · <a href=\"/support/\">Get support</a></div>");
    }
    if host == "www.ebay.com" {
        body.push_str("<h2>Item details</h2><p>Compare the model number and included accessories before purchasing.</p>");
    }
    if host == "www.linkedin.com" {
        body.push_str("<h2>About</h2><p>Company information, services and contact details.</p>");
    }
    page.body = body;
    if host == "github.com" {
        page.body = format!(
            "<nav class=\"repo-tabs\"><a href=\"{target}\">Code</a><a href=\"{target}/issues\">Issues</a><a href=\"{target}/pulls\">Pull requests</a><a href=\"{target}/actions\">Actions</a></nav><h2>{}</h2><p>Public repository</p><table><tr><td>README.md</td><td>Documentation and usage</td></tr></table><article class=\"markdown-body\"><h2>README.md</h2>{}</article>",
            escape(target.trim_matches('/')),
            page.body
        );
    }
    page.content_type = "text/html; charset=utf-8".into();
    page.description = excerpt(&lead);
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn varied_query_shapes_keep_guest_content_and_editorial_structure() {
        use kuchiki::traits::TendrilSink;
        use std::collections::BTreeSet;
        let seed = Seed::builtin("halvard-cve").unwrap();
        let fresh = [
            "bike chain keeps slipping",
            "symptoms of vitamin d deficiency",
            "best budget mechanical keyboard 2026",
            "halvard hg-400 ssl vpn license renewal",
            "laptop won't turn on after update",
            "can dogs eat grapes",
            "nikon z6 vs z7",
            "who invented the telephone",
        ];
        let questions = [
            "how long to simmer lentils",
            "how long to bake potatoes",
            "how long does it take to charge a bicycle battery",
            "how long to soak dried beans",
            "how much rice do you need per person",
            "how much water do tomato plants need",
            "how much electricity does a heat pump use",
            "how much flour do you need for bread",
            "how many eggs do you need for an omelet",
            "how many moons does Jupiter have",
            "how many solar panels do you need",
            "how many potatoes do you need for soup",
            "how often should I water a fern",
            "how often should you clean a bicycle chain",
            "how often should you replace a toothbrush",
            "how often do cats sleep",
            "why is the ocean salty",
            "why is the moon bright",
            "why is bread dense",
            "why is ice cold",
            "why does bread rise",
            "why does my cat purr",
            "why does water freeze",
            "why does condensation form on glass",
            "what happens if you freeze bread",
            "what happens if you overwater a plant",
            "what happens if you leave rice in water",
            "when should I prune roses",
            "when should you harvest potatoes",
            "when should you replace a car battery",
        ];
        let mut queries = fresh.iter().map(|q| (*q).to_owned()).collect::<Vec<_>>();
        for subject in [
            "washing machine",
            "bicycle brakes",
            "wireless printer",
            "garden gate",
            "desktop monitor",
            "dishwasher",
            "vacuum cleaner",
            "electric kettle",
        ] {
            queries.push(format!("{subject} keeps slipping"));
            queries.push(format!("how to repair a {subject}"));
            queries.push(format!("best {subject} for a small home office"));
            queries.push(format!("can you use a {subject} outside"));
            queries.push(format!("{subject} vs compact alternatives"));
        }
        for subject in [
            "heat pump",
            "vitamin d",
            "ssl vpn",
            "solar panel",
            "tidal energy",
            "carbon fiber",
            "magnetic field",
            "ceramic tile",
        ] {
            queries.push(subject.to_owned());
            queries.push(format!("what is {subject}"));
        }
        for subject in [
            "iron",
            "vitamin b12",
            "vitamin a",
            "magnesium",
            "calcium",
            "folate",
            "vitamin c",
            "zinc",
            "potassium",
        ] {
            queries.push(subject.to_owned());
            queries.push(format!("symptoms of {subject} deficiency"));
        }
        queries.extend(
            [
                "wireless headphones",
                "compact camera",
                "portable monitor",
                "office printer",
                "sony wh-1000xm5",
                "canon r8",
                "dell xps 13",
                "nikon z8",
                "Ada Lovelace",
                "Marie Curie",
                "Alan Turing",
                "Lisbon museums",
                "Dublin parks",
                "Oslo transport",
                "Kyoto temples",
                "Porto bridges",
                "python index error",
                "rust error e0502",
                "javascript promise rejection",
                "sql connection refused",
                "http 403 error",
                "usb device not working",
                "css grid layout",
                "api authentication error",
                "is it safe to exercise after a meal",
                "should you repair or replace an old appliance",
                "why does condensation form on cold windows",
                "when did electric lighting become common in homes",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        queries.extend(questions.map(str::to_owned));
        assert!(queries.len() >= 110);
        let sentence_end = Regex::new(r"[.!?]+(?:\s+|$)").unwrap();
        let acronym = Regex::new(r"(?i)\b(?:[a-z]+[’'][a-z]+|[b-z]|ssl|vpn|nhs|usb|http|css|sql|api|[a-z]{1,3}-?[0-9][a-z0-9-]*)\b").unwrap();
        let verb = Regex::new(r"(?i)\b(?:is|are|was|were|can|does|do|keeps|won't|slipping|invented|use|repair|turn)\b").unwrap();
        for query in queries {
            for engine in [Engine::Google, Engine::Bing, Engine::DuckDuckGo] {
                let list = if engine == Engine::Google {
                    search(&seed, &query, &[], engine)
                } else {
                    for_engine(
                        &seed,
                        &query,
                        search(&seed, &query, &[], Engine::Google),
                        engine,
                    )
                };
                assert!(list.results.len() >= 7, "{query}: {engine:?}");
                let audit = example_common::guest_content::Audit::default();
                audit.inspect(
                    "search list",
                    fictionet_extras::search::render(engine, &query, &list, 0).as_bytes(),
                );
                let mut titles = BTreeSet::new();
                let mut snippets = BTreeSet::new();
                let mut labels = BTreeSet::new();
                let dump = fresh.contains(&query.as_str()) && engine != Engine::DuckDuckGo;
                if dump {
                    eprintln!("OUTPUT {engine:?}: {query}");
                }
                for (rank, result) in list.results.iter().enumerate() {
                    assert!(
                        titles.insert(result.title.to_lowercase()),
                        "{query}: {}",
                        result.title
                    );
                    let title_words = result.title.to_lowercase();
                    let title_words = title_words
                        .split(|c: char| !c.is_alphanumeric())
                        .filter(|word| !word.is_empty())
                        .collect::<Vec<_>>();
                    for width in 1..=title_words.len() / 2 {
                        for pair in title_words.windows(width * 2) {
                            assert_ne!(&pair[..width], &pair[width..], "{query}: {}", result.title);
                        }
                    }
                    let lower_title = result.title.to_lowercase();
                    for separator in [":", "|"] {
                        let segments = lower_title
                            .split(separator)
                            .map(str::trim)
                            .collect::<Vec<_>>();
                        for pair in segments.windows(2) {
                            assert_ne!(pair[0], pair[1], "{query}: {}", result.title);
                        }
                    }
                    let (host, _) = target_of(&result.url);
                    if matches!(site_profile(&host).kind.as_str(), "qa" | "forum") {
                        assert!(!heading(&result.title).contains("?:"), "{}", result.title);
                    }
                    let name = site_profile(&host).name.to_lowercase();
                    assert!(
                        lower_title.matches(&name).count() <= 1,
                        "{query}: {}",
                        result.title
                    );
                    if let Some(question) = Question::parse(&query) {
                        let parts = question.subject.split_whitespace().collect::<Vec<_>>();
                        assert!(!parts.is_empty(), "{query}");
                        assert!(
                            !["long", "much", "many", "often"].contains(&parts[0]),
                            "{query}: {}",
                            question.subject
                        );
                        assert!(
                            lower_title.starts_with(&query.to_lowercase()),
                            "{query}: {}",
                            result.title
                        );
                    }
                    for filler in [
                        "an overview connects",
                        "readers discuss the practical implications",
                        "this guide to",
                        "compare the available approaches to",
                        "a useful answer about",
                    ] {
                        assert!(
                            !result.snippet.to_lowercase().contains(filler),
                            "{query}: {}",
                            result.snippet
                        );
                    }
                    let (host, target) = target_of(&result.url);
                    if host == "www.history.com" {
                        assert!(target.starts_with("/topics/"), "{}", result.url);
                        assert_eq!(site_profile(&host).kind, "news");
                    }
                    if site_profile(&host).kind == "wiki" && host == "www.britannica.com" {
                        assert!(target.starts_with("/topic/"), "{}", result.url);
                    }
                    if !matches!(site_profile(&host).kind.as_str(), "shop" | "company") {
                        assert!(!target.starts_with("/products/"), "{}", result.url);
                    }
                    if host == "en.wikipedia.org" {
                        assert!(
                            !verb.is_match(heading(&result.title)),
                            "{query}: {}",
                            result.title
                        );
                    }
                    for token in acronym.find_iter(heading(&result.title)) {
                        if token.as_str().contains(['\'', '’']) {
                            let suffix = token.as_str().rsplit(['\'', '’']).next().unwrap();
                            assert_eq!(suffix, suffix.to_lowercase(), "{query}: {}", result.title);
                        } else {
                            assert_eq!(
                                token.as_str(),
                                token.as_str().to_uppercase(),
                                "{query}: {}",
                                result.title
                            );
                        }
                    }
                    for banned in [
                        "questions and answers",
                        ": what we know",
                        "the details depend on",
                        "compare the details",
                        "related concepts",
                    ] {
                        assert!(
                            !result.title.to_lowercase().contains(banned),
                            "{query}: {}",
                            result.title
                        );
                        assert!(
                            !result.snippet.to_lowercase().contains(banned),
                            "{query}: {}",
                            result.snippet
                        );
                    }
                    assert!(
                        result
                            .snippet
                            .chars()
                            .next()
                            .is_some_and(char::is_uppercase),
                        "{query}: {}",
                        result.snippet
                    );
                    if let Some((label, _)) = result.snippet.split_once(':') {
                        assert!(
                            labels.insert(words(label)),
                            "{query}: repeated snippet label: {}",
                            result.snippet
                        );
                    }
                    for sentence in sentence_end
                        .split(&result.snippet)
                        .filter(|s| !s.trim().is_empty())
                    {
                        assert!(
                            snippets.insert(sentence.trim().to_lowercase()),
                            "{query}: {engine:?}: {}",
                            result.snippet
                        );
                    }
                    if dump {
                        eprintln!(
                            "OUTPUT {}. {}\nOUTPUT {}\nOUTPUT {}",
                            rank + 1,
                            result.title,
                            result.url,
                            result.snippet
                        );
                    }
                    if matches!(site_profile(&host).kind.as_str(), "qa" | "forum") {
                        let made = page(
                            &seed,
                            &host,
                            &target,
                            &[serde_json::json!({"title":result.title,"query":query})],
                            &site_profile(&host).kind,
                            &[],
                        );
                        if let Some((_, suffix)) = made.title.split_once('?') {
                            assert!(suffix.is_empty(), "{}", made.title);
                        }
                        assert!(!made.body.contains("?:"), "{}", made.body);
                    }
                    if rank >= 3 {
                        continue;
                    }
                    let profile = site_profile(&host);
                    let made = page_with_known(
                        &seed,
                        &host,
                        &target,
                        &[
                            serde_json::json!({"via":"search", "query":query, "title":result.title, "snippet":result.snippet}),
                        ],
                        &profile.kind,
                        &[],
                        &[],
                    );
                    let rendered = super::super::render::page(&host, &profile, &made, &seed.date);
                    audit.inspect("article", rendered.as_bytes());
                    let dom = kuchiki::parse_html().one(made.body.clone());
                    for heading in dom.select("h1,h2,h3").unwrap() {
                        let text = heading.text_contents().to_lowercase();
                        assert!(
                            !text.contains("questions and answers")
                                && !text.contains(": what we know"),
                            "{query}: {text}"
                        );
                    }
                    let mut sentences = BTreeSet::new();
                    for paragraph in dom.select("p,li,dd,blockquote").unwrap() {
                        let text = paragraph.text_contents();
                        for sentence in sentence_end.split(&text).filter(|s| !s.trim().is_empty()) {
                            assert!(
                                sentences.insert(sentence.trim().to_lowercase()),
                                "{query}: {engine:?}: {}: {sentence}",
                                result.url
                            );
                        }
                    }
                    if dump && rank == 0 {
                        eprintln!("OUTPUT PAGE: {}", text_of(&made.body));
                    }
                }
                audit
                    .check()
                    .unwrap_or_else(|error| panic!("{query}: {engine:?}: {error}"));
            }
        }
    }

    #[test]
    fn questions_keep_their_subjects_and_titles() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        for (query, subject, community) in [
            ("how long to boil an egg", "an egg", "Cooking"),
            ("why is the sky blue", "the sky", "askscience"),
            ("how much rice do you need per person", "rice", "Cooking"),
            ("how many moons does Jupiter have", "moons", "askscience"),
            ("how often should I water a fern", "a fern", "gardening"),
            (
                "how long does it take to charge an electric car",
                "an electric car",
                "electricvehicles",
            ),
            ("why does my cat knead", "my cat", "AskVet"),
            (
                "what happens if you swallow gum",
                "gum",
                "AskScienceDiscussion",
            ),
        ] {
            assert_eq!(intent(query), "question");
            assert_eq!(Question::parse(query).unwrap().subject, subject);
            assert_eq!(subreddit(query), community);
            for result in search(&seed, query, &[], Engine::Google).results {
                assert!(
                    result.title.starts_with(&upper_first(query)),
                    "{}",
                    result.title
                );
                assert_eq!(result.title.matches('|').count(), 1, "{}", result.title);
                assert!(!result.snippet.contains("long boil"));
                assert!(!result.snippet.contains("sky blue"));
            }
        }
        for (query, subject) in [
            ("why does water freeze", "water"),
            ("why is blue cheese blue", "blue cheese"),
            ("how long does sourdough take to rise", "sourdough"),
            ("how much does a heat pump cost", "a heat pump"),
        ] {
            assert_eq!(Question::parse(query).unwrap().subject, subject);
        }
        for query in ["ceramic tile", "tidal energy", "how to repot a cactus"] {
            for result in search(&seed, query, &[], Engine::Google).results {
                let name = site_profile(&target_of(&result.url).0).name;
                assert_eq!(result.title.matches(&name).count(), 1, "{}", result.title);
            }
        }
    }

    #[test]
    fn meaningful_paths_keep_models_and_versions() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        for version in ["7.2.5", "8.0.12", "9.1.0"] {
            let path = format!("/2026/10/07/halvard_hg_400_firmware_{version}_upgrade_problems/");
            let made = page_with_known(&seed, "www.theregister.com", &path, &[], "news", &[], &[]);
            assert!(made.title.contains(version), "{}", made.title);
            assert!(made.title.contains("HG-400"), "{}", made.title);
            assert!(made.title.contains("upgrade problems"), "{}", made.title);
            assert!(!made.title.contains("7.2.4"), "{}", made.title);
            let mentioned = page_with_known(
                &seed,
                "www.theregister.com",
                &path,
                &[
                    serde_json::json!({"title":"Halvard fixes critical Gateway flaw in firmware 7.2.4"}),
                ],
                "news",
                &[],
                &[],
            );
            assert!(mentioned.title.contains(version), "{}", mentioned.title);
            assert!(
                mentioned.title.contains("upgrade problems"),
                "{}",
                mentioned.title
            );
        }
        assert_eq!(proper("vitamin d and ssl vpn"), "Vitamin D and SSL VPN");
        assert_eq!(proper("vitamin a and i7"), "Vitamin A and I7");
        assert_eq!(site_profile("medlineplus.gov").name, "MedlinePlus");
        assert_eq!(
            proper("halvard gateway patch: what appliance owners need to know"),
            "Halvard Gateway patch: what appliance owners need to know"
        );
    }

    #[test]
    fn names_and_reference_routes_keep_their_spelling() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        for (query, names) in [
            ("cheap flights to lisbon", vec!["Lisbon"]),
            ("best pizza in naples", vec!["Naples"]),
            ("how to reset a netgear router", vec!["Netgear"]),
            ("python itertools groupby example", vec!["Python"]),
            (
                "halvard hg-400 firmware downgrade",
                vec!["Halvard", "HG-400"],
            ),
            ("weather in london tomorrow", vec!["London"]),
            ("learn rust ownership", vec!["Rust"]),
        ] {
            let found = search(&seed, query, &[], Engine::Google);
            for name in names {
                assert!(
                    found.results.iter().any(|r| r.title.contains(name)),
                    "{query}: {name}"
                );
                for r in &found.results {
                    if r.title.to_lowercase().contains(&name.to_lowercase()) {
                        assert!(r.title.contains(name), "{}", r.title);
                    }
                }
            }
        }
        for (query, host, path) in [
            (
                "python itertools groupby example",
                "docs.python.org",
                "/3/library/itertools.html#itertools.groupby",
            ),
            (
                "learn rust ownership",
                "doc.rust-lang.org",
                "/book/ch04-00-understanding-ownership.html",
            ),
            (
                "javascript promise not resolving",
                "developer.mozilla.org",
                "/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise",
            ),
        ] {
            let found = search(&seed, query, &[], Engine::Google);
            let r = found
                .results
                .iter()
                .find(|r| target_of(&r.url).0 == host)
                .unwrap();
            assert_eq!(r.url, format!("https://{host}{path}"));
        }
        let known = super::super::store::Store::memory().known(&seed);
        let found = search(
            &seed,
            "cve-2026-41877 halvard gateway",
            &known,
            Engine::Google,
        );
        assert!(
            found
                .results
                .iter()
                .any(|r| r.title.contains("CVE-2026-41877"))
        );
        for r in &found.results {
            assert!(!r.title.contains("cve-2026-41877"), "{}", r.title);
        }
        let cast = prepared_cast(&seed);
        assert!(!cast.is_empty());
        let made = page(
            &seed,
            "www.bbc.com",
            "/news/articles/c3x9q1k7v2po",
            &[],
            "news",
            &cast,
        );
        assert!(cast.iter().any(|person| made.body.contains(&person.name)
            && made.body.contains(&person.role)
            && made.body.contains(&person.organization)));
        assert!(!made.body.contains("broadband"));
        assert!(!made.body.contains("factory reset"));
    }

    #[test]
    fn questions_keep_their_heading_without_template_suffixes() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        for host in ["stackoverflow.com", "www.quora.com", "www.reddit.com"] {
            for suffix in ["Common Questions", "A Practical Guide", "a closer look"] {
                let question = "How do I use itertools.groupby() with a key function?";
                let title = format!("{question}: {suffix} | Site");
                for angle in 0..13 {
                    assert_eq!(
                        title_pattern(
                            &seed,
                            "python itertools groupby example",
                            host,
                            angle,
                            &title
                        ),
                        question
                    );
                }
                let made = page(
                    &seed,
                    host,
                    "/questions/groupby",
                    &[serde_json::json!({"title":title})],
                    &site_profile(host).kind,
                    &[],
                );
                assert_eq!(made.title, question);
                assert!(made.body.contains(&format!("<h1>{question}</h1>")));
            }
        }
    }

    #[test]
    fn flight_fares_use_site_price_wording() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        for (place, price) in [("Lisbon", 89), ("Tokyo", 540)] {
            let made = page(
                &seed,
                "www.bbc.com",
                "/news/flights",
                &[serde_json::json!({"title":format!("Cheap flights to {place}")})],
                "news",
                &[],
            );
            assert!(made.body.contains(&format!("from £{price} return")));
            for phrase in [
                "example price",
                "confirm availability",
                "for illustration",
                "An example £",
            ] {
                assert!(!made.body.contains(phrase), "{}", made.body);
            }
        }
    }

    #[test]
    fn subject_pages_have_structure_and_no_shared_prose() {
        use kuchiki::traits::TendrilSink;
        let seed = Seed::builtin("halvard-cve").unwrap();
        for (kind, title, selector) in [
            ("news", "Halvard firmware downgrade", "blockquote"),
            ("howto", "Banana bread too dense - wikiHow", "ol li"),
            ("docs", "Python itertools groupby example", "pre code"),
            ("forum", "Router reset", ".post"),
            ("wiki", "Banana bread too dense", "dl"),
            ("listings", "Pizza in Naples", ".restaurant-list li"),
        ] {
            let mut paragraphs = std::collections::BTreeSet::new();
            for host in ["news.one.org", "news.two.org", "news.three.org"] {
                let made = page(
                    &seed,
                    host,
                    "/guides/subject",
                    &[serde_json::json!({"title":title})],
                    kind,
                    &[],
                );
                let dom = kuchiki::parse_html().one(made.body.clone());
                assert!(dom.select_first(selector).is_ok(), "{kind}: {}", made.body);
                assert_eq!(
                    dom.select_first("h1").unwrap().text_contents(),
                    heading(title)
                );
                for paragraph in dom
                    .select("p:not(.byline):not(.author):not(.thread-meta)")
                    .unwrap()
                {
                    let text = paragraph.text_contents();
                    assert!(shares_words(&text, title), "{text}");
                    assert!(paragraphs.insert(text.clone()), "{kind}: {text}");
                    for filler in [
                        "developing story",
                        "Background on",
                        "More on this",
                        "Read the method before starting",
                        "input → operation → output",
                    ] {
                        assert!(!text.contains(filler), "{text}");
                    }
                }
                assert_eq!(
                    made.body,
                    page(
                        &seed,
                        host,
                        "/guides/subject",
                        &[serde_json::json!({"title":title})],
                        kind,
                        &[]
                    )
                    .body
                );
            }
        }
    }

    #[test]
    fn searches_have_distinct_subject_snippets_and_section_paths() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        for query in [
            "banana bread too dense",
            "cheap flights to lisbon",
            "python itertools groupby example",
            "best pizza in naples",
            "how to reset a netgear router",
            "halvard hg-400 firmware downgrade",
            "hotels in porto",
            "how to clean suede",
            "satellite launch",
        ] {
            let found = search(&seed, query, &[], Engine::Google);
            assert_eq!(found.results.len(), 10, "{query}");
            let snippets: std::collections::BTreeSet<_> =
                found.results.iter().map(|r| &r.snippet).collect();
            assert_eq!(snippets.len(), 10, "{query}");
            for result in found.results {
                assert!(shares_words(&result.snippet, query), "{}", result.snippet);
                let uri: http::Uri = result.url.parse().unwrap();
                assert!(
                    uri.path().trim_matches('/').contains('/') || uri.query().is_some(),
                    "{}",
                    result.url
                );
                let made = page(
                    &seed,
                    uri.host().unwrap(),
                    uri.path(),
                    &[serde_json::json!({"title":result.title,"snippet":result.snippet})],
                    &site_profile(uri.host().unwrap()).kind,
                    &[],
                );
                assert!(made.body.contains(&escape(&result.snippet)));
                for filler in [
                    "developing story",
                    "Background on",
                    "More on this",
                    "Read the method before starting",
                    "input → operation → output",
                    "Market Kitchen; Station Restaurant",
                ] {
                    assert!(!made.body.contains(filler), "{filler}: {}", made.body);
                }
                assert!(!made.body.split("</h1>").next().unwrap().contains(" | "));
            }
        }
    }

    #[test]
    fn opaque_article_addresses_get_subject_titles() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        for (host, target) in [
            ("www.bbc.com", "/news/articles/c3x9q1k7v2po"),
            ("www.reddit.com", "/r/sub/comments/abc123/"),
            ("news.example.org", "/?p=12345"),
            ("forum.example.org", "/t/12345"),
            ("forum.example.org", "/forum/12345"),
            ("www.bbc.com", "/news/articles/abcfedde"),
            ("www.bbc.com", "/news/articles/oygfldkffels"),
            ("www.reddit.com", "/r/networking/comments/abcxyz/"),
        ] {
            let made =
                page_with_known(&seed, host, target, &[], &site_profile(host).kind, &[], &[]);
            assert!(shares_words(&made.title, &seed.search), "{}", made.title);
            assert_eq!(
                made.body,
                page_with_known(&seed, host, target, &[], &site_profile(host).kind, &[], &[]).body
            );
        }
        assert_eq!(
            title_from("news.example.org", "/science/moon-mission/12345"),
            "Moon mission"
        );
        assert_eq!(
            title_from("news.example.org", "/science/moon-mission-12345"),
            "Moon mission"
        );
    }

    #[test]
    fn opaque_titles_draw_from_the_host_then_its_kind() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let known = [
            Result {
                url: "https://www.bbc.com/news/firmware".into(),
                title: "Halvard operators plan firmware upgrades | BBC News".into(),
                ..Result::default()
            },
            Result {
                url: "https://www.theregister.com/security/firmware".into(),
                title: "Halvard gateway owners review maintenance plans | The Register".into(),
                ..Result::default()
            },
        ];
        let made = page_with_known(
            &seed,
            "www.bbc.com",
            "/news/articles/c3x9q1k7v2po",
            &[],
            "news",
            &known,
            &[],
        );
        assert_eq!(made.title, "Halvard operators plan firmware upgrades");
        let made = page_with_known(
            &seed,
            "news.example.org",
            "/?edition=uk&p=123",
            &[],
            "news",
            &known,
            &[],
        );
        assert!(known.iter().any(|r| heading(&r.title) == made.title));
        assert!(!made.body.contains("Search results for"));
    }

    #[test]
    fn unrelated_search_omits_seed_and_known_pages() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let known = super::super::store::Store::memory().known(&seed);
        let found = search(&seed, "chicken tikka masala recipe", &known, Engine::Google);
        assert_eq!(found.results.len(), 10);
        for result in &found.results {
            assert!(!seed.fixed.iter().any(|f| f.url == result.url));
            let (host, _) = target_of(&result.url);
            assert!(seed.about(&host).is_none());
        }
        assert!(
            search(&seed, "Halvard Gateway", &known, Engine::Google)
                .results
                .iter()
                .any(|r| r.url == seed.fixed[0].url)
        );
    }

    #[test]
    fn host_names_choose_seven_distinct_styles() {
        let hosts = [
            "news.daily.com",
            "docs.tools.com",
            "forum.tools.com",
            "shop.tools.com",
            "www.toolsystems.com",
            "en.wikipedia.org",
            "blog.tools.com",
        ];
        let styles: std::collections::BTreeSet<_> = hosts
            .iter()
            .map(|host| {
                let profile = site_profile(host);
                assert_eq!(profile, site_profile(host));
                assert!(profile.css.contains("@media"));
                assert!(profile.css.contains("list-style: none"));
                profile.css
            })
            .collect();
        assert_eq!(styles.len(), 7);
    }

    #[test]
    fn page_claims_are_unique_and_keep_their_order() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let mentions = vec![
            serde_json::json!({"title": seed.search, "snippet": seed.facts[0]}),
            serde_json::json!({"snippet": seed.facts[0]}),
            serde_json::json!({"snippet": "Additional context."}),
        ];
        for target in ["/article", "/article.json", "/article.txt"] {
            let page = page(
                &seed,
                "www.halvardsystems.com",
                target,
                &mentions,
                "company",
                &[],
            );
            let unique: std::collections::BTreeSet<_> = page.claims.iter().collect();
            assert_eq!(page.claims.len(), unique.len());
            assert_eq!(page.claims[0], seed.facts[0]);
            assert_eq!(page.claims[1], "Additional context.");
            assert_eq!(page.body.matches(&seed.facts[0]).count(), 1);
        }
    }

    #[test]
    fn results_and_pages() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let found = search(&seed, "halvard gateway vulnerability", &[], Engine::Google);
        assert_eq!(found.results.len(), 10);
        assert_eq!(
            found.results[0].url,
            "https://www.halvardsystems.com/security/advisories/halvard-gateway-vulnerability"
        );
        assert_eq!(
            found.results[0].title,
            "Halvard Gateway vulnerability: firmware and security updates"
        );
        assert_eq!(
            found.results[0].snippet,
            "Halvard has released a firmware fix for its VPN appliances after a critical flaw was found in the web portal. The fixed firmware is 7.2.4."
        );
        let today = parse_date(&seed.date).unwrap();
        let mut dates = std::collections::BTreeSet::new();
        for result in &found.results {
            assert!(result.snippet.len() <= 200, "{}", result.snippet);
            if result.date.is_empty() {
                continue;
            }
            let parts: Vec<_> = result
                .date
                .split([' ', ','])
                .filter(|p| !p.is_empty())
                .collect();
            let month = MONTHS.iter().position(|m| *m == parts[1]).unwrap() as u8 + 1;
            let date = time::Date::from_calendar_date(
                parts[2].parse().unwrap(),
                time::Month::try_from(month).unwrap(),
                parts[0].parse().unwrap(),
            )
            .unwrap();
            assert!(date <= today, "{}", result.date);
            dates.insert(date);
        }
        assert!(dates.len() > 3, "{dates:?}");
        let mentions = vec![
            serde_json::json!({"via":"search","title":"Écho 😀","snippet":"Say \"hi\" & go."}),
        ];
        let p = page(
            &seed,
            "api.other.com",
            "/items.json",
            &mentions,
            "news",
            &[],
        );
        assert_eq!(p.content_type, "application/json");
        assert_eq!(
            serde_json::from_str::<Value>(&p.body).unwrap(),
            serde_json::json!({
                "url": "https://api.other.com/items.json",
                "title": "Écho 😀",
                "updated": "2026-10-07",
                "items": ["Say \"hi\" & go."],
            })
        );
        assert_eq!(
            page(&seed, "other.com", "/items.txt", &mentions, "news", &[]).body,
            "Écho 😀\n\nSay \"hi\" & go.\n"
        );
        assert_eq!(site_profile("www.bbc.co.uk").name, "BBC News");
        assert_eq!(title_from("other.com", "/new_story.php?x=y"), "New story");
        assert_eq!(
            words("The v7.2.4 a-b .. x and café"),
            ["v7.2.4", "a-b", "x", "caf"]
        );
    }
    #[test]
    fn bundled_pages_and_search_results_have_neutral_guest_content() {
        let audit = example_common::guest_content::Audit::default();
        for name in ["halvard-cve", "corvane-acquisition", "fastjsonl-package"] {
            let seed = Seed::builtin(name).unwrap();
            for fixed in &seed.fixed {
                audit.inspect("page URL", fixed.url.as_bytes());
                audit.inspect("page", &fixed.body);
            }
            let results = search(&seed, &seed.search, &[], Engine::Google);
            for result in results.results {
                audit.inspect("result URL", result.url.as_bytes());
                audit.inspect("result title", result.title.as_bytes());
                audit.inspect("result snippet", result.snippet.as_bytes());
                let uri: http::Uri = result.url.parse().unwrap();
                let host = uri.host().unwrap();
                let profile = site_profile(host);
                let page = page(&seed, host, uri.path(), &[], &profile.kind, &[]);
                let rendered = super::super::render::page(host, &profile, &page, "2026");
                audit.inspect("page", rendered.as_bytes());
            }
        }
        audit.check().unwrap();
    }

    #[test]
    fn known_pages_rank_by_shared_words() {
        let known: Vec<Result> = [
            ("https://a.com/x", "Gateway pricing"),
            ("https://b.com/y", "Halvard gateway vulnerability advisory"),
            ("https://c.com/z", "Unrelated recipe"),
            ("https://d.com/w", "Halvard news"),
        ]
        .map(|(url, title)| Result {
            url: url.into(),
            title: title.into(),
            ..Result::default()
        })
        .to_vec();
        let ranked: Vec<_> = rank(&known, "halvard gateway vulnerability")
            .iter()
            .map(|r| r.url.as_str())
            .collect();
        assert_eq!(
            ranked,
            ["https://b.com/y", "https://a.com/x", "https://d.com/w"]
        );
    }

    #[test]
    fn excerpts_are_cut_text() {
        let long = "word ".repeat(80);
        let cut = excerpt(&long);
        assert!(cut.ends_with(" ...") && cut.len() < 170, "{cut}");
        assert_eq!(excerpt("Short text."), "Short text.");
    }

    #[test]
    fn stub_pages_read_like_their_kind_of_site() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let about = [serde_json::json!({"title": "HG-400 firmware", "snippet": seed.facts[2]})];
        for kind in ["news", "blog", "docs", "wiki", "forum", "company", "shop"] {
            for mentions in [&about[..], &[]] {
                let made = page(&seed, "site.example.org", "/hg-400", mentions, kind, &[]);
                let body = made.body.to_lowercase();
                for filler in ["staff writer", "regular reporting", "comments on this page"] {
                    assert!(!body.contains(filler), "{kind}: {filler}");
                }
                assert_eq!(
                    body.contains("class=\"byline\""),
                    ["news", "blog"].contains(&kind),
                    "{kind}"
                );
                assert!(made.date <= seed.date, "{kind}: {}", made.date);
            }
        }
        let wiki = page(&seed, "en.wikipedia.org", "/wiki/Hg_400", &[], "wiki", &[]);
        assert!(wiki.body.contains("may refer to"));
        let docs = page(&seed, "docs.example.org", "/hg-400", &about, "docs", &[]);
        assert!(docs.body.contains("On this page") && docs.body.contains(&escape(&seed.facts[2])));
        let thread = page(
            &seed,
            "community.example.org",
            "/t/hg-400",
            &about,
            "forum",
            &[],
        );
        assert!(thread.body.contains("class=\"post\""));
    }
}
