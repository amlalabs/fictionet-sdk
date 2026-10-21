//! The offline generator: deterministic search results, site profiles and
//! page content, with no model.

use super::{Seed, prompts::expected_type, seed::parse_date, text::*};
use fictionet_extras::search::{Result, Search};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::OnceLock;

const STOP: &[&str] = &[
    "a", "an", "and", "are", "at", "be", "by", "can", "do", "does", "for", "from", "how", "i",
    "in", "is", "it", "my", "of", "on", "or", "should", "the", "to", "what", "when", "which",
    "who", "why", "with", "you", "our", "we", "this", "that", "was", "will", "about", "online",
    "news", "com", "www", "https", "http", "best", "example", "details", "safe", "owners",
    "version", "fixed", "fix", "latest",
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
/// A date as result lists and bylines show it: `Oct 3, 2026`.
pub fn short_date(d: time::Date) -> String {
    format!(
        "{} {}, {}",
        MONTHS[d.month() as usize - 1],
        d.day(),
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
            let have = words(&format!("{} {} {}", k.title, k.url, k.snippet));
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
    let (host, _) = target_of(&result.url);
    let named = asked.iter().any(|w| {
        w.len() > 3
            && host
                .split('.')
                .any(|label| label.trim_start_matches("the") == w)
    });
    score > 0 && (named || (score >= asked.len().min(2) && score * 2 >= asked.len()))
}

/// Text cut from a page as a snippet shows it: at most about 160
/// characters, ending at a word with "...". Some start part way through.
pub fn excerpt(text: &str, key: &str) -> String {
    let text = normalize_space(text);
    let words: Vec<&str> = text.split(' ').collect();
    let from = if words.len() > 18 && hash(key).is_multiple_of(3) {
        words.len() / 4
    } else {
        0
    };
    let mut out = String::new();
    for word in &words[from..] {
        if out.len() + word.len() > 160 {
            out.push_str(" ...");
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if from > 0 { format!("... {out}") } else { out }
}

/// Proposes candidates from known pages, scenario sites and search directories.
/// The request handler reserves their metadata and bounds unsupported searches.
pub fn search(seed: &Seed, query: &str, known: &[Result]) -> Search {
    let phrase = normalize_space(query);
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
    for k in rank(known, query)
        .into_iter()
        .filter(|k| relevant(k, query))
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
        add(
            k.url.clone(),
            k.title.clone(),
            excerpt(snippet, &k.url),
            date,
        );
    }
    for site in &seed.sites {
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
            let url = format!("https://{}/{slug}", site.host);
            let snippet = seed
                .facts
                .iter()
                .find(|f| shares_words(f, query))
                .unwrap_or(&site.about);
            add(
                url.clone(),
                format!(
                    "{} | {}",
                    upper_first(&phrase),
                    site.host.strip_prefix("www.").unwrap_or(&site.host)
                ),
                excerpt(snippet, &url),
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
    let topic = upper_first(&subject);
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
    let candidates = if baking {
        [
            ("www.kingarthurbaking.com", "King Arthur Baking"),
            ("www.bbcgoodfood.com", "Good Food"),
            ("www.seriouseats.com", "Serious Eats"),
            ("www.allrecipes.com", "Allrecipes"),
            ("www.simplyrecipes.com", "Simply Recipes"),
            ("www.epicurious.com", "Epicurious"),
            ("www.foodnetwork.com", "Food Network"),
            ("www.bonappetit.com", "Bon Appétit"),
            ("www.delish.com", "Delish"),
            ("www.thekitchn.com", "The Kitchn"),
        ].into_iter().map(|(host, name)| (host, format!("{topic}: kitchen techniques | {name}"),
            "Explore ingredients, preparation methods and cooking techniques. Compare measurements, timing and texture, and read the method before starting.")).collect()
    } else if flights {
        vec![
            (
                "www.britishairways.com",
                format!("{topic} | British Airways"),
                "Choose departure and return dates, airports and passenger numbers. Review baggage allowances and fare conditions before selecting a flight.",
            ),
            (
                "www.skyscanner.net",
                format!("Compare {subject} | Skyscanner"),
                "Compare departure times, connections and total journey duration. Prices and seat availability depend on the dates and must be confirmed with the airline.",
            ),
            (
                "www.expedia.co.uk",
                format!("{topic}: itinerary search | Expedia"),
                "Select your departure airport and travel dates. Compare itineraries, baggage charges and cancellation conditions before booking.",
            ),
            (
                "www.kayak.co.uk",
                format!("{topic}: travel information | KAYAK"),
                "Review departure terminals, connecting flights and baggage rules. Check passport and transit requirements for your itinerary before travelling.",
            ),
            (
                "www.momondo.co.uk",
                format!("{topic}: itinerary planning | momondo"),
                "Choose your departure date and cabin, then review the route and connection times. Confirm the full fare and included baggage with the airline.",
            ),
        ]
    } else if lodging {
        vec![
            (
                "www.booking.com",
                format!("The best {subject} | Booking.com"),
                "Compare rooms, neighbourhoods and cancellation conditions. Check the location and the full price for your travel dates before reserving.",
            ),
            (
                "www.tripadvisor.co.uk",
                format!("{topic}: traveller reviews - Tripadvisor"),
                "Read recent guest comments about comfort, cleanliness and service. Use the map to compare locations near the places you plan to visit.",
            ),
            (
                "www.hotels.com",
                format!("{topic} - Places to stay | Hotels.com"),
                "Find rooms by area and compare the included amenities. Check whether breakfast, parking and local charges are included.",
            ),
            (
                "www.expedia.co.uk",
                format!("{topic}: find your next stay | Expedia"),
                "Browse city-centre stays and quieter neighbourhoods. Review room types, accessibility information and cancellation terms.",
            ),
            (
                "www.kayak.co.uk",
                format!("{topic} - Compare places to stay | KAYAK"),
                "Compare accommodation options and check what is included in each room rate. Availability depends on your travel dates.",
            ),
            (
                "www.trivago.co.uk",
                format!("{topic}: compare accommodation | trivago"),
                "Compare room offers, locations and facilities. Read the booking conditions carefully before choosing where to stay.",
            ),
            (
                "www.reddit.com",
                format!("{topic}: accommodation recommendations : r/travel"),
                "Looking for a comfortable base with easy access to the centre. Locals discuss which areas are convenient without being too noisy at night.",
            ),
            (
                "www.theguardian.com",
                format!("Where to stay: {subject} | Travel | The Guardian"),
                "A guide to choosing a base, from small guesthouses to larger city-centre properties. Consider transport, noise and the places you want to explore.",
            ),
            (
                "www.independent.co.uk",
                format!("{topic}: a city break guide | The Independent"),
                "Plan a short stay around walkable neighbourhoods, local transport and a room that suits your budget.",
            ),
            (
                "www.lonelyplanet.com",
                format!("{topic}: neighbourhood and accommodation guide - Lonely Planet"),
                "Get to know the neighbourhoods before choosing a room. Staying close to transport can make day trips and late arrivals simpler.",
            ),
        ]
    } else if place {
        vec![
            (
                "www.tripadvisor.co.uk",
                format!("The 10 best places for {subject} - Tripadvisor"),
                "Compare traveller ratings, opening hours and neighbourhoods. Read recent reviews before choosing a table.",
            ),
            (
                "www.opentable.co.uk",
                format!("{topic}: restaurants you can book | OpenTable"),
                "Find a table for tonight. Browse menus, dining options and booking availability in the city centre and nearby neighbourhoods.",
            ),
            (
                "www.timeout.com",
                format!("{topic}: a local dining guide | Time Out"),
                "Compare menus, opening hours and dining options. The guide covers quick lunches and relaxed dinners at independent kitchens.",
            ),
            (
                "www.yelp.co.uk",
                format!("Top rated {subject} - Yelp"),
                "Browse local recommendations with photos, price ranges and opening times. Filter by neighbourhood and takeaway options.",
            ),
            (
                "www.reddit.com",
                format!("{topic}: dining recommendations : r/travel"),
                "Diners discuss menus, service and local restaurants. Read recent replies and check opening hours before planning a visit.",
            ),
            (
                "www.bbc.com",
                format!("{topic}: independent kitchens - BBC Food"),
                "Explore the ingredients, menus and people behind independent restaurants. Owners discuss their kitchens and approach to serving local diners.",
            ),
            (
                "www.theguardian.com",
                format!("A local’s guide to {subject} | Food | The Guardian"),
                "From busy market counters to quiet neighbourhood dining rooms, these are the places locals return to for a meal with friends.",
            ),
            (
                "www.deliveroo.co.uk",
                format!("{topic} delivered to your door | Deliveroo"),
                "Explore nearby kitchens, delivery areas and collection options. Check the menu for vegetarian choices and current opening hours.",
            ),
            (
                "www.designmynight.com",
                format!("Our guide to {subject} | DesignMyNight"),
                "Planning a casual evening out? Find relaxed dining rooms, outdoor tables and places that welcome groups.",
            ),
            (
                "www.independent.co.uk",
                format!("{topic}: a food lover’s guide | The Independent"),
                "Explore neighbourhood restaurants, compare menus and check recent recommendations before choosing where to eat.",
            ),
        ]
    } else if code {
        let docs = if terms.iter().any(|w| w == "rust") {
            "doc.rust-lang.org"
        } else if terms.iter().any(|w| w == "javascript") {
            "developer.mozilla.org"
        } else {
            "docs.python.org"
        };
        vec![
            (
                docs,
                format!("{topic} — Language reference"),
                "The reference describes the API, accepted arguments and return values. Check the examples and version notes before adapting the code.",
            ),
            (
                "stackoverflow.com",
                format!("{topic}: questions and answers - Stack Overflow"),
                "A short example makes the behaviour easier to see. Include the input, the output and the relevant part of the code when asking for help.",
            ),
            (
                "github.com",
                format!("Code notes / {subject} · GitHub"),
                "Usage notes, small examples and a discussion of common edge cases. Read the package documentation for supported versions.",
            ),
            (
                "www.reddit.com",
                format!("Help understanding {subject} : r/learnprogramming"),
                "I am working through a small example and trying to understand the behaviour. The replies compare approaches and explain the tradeoffs.",
            ),
            (
                "www.geeksforgeeks.org",
                format!("{topic} with examples - GeeksforGeeks"),
                "Start with a small input and inspect the result at each step. The examples cover ordinary use and common boundary cases.",
            ),
            (
                "www.programiz.com",
                format!("{topic}: practical examples | Programiz"),
                "A step-by-step explanation of the syntax and how the values flow through the program.",
            ),
            (
                "www.digitalocean.com",
                format!("{topic}: a practical tutorial | DigitalOcean"),
                "Prepare a small project, check the runtime version and work through the example one step at a time.",
            ),
            (
                "www.freecodecamp.org",
                format!("Understanding {subject}: a practical guide"),
                "An introduction to the main ideas, with small examples and notes on common errors.",
            ),
            (
                "realpython.com",
                format!("{topic}: related programming tutorials | Real Python"),
                "Python tutorials demonstrate small programs and debugging techniques. Check language differences before adapting an example to another runtime.",
            ),
            (
                "www.codecademy.com",
                format!("{topic}: tutorials and examples"),
                "A walkthrough of the syntax, the edge cases to consider and useful references for further reading.",
            ),
        ]
    } else if howto && network {
        [
            ("www.wikihow.com", "wikiHow"),
            ("www.tp-link.com", "TP-Link Support"),
            ("www.netgear.com", "NETGEAR Support"),
            ("www.reddit.com", "r/HomeNetworking"),
            ("superuser.com", "Super User"),
            ("www.howtogeek.com", "How-To Geek"),
            ("www.lifewire.com", "Lifewire"),
            ("www.asus.com", "ASUS Support"),
            ("www.techradar.com", "TechRadar"),
            ("www.which.co.uk", "Which?"),
        ].into_iter().map(|(host, name)| (host, format!("{topic}: home networking advice | {name}"),
            "Check the device model, connection status and manufacturer’s documentation. Record existing settings before making changes, and assess one change at a time.")).collect()
    } else if howto {
        vec![
            (
                "www.wikihow.com",
                format!("{topic}: a step-by-step guide - wikiHow"),
                "Gather what you need and prepare a clear workspace. Work through each step in order and check the care instructions before you begin.",
            ),
            (
                "www.ifixit.com",
                format!("{topic} - Repair Guide - iFixit"),
                "Check the model and review the tools list before starting. Take care around connectors and stop if parts do not move freely.",
            ),
            (
                "www.howtogeek.com",
                format!("{topic}: what to know before you start"),
                "Preparation makes the job easier. Check the product instructions and keep track of any settings or small parts as you work.",
            ),
            (
                "www.reddit.com",
                format!("{topic}: looking for practical advice : r/HowTo"),
                "I am looking for a careful approach and advice on common mistakes. People who have done it share what helped and what they would avoid.",
            ),
            (
                "www.quora.com",
                format!("What is a good way to {subject}? - Quora"),
                "Start with the simplest approach recommended in the product instructions. Consider the materials, tools and time involved before choosing a method.",
            ),
            (
                "superuser.com",
                format!("{topic}: practical questions - Super User"),
                "Check the model and the relevant documentation first. A small, reversible step is easier to assess than changing several things at once.",
            ),
            (
                "www.lifewire.com",
                format!("{topic}: a practical guide - Lifewire"),
                "Prepare the equipment, read the instructions and work carefully. Check the result before putting everything back into regular use.",
            ),
            (
                "www.techradar.com",
                format!("{topic}: the steps to follow | TechRadar"),
                "Our guide explains how to prepare, what to look out for and when to consult the manufacturer’s instructions.",
            ),
            (
                "www.instructables.com",
                format!("{topic} : Steps - Instructables"),
                "Read through the whole process before beginning. Gather the tools and materials, then work through the stages one at a time.",
            ),
            (
                "www.which.co.uk",
                format!("{topic}: practical advice - Which?"),
                "Check the care information and avoid methods that could damage delicate components. Contact the manufacturer if the instructions are unclear.",
            ),
        ]
    } else {
        vec![
            (
                "www.theregister.com",
                format!("{topic}: a closer look • The Register"),
                "A look at the details behind the headlines and the questions that remain open.",
            ),
            (
                "www.bbc.com",
                format!("{topic}: the key questions explained - BBC News"),
                "Background, recent developments and the questions readers are asking. Follow the links for further context.",
            ),
            (
                "www.reddit.com",
                format!("What should people know about {subject}? : r/AskReddit"),
                "Readers share their experiences and discuss which sources helped them understand the subject.",
            ),
            (
                "ask.metafilter.com",
                format!("Understanding {subject} - Ask MetaFilter"),
                "Members discuss practical experiences and share links for further reading. Read the replies for different approaches to the question.",
            ),
            (
                "www.theguardian.com",
                format!("{topic} | News and features | The Guardian"),
                "Reporting, analysis and background on recent developments and the people involved.",
            ),
            (
                "www.independent.co.uk",
                format!("{topic}: news and advice | The Independent"),
                "The latest coverage alongside practical advice and background information.",
            ),
            (
                "www.quora.com",
                format!("What is useful to know about {subject}? - Quora"),
                "Answers compare approaches and explain the background for readers getting started.",
            ),
            (
                "medium.com",
                format!("A closer look at {subject} | Medium"),
                "Notes on the main ideas, common questions and lessons from practical experience.",
            ),
            (
                "www.wikihow.com",
                format!("Getting started with {subject} - wikiHow"),
                "Work through the basics, gather the information you need and choose the next step.",
            ),
            (
                "github.com",
                format!("Resources for {subject} · GitHub"),
                "A collection of notes, useful links and background reading organised by topic.",
            ),
        ]
    };
    for (host, title, snippet) in candidates {
        let slug = terms.join("-");
        let path = match host {
            "www.reddit.com" => format!(
                "r/{}/comments/{}/{slug}/",
                title
                    .rsplit_once("r/")
                    .map(|(_, name)| name)
                    .unwrap_or("AskReddit"),
                base36(hash(query) % 2_176_782_336)
            ),
            "docs.python.org" => format!("3/library/{slug}.html"),
            "doc.rust-lang.org" => format!("book/{slug}.html"),
            "stackoverflow.com" => {
                format!("questions/{}/{slug}", 10_000_000 + hash(query) % 90_000_000)
            }
            "github.com" => format!("language-notes/{slug}"),
            "ask.metafilter.com" => format!("{}/{slug}", 100_000 + hash(query) % 900_000),
            "www.tripadvisor.co.uk" => format!(
                "{}-{slug}.html",
                if lodging { "Hotels" } else { "Restaurants" }
            ),
            "www.wikihow.com" => subject
                .split_whitespace()
                .map(capitalize)
                .collect::<Vec<_>>()
                .join("-"),
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
            "www.bbc.com" => format!("news/articles/{}", base36(hash(query))),
            "www.independent.co.uk" => format!(
                "life-style/{slug}-b{}.html",
                1_000_000 + hash(query) % 9_000_000
            ),
            "www.booking.com" => format!("searchresults.html?ss={}", quote_plus(&subject)),
            "www.opentable.co.uk" => format!("s?term={}", quote_plus(&subject)),
            "www.yelp.co.uk" => format!("search?find_desc={}", quote_plus(&subject)),
            "www.techradar.com" | "www.howtogeek.com" | "www.lifewire.com" => {
                format!("how-to/{slug}")
            }
            "www.freecodecamp.org" => format!("news/{slug}/"),
            "www.digitalocean.com" => format!("community/tutorials/{slug}"),
            _ => slug.clone(),
        };
        let url = format!("https://{host}/{path}");
        let date = if [
            "www.bbc.com",
            "www.theguardian.com",
            "www.independent.co.uk",
            "www.theregister.com",
            "medium.com",
        ]
        .contains(&host)
        {
            short_date(date_for(seed, &url, 45))
        } else {
            String::new()
        };
        let snippet = if place && !lodging && site_profile(host).kind == "listings" {
            format!(
                "{snippet} Places to consider: Market Kitchen; Station Restaurant; The Dining Room; North Street Kitchen; Riverside Kitchen; The Garden Room; Central Kitchen; Parkside Restaurant; The Courtyard; Corner Kitchen. Compare opening hours and menus before choosing a table."
            )
        } else {
            snippet.into()
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
    let mut results = if query.is_empty() {
        known.iter().take(12).cloned().collect::<Vec<_>>()
    } else {
        rank(&known, query)
            .into_iter()
            .filter(|r| relevant(r, query))
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
    };
    if results.is_empty() && !query.is_empty() {
        let topic = upper_first(&words(query).join(" "));
        for (i, suffix) in [
            "A practical walkthrough",
            "Getting started",
            "Common questions",
            "Step by step",
        ]
        .into_iter()
        .enumerate()
        {
            results.push(Result {
                url: format!("https://www.youtube.com/watch?v={:x}", hash(&format!("{query}{i}"))),
                title: format!("{topic}: {suffix}"),
                snippet: "A walkthrough of the basics, with preparation steps and answers to common questions.".into(),
                date: String::new(),
            });
        }
    }
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
        "www.youtube.com" => "YouTube",
        "ask.metafilter.com" => "Ask MetaFilter",
        "www.kingarthurbaking.com" => "King Arthur Baking",
        "www.bbcgoodfood.com" => "Good Food",
        "www.seriouseats.com" => "Serious Eats",
        "www.britishairways.com" => "British Airways",
        "www.skyscanner.net" => "Skyscanner",
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
        "www.tp-link.com" => "tp-link",
        "www.netgear.com" => "NETGEAR",
        "www.asus.com" => "ASUS",
        "www.techradar.com" => "TechRadar",
        "www.howtogeek.com" => "How-To Geek",
        "www.lifewire.com" => "Lifewire",
        "www.which.co.uk" => "Which?",
        _ => &name,
    }
    .to_owned();
    let kind = if host == "www.ebay.com" {
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
            | "www.wikihow.com"
    ) {
        "howto"
    } else if matches!(
        host,
        "www.britishairways.com" | "www.skyscanner.net" | "www.kayak.co.uk" | "www.momondo.co.uk"
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
            | "www.tp-link.com"
            | "www.netgear.com"
            | "www.asus.com"
    ) {
        "docs"
    } else if host.contains("wiki") {
        "wiki"
    } else if host.starts_with("docs.")
        || host.starts_with("doc.")
        || host == "developer.mozilla.org"
        || host.contains("github")
    {
        "docs"
    } else if host == "ask.metafilter.com"
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
    } else if host.starts_with("news.") || host.contains("bbc") || host.contains("register") {
        "news"
    } else {
        ["news", "company", "blog", "shop", "company", "news"][hash(host) % 6]
    };
    let links = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let (tagline, nav) = match kind {
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
        "forum" => (
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
        "www.britishairways.com" | "www.skyscanner.net" | "www.kayak.co.uk" | "www.momondo.co.uk"
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
/// A small family of layouts for the offline sites.
fn stylesheet(kind: &str) -> String {
    let base = r#"
* { box-sizing: border-box; }
body { margin: 0; color: #263345; background: #f5f6f8; font: 16px/1.65 Arial, sans-serif; }
a { color: var(--accent); text-decoration: none; } a:hover { text-decoration: underline; }
header { background: #fff; border-top: 5px solid var(--accent); border-bottom: 1px solid #d9dee5; padding: 24px max(24px, calc((100% - 1160px)/2)); }
.brand a, .logo, .home { font-size: 30px; font-weight: 800; letter-spacing: -1px; }
.tagline { display: block; font-size: 13px; color: #647085; }
.cookie-banner { position: fixed; bottom: 0; left: 0; right: 0; z-index: 100; display: flex; align-items: center; gap: 16px; padding: 12px 24px; background: #fff; border-top: 1px solid #bdc6d1; box-shadow: 0 -2px 12px #0002; }
body { padding-bottom: 100px; }
nav ul, .footer-links, .topbar ul { list-style: none; padding: 0; display: flex; gap: 24px; flex-wrap: wrap; }
nav a { color: inherit; font-size: 14px; font-weight: 600; }
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
            ":root {--accent:#3156ad} header {background:#17263f;color:#fff} .home, .brand a {color:#fff} .tagline {color:#becbe2} main {border:1px solid #d9dee5;border-radius:6px} h1 {font-size:34px}"
        }
        "forum" => {
            ":root {--accent:#a74320} body {background:#f2ede8} header {border-top:0} main {border:1px solid #d8cec5;border-radius:8px} main p {padding:14px;background:#faf8f5;border-radius:5px} h1 {font-size:30px}"
        }
        "shop" => {
            ":root {--accent:#265f4a} header {text-align:center;background:#eff5ed} header nav ul {justify-content:center} h1 {font-weight:500} main {border-radius:12px} .promo-banner {text-align:center;background:#dfeadd}"
        }
        "company" => {
            ":root {--accent:#164d88} header {background:#102e4d;color:white} header a {color:white} .tagline {color:#b9cede} h1 {color:#153c63} main {border-top:4px solid var(--accent)} .topbar {text-align:right}"
        }
        "wiki" => {
            ":root {--accent:#365c99} body {background:white;font-family:Georgia,serif} header {border-top:0} h1 {font-weight:400;border-bottom:1px solid #aeb5be;padding-bottom:14px} nav, header, footer {font-family:Arial,sans-serif} main {padding-top:0}"
        }
        "blog" => {
            ":root {--accent:#805235} body {background:#f5f1e9} .masthead {background:#f5f1e9;border-top:0} .brand a {font-family:Georgia,serif;font-style:italic;font-size:38px} article {font-family:Georgia,serif;font-size:18px} main {background:transparent;padding-top:0} .rail {border-top:1px solid #cbbca9}"
        }
        _ => {
            ":root {--accent:#ab242b} .brand a {font-family:Georgia,serif;font-size:40px;color:#20242a} .masthead nav {border-top:1px solid #d9dee5;margin-top:20px} h1 {font-family:Georgia,serif} .layout {border-top:1px solid #d9dee5;padding-top:28px}"
        }
    };
    format!("{base}\n{theme}")
}
/// Derives a page title from its path or site name.
pub fn title_from(host: &str, target: &str) -> String {
    static EXT: OnceLock<Regex> = OnceLock::new();
    static SEP: OnceLock<Regex> = OnceLock::new();
    let path = target.split('?').next().unwrap().trim_end_matches('/');
    let last = path.rsplit('/').next().unwrap_or("");
    let last = EXT
        .get_or_init(|| Regex::new(r"\.(html?|php|aspx?)$").unwrap())
        .replace(last, "");
    let text = SEP
        .get_or_init(|| Regex::new(r"[-_+]+").unwrap())
        .split(&last)
        .collect::<Vec<_>>()
        .join(" ");
    let text = text.trim();
    if text.is_empty() {
        site_profile(host).name
    } else {
        upper_first(text)
    }
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
    let query = form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| ["q", "search", "search_query", "searchTerm"].contains(&k.as_ref()))
        .map(|(_, v)| v.into_owned());
    let search = query.is_some();
    let directory = directory(target) && mentions.iter().all(|m| m["via"] != "search");
    if !search && !directory {
        let mut made = page(seed, host, target, mentions, kind);
        if path.starts_with("/security/advisories/") {
            made.body.push_str("<h2>Recommended action</h2><p>Review the affected component and apply the corresponding maintenance update from the download centre. Contact support with the advisory identifier and your installed release if you need assistance.</p><p><a href=\"/security/advisories/\">All security advisories</a></p>");
        }
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

/// Makes page content from prior mentions, in the shape of
/// a page on a site of `kind` (as [`Profile::kind`] names it).
pub fn page(seed: &Seed, host: &str, target: &str, mentions: &[Value], kind: &str) -> Page {
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
        .unwrap_or_else(|| title_from(host, target));
    // A snippet is text cut from the page, so the page holds it whole: a
    // fact it came from, or the snippet without its ellipses.
    let mut claims: Vec<String> = Vec::new();
    for claim in snippets.iter().map(|s| {
        s.trim()
            .trim_start_matches("...")
            .trim_end_matches("...")
            .trim()
            .to_owned()
    }) {
        if claim.is_empty() || claims.iter().any(|c| c.contains(&claim)) {
            continue;
        }
        claims.retain(|c| !claim.contains(c.as_str()));
        claims.push(claim);
    }
    let date = date_for(seed, &url, 30);
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
    let paras = |items: &[String]| {
        items
            .iter()
            .map(|s| format!("<p>{}</p>", escape(s)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let slug = words(&title)
        .into_iter()
        .take(5)
        .collect::<Vec<_>>()
        .join("-");
    let slug = if slug.is_empty() { "update" } else { &slug };
    let subject = heading(&title);
    let t = escape(subject);
    let when = short_date(date);
    let (body, sidebar, ad): (String, &[(&str, &str)], &str) = match kind {
        "wiki" => {
            let body = if claims.is_empty() {
                format!(
                    "<h1>{t}</h1><p>{t} may refer to:</p><ul><li><a href=\"/w/index.php?search={}\">Browse matching articles</a></li></ul>",
                    quote_plus(&title)
                )
            } else {
                format!("<h1>{t}</h1>{}", paras(&claims))
            };
            (
                body,
                &[
                    ("Main page", "/wiki/Main_Page"),
                    ("Current events", "/wiki/Portal:Current_events"),
                    ("Random article", "/wiki/Special:Random"),
                ],
                "",
            )
        }
        "docs" | "package" if host == "github.com" || host == "doc.rust-lang.org" => {
            (format!("<h1>{t}</h1>{}", paras(&claims)), &[], "")
        }
        "docs" | "package" => {
            let lead = claims
                .first()
                .cloned()
                .unwrap_or_else(|| format!("Reference for {title}."));
            let rest = paras(claims.get(1..).unwrap_or_default());
            let body = format!(
                "<h1>{t}</h1>\n<p class=\"lead\">{}</p>\n\
                 <nav class=\"toc\"><b>On this page</b><ul><li><a href=\"#overview\">Overview</a></li>\
                 <li><a href=\"#requirements\">Requirements</a></li><li><a href=\"#related\">Related pages</a></li></ul></nav>\n\
                 <h2 id=\"overview\">Overview</h2>\n{rest}\n\
                 <h2 id=\"requirements\">Requirements</h2>\n<ul><li>A supported release. See the <a href=\"/docs/release-notes/\">release notes</a>.</li>\
                 <li>An administrator account.</li></ul>\n\
                 <h2 id=\"related\">Related pages</h2>\n<ul><li><a href=\"/docs/{slug}/troubleshooting\">Troubleshooting</a></li>\
                 <li><a href=\"/docs/release-notes/\">Release notes</a></li></ul>\n\
                 <p class=\"updated\">Last updated {when}. Was this page helpful? <a href=\"/feedback\">Send feedback</a></p>",
                escape(&lead)
            );
            (
                body,
                &[
                    ("Getting started", "/docs/getting-started/"),
                    ("Installation", "/docs/install/"),
                    ("Configuration", "/docs/configuration/"),
                    ("Release notes", "/docs/release-notes/"),
                ],
                "",
            )
        }
        "forum" | "qa" => {
            let asker = pick(&USERS, 0);
            let question = format!(
                "{}{} {}",
                subject,
                if subject.ends_with('?') { "" } else { "?" },
                claims.first().map_or("", String::as_str)
            );
            let mut posts = vec![format!(
                "<div class=\"post\"><p class=\"author\"><b>{asker}</b> · <time datetime=\"{date}\">{when}</time></p><p>{}</p></div>",
                escape(&question)
            )];
            let generic = format!(
                "For {subject}, start with the details in the question: {}. Which part differs in your situation?",
                claims.first().map_or(subject, String::as_str)
            );
            for (i, claim) in claims
                .iter()
                .skip(1)
                .chain(std::iter::once(&generic))
                .enumerate()
            {
                let reply = (date + time::Duration::days(i as i64 + 1)).min(day(seed, 0));
                posts.push(format!(
                    "<div class=\"post\"><p class=\"author\"><b>{}</b> · <time datetime=\"{reply}\">{}</time></p><p>{}</p></div>",
                    pick(&USERS, i + 1),
                    short_date(reply),
                    escape(claim)
                ));
            }
            let body = format!(
                "<h1>{t}</h1>\n<p class=\"thread-meta\">{} {} · {} views</p>\n{}",
                posts.len() - 1,
                if posts.len() == 2 { "reply" } else { "replies" },
                hash(&url) % 2000 + 40,
                posts.join("\n")
            );
            (
                body,
                &[
                    ("Latest threads", "/latest"),
                    ("Top this week", "/top?period=weekly"),
                    ("Categories", "/categories"),
                ],
                "",
            )
        }
        "listings" | "lodging" | "howto" => (format!("<h1>{t}</h1>{}", paras(&claims)), &[], ""),
        "company" | "government" | "shop" => {
            let lead = claims
                .first()
                .cloned()
                .unwrap_or_else(|| format!("{title}."));
            let body = format!(
                "<h1>{t}</h1>\n<p class=\"lead\">{}</p>\n{}\n\
                 <p><a class=\"btn\" href=\"/contact/\">Contact us</a> · <a href=\"/support/\">Get support</a></p>",
                escape(&lead),
                paras(claims.get(1..).unwrap_or_default())
            );
            (
                body,
                &[
                    ("Products", "/products/"),
                    ("Downloads", "/downloads/"),
                    ("Support", "/support/"),
                ],
                if kind == "shop" {
                    "Free delivery on orders over $50."
                } else {
                    ""
                },
            )
        }
        _ => {
            let author = pick(&AUTHORS, 0);
            let text = if claims.is_empty() {
                format!("<p>{t}.</p>\n<p>This is a developing story and will be updated.</p>")
            } else {
                paras(&claims)
            };
            let byline = if kind == "blog" {
                format!("Posted by {author} on <time datetime=\"{date}\">{when}</time>")
            } else {
                format!("By {author} · <time datetime=\"{date}\">{when}</time>")
            };
            let mut body = format!("<h1>{t}</h1>\n<p class=\"byline\">{byline}</p>\n{text}");
            if claims.is_empty() {
                body.push_str(&format!(
                    "<p><a href=\"/{slug}-what-we-know\">Background on {t}</a></p>"
                ));
            }
            (body, &[], "")
        }
    };
    page.body = body;
    if host == "www.ebay.com" {
        page.body.push_str(&format!("<h2>Item details</h2><dl><dt>Item</dt><dd>{t}</dd><dt>Condition</dt><dd>See the seller’s description</dd><dt>Included accessories</dt><dd>Contact the seller for details</dd></dl><h2>Description</h2><p>Review the description and included accessories before purchasing. Ask the seller about compatibility with your equipment.</p>"));
    } else if host == "www.linkedin.com" {
        page.body.push_str(&format!("<h2>About</h2><p>{t}</p><h3>Company information</h3><p>Visit the company’s website for its services, locations and contact information.</p>"));
    }
    let topic = words(&title);
    if kind == "howto" && host != "www.wikihow.com" {
        page.body.push_str("<h2>Ingredients and techniques</h2><p>Read the method before starting. Compare ingredient weights, preparation, resting and cooking times. Techniques such as kneading, feeding cultures or folding mixtures depend on the recipe; follow the instructions for the food you are making.</p><h2>Check the result</h2><p>Keep notes on measurements, timing and texture. Change one variable at a time when comparing methods.</p>");
    } else if topic
        .iter()
        .any(|w| ["flight", "flights", "airfare", "airline"].contains(&w.as_str()))
    {
        page.body.push_str("<h2>Plan your departure</h2><p>Choose dates and airports before comparing itineraries. Compare nearby departure airports and allow time for the transfer from the arrival airport to your destination.</p><h2>Before booking</h2><ul><li>Compare direct journeys with connections and check the total travel time.</li><li>Review cabin baggage, checked baggage and change conditions for the fare.</li><li>Confirm the current schedule, price and availability on the booking page for your dates.</li></ul>");
    } else if kind == "docs"
        && !matches!(host, "www.tp-link.com" | "www.netgear.com" | "www.asus.com")
    {
        page.body.push_str("<h2>Work through a small example</h2><p>Check the language version and read the reference for the syntax or API involved. Reduce the program to the smallest input that reproduces the behaviour. Trace the data through each operation:</p><pre><code>input → operation → output</code></pre><h2>Compare approaches</h2><p>Review boundary cases and the lifetime of values. Consult the language reference for ownership and borrowing rules where applicable.</p>");
    } else if kind == "howto" {
        page.body.push_str(&format!("<h2>Steps: {t}</h2><ol>"));
        for step in claims
            .iter()
            .flat_map(|claim| claim.split(". "))
            .filter(|step| !step.is_empty())
        {
            page.body.push_str(&format!("<li>{}</li>", escape(step)));
        }
        page.body.push_str("<li>Read the instructions and check which tools and materials are needed.</li><li>Prepare the workspace and protect nearby surfaces.</li><li>Work through the method one stage at a time.</li><li>Inspect the result before returning the item to regular use.</li></ol>");
    } else if kind == "listings" || subject.to_lowercase().starts_with("the 10 best") {
        let venues = claims
            .first()
            .and_then(|claim| claim.split_once(": "))
            .map(|(_, names)| names.split(". Compare").next().unwrap_or(names))
            .filter(|names| names.contains(';'));
        let names: Vec<_> = venues
            .map(|names| names.split(';').map(str::trim).collect())
            .unwrap_or_default();
        let details = [
            "Compare the menu and recent comments about food and service.",
            "Check the walking route and allow time for a table at busy periods.",
            "Ask about the daily specials and any dietary requirements.",
            "Check whether the kitchen offers smaller portions at lunchtime.",
            "Compare indoor seating and collection options before travelling.",
            "Compare menus and check when the kitchen serves food.",
            "Check vegetarian choices and ask about ingredients.",
            "Confirm the last food orders when planning an evening visit.",
            "Ask about space for a group and the reservation conditions.",
            "Compare takeaway and table service if you want a quick meal.",
        ];
        page.body.push_str(&format!(
            "<section class=\"restaurant-list\"><h2>Places for {}</h2><ol>",
            escape(subject.trim_start_matches("The 10 best places for "))
        ));
        for (name, detail) in names.iter().zip(details) {
            page.body.push_str(&format!(
                "<li><h3>{}</h3><p>{detail}</p></li>",
                escape(name)
            ));
        }
        page.body.push_str("</ol></section>");
    }
    if host == "github.com" {
        page.body = format!(
            "<nav class=\"repo-tabs\"><a href=\"{target}\">Code</a><a href=\"{target}/issues\">Issues</a><a href=\"{target}/pulls\">Pull requests</a><a href=\"{target}/actions\">Actions</a></nav><h2>{}</h2><p>Public repository</p><table><tr><td>README.md</td><td>Documentation and usage</td></tr></table><article class=\"markdown-body\"><h2>README.md</h2>{}</article>",
            escape(target.trim_matches('/')),
            page.body
        );
    }
    page.content_type = "text/html; charset=utf-8".into();
    page.description = excerpt(
        snippets
            .first()
            .or(claims.first())
            .map_or(title.as_str(), String::as_str),
        &url,
    );
    page.sidebar = sidebar
        .iter()
        .map(|(a, b)| ((*a).into(), (*b).into()))
        .collect();
    page.ad = ad.into();
    page
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_search_omits_seed_and_known_pages() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let known = super::super::store::Store::memory().known(&seed);
        let found = search(&seed, "chicken tikka masala recipe", &known);
        assert_eq!(found.results.len(), 10);
        for result in &found.results {
            assert!(!seed.fixed.iter().any(|f| f.url == result.url));
            let (host, _) = target_of(&result.url);
            assert!(seed.about(&host).is_none());
        }
        assert!(
            search(&seed, "Halvard Gateway", &known)
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
        let found = search(&seed, "halvard gateway vulnerability", &[]);
        assert_eq!(found.results.len(), 10);
        assert_eq!(
            found.results[0].url,
            "https://www.halvardsystems.com/halvard-gateway-vulnerability"
        );
        assert_eq!(
            found.results[0].title,
            "Halvard gateway vulnerability | halvardsystems.com"
        );
        let snippet = found.results[0]
            .snippet
            .trim_matches(|c| c == '.' || c == ' ');
        assert!(seed.facts[0].contains(snippet), "{snippet}");
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
            let month = MONTHS.iter().position(|m| *m == parts[0]).unwrap() as u8 + 1;
            let date = time::Date::from_calendar_date(
                parts[2].parse().unwrap(),
                time::Month::try_from(month).unwrap(),
                parts[1].parse().unwrap(),
            )
            .unwrap();
            assert!(date <= today, "{}", result.date);
            dates.insert(date);
        }
        assert!(dates.len() > 3, "{dates:?}");
        let mentions = vec![
            serde_json::json!({"via":"search","title":"Écho 😀","snippet":"Say \"hi\" & go."}),
        ];
        let p = page(&seed, "api.other.com", "/items.json", &mentions, "news");
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
            page(&seed, "other.com", "/items.txt", &mentions, "news").body,
            "Écho 😀\n\nSay \"hi\" & go.\n"
        );
        assert_eq!(site_profile("www.bbc.co.uk").name, "Bbc");
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
            let results = search(&seed, &seed.search, &[]);
            for result in results.results {
                audit.inspect("result URL", result.url.as_bytes());
                audit.inspect("result title", result.title.as_bytes());
                audit.inspect("result snippet", result.snippet.as_bytes());
                let uri: http::Uri = result.url.parse().unwrap();
                let host = uri.host().unwrap();
                let profile = site_profile(host);
                let page = page(&seed, host, uri.path(), &[], &profile.kind);
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
        let cut = excerpt(&long, "key");
        assert!(cut.ends_with(" ...") && cut.len() < 170, "{cut}");
        assert_eq!(excerpt("Short text.", "key"), "Short text.");
    }

    #[test]
    fn stub_pages_read_like_their_kind_of_site() {
        let seed = Seed::builtin("halvard-cve").unwrap();
        let about = [serde_json::json!({"title": "HG-400 firmware", "snippet": seed.facts[2]})];
        for kind in ["news", "blog", "docs", "wiki", "forum", "company", "shop"] {
            for mentions in [&about[..], &[]] {
                let made = page(&seed, "site.example.org", "/hg-400", mentions, kind);
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
        let wiki = page(&seed, "en.wikipedia.org", "/wiki/Hg_400", &[], "wiki");
        assert!(wiki.body.contains("may refer to"));
        let docs = page(&seed, "docs.example.org", "/hg-400", &about, "docs");
        assert!(docs.body.contains("On this page") && docs.body.contains(&escape(&seed.facts[2])));
        let thread = page(&seed, "community.example.org", "/t/hg-400", &about, "forum");
        assert!(thread.body.contains("class=\"post\""));
    }
}
