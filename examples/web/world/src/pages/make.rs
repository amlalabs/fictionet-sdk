//! Shared text, branding and stored-page helpers for the model writer.

use super::{Seed, seed::parse_date, text::*};
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
pub(super) const AUTHORS: [&str; 16] = [
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
pub(super) const USERS: [&str; 12] = [
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
pub(super) fn hash(text: &str) -> usize {
    text.bytes()
        .fold(0usize, |n, b| n.wrapping_mul(31).wrapping_add(b as usize))
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

pub(super) fn prepared_cast(_seed: &Seed) -> Vec<super::prompts::Person> {
    Vec::new()
}

pub(super) fn engine_order(_engine: Engine, _query: &str, url: &str) -> usize {
    hash(url)
}

pub(super) fn finish_listing(_query: &str, search: &mut Search) {
    let mut urls = std::collections::HashSet::new();
    search.results.retain(|r| urls.insert(r.url.clone()));
}

/// Search only known page metadata when no model is configured.
pub fn search(_seed: &Seed, query: &str, known: &[Result], _engine: Engine) -> Search {
    Search {
        results: rank(known, query).into_iter().take(10).cloned().collect(),
        ..Default::default()
    }
}

pub(super) fn for_engine(_seed: &Seed, _query: &str, canonical: Search, _engine: Engine) -> Search {
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
    let readable = label.replace('-', " ");
    let readable = readable
        .replace("mechanicalkeyboards", "mechanical keyboards")
        .replace("consumerreports", "consumer reports")
        .replace("healthandsafety", "health and safety");
    let name = normalize_space(&readable)
        .split(' ')
        .map(capitalize)
        .collect::<Vec<_>>()
        .join(" ");
    let name = if name.is_empty() { host.into() } else { name };
    let name = match host {
        "docs.python.org" => "Python Documentation",
        "www.manualslib.com" | "manualslib.com" => "ManualsLib",
        "www.cvedetails.com" | "cvedetails.com" => "CVE Details",
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
        "www.cdc.gov" => "CDC",
        "www.who.int" => "WHO",
        "www.immunology.org" => "British Society for Immunology",
        "www.chop.edu" => "Children's Hospital of Philadelphia",
        "www.akc.org" => "American Kennel Club",
        "www.vet.cornell.edu" => "Cornell University College of Veterinary Medicine",
        "www.merckvetmanual.com" => "Merck Veterinary Manual",
        "www.pdsa.org.uk" => "PDSA",
        "www.bluecross.org.uk" => "Blue Cross",
        "www.bhf.org.uk" => "British Heart Foundation",
        "www.heart.org" => "American Heart Association",
        "www.health.harvard.edu" => "Harvard Health Publishing",
        "www.mentalfloss.com" => "Mental Floss",
        "www.discovermagazine.com" => "Discover",
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
            | "www.amazon.com"
            | "amazon.com"
            | "www.walmart.com"
            | "www.bestbuy.com"
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
            | "www.cdc.gov"
            | "www.who.int"
            | "www.immunology.org"
            | "www.chop.edu"
            | "www.akc.org"
            | "www.vet.cornell.edu"
            | "www.merckvetmanual.com"
            | "www.pdsa.org.uk"
            | "www.bluecross.org.uk"
            | "www.bhf.org.uk"
            | "www.heart.org"
            | "www.health.harvard.edu"
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
body:has(.cookie-banner) { padding-bottom: 80px; }
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
/// Derive a heading from a URL when no stored title exists.
pub fn title_from(host: &str, target: &str) -> String {
    let path = target
        .split('?')
        .next()
        .unwrap_or(target)
        .trim_end_matches('/');
    let part = path.rsplit('/').next().unwrap_or_default();
    if part.is_empty() {
        site_profile(host).name
    } else {
        part.replace(['-', '_'], " ")
    }
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
        if mentions.iter().all(|m| m["title"].as_str().is_none())
            && title_from(host, target).is_empty()
        {
            mentions.push(serde_json::json!({"title": title_from(host, target)}));
        }
        let made = page(seed, host, target, &mentions, kind);

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

/// No synthetic advisory details are supplied.
pub fn advisory(_host: &str, _target: &str, _title: &str, _date: &str) -> Option<Page> {
    None
}

/// Preserve prior mentions without inventing page content.
pub fn page(
    _seed: &Seed,
    host: &str,
    target: &str,
    mentions: &[Value],
    _kind: &str,
) -> Page {
    let title = mentions
        .iter()
        .find_map(|m| m["title"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| title_from(host, target));
    let mut body = format!("<h1>{}</h1>", escape(&title));
    for snippet in mentions.iter().filter_map(|m| m["snippet"].as_str()) {
        body.push_str(&format!("<p>{}</p>", escape(snippet)));
    }
    Page {
        status: 200,
        content_type: "text/html; charset=utf-8".into(),
        title,
        body,
        ..Default::default()
    }
}
