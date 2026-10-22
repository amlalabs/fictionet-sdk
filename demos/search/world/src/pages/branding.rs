//! Site names, navigation and page categories.

use super::make::*;
use super::text::*;

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
    let name = include_str!("site-names.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find_map(|(site, label)| (site == host).then_some(label))
        .unwrap_or(&name)
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
