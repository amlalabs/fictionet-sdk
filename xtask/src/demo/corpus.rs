//! Complete the bounded astronomy corpus through Wikimedia, retaining real URLs.

use crate::process::Result;

pub(super) fn run(args: &[String]) -> Result {
    match args {
        [] => fetch(),
        [action] if action == "report" => report(&crate::root().join("demos/downloads/astronomy")),
        [action, path] if action == "report" => report(std::path::Path::new(path)),
        _ => Err("usage: cargo xtask demo corpus [report [directory]]".into()),
    }
}

fn fetch() -> Result {
    use fictionet_extras::{
        capture::{Fetcher, links},
        warc::Archive,
    };
    use kuchiki::traits::TendrilSink;
    use std::{
        collections::{HashSet, VecDeque},
        time::Instant,
    };
    let destination = crate::root().join("demos/downloads/astronomy");
    let incomplete = crate::root().join("demos/downloads/astronomy-incomplete");
    if !destination.exists() && incomplete.exists() {
        // Validate the interrupted gzip members before adopting the capture.
        Archive::directory(&incomplete)?;
        std::fs::rename(incomplete, &destination)?;
    }
    let mut archive = Archive::directory(&destination)?;
    let mut count = archive
        .urls()
        .filter(|url| {
            archive.get(url).ok().flatten().is_some_and(|r| {
                r.status.is_success()
                    && r.headers
                        .get("content-type")
                        .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
            })
        })
        .count();
    if count >= 500 {
        println!("Corpus already has {count} HTML pages; no articles will be added");
    }
    let started = Instant::now();
    let fetcher = Fetcher::new(
        "FictionetAstronomyArchive/1.0 (offline astronomy demo; contact: souvik@amlalabs.com)",
    )?;
    let path = destination.join("wikipedia.warc.gz");
    let mut candidates =
        VecDeque::from(["Solar System", "Star", "Galaxy", "Exoplanet"].map(str::to_owned));
    let mut categories = VecDeque::from(
        [
            "Astronomy",
            "Astrophysics",
            "Stars",
            "Galaxies",
            "Nebulae",
            "Cosmology",
            "Planets",
            "Exoplanets",
        ]
        .map(|c| (format!("Category:{c}"), 0)),
    );
    let mut seen_categories = HashSet::new();
    let mut seen_pages = HashSet::new();
    let mut assets = VecDeque::new();
    while count < 500 {
        crate::process::interrupted()?;
        let Some(title) = candidates.pop_front() else {
            let (category, depth) = categories
                .pop_front()
                .ok_or("astronomy categories exhausted")?;
            if !seen_categories.insert(category.clone()) {
                continue;
            }
            let mut api = url::Url::parse("https://en.wikipedia.org/w/api.php")?;
            api.query_pairs_mut().extend_pairs([
                ("action", "query"),
                ("list", "categorymembers"),
                ("cmtitle", &category),
                ("cmlimit", "500"),
                ("format", "json"),
            ]);
            let response = fetcher.api(api.as_str())?;
            let value: serde_json::Value = serde_json::from_slice(&response.decoded()?)?;
            for member in value["query"]["categorymembers"]
                .as_array()
                .ok_or("missing category members")?
            {
                if let Some(title) = member["title"].as_str() {
                    if member["ns"] == 0 {
                        candidates.push_back(title.to_owned());
                    } else if member["ns"] == 14 && depth < 2 {
                        categories.push_back((title.to_owned(), depth + 1));
                    }
                }
            }
            continue;
        };
        if !seen_pages.insert(title.clone()) {
            continue;
        }
        let mut real = url::Url::parse("https://en.wikipedia.org/wiki/")?;
        real.path_segments_mut()
            .unwrap()
            .pop_if_empty()
            .push(&title.replace(' ', "_"));
        if archive
            .get(real.as_str())?
            .is_some_and(|r| r.status.is_success())
        {
            continue;
        }
        let mut api = url::Url::parse("https://en.wikipedia.org/w/api.php")?;
        api.query_pairs_mut().extend_pairs([
            ("action", "parse"),
            ("page", &title),
            ("prop", "text"),
            ("redirects", "1"),
            ("format", "json"),
            ("formatversion", "2"),
        ]);
        let response = fetcher.api(api.as_str())?;
        let value: serde_json::Value = serde_json::from_slice(&response.decoded()?)?;
        let article = value["parse"]["text"]
            .as_str()
            .ok_or("missing parsed article")?;
        // Keep the actual desktop skin, navigation, headings and license. The
        // article body comes from the Action API, not a hand written summary.
        let mut desktop = fetcher.api(real.as_str())?;
        if !desktop.status.is_success() {
            return Err(format!("desktop capture failed: {real} {}", desktop.status).into());
        }
        let dom = kuchiki::parse_html().one(String::from_utf8(desktop.decoded()?)?);
        let content = dom
            .select_first("#mw-content-text")
            .map_err(|_| "missing desktop article container")?;
        for node in content.as_node().children().collect::<Vec<_>>() {
            node.detach();
        }
        let parsed = kuchiki::parse_html().one(article);
        let body = parsed.select_first("body").unwrap();
        for node in body.as_node().children().collect::<Vec<_>>() {
            content.as_node().append(node);
        }
        // Static desktop pages use Wikipedia's no-JavaScript skin. Avoid
        // resource loader requests that cannot be discovered from markup.
        for node in dom.select("script").unwrap().collect::<Vec<_>>() {
            node.as_node().detach();
        }
        desktop.body = dom.to_string().into_bytes().into();
        desktop.headers.remove("content-encoding");
        desktop.headers.remove("etag");
        assets.extend(links(real.as_str(), &desktop)?.assets);
        archive.append(&path, real.as_str(), &desktop)?;
        count += 1;
        println!(
            "{count}/500 {real} ({:.1}s)",
            started.elapsed().as_secs_f64()
        );
    }
    // Resume asset completion too: a stopped run must never add extra articles.
    for url in archive
        .urls()
        .filter(|u| u.starts_with("https://en.wikipedia.org/wiki/"))
        .map(str::to_owned)
        .collect::<Vec<_>>()
    {
        if let Some(mut response) = archive.get(&url)? {
            if response.status.is_success()
                && response
                    .headers
                    .get("content-type")
                    .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
            {
                let dom = kuchiki::parse_html().one(String::from_utf8(response.decoded()?)?);
                let mut changed = false;
                if let Ok(redirect) = dom.select_first(".redirectText a[title]") {
                    let title = redirect
                        .attributes
                        .borrow()
                        .get("title")
                        .unwrap()
                        .to_owned();
                    let mut api = url::Url::parse("https://en.wikipedia.org/w/api.php")?;
                    api.query_pairs_mut().extend_pairs([
                        ("action", "parse"),
                        ("page", title.as_str()),
                        ("redirects", "1"),
                        ("prop", "text"),
                        ("format", "json"),
                        ("formatversion", "2"),
                    ]);
                    let parsed = fetcher.api(api.as_str())?;
                    let value: serde_json::Value = serde_json::from_slice(&parsed.decoded()?)?;
                    let article = value["parse"]["text"]
                        .as_str()
                        .ok_or("missing redirect target content")?;
                    let content = dom
                        .select_first("#mw-content-text")
                        .map_err(|_| "missing desktop article container")?;
                    for node in content.as_node().children().collect::<Vec<_>>() {
                        node.detach();
                    }
                    let parsed = kuchiki::parse_html().one(article);
                    for node in parsed
                        .select_first("body")
                        .unwrap()
                        .as_node()
                        .children()
                        .collect::<Vec<_>>()
                    {
                        content.as_node().append(node);
                    }
                    changed = true;
                    println!("Resolved copied redirect body: {url}");
                }
                for node in dom.select("script").unwrap().collect::<Vec<_>>() {
                    node.as_node().detach();
                    changed = true;
                }
                if changed {
                    response.body = dom.to_string().into_bytes().into();
                    response.headers.remove("content-encoding");
                    response.headers.remove("etag");
                    archive.append(&path, &url, &response)?;
                }
            }
            assets.extend(links(&url, &response)?.assets);
        }
    }
    let mut seen_assets = HashSet::new();
    let mut failures = Vec::new();
    while let Some(url) = assets.pop_front() {
        crate::process::interrupted()?;
        if !seen_assets.insert(url.clone()) {
            continue;
        }
        if let Some(response) = archive.get(&url)?
            && (response.status.is_success() || response.status.is_redirection())
        {
            let discovered = links(&url, &response)?;
            assets.extend(discovered.assets);
            if response.status.is_redirection() {
                for target in discovered.pages.into_iter().rev() {
                    assets.push_front(target);
                }
            }
            continue;
        }
        let response = (|| {
            let mut response = fetcher.api(&url)?;
            for _ in 0..3 {
                if response.status.as_u16() != 429 && response.status.as_u16() != 503 {
                    break;
                }
                let delay = response
                    .headers
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(60);
                eprintln!("Server rate limit; retrying {url} after {delay}s");
                std::thread::sleep(std::time::Duration::from_secs(delay));
                crate::process::interrupted().map_err(|e| std::io::Error::other(e.to_string()))?;
                response = fetcher.api(&url)?;
            }
            Ok::<_, std::io::Error>(response)
        })();
        match response {
            Ok(response) => {
                let discovered = links(&url, &response)?;
                assets.extend(discovered.assets);
                if response.status.is_redirection() {
                    for target in discovered.pages.into_iter().rev() {
                        assets.push_front(target);
                    }
                }
                if !response.status.is_success() && !response.status.is_redirection() {
                    failures.push(format!("{} {url}", response.status));
                }
                archive.append(&path, &url, &response)?;
            }
            Err(error) => failures.push(format!("{url}: {error}")),
        }
        if seen_assets.len() % 100 == 0 {
            println!(
                "{} assets visited, {} remaining ({:.1}s)",
                seen_assets.len(),
                assets.len(),
                started.elapsed().as_secs_f64()
            );
        }
    }
    println!(
        "{count} HTML pages; {} asset URLs; {:.1}s",
        seen_assets.len(),
        started.elapsed().as_secs_f64()
    );
    for failure in &failures {
        eprintln!("Asset unavailable: {failure}");
    }
    if !failures.is_empty() {
        return Err(format!(
            "{} unavailable assets; archive retained for inspection",
            failures.len()
        )
        .into());
    }
    report(&destination)
}

fn report(root: &std::path::Path) -> Result {
    use fictionet_extras::{crawl::Index, warc::Archive};
    use std::{collections::BTreeMap, time::Instant};
    let start = Instant::now();
    let archive = Archive::directory(root)?;
    let scan = start.elapsed();
    let seeds = include_str!("../../../demos/search/corpus/astronomy.urls")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let start = Instant::now();
    let index = Index::crawl(&seeds, |url| archive.contains(url), |url| archive.get(url))?;
    let crawl = start.elapsed();
    let mut sites = BTreeMap::<String, usize>::new();
    for url in archive.urls() {
        let Some(response) = archive.get(url)? else {
            continue;
        };
        if response.status.is_success()
            && response
                .headers
                .get("content-type")
                .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
        {
            *sites
                .entry(
                    url::Url::parse(url)?
                        .host_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
                .or_default() += 1;
        }
    }
    for (site, count) in sites {
        println!("{site}: {count} HTML pages");
    }
    let bytes = std::fs::read_dir(root)?.try_fold(0u64, |sum, entry| -> std::io::Result<_> {
        let path = entry?.path();
        Ok(sum
            + if path.to_string_lossy().ends_with(".warc.gz") {
                std::fs::metadata(path)?.len()
            } else {
                0
            })
    })?;
    println!(
        "WARC bytes: {bytes}; URL records: {}; indexed pages: {}; scan: {:.3}s; crawl/index: {:.3}s",
        archive.urls().count(),
        index.len(),
        scan.as_secs_f64(),
        crawl.as_secs_f64()
    );
    let _world_pages = web_world::pages::Pages::copied(
        web_world::pages::Seed::builtin("web")?,
        root,
        &seeds,
        None,
    )?;
    for query in [
        "black hole accretion",
        "exoplanet transit",
        "stellar evolution",
    ] {
        println!("query: {query}");
        for result in index.search(query, 0, 3).results {
            println!("  {} — {}\n  {}", result.title, result.url, result.snippet);
        }
    }
    Ok(())
}
