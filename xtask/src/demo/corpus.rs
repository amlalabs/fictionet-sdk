//! Capture astronomy sites with wget, retaining responses at original URLs.

use crate::process::Result;
use std::process::Command;

pub(super) fn run(args: &[String]) -> Result {
    match args {
        [] => fetch(),
        [action] if action == "report" => report(&crate::root().join("demos/downloads/astronomy")),
        [action, path] if action == "report" => report(std::path::Path::new(path)),
        _ => Err("usage: cargo xtask demo corpus [report [directory]]".into()),
    }
}

fn fetch() -> Result {
    let destination = crate::root().join("demos/downloads/astronomy");
    if destination.exists() {
        return Err("astronomy already exists; run cargo xtask demo corpus report to inspect it, or move it aside before recapturing".into());
    }
    let root = crate::root().join("demos/downloads/astronomy-capture");
    std::fs::create_dir_all(&root)?;
    let seeds = crate::root().join("demos/corpus/astronomy.urls");
    let stem = root.join("astronomy");
    if stem.with_extension("warc.gz").exists() {
        return Err(
            "astronomy.warc.gz already exists; move the archive aside before recapturing".into(),
        );
    }
    let scratch = root.join("capture");
    std::fs::create_dir_all(&scratch)?;
    // One wget traversal shares downloaded requisites between every page.
    // The byte and depth limits bound the capture; page counts must be measured.
    let status = Command::new("wget")
        .args(["--mirror", "--page-requisites", "--level=2", "--span-hosts",
            "--wait=0.5", "--random-wait", "--limit-rate=2m", "--quota=12g",
            "--timeout=30", "--tries=2", "--execute=robots=on",
            "--user-agent=FictionetAstronomyArchive/1.0 wget (offline astronomy research demo; respects robots.txt)",
            "--warc-compression", "--no-warc-keep-log"])
        .arg(format!("--input-file={}", seeds.display()))
        .arg(format!("--warc-file={}", stem.display()))
        .arg(format!("--directory-prefix={}", scratch.display()))
        .arg(format!("--output-file={}", stem.with_extension("log").display()))
        .status()?;
    // Wget uses temporary files for discovery. The world reads only WARCs.
    std::fs::remove_dir_all(scratch)?;
    if !status.success() {
        return Err(format!("wget capture failed ({status}); incomplete WARC retained in {}; inspect astronomy.log before using it", root.display()).into());
    }
    let archive = fictionet_extras::warc::Archive::directory(&root)?;
    let mut pages = 0;
    for url in archive.urls() {
        if archive.get(url)?.is_some_and(|response| {
            response.status.is_success()
                && response
                    .headers
                    .get("content-type")
                    .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
        }) {
            pages += 1;
        }
    }
    if !(9_000..=11_000).contains(&pages) {
        return Err(format!(
            "capture has {pages} HTML pages, not about 10000; retained at {} for inspection",
            root.display()
        )
        .into());
    }
    drop(archive);
    std::fs::rename(&root, &destination)?;
    println!("astronomy archives: {}", destination.display());
    Ok(())
}

fn report(root: &std::path::Path) -> Result {
    use fictionet_extras::{crawl::Index, warc::Archive};
    use std::{collections::BTreeMap, time::Instant};
    let start = Instant::now();
    let archive = Archive::directory(root)?;
    let scan = start.elapsed();
    let seeds = include_str!("../../../demos/corpus/astronomy.urls")
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
