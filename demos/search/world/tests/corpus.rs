//! Acceptance checks over real captures, invoked with `cargo test --test corpus`.

use fictionet_extras::{models::Engine, warc::Archive};
use kuchiki::traits::TendrilSink;
use std::{collections::HashSet, path::PathBuf, sync::Arc};
use web_world::pages::{Meta, Pages, Seed};

#[test]
fn repository_metadata_and_the_cited_vulnerability_are_real_documents() {
    let downloads = std::env::var_os("SEARCH_DOWNLOADS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../downloads"));
    let seed = Seed::builtin("security").unwrap();
    let archive = Archive::directory(&downloads.join(&seed.corpus.unwrap().directory)).unwrap();
    let cve = "https://nvd.nist.gov/vuln/detail/cve-2025-30154";
    let response = archive
        .get(cve)
        .unwrap()
        .expect("captured vulnerability detail");
    let title = fictionet_extras::capture::title(&response).unwrap();
    assert_eq!(response.status, 200, "{cve}: {:?}", response.headers);
    assert!(
        title.contains("CVE-2025-30154"),
        "{cve}: {title}: {}",
        String::from_utf8_lossy(&response.decoded().unwrap())
    );
    assert!(String::from_utf8_lossy(&response.decoded().unwrap()).contains("reviewdog"));
    for repo in ["psf/requests", "networkx/networkx", "pallets/click"] {
        let url = format!("https://api.github.com/repos/{repo}");
        let response = archive
            .get(&url)
            .unwrap()
            .unwrap_or_else(|| panic!("missing {url}"));
        assert_eq!(
            response.status,
            200,
            "{url}: {:?}: {}",
            response.headers,
            String::from_utf8_lossy(&response.decoded().unwrap())
        );
        let metadata: serde_json::Value =
            serde_json::from_slice(&response.decoded().unwrap()).unwrap();
        assert_eq!(metadata["full_name"], repo);
    }
}

#[test]
fn cited_commits_and_pull_requests_have_their_own_captures() {
    let downloads = std::env::var_os("SEARCH_DOWNLOADS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../downloads"));
    let seed = Seed::builtin("security").unwrap();
    let archive = Archive::directory(&downloads.join(&seed.corpus.unwrap().directory)).unwrap();
    let mut commits = 0;
    let mut pulls = 0;
    for source in [
        "https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/",
        "https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised",
        "https://www.stepsecurity.io/blog/state-of-open-source-supply-chain-attacks",
        "https://www.wiz.io/blog/new-github-action-supply-chain-attack-reviewdog-action-setup",
    ] {
        let response = archive.get(source).unwrap().unwrap();
        for reference in fictionet_extras::capture::references(source, &response).unwrap() {
            let url = url::Url::parse(&reference).unwrap();
            if url.host_str() != Some("github.com") {
                continue;
            }
            let parts = url.path_segments().unwrap().collect::<Vec<_>>();
            if !matches!(parts.get(2), Some(&"commit") | Some(&"pull")) {
                continue;
            }
            let page = archive
                .get(&reference)
                .unwrap()
                .unwrap_or_else(|| panic!("missing citation: {source} -> {reference}"));
            assert!(
                page.status.is_success() || page.status == 404,
                "{reference}: {}",
                page.status
            );
            if page.status.is_success() {
                if parts[2] == "commit" {
                    commits += 1;
                } else {
                    pulls += 1;
                }
            }
        }
    }
    assert!(
        commits > 0 && pulls > 0,
        "captured {commits} commits and {pulls} pull requests"
    );
}

#[test]
fn long_articles_retain_their_headline_and_paragraphs_for_the_reader() {
    let downloads = std::env::var_os("SEARCH_DOWNLOADS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../downloads"));
    let pages =
        Arc::new(Pages::from_corpus(Seed::builtin("security").unwrap(), &downloads, None).unwrap());
    let (send, mut receive) = tokio::sync::mpsc::channel(256);
    pages.observe(send);
    fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(13), |cx| async move {
        for url in [
            "https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised",
            "https://docs.github.com/en/actions/reference/security/secure-use",
        ] {
            let page = pages.clone().fetch(cx.clone(), url.into()).await?;
            assert!(page.body.len() > 64 * 1024, "{url}");
            let mut body = None;
            while let Ok(row) = receive.try_recv() {
                if let web_world::observation::SearchObs::Request { status, preview, .. } = row.fact
                    && status == 200 { body = preview; }
            }
            let body = body.expect("retained page identity").text().unwrap();
            assert_eq!(body.as_bytes(), page.body);
            let dom = kuchiki::parse_html().one(body.to_string());
            let article = dom.select_first("main, article, [role=main]").unwrap();
            assert!(article.as_node().select("h1").unwrap().next().is_some(), "{url}");
            assert!(article.as_node().select("p").unwrap().count() >= 2, "{url}");
        }
        Ok(())
    })).unwrap();
}

#[test]
fn linked_security_guidance_is_available_to_the_researcher() {
    let downloads = std::env::var_os("SEARCH_DOWNLOADS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../downloads"));
    let seed = Seed::builtin("security").unwrap();
    let archive =
        Archive::directory(&downloads.join(&seed.corpus.as_ref().unwrap().directory)).unwrap();
    let source = "https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/";
    let response = archive.get(source).unwrap().unwrap();
    let references = fictionet_extras::capture::references(source, &response).unwrap();
    let pages = Arc::new(Pages::from_corpus(seed, &downloads, None).unwrap());
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(12),
        |cx| async move {
            for host in ["securitylab.github.com", "owasp.org"] {
                let url = references
                    .iter()
                    .find(|url| url::Url::parse(url).unwrap().host_str() == Some(host))
                    .unwrap_or_else(|| panic!("no citation to {host}"));
                let page = pages.clone().fetch(cx.clone(), url.clone()).await?;
                assert!(!page.title.is_empty(), "{url}");
                assert!(!page.body.is_empty(), "{url}");
                eprintln!("reference {url}: {}", page.title);
            }
            for url in [
                "https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem",
                "https://owasp.org/www-project-top-10-ci-cd-security-risks/",
            ] {
                let page = pages.clone().fetch(cx.clone(), url.into()).await?;
                assert!(!page.title.is_empty(), "{url}");
                assert!(!page.body.is_empty(), "{url}");
            }
            Ok(())
        },
    ))
    .unwrap();
}

#[test]
fn security_research_searches_and_citations_replay_without_internet() {
    let downloads = std::env::var_os("SEARCH_DOWNLOADS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../downloads"));
    let seed = Seed::builtin("security").unwrap();
    let corpus = seed.corpus.as_ref().unwrap();
    let source_urls = corpus.urls.clone();
    let archive = Archive::directory(&downloads.join(&corpus.directory)).unwrap();
    let mut sources = HashSet::new();
    for url in &corpus.urls {
        let response = archive
            .get(url)
            .unwrap()
            .unwrap_or_else(|| panic!("missing {url}"));
        assert!(
            response.status.is_success() || response.status.is_redirection(),
            "{url}: {}",
            response.status
        );
        sources.insert(url::Url::parse(url).unwrap().host_str().unwrap().to_owned());
    }
    assert!(sources.len() >= 8);
    let pages = Arc::new(Pages::from_corpus(seed, &downloads, None).unwrap());
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(11),
        |cx| async move {
            let mut followed = HashSet::new();
            for url in &source_urls {
                let page = pages.clone().fetch(cx.clone(), url.clone()).await?;
                assert!(!page.title.is_empty(), "{url}");
                eprintln!("source {url}: {}", page.title);
                let base = url::Url::parse(url)?;
                let links: Vec<_> = {
                    let dom =
                        kuchiki::parse_html().one(String::from_utf8_lossy(&page.body).into_owned());
                    dom.select("a[href]")
                        .unwrap()
                        .filter_map(|node| {
                            let mut next = base.join(node.attributes.borrow().get("href")?).ok()?;
                            next.set_fragment(None);
                            (next.as_str() != url).then(|| next.to_string())
                        })
                        .collect()
                };
                for next in links {
                    let Some(response) = archive.get(&next)? else {
                        continue;
                    };
                    if response.status == 200
                        && response
                            .headers
                            .get("content-type")
                            .is_some_and(|value| value.as_bytes().starts_with(b"text/html"))
                    {
                        let linked = pages.clone().fetch(cx.clone(), next.clone()).await?;
                        assert!(!linked.body.is_empty(), "{url} -> {next}");
                        followed.insert(url.clone());
                        break;
                    }
                }
            }
            assert!(
                followed.len() >= 8,
                "only {} sources have a replayable onward article",
                followed.len()
            );
            for query in [
                "solarwinds supply chain attack",
                "xz backdoor",
                "XZ Utils backdoor CVE-2024-3094 CISA alert",
                "recent supply-chain attacks on CI/CD",
                "tj-actions changed-files CVE-2025-30066",
                "Shai-Hulud npm supply chain",
                "3CX supply chain compromise",
                "Codecov bash uploader compromise",
                "PyTorch nightly dependency compromise",
                "nist zero trust architecture",
                "mitre attack lateral movement",
                "GitHub Actions supply chain attack tj-actions changed-files analysis",
                "CI/CD pipeline supply chain attacks 2025 2026 Shai-Hulud GitHub Actions compromise",
            ] {
                let hits = pages
                    .clone()
                    .search(cx.clone(), query.into(), Default::default())
                    .await?;
                assert!(!hits.is_empty(), "{query}");
                let mut distinct = HashSet::new();
                for hit in &hits {
                    let mut url = url::Url::parse(&hit.url)?;
                    assert_ne!(url.host_str(), Some("www.linkedin.com"), "{}", hit.url);
                    assert_ne!(url.host_str(), Some("linkedin.com"), "{}", hit.url);
                    let query = url.query_pairs().filter(|(key, _)| !key.starts_with("utm_"))
                        .map(|(key, value)| (key.into_owned(), value.into_owned())).collect::<Vec<_>>();
                    url.set_query(None);
                    if !query.is_empty() { url.query_pairs_mut().extend_pairs(query); }
                    assert!(distinct.insert(url), "duplicate search result {}", hit.url);
                }
                if query.starts_with("XZ Utils") {
                    assert!(hits[0].url.contains("xz"), "{}", hits[0].url);
                }
                if query.starts_with("tj-actions") {
                    assert!(hits.iter().take(3).any(|hit| hit.url.contains("tj-actions")
                        || hit.url.contains("github-actions-supply-chain")));
                }
                eprintln!("{query}: {} results on the first page", hits.len());
                for hit in hits.iter().take(3) {
                    let page = pages.clone().fetch(cx.clone(), hit.url.clone()).await?;
                    assert!(!page.body.is_empty(), "{}", hit.url);
                    assert!(!page.title.is_empty(), "{}", hit.url);
                    eprintln!("  {}: {}", hit.url, page.title);
                }
            }
            for host in ["www.google.com", "www.bing.com", "html.duckduckgo.com"] {
                let path = if host == "html.duckduckgo.com" {
                    "/html/"
                } else {
                    "/search"
                };
                for query in ["dishwasher+astronomy", "solarwinds+hydrogen"] {
                    let response = pages
                        .handle(&cx, "GET", host, &format!("{path}?q={query}"), None)
                        .await;
                    assert_eq!(response.status, 200);
                    let Meta::Search(list) = response.meta else {
                        panic!("search metadata missing")
                    };
                    assert!(list.listed.is_empty(), "{query}");
                }
            }
            Ok(())
        },
    ))
    .unwrap();
}
