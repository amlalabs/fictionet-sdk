//! Acceptance checks over real captures, invoked with `cargo test --test corpus`.

use fictionet_extras::{models::Engine, warc::Archive};
use kuchiki::traits::TendrilSink;
use std::{collections::HashSet, path::PathBuf, sync::Arc};
use web_world::pages::{Meta, Pages, Seed};

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
            ] {
                let hits = pages
                    .clone()
                    .search(cx.clone(), query.into(), Default::default())
                    .await?;
                assert!(!hits.is_empty(), "{query}");
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
