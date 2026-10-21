//! `search bake`: makes the canned pages ahead of time, with a model and no
//! VM. It runs every search and address in the seed's query list
//! (`examples/adaptive-web/seeds/<seed>.queries`), makes the page behind
//! every result, and keeps them in `examples/adaptive-web/stores/<seed>/`.
//! Worlds can load the store to serve those pages ahead of new generation.
//!
//! The key comes from `OPENROUTER_API_KEY`. Model calls stop before they
//! could pass [`CALLS`]: each search or page is started only while the calls
//! it could take still fit.

use std::path::Path;
use std::sync::Arc;

use adaptive_web_world::pages::{
    Maker, Meta, Pages, Seed,
    model::{Model, Provider},
    render,
    store::{self, Store},
    text::{target_of, validate_page},
};
use fictionet_extras::models::{Https, Key};
use fictionet_extras::search::Engine;

use super::{Result, checks::search_url};

/// The most model calls one bake makes, retries included.
const CALLS: usize = 400;
/// The most calls one search or page can take: three attempts for each of
/// two asks.
const MOST_PER_ITEM: usize = 6;

/// One line of the query list.
#[derive(Debug, PartialEq)]
enum Line {
    Search(Engine, String),
    Visit(String),
}

fn lines(text: &str) -> Result<Vec<Line>> {
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (first, rest) = line
            .split_once(' ')
            .ok_or_else(|| format!("query list line has no words: {line}"))?;
        let rest = rest.trim().to_owned();
        out.push(match first {
            "google" => Line::Search(Engine::Google, rest),
            "bing" => Line::Search(Engine::Bing, rest),
            "duckduckgo" => Line::Search(Engine::DuckDuckGo, rest),
            "visit" => Line::Visit(rest),
            other => return Err(format!("query list: unknown engine {other:?}").into()),
        });
    }
    Ok(out)
}

/// Model attempts after the starting count.
fn calls(root: &Path, started: usize) -> usize {
    std::fs::read_to_string(root.join("generations.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains("\"record\":\"attempt\""))
        .count()
        .saturating_sub(started)
}

pub async fn run() -> Result {
    let seed = Seed::builtin(super::SEED)?;
    let list = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../examples/adaptive-web/seeds")
            .join(format!("{}.queries", seed.name)),
    )?;
    let list = lines(&list)?;
    let root = store::canned_root(&seed.name);
    let started = calls(&root, 0);
    let provider = Provider::OpenRouter;
    let key = Key::from_env(provider.into())?;
    println!(
        "Baking {} into {} with {} on OpenRouter, at most {CALLS} calls",
        seed.name,
        root.display(),
        provider.default_model()
    );
    let result = fictionet::run(
        fictionet::RunOptions::new(fictionet::Seed::from_u64(11)),
        move |cx| async move {
            let https = Arc::new(Https::new(&cx, provider.into())?);
            let maker = Maker::Model(Model::new(provider, "", "", key, https));
            let (store, _) = Store::open(&root, &seed, Some(&maker.identity()))
                .map_err(fictionet::Error::msg)?;
            let pages = Arc::new(Pages::open(seed, store, Some(maker), 0));
            let fits = || calls(&root, started) + MOST_PER_ITEM <= CALLS;
            let mut searches = 0;
            let mut failed = 0;
            let mut stopped = None;
            'list: for line in &list {
                let urls = match line {
                    Line::Search(engine, words) => {
                        if !fits() {
                            stopped = Some(format!("before the search {words:?}"));
                            break;
                        }
                        let (host, target) = target_of(&search_url(*engine, words));
                        let response = pages.handle(&cx, "GET", &host, &target, None).await;
                        // A search the model could not write within its
                        // attempts is left out; the app makes it on the spot.
                        let Meta::Search(listing) = &response.meta else {
                            println!(
                                "{} search {words:?} not made: HTTP {}: {:?}",
                                example_common::names::name(engine),
                                response.status,
                                response.meta
                            );
                            failed += 1;
                            continue;
                        };
                        searches += 1;
                        println!(
                            "{} search {words:?}: {} results, {} calls so far",
                            example_common::names::name(engine),
                            listing.listed.len(),
                            calls(&root, started)
                        );
                        listing
                            .listed
                            .iter()
                            .map(|(url, _, _)| url.clone())
                            .collect()
                    }
                    Line::Visit(url) => vec![url.clone()],
                };
                for url in urls {
                    if !fits() {
                        stopped = Some(format!("before the page {url}"));
                        break 'list;
                    }
                    let (host, target) = target_of(&url);
                    let response = pages.handle(&cx, "GET", &host, &target, None).await;
                    if response.status != 200 {
                        println!("  {url}: HTTP {}", response.status);
                    }
                }
            }
            println!(
                "{searches} searches, {failed} not made, {} model calls{}",
                calls(&root, started),
                stopped.map_or(String::new(), |at| format!(", stopped {at}"))
            );
            Ok(())
        },
    )
    .await;
    result?;
    let root = store::canned_root(super::SEED);
    let seed = Seed::builtin(super::SEED)?;
    let dropped = keep_made(&root, &seed)?;
    println!("{dropped} results without a page dropped from their lists");
    let laid_out = lay_out_again(&root, &seed)?;
    println!("{laid_out} pages on captured layouts laid out again");
    let (store, _) = Store::load(&root, &seed)?;
    for page in store.pages() {
        validate_page(&page.content_type, &page.body)
            .map_err(|error| format!("{}: {error}", page.url))?;
    }
    // The lock files only coordinate worlds writing one store.
    let _ = std::fs::remove_file(root.join("store.lock"));
    let _ = std::fs::remove_dir_all(root.join("locks"));
    Ok(())
}

/// Records each page on a host with a captured layout again in the layout as
/// it is now; its text stays as the model wrote it. Returns how many changed.
fn lay_out_again(root: &Path, seed: &Seed) -> Result<usize> {
    let (mut store, _) = Store::open(root, seed, None)?;
    let pages: Vec<_> = store.pages().cloned().collect();
    let mut changed = 0;
    for mut page in pages {
        let html = String::from_utf8_lossy(&page.body).into_owned();
        if !page.content_type.starts_with("text/html") {
            continue;
        }
        if let Some(again) = render::again(
            &page.host,
            &page.target,
            &page.title,
            &html,
            &page.date,
            &seed.date,
        ) {
            page.body = again.into_bytes();
            store.insert_page(page)?;
            changed += 1;
        }
    }
    Ok(changed)
}

/// Records each list again without the results whose page the model could
/// not write, so every canned result opens a canned page. Returns how many
/// results were dropped.
fn keep_made(root: &Path, seed: &Seed) -> Result<usize> {
    let (mut store, _) = Store::open(root, seed, None)?;
    let lists: Vec<_> = store.searches().cloned().collect();
    let mut dropped = 0;
    for mut list in lists {
        let before = list.search.results.len();
        list.search.results.retain(|result| {
            let (host, target) = target_of(&result.url);
            store
                .page(&host, &target)
                .is_some_and(|page| page.status == 200)
        });
        if list.search.results.len() < before {
            dropped += before - list.search.results.len();
            store.insert_search(list)?;
        }
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bake_counts_only_its_own_attempts() {
        let root = std::env::temp_dir().join(format!("bake-calls-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let row = "{\"record\":\"attempt\"}\n";
        std::fs::write(root.join("generations.jsonl"), row.repeat(151)).unwrap();
        let started = calls(&root, 0);
        assert_eq!(started, 151);
        assert_eq!(calls(&root, started), 0);
        std::fs::write(root.join("generations.jsonl"), row.repeat(545)).unwrap();
        assert_eq!(calls(&root, started), CALLS - MOST_PER_ITEM);
        assert!(calls(&root, started) + MOST_PER_ITEM <= CALLS);
        std::fs::write(root.join("generations.jsonl"), row.repeat(546)).unwrap();
        assert!(calls(&root, started) + MOST_PER_ITEM > CALLS);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_query_list_names_an_engine_or_an_address_per_line() {
        let text = "# comment\n\ngoogle a b\nbing c\nduckduckgo d e\nvisit https://x.com/\n";
        assert_eq!(
            lines(text).unwrap(),
            [
                Line::Search(Engine::Google, "a b".into()),
                Line::Search(Engine::Bing, "c".into()),
                Line::Search(Engine::DuckDuckGo, "d e".into()),
                Line::Visit("https://x.com/".into()),
            ]
        );
        assert!(lines("yahoo a").is_err());
        assert!(lines("google").is_err());
    }

    #[test]
    fn the_query_list_has_forty_searches_and_every_engine() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../examples/adaptive-web/seeds/web.queries"),
        )
        .unwrap();
        let list = lines(&text).unwrap();
        let searches = list
            .iter()
            .filter(|line| matches!(line, Line::Search(..)))
            .count();
        assert!(searches >= 40, "{searches}");
        for engine in [Engine::Google, Engine::Bing, Engine::DuckDuckGo] {
            assert!(
                list.iter()
                    .any(|line| matches!(line, Line::Search(e, _) if *e == engine))
            );
        }
    }
}
