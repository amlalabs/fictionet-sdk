//! A bounded crawler and BM25 index built through a site's response handler.

use crate::{search, warc};
use kuchiki::traits::TendrilSink;
use std::collections::{HashMap, HashSet, VecDeque};

/// A page's searchable representation.
#[derive(Debug)]
struct Document {
    url: String,
    title: String,
    text: String,
    length: usize,
}

/// An in memory inverted index. No predetermined queries or result lists.
#[derive(Debug, Default)]
pub struct Index {
    documents: Vec<Document>,
    postings: HashMap<String, Vec<(usize, usize)>>,
    words: usize,
}

fn terms(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect()
}

impl Index {
    /// Follow links from the starting URLs, fetching only URLs in the corpus.
    /// `fetch` must be the same response handler used to serve copied sites.
    pub fn crawl(
        seeds: &[String],
        contains: impl Fn(&str) -> bool,
        mut fetch: impl FnMut(&str) -> std::io::Result<Option<warc::Response>>,
    ) -> std::io::Result<Self> {
        let mut index = Self::default();
        let mut seen = HashSet::new();
        let mut pending: VecDeque<_> = seeds.iter().filter_map(|s| warc::key(s)).collect();
        while let Some(url) = pending.pop_front() {
            if !contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            let Some(response) = fetch(&url)? else {
                continue;
            };
            let base = url::Url::parse(&url).expect("canonical HTTP URL");
            if response.status.is_redirection() {
                if let Some(next) = response
                    .headers
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| base.join(v).ok())
                    .and_then(|u| warc::key(u.as_str()))
                {
                    pending.push_back(next);
                }
                continue;
            }
            if !response.status.is_success()
                || !response
                    .headers
                    .get("content-type")
                    .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
            {
                continue;
            }
            let body = response.decoded()?;
            let dom = kuchiki::parse_html().one(String::from_utf8_lossy(&body).into_owned());
            let base = dom
                .select_first("base[href]")
                .ok()
                .and_then(|node| {
                    node.attributes
                        .borrow()
                        .get("href")
                        .and_then(|href| base.join(href).ok())
                })
                .unwrap_or(base);
            if let Ok(links) = dom.select("a[href]") {
                for link in links {
                    if let Some(next) = link
                        .attributes
                        .borrow()
                        .get("href")
                        .and_then(|href| base.join(href).ok())
                        .and_then(|u| warc::key(u.as_str()))
                        .filter(|url| contains(url))
                    {
                        pending.push_back(next);
                    }
                }
            }
            let title = dom
                .select_first("title")
                .ok()
                .map(|n| n.text_contents())
                .unwrap_or_default();
            if let Ok(nodes) = dom.select("script, style, noscript, template") {
                for node in nodes.collect::<Vec<_>>() {
                    node.as_node().detach();
                }
            }
            let text = dom
                .select_first("main")
                .or_else(|_| dom.select_first("article"))
                .or_else(|_| dom.select_first("body"))
                .ok()
                .map(|n| {
                    n.as_node()
                        .descendants()
                        .filter_map(|node| node.as_text().map(|text| text.borrow().to_string()))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            index.add(url, title.trim().to_owned(), text);
        }
        Ok(index)
    }

    fn add(&mut self, url: String, title: String, text: String) {
        let words = terms(&format!("{title} {title} {text}"));
        let length = words.len();
        let mut counts = HashMap::new();
        for word in words {
            *counts.entry(word).or_insert(0) += 1;
        }
        let id = self.documents.len();
        for (word, count) in counts {
            self.postings.entry(word).or_default().push((id, count));
        }
        self.words += length;
        self.documents.push(Document {
            url,
            title,
            text,
            length,
        });
    }

    /// Number of HTML documents reached by the crawler.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Whether the crawler reached any HTML documents.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Rank matching documents with BM25, using URL order to break ties.
    pub fn search(&self, query: &str, start: usize, limit: usize) -> search::Search {
        if self.is_empty() {
            return search::Search::default();
        }
        let n = self.documents.len() as f64;
        let average = (self.words as f64 / n).max(1.0);
        let mut scores = HashMap::<usize, f64>::new();
        let mut words = terms(query);
        words.sort();
        words.dedup();
        for word in &words {
            let Some(postings) = self.postings.get(word) else {
                continue;
            };
            let frequency = postings.len() as f64;
            let idf = (1.0 + (n - frequency + 0.5) / (frequency + 0.5)).ln();
            for &(id, count) in postings {
                let tf = count as f64;
                let norm = 1.2 * (0.25 + 0.75 * self.documents[id].length as f64 / average);
                *scores.entry(id).or_default() += idf * tf * 2.2 / (tf + norm);
            }
        }
        let mut ranked: Vec<_> = scores.into_iter().collect();
        ranked.sort_by(|(a, x), (b, y)| {
            y.total_cmp(x)
                .then(self.documents[*a].url.cmp(&self.documents[*b].url))
        });
        search::Search {
            results: ranked
                .into_iter()
                .skip(start)
                .take(limit)
                .map(|(id, _)| {
                    let doc = &self.documents[id];
                    let lower = doc.text.to_lowercase();
                    let matched = words
                        .iter()
                        .filter_map(|word| {
                            let frequency = self.postings.get(word)?.len();
                            lower.find(word).map(|position| (frequency, position))
                        })
                        .min()
                        .map_or(0, |(_, position)| position);
                    // Character offsets come from the original string, so non ASCII case folding
                    // cannot make a slice land inside a code point.
                    let begin = doc
                        .text
                        .char_indices()
                        .map(|(i, _)| i)
                        .take_while(|i| *i <= matched.saturating_sub(60))
                        .last()
                        .unwrap_or(0);
                    let begin = doc.text[..begin]
                        .char_indices()
                        .rev()
                        .find(|(_, c)| c.is_whitespace())
                        .map_or(0, |(i, c)| i + c.len_utf8());
                    let snippet: String = doc.text[begin..].chars().take(220).collect();
                    search::Result {
                        title: doc.title.clone(),
                        url: doc.url.clone(),
                        snippet,
                        ..Default::default()
                    }
                })
                .collect(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn follows_only_corpus_links_and_ranks_page_text() {
        let pages = HashMap::from([
            (
                "https://sky.org/",
                "<title>Sky</title><a href='/black-hole#intro'>First article</a><a href='/stars'>Second article</a><a href='https://outside.org/'>Outside</a>",
            ),
            (
                "https://sky.org/black-hole",
                "<title>Black holes</title><p>A black hole bends spacetime. Black hole accretion.</p><a href='/'>Home</a>",
            ),
            (
                "https://sky.org/stars",
                "<title>Stars</title><p>Stars burn hydrogen. A star can become a black hole.</p>",
            ),
            (
                "https://sky.org/unlinked",
                "<title>Unlinked</title><p>Black hole</p>",
            ),
        ]);
        let mut fetched = Vec::new();
        let index = Index::crawl(
            &["https://sky.org/".into()],
            |url| pages.contains_key(url),
            |url| {
                fetched.push(url.to_owned());
                Ok::<_, std::io::Error>(Some(warc::Response {
                    status: http::StatusCode::OK,
                    headers: HeaderMap::from_iter([(
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("text/html"),
                    )]),
                    body: pages[url].into(),
                }))
            },
        )
        .unwrap();
        assert_eq!(index.len(), 3);
        assert_eq!(fetched.len(), 3);
        assert!(
            !fetched
                .iter()
                .any(|u| u.contains("outside") || u.contains("unlinked"))
        );
        let results = index.search("black hole", 0, 10).results;
        assert_eq!(results[0].url, "https://sky.org/black-hole");
        assert_eq!(results.len(), 2);
        assert!(results[0].snippet.contains("spacetime"));
        assert_eq!(index.search("hydrogen", 0, 10).results[0].title, "Stars");
        assert!(index.search("dishwasher", 0, 10).results.is_empty());
        assert_eq!(index.search("black hole", 1, 1).results[0], results[1]);
    }
    #[test]
    fn snippets_prefer_the_specific_matching_passage_over_repeated_navigation() {
        let mut index = Index::default();
        index.add(
            "https://sky.org/black-hole".into(),
            "Black holes".into(),
            format!(
                "Black holes {} Accretion disks heat gas around a black hole.",
                "Navigation section ".repeat(40)
            ),
        );
        index.add(
            "https://sky.org/stars".into(),
            "Stars".into(),
            "Stars may collapse into a black hole.".into(),
        );
        let found = index.search("black hole accretion", 0, 10);
        assert_eq!(found.results[0].url, "https://sky.org/black-hole");
        assert!(
            found.results[0]
                .snippet
                .contains("Accretion disks heat gas")
        );
    }

    #[test]
    fn non_ascii_whitespace_is_safe_in_snippets() {
        let mut index = Index::default();
        index.add(
            "https://sky.org/hydrogen".into(),
            "Hydrogen".into(),
            format!("alpha\u{2003}{} hydrogen powers stars", "x".repeat(80)),
        );
        let found = index.search("hydrogen", 0, 10);
        assert_eq!(found.results.len(), 1);
        assert!(found.results[0].snippet.contains("hydrogen powers stars"));
    }

    use http::HeaderMap;
}
