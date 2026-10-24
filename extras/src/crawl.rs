//! A bounded crawler and BM25 index built through a site's response handler.

use crate::{search, warc};
use kuchiki::traits::TendrilSink;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

mod disk;
pub use disk::{DiskIndex, DiskWriter};

/// A page's searchable representation.
#[derive(Debug, Serialize, Deserialize)]
struct Document {
    url: String,
    title: String,
    text: String,
    length: usize,
}

/// An in memory inverted index. No predetermined queries or result lists.
#[derive(Debug, Default, Serialize, Deserialize)]
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

fn search_key(value: &str) -> String {
    let mut url = url::Url::parse(value).expect("HTTP URL");
    let query: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| !key.starts_with("utm_"))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    // ATT&CK publishes historical snapshots under this archive namespace.
    // Search groups those editions while replay keeps every original URL.
    if url.host_str() == Some("attack.mitre.org") {
        let path = url.path().to_owned();
        if let Some(rest) = path.strip_prefix("/versions/")
            && let Some((version, current)) = rest.split_once('/')
            && version
                .strip_prefix('v')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            url.set_path(&format!("/{current}"));
        }
    }
    url.set_fragment(None);
    url.into()
}

impl Index {
    /// Copy the crawled documents into a persistent index.
    pub fn write_to(&self, writer: &DiskWriter) -> std::io::Result<()> {
        for document in &self.documents {
            writer.add(&document.url, &document.title, &document.text)?;
        }
        Ok(())
    }
    /// Follow links from the starting URLs, fetching only URLs in the corpus.
    /// `fetch` must be the same response handler used to serve copied sites.
    pub fn crawl(
        seeds: &[String],
        contains: impl Fn(&str) -> bool,
        mut fetch: impl FnMut(&str) -> std::io::Result<Option<warc::Response>>,
    ) -> std::io::Result<Self> {
        let mut index = Self::default();
        let mut seen = HashSet::new();
        let mut indexed = std::collections::BTreeMap::<String, (String, String, String)>::new();
        let mut contents = HashSet::new();
        let mut pending: VecDeque<_> = seeds.iter().filter_map(|s| warc::key(s)).collect();
        while let Some(url) = pending.pop_front() {
            if !contains(&url) || !seen.insert(url.clone()) {
                continue;
            }
            let response = match fetch(&url) {
                Ok(response) => response,
                Err(error) => {
                    eprintln!("Cannot index {url}: {error}");
                    continue;
                }
            };
            let Some(response) = response else {
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
            // Navigation still reaches article links from profiles and noindex pages.
            // Their surrounding text does not make them topical search documents.
            let excluded = dom
                .select(r#"meta[property="og:type"], meta[name=robots]"#)
                .unwrap()
                .any(|node| {
                    node.attributes
                        .borrow()
                        .get("content")
                        .is_some_and(|content| {
                            content.eq_ignore_ascii_case("profile")
                                || content
                                    .split([',', ' '])
                                    .any(|part| part.eq_ignore_ascii_case("noindex"))
                        })
                });
            if excluded {
                continue;
            }
            let canonical = dom
                .select_first("link[rel=canonical][href]")
                .ok()
                .and_then(|node| base.join(node.attributes.borrow().get("href")?).ok())
                .filter(|canonical| canonical.origin() == base.origin())
                .map(|canonical| canonical.to_string())
                .unwrap_or_else(|| url.clone());
            let identity = search_key(&canonical);
            let title = dom
                .select_first("title")
                .ok()
                .map(|n| n.text_contents())
                .unwrap_or_default();
            if let Ok(nodes) = dom.select(
                "script, style, noscript, template, nav, aside, header, footer, [role=navigation]",
            ) {
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
            let title = title.trim().to_owned();
            let candidate = (url, title, text);
            let priority = |value: &str| (value != search_key(value), value.to_owned());
            match indexed.entry(identity) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if priority(&candidate.0) < priority(&entry.get().0) {
                        entry.insert(candidate);
                    }
                }
            }
        }
        for (_, (url, title, text)) in indexed {
            let digest: [u8; 32] =
                ring::digest::digest(&ring::digest::SHA256, format!("{title}\0{text}").as_bytes())
                    .as_ref()
                    .try_into()
                    .expect("SHA256 digest");
            if contents.insert(digest) {
                index.add(url, title, text);
            }
        }
        Ok(index)
    }

    fn add(&mut self, url: String, title: String, text: String) {
        let words = terms(&format!("{url} {title} {title} {text}"));
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

    /// Rank all partial matches by BM25, with URL order breaking ties.
    pub fn search(&self, query: &str, start: usize, limit: usize) -> search::Search {
        if self.is_empty() {
            return search::Search {
                total: Some(0),
                ..Default::default()
            };
        }
        let n = self.documents.len() as f64;
        let average = (self.words as f64 / n).max(1.0);
        let mut scores = HashMap::<usize, (f64, usize)>::new();
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
                let (score, covered) = scores.entry(id).or_default();
                *score += idf * tf * 2.2 / (tf + norm);
                *covered += 1;
            }
        }
        let mut ranked: Vec<_> = scores
            .into_iter()
            .map(|(id, (score, covered))| (id, covered, score))
            .collect();
        ranked.sort_by(|(a, ac, x), (b, bc, y)| {
            y.total_cmp(x)
                .then_with(|| bc.cmp(ac))
                .then(self.documents[*a].url.cmp(&self.documents[*b].url))
        });
        search::Search {
            total: Some(ranked.len()),
            results: ranked
                .into_iter()
                .skip(start)
                .take(limit)
                .map(|(id, _, _)| {
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
