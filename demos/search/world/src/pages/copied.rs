//! Copied pages and search results share one WARC response handler.

use super::*;
use fictionet_extras::{crawl::Index, warc::Archive};
use std::{path::Path, time::Instant};

pub(super) struct Corpus {
    archive: Archive,
    index: Index,
}

impl Corpus {
    pub(super) fn response(
        &self,
        url: &str,
    ) -> std::io::Result<Option<fictionet_extras::warc::Response>> {
        use kuchiki::traits::TendrilSink;
        let Some(mut response) = self.archive.get(url)? else {
            return Ok(None);
        };
        // Reporting headers and these script elements only send telemetry or ads.
        response.headers.remove("report-to");
        response.headers.remove("nel");
        if response
            .headers
            .get("content-type")
            .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
        {
            let decoded = response.decoded()?;
            let dom = kuchiki::parse_html().one(String::from_utf8_lossy(&decoded).into_owned());
            let mut changed = false;
            for selector in [
                "script[src*=\"googletagmanager.com\"]",
                "script[src*=\"google-analytics.com\"]",
                "script[src*=\"doubleclick.net\"]",
                "script[src*=\"googlesyndication.com\"]",
                "script[src*=\"connect.facebook.net\"]",
                "iframe[src*=\"doubleclick.net\"]",
                "ins.adsbygoogle",
            ] {
                for node in dom.select(selector).unwrap().collect::<Vec<_>>() {
                    node.as_node().detach();
                    changed = true;
                }
            }
            if changed {
                response.body = dom.to_string().into_bytes().into();
                response.headers.remove("content-encoding");
                response.headers.remove("etag");
                response.headers.remove("content-md5");
                response.headers.insert(
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from(response.body.len()),
                );
            }
        }
        Ok(Some(response))
    }
}

impl Pages {
    pub(crate) fn capture_date(&self, url: &str) -> Option<String> {
        self.copied
            .as_ref()?
            .archive
            .captured(url)
            .map(str::to_owned)
    }
    pub fn has_copied(&self) -> bool {
        self.copied.is_some()
    }

    /// Open the copied sites and crawl them from their starting URLs.
    /// The crawler and HTTP replay use the same response handler.
    pub fn copied(
        seed: Seed,
        root: &Path,
        seeds: &[String],
        model: Option<Model>,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let archive = Archive::directory(root).map_err(|e| e.to_string())?;
        let scanned = started.elapsed();
        let mut corpus = Corpus {
            archive,
            index: Index::default(),
        };
        corpus.index = Index::crawl(
            seeds,
            |url| corpus.archive.contains(url),
            |url| corpus.response(url),
        )
        .map_err(|e| e.to_string())?;
        if corpus.index.is_empty() {
            return Err("the copied corpus has no reachable HTML pages".into());
        }
        eprintln!(
            "WARC scan: {:.3}s; crawl and index: {:.3}s; {} pages",
            scanned.as_secs_f64(),
            (started.elapsed() - scanned).as_secs_f64(),
            corpus.index.len()
        );
        let mut pages = match model {
            Some(model) => Self::with_model(seed, model),
            None => Self::open(seed, Store::memory(), None, 0),
        };
        pages.prefetch = 0;
        pages.copied = Some(corpus);
        pages.copied_active = true.into();
        pages.store().generation.generate = true;
        Ok(pages)
    }

    pub(crate) fn copied_only(&self) -> bool {
        self.copied.is_some() && self.copied_active.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn copied_listing(
        &self,
        query: &str,
        start: u64,
    ) -> (search::Search, Cache, Option<Usage>, u64) {
        (
            self.copied.as_ref().unwrap().index.search(
                query,
                start.try_into().unwrap_or(usize::MAX),
                10,
            ),
            Cache::Cached,
            None,
            0,
        )
    }

    pub(super) fn copied_page(&self, host: &str, target: &str) -> Response {
        self.copied_url(&format!("https://{host}{target}"))
    }

    pub(crate) fn copied_url(&self, url: &str) -> Response {
        replay(url, self.copied.as_ref().unwrap().response(url))
    }
}

pub(super) fn replay(
    url: &str,
    response: std::io::Result<Option<fictionet_extras::warc::Response>>,
) -> Response {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    match response {
        Ok(Some(page)) => {
            let content_type = page
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_owned();
            let meta = if page.status.is_redirection() {
                Meta::Redirect {
                    location: page
                        .headers
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("/")
                        .to_owned(),
                }
            } else if content_type.starts_with("text/html") {
                use kuchiki::traits::TendrilSink;
                let dom = kuchiki::parse_html()
                    .one(String::from_utf8_lossy(&page.decoded().unwrap_or_default()).into_owned());
                let title = dom
                    .select_first("title")
                    .ok()
                    .map(|n| n.text_contents())
                    .unwrap_or_default();
                Meta::Fixed { title }
            } else {
                Meta::Asset
            };
            let mut answer = Response::new(
                page.status.as_u16(),
                content_type,
                page.body.to_vec(),
                vec![],
                meta,
            );
            let mut headers = page.headers;
            if let Some(connection) = headers
                .get("connection")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
            {
                for name in connection.split(',').map(str::trim) {
                    headers.remove(name);
                }
            }
            for name in [
                "connection",
                "keep-alive",
                "transfer-encoding",
                "proxy-connection",
            ] {
                headers.remove(name);
            }
            answer.stored_headers = Some(headers);
            answer
        }
        Ok(None) => Response::html(
            format!(
                "<!doctype html><title>Page not found</title><h1>Page not found</h1><p>The requested page is unavailable on {}.</p>",
                text::escape(&host)
            ),
            Meta::Missing,
            404,
            "nginx",
        ),
        Err(error) => Response::html(
            format!(
                "<!doctype html><title>Server error</title><h1>Server error</h1><p>{}</p>",
                text::escape(&error.to_string())
            ),
            Meta::Missing,
            500,
            "nginx",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engines_and_page_requests_share_the_copied_corpus() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../extras/tests/fixtures");
        let pages = Arc::new(
            Pages::copied(
                Seed::builtin("web").unwrap(),
                &root,
                &["https://sky.org/".into()],
                None,
            )
            .unwrap(),
        );
        let archived = pages
            .copied
            .as_ref()
            .unwrap()
            .response("https://sky.org/black-hole")
            .unwrap()
            .unwrap();
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(11)),
            |cx| async move {
                let mut lists = Vec::new();
                for (host, target) in [
                    ("www.google.com", "/search?q=black+hole"),
                    ("www.bing.com", "/search?q=black+hole"),
                    ("html.duckduckgo.com", "/html/?q=black+hole"),
                ] {
                    let response = pages.handle(&cx, "GET", host, target, None).await;
                    assert_eq!(response.status, 200);
                    let Meta::Search(list) = response.meta else {
                        panic!("search metadata missing")
                    };
                    assert_eq!(list.listed.len(), 1);
                    assert_eq!(list.listed[0].0, "https://sky.org/black-hole");
                    assert_eq!(list.listed[0].1, "Black holes");
                    assert!(
                        String::from_utf8(response.body)
                            .unwrap()
                            .contains("spacetime")
                    );
                    lists.push(list.listed);
                    let missing = pages
                        .handle(
                            &cx,
                            "GET",
                            host,
                            &target.replace("black+hole", "dishwasher"),
                            None,
                        )
                        .await;
                    let Meta::Search(list) = missing.meta else {
                        panic!("search metadata missing")
                    };
                    assert!(list.listed.is_empty());
                }
                assert!(lists.windows(2).all(|pair| pair[0] == pair[1]));
                let response = pages
                    .handle(&cx, "GET", "sky.org", "/black-hole", None)
                    .await;
                assert_eq!(response.status, archived.status.as_u16());
                assert_eq!(response.body, archived.body);
                assert_eq!(
                    pages
                        .handle(&cx, "GET", "sky.org", "/outside", None)
                        .await
                        .status,
                    404
                );
                assert_eq!(pages.new_pages(), NewPages::Copied);
                let refused = pages.apply(
                    &cx,
                    Command::SetNewPages {
                        new_pages: NewPages::ModelWritten,
                        expected_revision: 0,
                    },
                );
                assert!(matches!(refused, Err(Rejected::Invalid { .. })));
                assert_eq!(pages.new_pages(), NewPages::Copied);
                assert_eq!(pages.generation().revision, 0);
                Ok(())
            },
        ))
        .unwrap();
    }
}
