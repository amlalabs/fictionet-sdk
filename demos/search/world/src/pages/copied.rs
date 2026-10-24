//! Copied pages and search results share one WARC response handler.

mod git;
mod reference;

use super::*;
use fictionet_extras::{crawl::Index, warc::Archive};
use std::{path::Path, time::Instant};

const INDEX_VERSION: u32 = 6;

pub(super) struct Corpus {
    archive: Archive,
    missing: Archive,
    search: CorpusSearch,
    hosts: HashSet<String>,
    packages: Option<PackageSites>,
}

enum CorpusSearch {
    Crawled(Index),
    Reference(Box<reference::ReferenceWeb>),
}

/// A retained page identity. Copied bodies are read from the immutable corpus
/// when the reader opens them, independently of observation retention limits.
#[derive(Clone)]
pub struct PageBody(BodySource);

#[derive(Clone)]
enum BodySource {
    Copied { corpus: Arc<Corpus>, url: String },
    Text(Arc<str>),
}

impl std::fmt::Debug for PageBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PageBody")
    }
}

impl From<Arc<str>> for PageBody {
    fn from(text: Arc<str>) -> Self {
        Self(BodySource::Text(text))
    }
}

impl PageBody {
    /// Load the complete decoded document without making a guest request.
    pub fn text(&self) -> std::io::Result<Arc<str>> {
        match &self.0 {
            BodySource::Text(text) => Ok(text.clone()),
            BodySource::Copied { corpus, url } => {
                let response = corpus
                    .response(url)?
                    .ok_or_else(|| std::io::Error::other("recorded page is unavailable"))?;
                Ok(Arc::from(
                    String::from_utf8_lossy(&response.decoded()?).as_ref(),
                ))
            }
        }
    }
}

struct PackageSites {
    git: std::path::PathBuf,
    archive: Archive,
    missing: Archive,
    hosts: HashSet<String>,
}

fn archived_response(
    archive: &Archive,
    missing: &Archive,
    url: &str,
) -> std::io::Result<Option<fictionet_extras::warc::Response>> {
    let mut absent = url::Url::parse(url).map_err(std::io::Error::other)?;
    absent.set_path("/404");
    absent.set_query(None);
    absent.set_fragment(None);
    let fallback = missing
        .get(absent.as_str())?
        .filter(|response| response.status == http::StatusCode::NOT_FOUND);
    // The curated not-found response takes precedence over raw captures of /404.
    if fictionet_extras::warc::key(url).as_deref() == Some(absent.as_str()) && fallback.is_some() {
        return Ok(fallback);
    }
    if let Some(response) = archive.get(url)? {
        return Ok(Some(response));
    }
    if fallback.is_some() {
        return Ok(fallback);
    }
    Ok(archive
        .get(absent.as_str())?
        .filter(|response| response.status == http::StatusCode::NOT_FOUND))
}

fn missing_pages(root: &Path) -> std::io::Result<Archive> {
    let path = root.join("missing-pages.warc.gz");
    Archive::open(path.is_file().then_some(path))
}

impl Corpus {
    pub(super) fn response(
        &self,
        url: &str,
    ) -> std::io::Result<Option<fictionet_extras::warc::Response>> {
        use kuchiki::traits::TendrilSink;
        let response = if let CorpusSearch::Reference(reference) = &self.search {
            reference.response(url)?
        } else {
            None
        };
        let Some(mut response) = response.or(archived_response(&self.archive, &self.missing, url)?)
        else {
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

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ArchiveFile {
    path: std::path::PathBuf,
    bytes: u64,
    modified: std::time::SystemTime,
}

#[derive(Serialize, Deserialize)]
struct CachedCorpus {
    version: u32,
    files: Vec<ArchiveFile>,
    seeds: Vec<String>,
    archive: Archive,
    missing: Archive,
    index: Index,
}

fn archive_files(root: &Path) -> std::io::Result<Vec<ArchiveFile>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            continue;
        }
        let path = entry.path();
        if path.to_string_lossy().ends_with(".warc.gz") {
            let path = std::fs::canonicalize(path)?;
            let metadata = path.metadata()?;
            files.push(ArchiveFile {
                path,
                bytes: metadata.len(),
                modified: metadata.modified()?,
            });
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

impl Pages {
    pub(super) fn reference_text(&self, url: &str) -> std::io::Result<Option<String>> {
        let Some(corpus) = &self.copied else {
            return Ok(None);
        };
        let Some(response) = corpus.response(url)? else {
            return Ok(None);
        };
        if response.status != http::StatusCode::OK
            || !response
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html"))
        {
            return Ok(None);
        }
        fictionet_extras::capture::page_text(&String::from_utf8_lossy(&response.decoded()?))
            .map(Some)
    }

    pub(crate) fn copied_body(&self, url: String) -> Option<PageBody> {
        self.copied_only().then(|| {
            PageBody(BodySource::Copied {
                corpus: self.copied.as_ref().unwrap().clone(),
                url,
            })
        })
    }

    pub(crate) fn capture_date(&self, url: &str) -> Option<String> {
        let corpus = self.copied.as_ref()?;
        corpus
            .archive
            .captured(url)
            .or_else(|| corpus.packages.as_ref()?.archive.captured(url))
            .map(str::to_owned)
    }

    /// Package sites always replay captured responses, regardless of the page source.
    pub(crate) fn package_url(&self, url: &str) -> Option<Response> {
        let corpus = self.copied.as_ref()?;
        let packages = corpus.packages.as_ref()?;
        let parsed = url::Url::parse(url).ok()?;
        packages.hosts.contains(parsed.host_str()?).then(|| {
            let captured = if !packages.archive.contains(url) && corpus.archive.contains(url) {
                corpus.response(url)
            } else {
                archived_response(&packages.archive, &packages.missing, url)
            };
            let response = captured.and_then(|response| {
                response
                    .map(|mut response| {
                        // Installers hash the distribution's identity bytes. Their
                        // requests need not accept the capture's content encoding.
                        response.body = response.decoded()?.into();
                        response.headers.remove(http::header::CONTENT_ENCODING);
                        response
                            .headers
                            .insert(http::header::CONTENT_LENGTH, response.body.len().into());
                        Ok(response)
                    })
                    .transpose()
            });
            replay(response)
        })
    }
    pub fn has_copied(&self) -> bool {
        self.copied.is_some()
    }

    /// In copied mode only captured hosts and the local search engines exist.
    /// Generated and live worlds may admit new public hostnames.
    pub fn serves_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        crate::admit(&host).is_ok()
            && (!self.copied_only()
                || crate::route::SEARCH_HOSTS.contains(&host.as_str())
                || self.copied.as_ref().is_some_and(|corpus| {
                    corpus.hosts.contains(&host)
                        || matches!(&corpus.search, CorpusSearch::Reference(web) if web.serves(&host))
                        || corpus
                            .packages
                            .as_ref()
                            .is_some_and(|packages| packages.hosts.contains(&host))
                }))
    }

    /// Open the corpus chosen by the world's brief, relative to the downloads root.
    /// Its search index is cached beside the immutable archives.
    pub fn from_corpus(seed: Seed, downloads: &Path, model: Option<Model>) -> Result<Self, String> {
        let corpus = seed
            .corpus
            .as_ref()
            .ok_or("the seed has no copied corpus")?;
        let root = downloads.join(&corpus.directory);
        let urls = corpus.urls.clone();
        let reference = corpus
            .reference
            .as_ref()
            .map(|directory| reference::ReferenceWeb::open(&downloads.join(directory)))
            .transpose()?;
        Self::load_copied(seed, &root, &urls, model, true, reference)
    }

    /// Open the copied sites and crawl them from their starting URLs.
    /// The crawler and HTTP replay use the same response handler.
    pub fn copied(
        seed: Seed,
        root: &Path,
        seeds: &[String],
        model: Option<Model>,
    ) -> Result<Self, String> {
        Self::load_copied(seed, root, seeds, model, false, None)
    }

    fn load_copied(
        seed: Seed,
        root: &Path,
        seeds: &[String],
        model: Option<Model>,
        cache_index: bool,
        reference: Option<reference::ReferenceWeb>,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let research_root = Archive::directory_root(root).map_err(|e| e.to_string())?;
        eprintln!("Loading copied pages…");
        let files = match &reference {
            Some(reference) => reference.files_for(&research_root),
            None => archive_files(&research_root).map_err(|e| e.to_string())?,
        };
        let cache_path = cache_index.then(|| research_root.join("search-index.json"));
        let cached = cache_path
            .as_ref()
            .and_then(|path| std::fs::File::open(path).ok())
            .and_then(|file| {
                serde_json::from_reader::<_, CachedCorpus>(std::io::BufReader::new(file)).ok()
            })
            .filter(|cache| {
                (reference.is_some() || cache.version == INDEX_VERSION)
                    && cache.files == files
                    && cache.seeds == seeds
            });
        let (archive, missing, index) = match cached {
            Some(cache) => (cache.archive, cache.missing, Some(cache.index)),
            None => (
                Archive::open(files.iter().map(|file| file.path.clone()))
                    .map_err(|e| e.to_string())?,
                missing_pages(&research_root).map_err(|e| e.to_string())?,
                None,
            ),
        };
        if !seeds.iter().any(|url| archive.contains(url)) {
            return Err("the copied corpus has none of its starting URLs".into());
        }
        let hosts = archive
            .urls()
            .filter_map(|url| url::Url::parse(url).ok()?.host_str().map(str::to_owned))
            .collect();
        let package_root = root.join("packages");
        let packages = if package_root.is_dir() {
            // Resolve once: a later publication must not change this reader's paths.
            let package_root = if package_root
                .join("current")
                .try_exists()
                .map_err(|e| e.to_string())?
            {
                std::fs::canonicalize(package_root.join("current")).map_err(|e| e.to_string())?
            } else {
                package_root
            };
            let archive = Archive::directory(&package_root).map_err(|e| e.to_string())?;
            let hosts = archive
                .urls()
                .filter_map(|url| url::Url::parse(url).ok()?.host_str().map(str::to_owned))
                .collect();
            Some(PackageSites {
                git: package_root.join("git"),
                archive,
                missing: missing_pages(&package_root).map_err(|e| e.to_string())?,
                hosts,
            })
        } else {
            None
        };
        let mut corpus = Corpus {
            archive,
            missing,
            search: CorpusSearch::Crawled(Index::default()),
            hosts,
            packages,
        };
        corpus.search = if let Some(reference) = reference {
            CorpusSearch::Reference(Box::new(reference))
        } else {
            CorpusSearch::Crawled(match index {
                Some(index) => index,
                None => {
                    let index = Index::crawl(
                        &corpus.archive.urls().map(str::to_owned).collect::<Vec<_>>(),
                        |url| corpus.archive.contains(url),
                        |url| corpus.response(url),
                    )
                    .map_err(|e| e.to_string())?;
                    if let Some(cache_path) = cache_path {
                        let cache = CachedCorpus {
                            version: INDEX_VERSION,
                            files,
                            seeds: seeds.to_vec(),
                            archive: corpus.archive,
                            missing: corpus.missing,
                            index,
                        };
                        let temporary = cache_path.with_extension(format!(
                            "{}-{}.tmp",
                            std::process::id(),
                            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
                        ));
                        let saved = (|| -> std::io::Result<()> {
                            use std::io::Write;
                            let mut file =
                                std::io::BufWriter::new(std::fs::File::create(&temporary)?);
                            serde_json::to_writer(&mut file, &cache)?;
                            file.flush()?;
                            std::fs::rename(&temporary, &cache_path)
                        })();
                        if let Err(error) = saved {
                            let _ = std::fs::remove_file(&temporary);
                            eprintln!("Search index cache unavailable: {error}");
                        }
                        corpus.archive = cache.archive;
                        corpus.missing = cache.missing;
                        cache.index
                    } else {
                        index
                    }
                }
            })
        };
        if matches!(&corpus.search, CorpusSearch::Crawled(index) if index.is_empty()) {
            return Err("the copied corpus has no reachable HTML pages".into());
        }
        eprintln!(
            "Copied pages: {} indexed; ready in {:.3}s",
            match &corpus.search {
                CorpusSearch::Crawled(index) => index.len() as u64,
                CorpusSearch::Reference(reference) => reference.index.len(),
            },
            started.elapsed().as_secs_f64()
        );
        let mut pages = match model {
            Some(model) => Self::with_model(seed, model),
            None => Self::open(seed, Store::memory(), None, 0),
        };
        pages.prefetch = 0;
        pages.copied = Some(Arc::new(corpus));
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
    ) -> Result<(search::Search, Cache, Option<Usage>, u64), Stop> {
        let corpus = self.copied.as_ref().unwrap();
        let search = match &corpus.search {
            CorpusSearch::Reference(reference) => reference
                .index
                .search(query, start.try_into().unwrap_or(usize::MAX), 10, |url| {
                    let response = corpus
                        .response(url)?
                        .ok_or_else(|| std::io::Error::other("indexed page is unavailable"))?;
                    fictionet_extras::capture::page_text(&String::from_utf8_lossy(
                        &response.decoded()?,
                    ))
                })
                .map_err(Stop::store)?,
            CorpusSearch::Crawled(index) => {
                index.search(query, start.try_into().unwrap_or(usize::MAX), 10)
            }
        };
        Ok((search, Cache::Cached, None, 0))
    }

    pub(super) fn copied_page(&self, host: &str, target: &str) -> Response {
        self.copied_url(&format!("https://{host}{target}"))
    }

    pub(crate) fn copied_url(&self, url: &str) -> Response {
        replay(self.copied.as_ref().unwrap().response(url))
    }
}

pub(super) fn replay(
    response: std::io::Result<Option<fictionet_extras::warc::Response>>,
) -> Response {
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
                let title = fictionet_extras::capture::title(&page).unwrap_or_default();
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
        Ok(None) => Response::new(
            404,
            "text/plain; charset=utf-8",
            "Not Found\n",
            vec![],
            Meta::Missing,
        ),
        Err(_) => Response::new(
            500,
            "text/plain; charset=utf-8",
            "Internal Server Error\n",
            vec![],
            Meta::Missing,
        ),
    }
}
