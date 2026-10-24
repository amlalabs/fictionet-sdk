//! Copied pages and search results share one WARC response handler.

mod git;
mod reference;

use super::*;
use fictionet_extras::{crawl::Index, warc::Archive};
use std::collections::HashMap;
use std::{path::Path, time::Instant};
use tokio::sync::OnceCell;

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
    /// Package files the capture lacks, copied from their real hosts when
    /// first asked for and kept for the run.
    fetched: Mutex<HashMap<String, Arc<OnceCell<fictionet_extras::warc::Response>>>>,
}

impl PackageSites {
    /// The copy of `url` made this run, if one is done.
    fn fetched(&self, url: &str) -> Option<fictionet_extras::warc::Response> {
        self.fetched.lock().unwrap().get(url)?.get().cloned()
    }
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
    if let Some(file) = static_file(url)
        && let Some(response) = archive.get(&file)?
    {
        return Ok(Some(response));
    }
    if fallback.is_some() {
        return Ok(fallback);
    }
    Ok(archive
        .get(absent.as_str())?
        .filter(|response| response.status == http::StatusCode::NOT_FOUND))
}

/// A stylesheet, script, image or font asked for with a query, without it.
/// Pages version their files (`pydoctheme.css?v=48df1187`) and their servers
/// send the same file whatever the query; captures keep the file once.
fn static_file(url: &str) -> Option<String> {
    let mut url = url::Url::parse(url).ok()?;
    url.query()?;
    let (_, extension) = url.path().rsplit_once('.')?;
    let file = matches!(
        extension.to_ascii_lowercase().as_str(),
        "css"
            | "js"
            | "mjs"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "svg"
            | "webp"
            | "avif"
            | "ico"
            | "woff"
            | "woff2"
            | "ttf"
            | "otf"
            | "eot"
    );
    file.then(|| {
        url.set_query(None);
        url.into()
    })
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
        // Captured pages replay as recorded, including their own scripts.
        if let CorpusSearch::Reference(reference) = &self.search
            && let Some(response) = reference.response(url)?
        {
            return Ok(Some(response));
        }
        archived_response(&self.archive, &self.missing, url)
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
    pub(crate) fn copied_body(&self, url: String) -> Option<PageBody> {
        (self.source() == Source::Copied).then(|| {
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

    /// A package site's answer for `url`, whatever the page source: the
    /// captured response, else the real host's, copied when first asked
    /// for and kept for the run, so installs work for packages the capture
    /// never saw. `None` for other sites.
    pub(crate) async fn package(&self, cx: &Cx, url: &str) -> Option<Response> {
        let captured = self.package_url(url)?;
        if captured.status != 404 {
            return Some(captured);
        }
        let packages = self.copied.as_ref()?.packages.as_ref()?;
        let cell = packages
            .fetched
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_default()
            .clone();
        // A host that cannot be reached leaves the capture's answer.
        match cell.get_or_try_init(|| self.fetcher.package(cx, url)).await {
            Ok(response) => Some(package_response(Ok(Some(response.clone())))),
            Err(error) => {
                eprintln!("Package file {url} could not be copied: {error}");
                Some(captured)
            }
        }
    }

    /// A package site's captured answer, or one already copied this run.
    pub(crate) fn package_url(&self, url: &str) -> Option<Response> {
        let corpus = self.copied.as_ref()?;
        let packages = corpus.packages.as_ref()?;
        let parsed = url::Url::parse(url).ok()?;
        if let Some(fetched) = packages.fetched(url) {
            return Some(package_response(Ok(Some(fetched))));
        }
        packages.hosts.contains(parsed.host_str()?).then(|| {
            let captured = if !packages.archive.contains(url) && corpus.archive.contains(url) {
                corpus.response(url)
            } else {
                archived_response(&packages.archive, &packages.missing, url)
            };
            package_response(captured)
        })
    }

    pub fn has_copied(&self) -> bool {
        self.copied.is_some()
    }

    /// In copied mode only captured hosts and the local search engines exist.
    /// Live worlds may admit any public hostname.
    pub fn serves_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        crate::admit(&host).is_ok()
            && (self.source() != Source::Copied
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
    pub fn from_corpus(seed: Seed, downloads: &Path) -> Result<Self, String> {
        let corpus = seed
            .corpus
            .as_ref()
            .ok_or("the seed has no copied corpus")?;
        let root = downloads.join(&corpus.directory);
        let urls = corpus.urls.clone();
        let reference = corpus
            .reference
            .as_ref()
            .map(|directory| reference::ReferenceWeb::open(&downloads.join(directory), &root))
            .transpose()?;
        Self::load_copied(seed, &root, &urls, reference)
    }

    /// Opens the copied sites; without a reference web, they are crawled
    /// from their starting URLs with the same response handler replay uses.
    fn load_copied(
        seed: Seed,
        root: &Path,
        seeds: &[String],
        mut reference: Option<reference::ReferenceWeb>,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let research_root = Archive::directory_root(root).map_err(|e| e.to_string())?;
        eprintln!("Loading copied pages…");
        let files = match &reference {
            Some(_) => Vec::new(),
            None => archive_files(&research_root).map_err(|e| e.to_string())?,
        };
        let cache_path = reference
            .is_none()
            .then(|| research_root.join("search-index.json"));
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
        let (archive, missing, index) = if let Some(reference) = &mut reference {
            (
                std::mem::take(&mut reference.research),
                std::mem::take(&mut reference.missing),
                None,
            )
        } else {
            match cached {
                Some(cache) => (cache.archive, cache.missing, Some(cache.index)),
                None => (
                    Archive::open(files.iter().map(|file| file.path.clone()))
                        .map_err(|e| e.to_string())?,
                    missing_pages(&research_root).map_err(|e| e.to_string())?,
                    None,
                ),
            }
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
                fetched: Mutex::default(),
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
        let mut pages = Self::with_source(seed, Source::Copied);
        pages.copied = Some(Arc::new(corpus));
        Ok(pages)
    }

    /// The day the copied pages were copied, which Copied mode shows as
    /// the world's day.
    pub fn copied_date(&self) -> Option<time::Date> {
        match &self.copied.as_ref()?.search {
            CorpusSearch::Reference(reference) => reference.date,
            CorpusSearch::Crawled(_) => None,
        }
    }

    /// How far the copied pages' day is behind the world's own day: Copied
    /// mode sets the guest's clock and the sites' dates back by this much.
    pub fn copied_lag(&self) -> Option<std::time::Duration> {
        let lag = seed::parse_date(&self.seed.date).ok()? - self.copied_date()?;
        std::time::Duration::try_from(lag)
            .ok()
            .filter(|lag| !lag.is_zero())
    }

    /// The world's day as the active source shows it.
    pub fn world_date(&self) -> String {
        match self
            .copied_date()
            .filter(|_| self.source() == Source::Copied)
        {
            Some(date) => date.to_string(),
            None => self.seed.date.clone(),
        }
    }

    pub(super) fn copied_listing(
        &self,
        query: &str,
        start: u64,
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<search::Search, String> {
        let corpus = self.copied.as_ref().unwrap();
        Ok(match &corpus.search {
            CorpusSearch::Reference(reference) => reference
                .index
                .search_in(
                    query,
                    start.try_into().unwrap_or(usize::MAX),
                    10,
                    domains,
                    |url| {
                        let response = corpus
                            .response(url)?
                            .ok_or_else(|| std::io::Error::other("indexed page is unavailable"))?;
                        fictionet_extras::capture::page_text(&String::from_utf8_lossy(
                            &response.decoded()?,
                        ))
                    },
                )
                .map_err(|error| error.to_string())?,
            CorpusSearch::Crawled(index) => {
                index.search_in(query, start.try_into().unwrap_or(usize::MAX), 10, |url| {
                    fictionet_extras::models::tools::allowed(domains, url)
                })
            }
        })
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
                Meta::Document { title }
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
        Ok(None) => Response::not_found(),
        Err(_) => Response::new(
            500,
            "text/plain; charset=utf-8",
            "Internal Server Error\n",
            vec![],
            Meta::Missing,
        ),
    }
}

/// A package file as installers need it: the identity bytes they hash,
/// whatever content encoding the capture kept.
fn package_response(
    response: std::io::Result<Option<fictionet_extras::warc::Response>>,
) -> Response {
    replay(response.and_then(|response| {
        response
            .map(|mut response| {
                response.body = response.decoded()?.into();
                response.headers.remove(http::header::CONTENT_ENCODING);
                response
                    .headers
                    .insert(http::header::CONTENT_LENGTH, response.body.len().into());
                Ok(response)
            })
            .transpose()
    }))
}
