//! Copied pages and search results share one WARC response handler.

mod git;

use super::*;
use fictionet_extras::{crawl::Index, warc::Archive};
use std::{path::Path, time::Instant};

// Captured distributions and repository packs can exceed a public web response.
const PACKAGE_BYTES: usize = 256 * 1024 * 1024;
const INDEX_VERSION: u32 = 4;

pub(super) struct Corpus {
    archive: Archive,
    missing: Archive,
    index: Index,
    hosts: HashSet<String>,
    packages: Option<PackageSites>,
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
        let Some(mut response) = archived_response(&self.archive, &self.missing, url)? else {
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

#[derive(Serialize, Deserialize, PartialEq, Eq)]
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
        let path = entry?.path();
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
                        response.body = response.decoded_with_limit(PACKAGE_BYTES)?.into();
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
        Self::load_copied(seed, &root, &urls, model, true)
    }

    /// Open the copied sites and crawl them from their starting URLs.
    /// The crawler and HTTP replay use the same response handler.
    pub fn copied(
        seed: Seed,
        root: &Path,
        seeds: &[String],
        model: Option<Model>,
    ) -> Result<Self, String> {
        Self::load_copied(seed, root, seeds, model, false)
    }

    fn load_copied(
        seed: Seed,
        root: &Path,
        seeds: &[String],
        model: Option<Model>,
        cache_index: bool,
    ) -> Result<Self, String> {
        let started = Instant::now();
        let research_root = Archive::directory_root(root).map_err(|e| e.to_string())?;
        eprintln!("Loading copied pages…");
        let files = archive_files(&research_root).map_err(|e| e.to_string())?;
        let cache_path = cache_index.then(|| research_root.join("search-index.json"));
        let cached = cache_path
            .as_ref()
            .and_then(|path| std::fs::File::open(path).ok())
            .and_then(|file| {
                serde_json::from_reader::<_, CachedCorpus>(std::io::BufReader::new(file)).ok()
            })
            .filter(|cache| {
                cache.version == INDEX_VERSION && cache.files == files && cache.seeds == seeds
            });
        let (archive, missing, index) = match cached {
            Some(cache) => (cache.archive, cache.missing, Some(cache.index)),
            None => {
                eprintln!("Indexing copied pages…");
                (
                    Archive::directory(&research_root).map_err(|e| e.to_string())?,
                    missing_pages(&research_root).map_err(|e| e.to_string())?,
                    None,
                )
            }
        };
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
            index: Index::default(),
            hosts,
            packages,
        };
        corpus.index = match index {
            Some(index) => index,
            None => {
                let index = Index::crawl(
                    seeds,
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
                        let mut file = std::io::BufWriter::new(std::fs::File::create(&temporary)?);
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
        };
        if corpus.index.is_empty() {
            return Err("the copied corpus has no reachable HTML pages".into());
        }
        eprintln!(
            "Copied pages: {} indexed; ready in {:.3}s",
            corpus.index.len(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_indexes_are_reused_and_archive_changes_invalidate_them() {
        let root = std::env::temp_dir().join(format!(
            "search-cache-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("pages.warc.gz");
        let mut archive = Archive::default();
        let mut write = |body: &'static str| {
            archive
                .append(
                    &path,
                    "https://source.org/",
                    &fictionet_extras::warc::Response {
                        status: http::StatusCode::OK,
                        headers: http::HeaderMap::from_iter([(
                            http::header::CONTENT_TYPE,
                            "text/html".parse().unwrap(),
                        )]),
                        body: body.into(),
                    },
                )
                .unwrap()
        };
        let open = || {
            Pages::load_copied(
                Seed::builtin("web").unwrap(),
                &root,
                &["https://source.org/".into()],
                None,
                true,
            )
            .unwrap()
        };
        write("<title>Supply chain</title><p>Immutable actions</p>");
        let first = open();
        let cache = root.join("search-index.json");
        let saved = std::fs::read(&cache).unwrap();
        let second = open();
        assert_eq!(std::fs::read(&cache).unwrap(), saved);
        assert_eq!(
            first.copied_listing("immutable", 0).0,
            second.copied_listing("immutable", 0).0
        );
        write("<title>Build security</title><p>Credential isolation</p>");
        let updated = open();
        assert_eq!(updated.copied_listing("credential", 0).0.results.len(), 1);
        assert!(updated.copied_listing("immutable", 0).0.results.is_empty());
        assert_ne!(std::fs::read(&cache).unwrap(), saved);
        std::fs::write(&cache, b"interrupted write").unwrap();
        assert_eq!(open().copied_listing("credential", 0).0.results.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_real_not_found_pages_are_reused_and_override_raw_successes() {
        let root = std::env::temp_dir().join(format!(
            "copied-errors-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut archive = Archive::default();
        let mut missing = Archive::default();
        for (host, status) in [
            ("github.com", 404),
            ("denied.org", 403),
            ("limited.org", 429),
            ("login.org", 401),
        ] {
            let url = format!("https://{host}/404");
            let response = fictionet_extras::warc::Response {
                status: http::StatusCode::from_u16(status).unwrap(),
                headers: http::HeaderMap::new(),
                body: "Page not found · GitHub".into(),
            };
            missing
                .append(&root.join("missing-pages.warc.gz"), &url, &response)
                .unwrap();
            let mut raw = response;
            raw.status = http::StatusCode::OK;
            archive
                .append(&root.join("raw.warc.gz"), &url, &raw)
                .unwrap();
            archive
                .append(
                    &root.join("raw.warc.gz"),
                    &format!("https://{host}/denied"),
                    &fictionet_extras::warc::Response {
                        status: http::StatusCode::FORBIDDEN,
                        headers: Default::default(),
                        body: "Forbidden".into(),
                    },
                )
                .unwrap();
            for path in ["/psf/requests", "/psf", "/absent?query=1"] {
                let response =
                    archived_response(&archive, &missing, &format!("https://{host}{path}"))
                        .unwrap();
                if status == 404 {
                    let response = replay(Ok(response));
                    assert_eq!(response.status, 404);
                    assert_eq!(
                        String::from_utf8(response.body).unwrap(),
                        "Page not found · GitHub"
                    );
                } else {
                    assert!(response.is_none());
                    let response = replay(Ok(response));
                    assert_eq!(response.status, 404);
                    assert_eq!(response.body, b"Not Found\n");
                }
            }
            assert_eq!(
                archived_response(&archive, &missing, &format!("https://{host}/denied"))
                    .unwrap()
                    .unwrap()
                    .status,
                403
            );
        }
        let loaded = Archive::directory(&root).unwrap();
        assert_eq!(
            loaded
                .get("https://github.com/404")
                .unwrap()
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            archived_response(
                &loaded,
                &missing_pages(&root).unwrap(),
                "https://github.com/404"
            )
            .unwrap()
            .unwrap()
            .status,
            404
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn packages_keep_identity_bytes_and_missing_pages_keep_the_sites_response() {
        use fictionet_extras::warc;
        use std::io::Write;
        let root = std::env::temp_dir().join(format!(
            "search-copies-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(root.join("packages")).unwrap();
        let mut archive = Archive::default();
        let response = |status, content_type: &'static str, body: &[u8]| warc::Response {
            status,
            headers: http::HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static(content_type),
            )]),
            body: bytes::Bytes::copy_from_slice(body),
        };
        archive
            .append(
                &root.join("pages.warc.gz"),
                "https://source.org/",
                &response(
                    http::StatusCode::OK,
                    "text/html",
                    b"<title>Research</title><p>Source material</p>",
                ),
            )
            .unwrap();
        archive
            .append(
                &root.join("pages.warc.gz"),
                "https://github.com/research/advisory",
                &response(
                    http::StatusCode::OK,
                    "text/html",
                    b"<title>Security advisory</title><p>Research reference</p>",
                ),
            )
            .unwrap();
        archive
            .append(
                &root.join("packages/missing-pages.warc.gz"),
                "https://github.com/404",
                &response(
                    http::StatusCode::NOT_FOUND,
                    "text/html",
                    "<title>Page not found · GitHub</title>".as_bytes(),
                ),
            )
            .unwrap();
        let missing = b"<title>404 | Source</title><main><h1>We couldn't find that page.</h1><a href='/'>Source</a></main>";
        archive
            .append(
                &root.join("pages.warc.gz"),
                "https://source.org/404",
                &response(http::StatusCode::NOT_FOUND, "text/html", missing),
            )
            .unwrap();
        let identity = b"Metadata-Version: 2.4\nName: source\n";
        let mut compressed =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        compressed.write_all(identity).unwrap();
        let mut package = response(
            http::StatusCode::OK,
            "binary/octet-stream",
            &compressed.finish().unwrap(),
        );
        package.headers.insert(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_static("gzip"),
        );
        archive
            .append(
                &root.join("packages/files.warc.gz"),
                "https://files.pythonhosted.org/source.whl.metadata",
                &package,
            )
            .unwrap();
        let pages = Arc::new(
            Pages::copied(
                Seed::builtin("web").unwrap(),
                &root,
                &["https://source.org/".into()],
                None,
            )
            .unwrap(),
        );
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(5),
            |cx| async move {
                let (sender, mut records) =
                    tokio::sync::mpsc::channel(crate::observation::OBSERVATION_CAPACITY);
                pages.observe(sender);
                assert!(pages.serves_host("files.pythonhosted.org"));
                let reference = pages
                    .handle(&cx, "GET", "github.com", "/research/advisory", None)
                    .await;
                assert_eq!(reference.status, 200);
                assert!(
                    String::from_utf8(reference.body)
                        .unwrap()
                        .contains("Security advisory")
                );
                let absent = pages
                    .handle(&cx, "GET", "source.org", "/old-article", None)
                    .await;
                assert_eq!(absent.status, 404);
                assert_eq!(absent.body, missing);
                for copied in [true, false] {
                    pages
                        .copied_active
                        .store(copied, std::sync::atomic::Ordering::SeqCst);
                    let answer = pages
                        .handle(
                            &cx,
                            "GET",
                            "files.pythonhosted.org",
                            "/source.whl.metadata",
                            None,
                        )
                        .await;
                    assert_eq!(answer.status, 200);
                    assert_eq!(answer.body, identity);
                    let headers = answer.stored_headers.unwrap();
                    assert!(!headers.contains_key(http::header::CONTENT_ENCODING));
                    assert_eq!(
                        headers[http::header::CONTENT_LENGTH],
                        identity.len().to_string()
                    );
                    assert_eq!(
                        pages
                            .handle(&cx, "GET", "files.pythonhosted.org", "/absent.whl", None)
                            .await
                            .status,
                        404
                    );
                    let fetched = fictionet_extras::models::Engine::fetch(
                        pages.clone(),
                        cx.clone(),
                        "https://files.pythonhosted.org/source.whl.metadata".into(),
                    )
                    .await?;
                    assert_eq!(fetched.body, identity);
                    assert!(matches!(
                        records.try_recv().unwrap().fact,
                        crate::observation::SearchObs::Request {
                            source: crate::observation::PageSource::Copy { captured: Some(_) },
                            ..
                        }
                    ));
                }
                Ok(())
            },
        ))
        .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn the_seed_selects_the_corpus_and_starting_urls() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../extras/tests/fixtures/sky.warc.gz");
        let root = std::env::temp_dir().join(format!(
            "seed-corpus-{}-{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::copy(fixture, root.join("sky.warc.gz")).unwrap();
        let seed = Seed::parse(
            "capture",
            "+++\n[corpus]\ndirectory='.'\nurls=['https://sky.org/']\n+++\nCaptured pages",
            |_| unreachable!(),
        )
        .unwrap();
        let pages = Pages::from_corpus(seed.clone(), &root, None).unwrap();
        assert!(pages.serves_host("SKY.ORG."));
        assert!(!pages.serves_host("uncaptured.org"));
        assert_eq!(pages.copied.as_ref().unwrap().index.len(), 3);
        let mut absent = seed;
        absent.corpus.as_mut().unwrap().urls = vec!["https://uncaptured.org/".into()];
        assert!(Pages::from_corpus(absent, &root, None).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

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
            fictionet::Seed::from_u64(11),
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
