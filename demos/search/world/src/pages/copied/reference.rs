//! The offline reference web and its prepared search index.

use super::*;
use fictionet_extras::{
    crawl::{DiskIndex, DiskWriter},
    warc,
};
use rayon::prelude::*;
use std::io;
use zim::{MimeType, Namespace, Target, Zim};

pub(super) struct ReferenceWeb {
    /// The day the Wikipedia copy was made, from its own metadata.
    pub(super) date: Option<time::Date>,
    pub index: DiskIndex,
    wikipedia: Zim,
    documents: Archive,
    hosts: HashSet<String>,
    pub(super) research: Archive,
    pub(super) missing: Archive,
}

fn wiki_file(root: &Path) -> std::path::PathBuf {
    root.join("wikipedia_en_all_nopic_2026-06.zim")
}

#[derive(Serialize, Deserialize)]
struct Prepared {
    #[serde(default)]
    documents_version: u32,
    files: Vec<ArchiveFile>,
    documents: Archive,
    research: Archive,
    missing: Archive,
}

fn sources(root: &Path, research: &Path) -> io::Result<Vec<ArchiveFile>> {
    let mut files = archive_files(&Archive::directory_root(research)?)?;
    files.extend(archive_files(root)?);
    let path = std::fs::canonicalize(wiki_file(root))?;
    let metadata = path.metadata()?;
    files.push(ArchiveFile {
        path,
        bytes: metadata.len(),
        modified: metadata.modified()?,
    });
    Ok(files)
}

fn available_space(root: &Path) -> io::Result<u64> {
    let path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // statvfs initializes the output on success; the path is NUL terminated.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail * stats.f_frsize)
}

impl ReferenceWeb {
    /// Open the prepared index. Research batches published after preparation,
    /// such as later page requisites, are served without reindexing.
    pub fn open(root: &Path, research_path: &Path) -> Result<Self, String> {
        let wikipedia = Zim::new(wiki_file(root))
            .map_err(|e| format!("Offline Wikipedia: {e}. Run cargo xtask search-web"))?;
        let index = DiskIndex::open(&root.join("index/current"))
            .map_err(|e| format!("Offline search index: {e}. Run cargo xtask search-web"))?;
        let prepared: Prepared = serde_json::from_str(
            &index
                .source()
                .map_err(|e| e.to_string())?
                .ok_or("offline index has no sources")?,
        )
        .map_err(|e| e.to_string())?;
        for file in &prepared.files {
            let metadata = file.path.metadata().map_err(|e| e.to_string())?;
            if metadata.len() != file.bytes
                || metadata.modified().map_err(|e| e.to_string())? != file.modified
            {
                return Err(format!(
                    "Indexed archive changed: {}. Run cargo xtask search-web with --index",
                    file.path.display()
                ));
            }
        }
        let mut research = prepared.research;
        let indexed: HashSet<_> = prepared.files.iter().map(|file| &file.path).collect();
        let mut later =
            archive_files(&Archive::directory_root(research_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        later.retain(|file| !indexed.contains(&file.path));
        if !later.is_empty() {
            later.sort_by(|a, b| (a.modified, &a.path).cmp(&(b.modified, &b.path)));
            eprintln!(
                "Captured archives published after indexing: {}",
                later.len()
            );
            research.extend(
                Archive::open(later.into_iter().map(|file| file.path))
                    .map_err(|e| e.to_string())?,
            );
        }
        let documents = prepared.documents;
        let hosts = documents
            .urls()
            .filter_map(|url| url::Url::parse(url).ok()?.host_str().map(str::to_owned))
            .collect();
        eprintln!("Offline web: {} indexed pages", index.len());
        let date = wikipedia
            .metadata("Date")
            .ok()
            .flatten()
            .and_then(|content| content.to_vec().ok())
            .and_then(|date| super::seed::parse_date(String::from_utf8_lossy(&date).trim()).ok());
        Ok(Self {
            date,
            index,
            wikipedia,
            documents,
            hosts,
            research,
            missing: prepared.missing,
        })
    }

    pub fn serves(&self, host: &str) -> bool {
        host == "en.wikipedia.org" || self.hosts.contains(host)
    }

    /// The Wikipedia copy's entry for `url`, when it holds one.
    fn article(&self, parsed: &url::Url) -> io::Result<Option<zim::DirectoryEntry>> {
        if parsed.host_str() != Some("en.wikipedia.org") {
            return Ok(None);
        }
        let path = percent_encoding::percent_decode_str(parsed.path())
            .decode_utf8()
            .map_err(io::Error::other)?;
        let path = path
            .strip_prefix("/wiki/")
            .unwrap_or_else(|| path.trim_start_matches('/'));
        let path = path.replace(' ', "_");
        self.wikipedia
            .get_by_path(Namespace::UserContent, &path)
            .map_err(io::Error::other)
    }

    /// When each page this web copied besides Wikipedia's was copied
    /// (RFC 3339).
    pub fn capture_times(&self) -> impl Iterator<Item = &str> {
        self.documents
            .capture_times()
            .chain(self.research.capture_times())
    }

    /// When the copy this web answers `url` with was made (RFC 3339): the
    /// Wikipedia copy's day for its articles, the capture's time for other
    /// pages. `None` when this web does not answer it.
    pub fn captured(&self, url: &str) -> Option<Option<String>> {
        let parsed = url::Url::parse(url).ok()?;
        if self.article(&parsed).ok().flatten().is_some() {
            return Some(self.date.map(|date| format!("{date}T00:00:00Z")));
        }
        self.documents
            .contains(url)
            .then(|| self.documents.captured(url).map(str::to_owned))
    }

    pub fn response(&self, url: &str) -> io::Result<Option<warc::Response>> {
        let parsed = url::Url::parse(url).map_err(io::Error::other)?;
        let Some(entry) = self.article(&parsed)? else {
            return archived_response(&self.documents, &self.documents, url);
        };
        if let Some(Target::Redirect(target)) = entry.target {
            let target = self
                .wikipedia
                .get_by_url_index(target)
                .map_err(io::Error::other)?;
            return Ok(Some(warc::Response {
                status: http::StatusCode::MOVED_PERMANENTLY,
                headers: http::HeaderMap::from_iter([(
                    http::header::LOCATION,
                    article_url(&target.url).parse().map_err(io::Error::other)?,
                )]),
                body: Default::default(),
            }));
        }
        let MimeType::Type(content_type) = &entry.mime_type else {
            return Ok(None);
        };
        let content = self
            .wikipedia
            .entry_content(&entry)
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("Wikipedia entry has no content"))?;
        let body = content.to_vec().map_err(io::Error::other)?;
        if content_type.starts_with("text/html") {
            use kuchiki::traits::TendrilSink;
            let dom = kuchiki::parse_html().one(String::from_utf8_lossy(&body).into_owned());
            if let Ok(refresh) = dom.select_first("meta[http-equiv]") {
                let attributes = refresh.attributes.borrow();
                if attributes
                    .get("http-equiv")
                    .is_some_and(|value| value.eq_ignore_ascii_case("refresh"))
                    && let Some((_, destination)) = attributes
                        .get("content")
                        .and_then(|value| value.split_once(';'))
                    && let Some((key, destination)) = destination.trim().split_once('=')
                    && key.eq_ignore_ascii_case("url")
                {
                    let destination = parsed
                        .join(destination.trim_matches(['\'', '"']))
                        .map_err(io::Error::other)?;
                    return Ok(Some(warc::Response {
                        status: http::StatusCode::MOVED_PERMANENTLY,
                        headers: http::HeaderMap::from_iter([(
                            http::header::LOCATION,
                            destination.as_str().parse().map_err(io::Error::other)?,
                        )]),
                        body: Default::default(),
                    }));
                }
            }
        }
        Ok(Some(warc::Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                content_type.parse().map_err(io::Error::other)?,
            )]),
            body: body.into(),
        }))
    }
}

fn article_url(path: &str) -> String {
    let mut url = url::Url::parse("https://en.wikipedia.org/wiki/").unwrap();
    url.path_segments_mut().unwrap().pop_if_empty().push(path);
    url.into()
}

impl Pages {
    /// Build one BM25 index over every captured research and reference page.
    /// The resulting immutable directory is published only after all merges finish.
    pub fn prepare_reference(mut seed: Seed, downloads: &Path) -> Result<(), String> {
        let corpus = seed.corpus.as_mut().ok_or("seed has no corpus")?;
        let research = downloads.join(&corpus.directory);
        let root = downloads.join(corpus.reference.take().ok_or("seed has no reference web")?);
        let source = sources(&root, &research).map_err(|e| e.to_string())?;
        let research_root = Archive::directory_root(&research).map_err(|e| e.to_string())?;
        let captured = Corpus {
            archive: Archive::open(
                source
                    .iter()
                    .filter(|file| file.path.parent() == Some(research_root.as_path()))
                    .map(|file| file.path.clone()),
            )
            .map_err(|e| e.to_string())?,
            missing: missing_pages(&research_root).map_err(|e| e.to_string())?,
            search: CorpusSearch::Crawled(Index::default()),
            hosts: HashSet::new(),
            packages: None,
            newest: Default::default(),
        };
        let wikipedia = Zim::new(wiki_file(&root)).map_err(|e| e.to_string())?;
        let parent = root.join("index");
        std::fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
        let stamp = format!(
            "pages-{}",
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let staged = parent.join(format!(".{stamp}"));
        let previous = if let Ok(index) = DiskIndex::open(&root.join("index/current")) {
            index
                .source()
                .map_err(|e| e.to_string())?
                .and_then(|payload| serde_json::from_str::<Prepared>(&payload).ok())
        } else {
            None
        };
        if previous.as_ref().is_some_and(|prepared| {
            prepared.files == source && prepared.documents_version == INDEX_VERSION
        }) {
            eprintln!("Offline search index is current");
            return Ok(());
        }
        let wikipedia_path = std::fs::canonicalize(wiki_file(&root)).map_err(|e| e.to_string())?;
        let reusable = previous.as_ref().filter(|prepared| {
            let wikipedia = source.iter().find(|file| file.path == wikipedia_path);
            wikipedia.is_some_and(|file| prepared.files.contains(file))
        });
        let writer = if let Some(prepared) = reusable {
            let current = root.join("index/current");
            let size = std::fs::read_dir(&current)
                .map_err(|e| e.to_string())?
                .map(|entry| {
                    entry
                        .and_then(|entry| entry.metadata())
                        .map(|meta| meta.len())
                })
                .sum::<io::Result<u64>>()
                .map_err(|e| e.to_string())?;
            if available_space(&root).map_err(|e| e.to_string())? < size + 60 * 1024 * 1024 * 1024 {
                return Err("index refresh must leave at least 60 GiB free".into());
            }
            std::fs::create_dir_all(&staged).map_err(|e| e.to_string())?;
            for file in std::fs::read_dir(&current).map_err(|e| e.to_string())? {
                let file = file.map_err(|e| e.to_string())?;
                if file.file_type().map_err(|e| e.to_string())?.is_file() {
                    std::fs::copy(file.path(), staged.join(file.file_name()))
                        .map_err(|e| e.to_string())?;
                }
            }
            let writer = DiskWriter::open(&staged).map_err(|e| e.to_string())?;
            let archives = Archive::open(
                prepared
                    .files
                    .iter()
                    .filter(|file| file.path.to_string_lossy().ends_with(".warc.gz"))
                    .map(|file| file.path.clone()),
            )
            .map_err(|e| e.to_string())?;
            for url in archives.urls() {
                writer.remove(url);
            }
            eprintln!("Reusing indexed Wikipedia; refreshing captured documents…");
            writer
        } else {
            DiskWriter::create(&staged).map_err(|e| e.to_string())?
        };
        let index = Index::crawl(
            &captured
                .archive
                .urls()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            |url| captured.archive.contains(url),
            |url| captured.response(url),
        )
        .map_err(|e| e.to_string())?;
        index.write_to(&writer).map_err(|e| e.to_string())?;
        if reusable.is_none() {
            eprintln!("Preparing Wikipedia articles…");
            // Physical cluster order decompresses each cluster once. Directory order
            // would repeatedly decompress the same multi-megabyte cluster.
            let mut entries = Vec::new();
            for entry in wikipedia.iterate_by_urls() {
                let entry = entry.map_err(|e| e.to_string())?;
                if entry.namespace == Namespace::UserContent
                    && matches!(&entry.mime_type, MimeType::Type(mime) if mime.starts_with("text/html"))
                    && let Some(Target::Cluster(cluster, blob)) = entry.target
                {
                    entries.push((cluster, blob, entry.url, entry.title));
                }
            }
            entries.sort_unstable_by_key(|entry| (entry.0, entry.1));
            let count = std::sync::atomic::AtomicUsize::new(0);
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(
                    std::thread::available_parallelism()
                        .map_err(|e| e.to_string())?
                        .get()
                        .div_ceil(2),
                )
                .build()
                .map_err(|e| e.to_string())?;
            pool.install(|| {
                entries.par_chunk_by(|a, b| a.0 == b.0).try_for_each(
                    |group| -> Result<(), String> {
                        if available_space(&root).map_err(|e| e.to_string())?
                            < 60 * 1024 * 1024 * 1024
                        {
                            return Err("index preparation must leave at least 60 GiB free".into());
                        }
                        let cluster = wikipedia
                            .get_cluster(group[0].0)
                            .map_err(|e| e.to_string())?;
                        let blobs = cluster.read().map_err(|e| e.to_string())?;
                        for (_, blob, path, title) in group {
                            let body = blobs.blob(*blob).map_err(|e| e.to_string())?;
                            let text = fictionet_extras::capture::page_text(
                                &String::from_utf8_lossy(body),
                            )
                            .map_err(|e| e.to_string())?;
                            writer
                                .add(
                                    &article_url(path),
                                    if title.is_empty() { path } else { title },
                                    &text,
                                )
                                .map_err(|e| e.to_string())?;
                            let done = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                            if done.is_multiple_of(100_000) {
                                eprintln!("Indexed {done} Wikipedia articles");
                            }
                        }
                        Ok(())
                    },
                )
            })?;
            drop(entries);
            drop(wikipedia);
        }
        for file in &source {
            let metadata = file.path.metadata().map_err(|e| e.to_string())?;
            if metadata.len() != file.bytes
                || metadata.modified().map_err(|e| e.to_string())? != file.modified
            {
                return Err(
                    "Captured archive changed during indexing; prepare the index again".into(),
                );
            }
        }
        let document_root = std::fs::canonicalize(&root).map_err(|e| e.to_string())?;
        let documents = Archive::open(
            source
                .iter()
                .filter(|file| {
                    file.path.parent() == Some(document_root.as_path())
                        && file.path.to_string_lossy().ends_with(".warc.gz")
                })
                .map(|file| file.path.clone()),
        )
        .map_err(|e| e.to_string())?;
        let seeds = documents.urls().map(str::to_owned).collect::<Vec<_>>();
        let document_index = Index::crawl(
            &seeds,
            |url| documents.contains(url),
            |url| documents.get(url),
        )
        .map_err(|e| e.to_string())?;
        document_index
            .write_to(&writer)
            .map_err(|e| e.to_string())?;
        let prepared = Prepared {
            documents_version: INDEX_VERSION,
            files: source,
            documents,
            research: captured.archive,
            missing: captured.missing,
        };
        writer
            .finish(&serde_json::to_string(&prepared).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let published = parent.join(&stamp);
        std::fs::rename(&staged, &published).map_err(|e| e.to_string())?;
        let pointer = parent.join(format!(".{stamp}-current"));
        std::os::unix::fs::symlink(&stamp, &pointer).map_err(|e| e.to_string())?;
        std::fs::rename(pointer, parent.join("current")).map_err(|e| e.to_string())?;
        eprintln!("Prepared offline web index");
        Ok(())
    }
}
