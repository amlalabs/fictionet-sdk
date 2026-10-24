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
    pub index: DiskIndex,
    wikipedia: Zim,
    documents: Archive,
    hosts: HashSet<String>,
}

fn wiki_file(root: &Path) -> std::path::PathBuf {
    root.join("wikipedia_en_all_nopic_2026-06.zim")
}

#[derive(Serialize, Deserialize)]
struct Prepared {
    files: Vec<ArchiveFile>,
    documents: Archive,
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

fn documents(root: &Path) -> io::Result<Archive> {
    Archive::open(archive_files(root)?.into_iter().map(|file| file.path))
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
    pub fn open(root: &Path, research: &Path) -> Result<Self, String> {
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
        if prepared.files != sources(root, research).map_err(|e| e.to_string())? {
            return Err("Offline corpus changed. Run cargo xtask search-web with --index".into());
        }
        let documents = prepared.documents;
        let hosts = documents
            .urls()
            .filter_map(|url| url::Url::parse(url).ok()?.host_str().map(str::to_owned))
            .collect();
        eprintln!("Offline web: {} indexed pages", index.len());
        Ok(Self {
            index,
            wikipedia,
            documents,
            hosts,
        })
    }

    pub fn serves(&self, host: &str) -> bool {
        host == "en.wikipedia.org" || self.hosts.contains(host)
    }

    pub fn response(&self, url: &str) -> io::Result<Option<warc::Response>> {
        let parsed = url::Url::parse(url).map_err(io::Error::other)?;
        if parsed.host_str() != Some("en.wikipedia.org") {
            return archived_response(&self.documents, &self.documents, url);
        }
        let path = percent_encoding::percent_decode_str(parsed.path())
            .decode_utf8()
            .map_err(io::Error::other)?;
        let path = path
            .strip_prefix("/wiki/")
            .unwrap_or_else(|| path.trim_start_matches('/'));
        let path = path.replace(' ', "_");
        let entry = self
            .wikipedia
            .get_by_path(Namespace::UserContent, &path)
            .map_err(io::Error::other)?;
        let Some(entry) = entry else {
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
        Ok(Some(warc::Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([(
                http::header::CONTENT_TYPE,
                content_type.parse().map_err(io::Error::other)?,
            )]),
            body: content.to_vec().map_err(io::Error::other)?.into(),
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
        let pages = Self::from_corpus(seed, downloads, None)?;
        let captured = pages.copied.as_ref().unwrap();
        let wikipedia = Zim::new(wiki_file(&root)).map_err(|e| e.to_string())?;
        let parent = root.join("index");
        std::fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
        let stamp = format!(
            "pages-{}",
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let staged = parent.join(format!(".{stamp}"));
        let source = sources(&root, &research).map_err(|e| e.to_string())?;
        if let Ok(index) = DiskIndex::open(&root.join("index/current"))
            && let Some(prepared) = index
                .source()
                .map_err(|e| e.to_string())?
                .and_then(|payload| serde_json::from_str::<Prepared>(&payload).ok())
            && prepared.files == source
        {
            eprintln!("Offline search index is current");
            return Ok(());
        }
        let writer = DiskWriter::create(&staged).map_err(|e| e.to_string())?;
        captured
            .index
            .write_to(&writer)
            .map_err(|e| e.to_string())?;
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
            entries
                .par_chunk_by(|a, b| a.0 == b.0)
                .try_for_each(|group| -> Result<(), String> {
                    // Leave room for in-flight segment writes and merges above the reserve.
                    if available_space(&root).map_err(|e| e.to_string())? < 68 * 1024 * 1024 * 1024
                    {
                        return Err("index preparation must leave at least 60 GiB free".into());
                    }
                    let cluster = wikipedia
                        .get_cluster(group[0].0)
                        .map_err(|e| e.to_string())?;
                    let blobs = cluster.read().map_err(|e| e.to_string())?;
                    for (_, blob, path, title) in group {
                        let body = blobs.blob(*blob).map_err(|e| e.to_string())?;
                        let text =
                            fictionet_extras::capture::page_text(&String::from_utf8_lossy(body))
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
                })
        })?;
        let documents = documents(&root).map_err(|e| e.to_string())?;
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
            files: sources(&root, &research).map_err(|e| e.to_string())?,
            documents,
        };
        writer
            .finish(&serde_json::to_string(&prepared).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let published = parent.join(&stamp);
        std::fs::rename(&staged, &published).map_err(|e| e.to_string())?;
        let pointer = parent.join(format!(".{stamp}-current"));
        std::os::unix::fs::symlink(&stamp, &pointer).map_err(|e| e.to_string())?;
        std::fs::rename(pointer, parent.join("current")).map_err(|e| e.to_string())?;
        eprintln!(
            "Prepared {} Wikipedia articles and all captured pages",
            count.load(std::sync::atomic::Ordering::Relaxed)
        );
        Ok(())
    }
}
