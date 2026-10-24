//! Capture the research web and Python distributions at their original URLs.

mod render;

use crate::Result;
use fictionet_extras::{capture, warc::Archive};
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
    time::SystemTime,
};
use tokio::process::Command;

#[derive(Deserialize)]
struct Resolution {
    install: Vec<Distribution>,
}

#[derive(Deserialize)]
struct Distribution {
    download_info: Download,
    metadata: Metadata,
}

#[derive(Deserialize)]
struct Download {
    url: String,
}

#[derive(Deserialize)]
struct Metadata {
    name: String,
}

const TOOLS: &[&str] = &[
    "requests",
    "pandas",
    "numpy",
    "matplotlib",
    "beautifulsoup4",
    "scipy",
    "networkx",
    "pyyaml",
    "packaging",
    "rich",
    "pytest",
];

const REPOSITORIES: &[(&str, &str)] = &[
    ("psf/requests", "v2.32.3"),
    ("networkx/networkx", "networkx-3.4.2"),
    ("pallets/click", "8.1.8"),
];

struct Batch(std::path::PathBuf);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Resource {
    Document,
    Requisite,
}

impl Drop for Batch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn capture_cached(root: &Path, name: &str, urls: &[String]) -> Result {
    download(root, name, urls).await?;
    if urls.is_empty() {
        return Ok(());
    }
    let assets = render::requisites(root, urls).await?;
    download(root, name, &assets).await
}

async fn download(root: &Path, name: &str, urls: &[String]) -> Result {
    if urls.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(root)?;
    let existing = if std::fs::read_dir(root)?
        .any(|entry| entry.is_ok_and(|entry| entry.path().to_string_lossy().ends_with(".warc.gz")))
    {
        Archive::directory(root)?
    } else {
        Archive::default()
    };
    let batch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let staging = Batch(root.join(format!(".download-{}-{batch}", std::process::id())));
    std::fs::create_dir_all(&staging.0)?;
    let prefix = staging.0.join(format!("{name}-{batch}"));
    let path = prefix.with_extension("warc.gz");
    let mut archive = Archive::default();
    let mut pending = urls
        .iter()
        .cloned()
        .map(|url| (url, Resource::Document))
        .collect::<std::collections::VecDeque<_>>();
    let mut seen = HashSet::new();
    let mut requests = tokio::task::JoinSet::new();
    let workers = std::thread::available_parallelism()?.get();
    loop {
        while requests.len() < workers
            && let Some((url, resource)) = pending.pop_front()
        {
            if !seen.insert((url.clone(), resource)) {
                continue;
            }
            if let Some(response) = existing.get(&url)?
                && (response.status.is_success()
                    || response.status.is_redirection()
                    || (resource == Resource::Document
                        && response.status == http::StatusCode::NOT_FOUND))
            {
                let links = capture::links(&url, &response)?;
                pending.extend(
                    links
                        .assets
                        .into_iter()
                        .map(|url| (url, Resource::Requisite)),
                );
                if response.status.is_redirection() {
                    pending.extend(links.pages.into_iter().map(|url| (url, resource)));
                }
                continue;
            }
            requests.spawn(async move {
                let response = async {
                    let destination = url::Url::parse(&url).map_err(std::io::Error::other)?;
                    let client = capture::client(&destination).await?;
                    let response = client
                        .get(destination.clone())
                        .header("accept-encoding", "identity")
                        .send()
                        .await
                        .map_err(std::io::Error::other)?;
                    let mut response = capture::receive(response).await?;
                    response.body = response.decoded()?.into();
                    response.headers.remove(http::header::CONTENT_ENCODING);
                    response
                        .headers
                        .insert(http::header::CONTENT_LENGTH, response.body.len().into());
                    Ok::<_, std::io::Error>(response)
                }
                .await;
                (url, resource, response)
            });
        }
        let Some(result) = requests.join_next().await else {
            break;
        };
        let (url, resource, response) = result?;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                eprintln!("Capture unavailable: {url}: {error:?}");
                continue;
            }
        };
        archive.append(&path, &url, &response)?;
        eprintln!("Captured {}: {url}", response.status);
        let links = capture::links(&url, &response)?;
        pending.extend(
            links
                .assets
                .into_iter()
                .map(|url| (url, Resource::Requisite)),
        );
        if response.status.is_redirection() {
            pending.extend(links.pages.into_iter().map(|url| (url, resource)));
        }
    }
    if path.exists() {
        std::fs::File::open(&path)?.sync_all()?;
        std::fs::rename(&path, root.join(path.file_name().unwrap()))?;
        std::fs::File::open(root)?.sync_all()?;
    }
    Ok(())
}

pub async fn requisites(root: &Path, urls: &[String]) -> Result {
    std::fs::create_dir_all(root)?;
    let root = Archive::directory_root(root)?;
    let lock = std::fs::File::open(&root)?;
    lock.try_lock()?;
    let mut urls = if urls.is_empty() {
        Archive::directory(&root)?
            .urls()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    } else {
        urls.to_vec()
    };
    urls.sort();
    println!("Completing requisites for {} captured URLs", urls.len());
    capture_cached(&root, "requisites", &urls).await
}

fn captured_at(archive: &Archive, url: &str) -> Result<(String, fictionet_extras::warc::Response)> {
    let mut url = url::Url::parse(url)?;
    let mut seen = HashSet::new();
    while seen.insert(url.clone()) {
        let response = archive
            .get(url.as_str())?
            .ok_or_else(|| format!("missing capture: {url}"))?;
        if !response.status.is_redirection() {
            return Ok((url.into(), response));
        }
        let location = response
            .headers
            .get("location")
            .ok_or("redirect without location")?
            .to_str()?;
        url = url.join(location)?;
    }
    Err(format!("redirect cycle: {url}").into())
}

fn captured(archive: &Archive, url: &str) -> Result<fictionet_extras::warc::Response> {
    captured_at(archive, url).map(|(_, response)| response)
}

fn not_found(archive: &Archive, url: &str) -> Result<fictionet_extras::warc::Response> {
    let response = captured(archive, url)?;
    if response.status != http::StatusCode::NOT_FOUND {
        return Err(format!(
            "expected a not-found response for {url}, got {}",
            response.status
        )
        .into());
    }
    Ok(response)
}

fn verify(archive: &Archive, url: &str) -> Result {
    let response = captured(archive, url)?;
    if response.status.is_success() {
        Ok(())
    } else {
        Err(format!("capture {url}: {}", response.status).into())
    }
}

fn site_not_found(
    archive: &Archive,
    origin: &url::Origin,
) -> Result<Option<fictionet_extras::warc::Response>> {
    let mut urls: Vec<_> = archive
        .urls()
        .filter(|url| url::Url::parse(url).is_ok_and(|url| &url.origin() == origin))
        .collect();
    urls.sort();
    for url in urls {
        if let Some(response) = archive.get(url)?
            && response.status == http::StatusCode::NOT_FOUND
        {
            return Ok(Some(response));
        }
    }
    Ok(None)
}

async fn missing_pages(root: &Path, sources: &[String], required: &[String]) -> Result {
    let required: HashSet<_> = required
        .iter()
        .map(|url| url::Url::parse(url).map(|url| url.origin()))
        .collect::<std::result::Result<_, _>>()?;
    let urls: BTreeSet<_> = sources
        .iter()
        .map(|url| {
            Ok(format!(
                "{}/404",
                url::Url::parse(url)?.origin().ascii_serialization()
            ))
        })
        .collect::<Result<_>>()?;
    let urls: Vec<_> = urls.into_iter().collect();
    let path = root.join("missing-pages.warc.gz");
    let mut missing = Archive::open(path.is_file().then_some(path.clone()))?;
    let pending = urls
        .iter()
        .filter(|url| not_found(&missing, url).is_err())
        .cloned()
        .collect::<Vec<_>>();
    documents(root, "missing", &pending).await?;
    let mut archive = Archive::directory(root)?;
    let mut alternatives = Vec::new();
    for url in &urls {
        if not_found(&missing, url).is_ok() {
            continue;
        }
        if let Ok(response) = not_found(&archive, url) {
            missing.append(&path, url, &response)?;
        } else {
            let alternate = url::Url::parse(url)?.join("404/not-found")?.to_string();
            alternatives.push((url.clone(), alternate));
        }
    }
    if !alternatives.is_empty() {
        documents(
            root,
            "missing",
            &alternatives
                .iter()
                .map(|(_, url)| url.clone())
                .collect::<Vec<_>>(),
        )
        .await?;
        archive = Archive::directory(root)?;
        let mut failures = Vec::new();
        for (canonical, alternate) in alternatives {
            match not_found(&archive, &alternate) {
                Ok(response) => missing.append(&path, &canonical, &response)?,
                Err(error) => {
                    let origin = url::Url::parse(&canonical)?.origin();
                    if let Some(response) = site_not_found(&archive, &origin)? {
                        missing.append(&path, &canonical, &response)?;
                    } else if required.contains(&origin) {
                        failures.push(error.to_string());
                    } else {
                        eprintln!(
                            "No not-found capture for {}: {error}",
                            origin.ascii_serialization()
                        );
                    }
                }
            }
        }
        if !failures.is_empty() {
            return Err(failures.join("\n").into());
        }
    }
    let mut assets = BTreeSet::new();
    for url in urls {
        if let Some(response) = missing.get(&url)? {
            match fictionet_extras::capture::links(&url, &response) {
                Ok(links) => assets.extend(links.assets),
                Err(error) => eprintln!("Not-found asset discovery unavailable: {url}: {error}"),
            }
        }
    }
    capture_cached(
        root,
        "missing-assets",
        &assets.into_iter().collect::<Vec<_>>(),
    )
    .await
}

async fn documents(root: &Path, name: &str, urls: &[String]) -> Result {
    capture_cached(root, name, urls).await
}

fn github_api(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    if url.host_str()? != "github.com" {
        return None;
    }
    let segments: Vec<_> = url
        .path_segments()?
        .filter(|part| !part.is_empty())
        .collect();
    let [owner, repo, rest @ ..] = segments.as_slice() else {
        return None;
    };
    let suffix = match rest {
        [] => String::new(),
        ["commit", sha] => format!("/commits/{sha}"),
        ["pull", number] if number.bytes().all(|b| b.is_ascii_digit()) => {
            format!("/pulls/{number}")
        }
        ["actions", "runs", number] if number.bytes().all(|b| b.is_ascii_digit()) => {
            format!("/actions/runs/{number}")
        }
        _ => return None,
    };
    Some(format!(
        "https://api.github.com/repos/{owner}/{repo}{suffix}"
    ))
}

async fn research(root: &Path, sources: &[String]) -> Result {
    // New batches sort after the original archives to supersede stale errors.
    capture_cached(root, "zz-research", sources).await?;
    let mut archive = Archive::directory(root)?;
    let mut frontier = sources.to_vec();
    let mut seen = HashSet::new();
    let mut origins = BTreeSet::new();
    let mut api = BTreeSet::new();
    for url in sources {
        verify(&archive, url)?;
    }
    for depth in 1..=2 {
        let mut references = BTreeSet::new();
        for url in &frontier {
            let (url, response) = captured_at(&archive, url)?;
            origins.insert(url.clone());
            if seen.insert(url.clone()) {
                match fictionet_extras::capture::references(&url, &response) {
                    Ok(found) => {
                        references.extend(
                            found
                                .iter()
                                .filter(|url| github_api(url).is_some())
                                .cloned(),
                        );
                        references.extend(found);
                    }
                    Err(error) => eprintln!("Reference discovery unavailable: {url}: {error}"),
                }
            }
        }
        for url in &references {
            if let Some(endpoint) = github_api(url) {
                api.insert(endpoint);
            }
        }
        references.retain(|url| !seen.contains(url));
        let pending = references
            .iter()
            .filter(|url| verify(&archive, url).is_err())
            .cloned()
            .collect::<Vec<_>>();
        println!(
            "Capturing hop {depth}: {} article references ({} already present)",
            references.len(),
            references.len() - pending.len()
        );
        documents(root, "zz-references", &pending).await?;
        archive = Archive::directory(root)?;
        for reference in &references {
            let url = url::Url::parse(reference)?;
            if url.host_str() == Some("nvd.nist.gov")
                && let Some(cve) = url.path().strip_prefix("/vuln/detail/")
                && verify(&archive, reference).is_ok()
                && !capture::title(&captured(&archive, reference)?)?
                    .to_ascii_lowercase()
                    .contains(&cve.to_ascii_lowercase())
            {
                render::document(root, reference, cve).await?;
                archive = Archive::directory(root)?;
            }
        }
        frontier.clear();
        for url in references {
            if verify(&archive, &url).is_ok() {
                frontier.push(url);
            } else {
                eprintln!("Reference unavailable: {url}");
            }
        }
    }
    origins.extend(frontier);
    let mut endpoints = api.into_iter().take(32).collect::<Vec<_>>();
    endpoints.sort();
    endpoints.dedup();
    let pending = endpoints
        .into_iter()
        .filter(|url| verify(&archive, url).is_err())
        .collect::<Vec<_>>();
    documents(root, "zz-github-api", &pending).await?;
    let roots = origins
        .iter()
        .map(|url| {
            Ok(format!(
                "{}/",
                url::Url::parse(url)?.origin().ascii_serialization()
            ))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let pending = roots
        .iter()
        .filter(|url| verify(&archive, url).is_err())
        .cloned()
        .collect::<Vec<_>>();
    documents(root, "zz-roots", &pending).await?;
    let archive = Archive::directory(root)?;
    for url in roots {
        if verify(&archive, &url).is_ok() {
            origins.insert(url);
        }
    }
    missing_pages(root, &origins.into_iter().collect::<Vec<_>>(), sources).await
}

fn package_root(root: &Path) -> std::io::Result<std::path::PathBuf> {
    if root.join("current").try_exists()? {
        std::fs::canonicalize(root.join("current"))
    } else {
        Ok(root.to_owned())
    }
}

struct Publication {
    directory: std::path::PathBuf,
    destination: std::path::PathBuf,
    published: bool,
}

impl Publication {
    fn prepare(staged: &Path, destination: &Path) -> Result<Self> {
        std::fs::create_dir_all(destination)?;
        let name = format!(
            "batch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_nanos()
        );
        let directory = destination.join(name);
        std::fs::rename(staged, &directory)?;
        Ok(Self {
            directory,
            destination: destination.to_owned(),
            published: false,
        })
    }

    fn commit(mut self) -> Result {
        let name = self.directory.file_name().unwrap();
        let pointer = self
            .destination
            .join(format!(".{}", name.to_string_lossy()));
        std::os::unix::fs::symlink(name, &pointer)?;
        std::fs::rename(pointer, self.destination.join("current"))?;
        self.published = true;
        Ok(())
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
}

fn publish(staged: &Path, destination: &Path) -> Result {
    Publication::prepare(staged, destination)?.commit()
}

pub async fn run(downloads: &Path, python: Option<&Path>) -> Result {
    let seed = web_world::pages::Seed::builtin("security")?;
    let corpus = seed.corpus.ok_or("missing corpus declaration")?;
    let root = downloads.join(&corpus.directory);
    std::fs::create_dir_all(&root)?;
    let root = std::fs::canonicalize(root)?;
    let capture = std::fs::File::open(&root)?;
    capture
        .try_lock()
        .map_err(|error| format!("cannot own corpus capture: {error}"))?;
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let batch = Batch(downloads.join(format!(".capture-{}-{stamp}", std::process::id())));
    let staged_corpus = batch.0.join(&corpus.directory);
    std::fs::create_dir_all(&staged_corpus)?;
    let previous = package_root(&root)?;
    for entry in std::fs::read_dir(&previous)? {
        let entry = entry?;
        if entry.path().to_string_lossy().ends_with(".warc.gz") {
            let destination = staged_corpus.join(entry.file_name());
            if entry.file_name() == "missing-pages.warc.gz" {
                std::fs::copy(entry.path(), destination)?;
            } else {
                std::os::unix::fs::symlink(entry.path(), destination)?;
            }
        }
    }
    let repositories = REPOSITORIES
        .iter()
        .map(|(repo, _)| format!("https://api.github.com/repos/{repo}"))
        .collect::<Vec<_>>();
    capture_cached(&staged_corpus, "zz-github-api", &repositories).await?;
    let archive = Archive::directory(&staged_corpus)?;
    for url in &repositories {
        verify(&archive, url)?;
    }
    research(&staged_corpus, &corpus.urls).await?;
    if root.join("packages").is_dir() {
        std::os::unix::fs::symlink(root.join("packages"), staged_corpus.join("packages"))?;
    }
    let publication = Publication::prepare(&staged_corpus, &root)?;
    std::os::unix::fs::symlink(&publication.directory, &staged_corpus)?;
    // Package pointers are owned separately from the immutable research batch.
    if staged_corpus.join("packages").is_symlink() {
        std::fs::remove_file(staged_corpus.join("packages"))?;
    }
    publication.commit()?;
    let Some(python) = python else {
        println!("Captured research sources in {}", root.display());
        return Ok(());
    };
    std::fs::remove_file(&staged_corpus)?;
    std::fs::create_dir_all(&staged_corpus)?;
    for entry in std::fs::read_dir(package_root(&root)?)? {
        let entry = entry?;
        if entry.path().to_string_lossy().ends_with(".warc.gz") {
            std::os::unix::fs::symlink(entry.path(), staged_corpus.join(entry.file_name()))?;
        }
    }
    // Resolve packages into an empty batch. Indexes and distributions are
    // published together only after an offline install.
    let output = Command::new(python)
        .args([
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--only-binary=:all:",
            "--python-version=3.12",
            "--implementation=cp",
            "--abi=cp312",
            "--platform=manylinux_2_28_x86_64",
            "--platform=manylinux2014_x86_64",
            "--report",
            "-",
            "--quiet",
            "--index-url",
            "https://pypi.org/simple",
        ])
        .args(TOOLS)
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!(
            "pip resolution failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let resolution: Resolution = serde_json::from_slice(&output.stdout)?;
    let mut urls = Vec::new();
    let mut required = Vec::new();
    let mut immutable = Vec::new();
    for distribution in resolution.install {
        let name = distribution
            .metadata
            .name
            .to_ascii_lowercase()
            .replace(['_', '.'], "-");
        let index = format!("https://pypi.org/simple/{name}/");
        let metadata = format!("{}.metadata", distribution.download_info.url);
        urls.extend([
            index.clone(),
            distribution.download_info.url.clone(),
            metadata.clone(),
        ]);
        immutable.extend([distribution.download_info.url.clone(), metadata.clone()]);
        required.extend([index, distribution.download_info.url, metadata]);
    }
    for (repo, tag) in REPOSITORIES {
        for extension in ["tar.gz", "zip"] {
            let url = format!("https://github.com/{repo}/archive/refs/tags/{tag}.{extension}");
            urls.push(url.clone());
            required.push(url);
        }
    }
    let packages = staged_corpus.join("packages");
    std::fs::create_dir_all(&packages)?;
    if root.join("packages").is_dir() {
        let previous = Archive::directory(&package_root(&root.join("packages"))?)?;
        let mut reused = Archive::default();
        for url in immutable {
            if let Some(response) = previous.get(&url)?
                && response.status.is_success()
            {
                reused.append(&packages.join("distributions.warc.gz"), &url, &response)?;
            }
        }
    }
    capture_cached(&packages, "distributions", &urls).await?;
    let sources = Archive::directory(&packages)?
        .urls()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    missing_pages(&packages, &sources, &sources).await?;
    let archive = Archive::directory(&packages)?;
    for url in required {
        verify(&archive, &url)?;
    }
    for (repo, _) in REPOSITORIES {
        let destination = packages.join("git").join(format!("{repo}.git"));
        std::fs::create_dir_all(destination.parent().unwrap())?;
        let status = Command::new("git")
            .args(["clone", "--bare"])
            .arg(format!("https://github.com/{repo}.git"))
            .arg(&destination)
            .status()
            .await?;
        if !status.success() {
            return Err(format!("Git capture failed: {repo}").into());
        }
    }
    let status = Command::new("rustup")
        .args([
            "run",
            "1.99.0",
            "cargo",
            "test",
            "--offline",
            "-p",
            "web-world",
            "--test",
            "packages",
        ])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .env("SEARCH_DOWNLOADS", std::fs::canonicalize(&batch.0)?)
        .env("SEARCH_PYTHON", std::path::absolute(python)?)
        .status()
        .await?;
    if !status.success() {
        return Err("offline package installation and clone validation failed".into());
    }
    publish(&packages, &root.join("packages"))?;
    println!(
        "Captured research sources and package distributions in {}",
        root.display()
    );
    Ok(())
}
