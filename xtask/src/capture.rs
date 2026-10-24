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

#[derive(Clone, Copy)]
enum Material {
    Page,
    Distribution,
}

impl Material {
    fn bytes(self) -> usize {
        match self {
            Self::Page => fictionet_extras::warc::Response::DECODED_BYTES,
            Self::Distribution => 256 * 1024 * 1024,
        }
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn capture_cached(
    root: &Path,
    name: &str,
    urls: &[String],
    requisites: bool,
    material: Material,
) -> Result {
    std::fs::create_dir_all(root)?;
    let archive = if std::fs::read_dir(root)?
        .any(|entry| entry.is_ok_and(|entry| entry.path().to_string_lossy().ends_with(".warc.gz")))
    {
        Some(Archive::directory(root)?)
    } else {
        None
    };
    let mut pending = Vec::new();
    for url in urls {
        let response = archive
            .as_ref()
            .map(|archive| archive.get(url))
            .transpose()?
            .flatten();
        if response.is_none_or(|response| {
            !(response.status.is_success()
                || response.status.is_redirection()
                || response.status == http::StatusCode::NOT_FOUND)
        }) {
            pending.push(url.clone());
        }
    }
    download(root, name, &pending, requisites, material).await
}

async fn download(
    root: &Path,
    name: &str,
    urls: &[String],
    requisites: bool,
    material: Material,
) -> Result {
    if urls.is_empty() {
        return Ok(());
    }
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
        .map(|url| (url, 0, 0))
        .collect::<std::collections::VecDeque<_>>();
    let mut seen = HashSet::new();
    while let Some((url, redirects, depth)) = pending.pop_front() {
        if !seen.insert(url.clone()) {
            continue;
        }
        if seen.len() > 2048 {
            return Err("capture exceeds URL limit".into());
        }
        let destination = url::Url::parse(&url)?;
        let response = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            let client = {
                #[cfg(test)]
                if destination.host_str().is_some_and(|host| {
                    host.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
                }) {
                    reqwest::Client::builder()
                        .no_proxy()
                        .redirect(reqwest::redirect::Policy::none())
                        .build()
                        .map_err(std::io::Error::other)?
                } else {
                    capture::client(&destination).await?
                }
                #[cfg(not(test))]
                capture::client(&destination).await?
            };
            let response = client
                .get(destination.clone())
                .header("accept-encoding", "identity")
                .send()
                .await
                .map_err(std::io::Error::other)?;
            let mut response = capture::receive(response, material.bytes()).await?;
            response.body = response.decoded_with_limit(material.bytes())?.into();
            response.headers.remove(http::header::CONTENT_ENCODING);
            response
                .headers
                .insert(http::header::CONTENT_LENGTH, response.body.len().into());
            Ok::<_, std::io::Error>(response)
        })
        .await;
        let response = match response {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                eprintln!("Capture unavailable: {url}: {error}");
                continue;
            }
            Err(_) => {
                eprintln!("Capture timed out: {url}");
                continue;
            }
        };
        archive.append(&path, &url, &response)?;
        if response.status.is_redirection() && redirects < 10 {
            if let Some(next) = response
                .headers
                .get(http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| destination.join(v).ok())
            {
                pending.push_back((next.into(), redirects + 1, depth));
            }
        } else if requisites && depth < 8 {
            match capture::links(&url, &response) {
                Ok(links) => {
                    pending.extend(links.assets.into_iter().map(|url| (url, 0, depth + 1)))
                }
                Err(error) => eprintln!("Asset discovery unavailable: {url}: {error}"),
            }
        }
    }
    if path.exists() {
        std::fs::rename(&path, root.join(path.file_name().unwrap()))?;
    }
    Ok(())
}

fn captured_at(archive: &Archive, url: &str) -> Result<(String, fictionet_extras::warc::Response)> {
    let mut url = url::Url::parse(url)?;
    for _ in 0..10 {
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
    Err(format!("too many redirects: {url}").into())
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
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        capture_cached(
            root,
            "missing-assets",
            &assets.into_iter().collect::<Vec<_>>(),
            true,
            Material::Page,
        ),
    )
    .await
    {
        Err(_) => {
            eprintln!("Optional not-found assets exceeded their capture deadline");
            Ok(())
        }
        Ok(Err(error))
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::InvalidData) =>
        {
            eprintln!("Optional not-found assets were rejected: {error}");
            Ok(())
        }
        Ok(result) => result,
    }
}

async fn documents(root: &Path, name: &str, urls: &[String]) -> Result {
    let mut jobs = tokio::task::JoinSet::new();
    let mut urls = urls.iter();
    loop {
        while jobs.len() < 8 {
            let Some(url) = urls.next() else {
                break;
            };
            let root = root.to_owned();
            let name = name.to_owned();
            let url = url.clone();
            jobs.spawn(async move {
                match download(
                    &root,
                    &name,
                    std::slice::from_ref(&url),
                    false,
                    Material::Page,
                )
                .await
                {
                    Err(error)
                        if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                            matches!(
                                error.kind(),
                                std::io::ErrorKind::TimedOut | std::io::ErrorKind::InvalidData
                            )
                        }) =>
                    {
                        eprintln!("Capture unavailable: {url}: {error}");
                        Ok(())
                    }
                    result => result,
                }
            });
        }
        let Some(result) = jobs.join_next().await else {
            return Ok(());
        };
        result??;
    }
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
    capture_cached(root, "zz-research", sources, true, Material::Page).await?;
    documents(root, "zz-research", sources).await?;
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
                        references.extend(found.into_iter().take(32));
                    }
                    Err(error) => eprintln!("Reference discovery unavailable: {url}: {error}"),
                }
            }
        }
        if references.len() > 8192 {
            return Err("article references exceed capture page limit".into());
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
    capture_cached(
        &staged_corpus,
        "zz-github-api",
        &repositories,
        false,
        Material::Page,
    )
    .await?;
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
            "corpus",
            "--",
            "--test-threads=1",
        ])
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .env("SEARCH_DOWNLOADS", std::fs::canonicalize(&batch.0)?)
        .status()
        .await?;
    if !status.success() {
        return Err("offline research replay failed".into());
    }
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
    capture_cached(
        &packages,
        "distributions",
        &urls,
        false,
        Material::Distribution,
    )
    .await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_paths_survive_publication_and_failed_batches_stay_private() {
        let root = Batch(std::env::temp_dir().join(format!(
                "corpus-validation-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        let staged = root.0.join("staged");
        let destination = root.0.join("corpus");
        std::fs::create_dir_all(&staged).unwrap();
        let body = "<title>Source</title><p>complete article</p>";
        Archive::default()
            .append(
                &staged.join("pages.warc.gz"),
                "https://source.org/article",
                &fictionet_extras::warc::Response {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::from_iter([(
                        http::header::CONTENT_TYPE,
                        "text/html".parse().unwrap(),
                    )]),
                    body: body.into(),
                },
            )
            .unwrap();
        let publication = Publication::prepare(&staged, &destination).unwrap();
        let validation_reader = Archive::directory(&publication.directory).unwrap();
        assert!(!destination.join("current").exists());
        let seed = web_world::pages::Seed::parse(
            "capture",
            "+++\n[corpus]\ndirectory='.'\nurls=['https://source.org/article']\n+++\nResearch",
            |_| unreachable!(),
        )
        .unwrap();
        web_world::pages::Pages::from_corpus(seed.clone(), &publication.directory, None).unwrap();
        let cache_path = publication.directory.join("search-index.json");
        let cached = std::fs::read(&cache_path).unwrap();
        publication.commit().unwrap();
        web_world::pages::Pages::from_corpus(seed, &destination, None).unwrap();
        assert_eq!(std::fs::read(cache_path).unwrap(), cached);
        assert_eq!(
            validation_reader
                .get("https://source.org/article")
                .unwrap()
                .unwrap()
                .body,
            body
        );
        std::fs::create_dir_all(&staged).unwrap();
        let failed = Publication::prepare(&staged, &destination).unwrap();
        let discarded = failed.directory.clone();
        drop(failed);
        assert!(!discarded.exists());
        assert_eq!(
            Archive::directory(&destination)
                .unwrap()
                .get("https://source.org/article")
                .unwrap()
                .unwrap()
                .body,
            body
        );
    }

    #[test]
    fn research_publication_switches_the_whole_batch_and_keeps_old_readers() {
        let root = Batch(std::env::temp_dir().join(format!(
                "research-publication-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        let destination = root.0.join("security");
        std::fs::create_dir_all(&destination).unwrap();
        let write = |path: &Path, url, body: &'static str| {
            Archive::default()
                .append(
                    path,
                    url,
                    &fictionet_extras::warc::Response {
                        status: http::StatusCode::OK,
                        headers: Default::default(),
                        body: body.into(),
                    },
                )
                .unwrap()
        };
        write(
            &destination.join("old.warc.gz"),
            "https://source.org/article",
            "old article",
        );
        let old = Archive::directory(&destination).unwrap();
        let staged = root.0.join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        write(
            &staged.join("article.warc.gz"),
            "https://source.org/article",
            "new article with citation",
        );
        assert_eq!(
            Archive::directory(&destination)
                .unwrap()
                .get("https://source.org/article")
                .unwrap()
                .unwrap()
                .body,
            "old article"
        );
        write(
            &staged.join("citation.warc.gz"),
            "https://source.org/citation",
            "cited research",
        );
        publish(&staged, &destination).unwrap();
        let new = Archive::directory(&destination).unwrap();
        assert_eq!(
            new.get("https://source.org/article").unwrap().unwrap().body,
            "new article with citation"
        );
        assert_eq!(
            new.get("https://source.org/citation")
                .unwrap()
                .unwrap()
                .body,
            "cited research"
        );
        assert_eq!(
            old.get("https://source.org/article").unwrap().unwrap().body,
            "old article"
        );
        assert!(old.get("https://source.org/citation").unwrap().is_none());
    }

    #[tokio::test]
    async fn large_not_found_documents_survive_optional_asset_discovery() {
        let root = Batch(std::env::temp_dir().join(format!(
            "missing-page-capture-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir_all(&root.0).unwrap();
        let path = root.0.join("missing-pages.warc.gz");
        let url = "https://publisher.org/404";
        let mut response = fictionet_extras::warc::Response {
            status: http::StatusCode::NOT_FOUND,
            headers: Default::default(),
            body: format!(
                "<title>Page not found</title>{}",
                " ".repeat(fictionet_extras::capture::PARSE_BYTES)
            )
            .into(),
        };
        response
            .headers
            .insert("content-type", "text/html".parse().unwrap());
        response.headers.insert(
            "content-length",
            response.body.len().to_string().parse().unwrap(),
        );
        let mut archive = Archive::default();
        archive.append(&path, url, &response).unwrap();
        missing_pages(
            &root.0,
            &["https://publisher.org/article".into()],
            &["https://publisher.org/article".into()],
        )
        .await
        .unwrap();
        let replay = not_found(&Archive::open([path]).unwrap(), url).unwrap();
        assert_eq!(replay.body, response.body);
        assert_eq!(replay.headers, response.headers);
    }

    #[tokio::test]
    async fn research_captures_two_article_hops_and_site_roots() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        assert!(request.len() < 8192);
                        request.push(stream.read_u8().await.unwrap());
                    }
                    let request = std::str::from_utf8(&request).unwrap();
                    let (status, body) = match request.split_whitespace().nth(1).unwrap() {
                        "/incident" => (
                            200,
                            "<title>Incident</title><article><a href='/reviewdog#details'>Analysis</a></article>",
                        ),
                        "/reviewdog" => (
                            200,
                            "<title>Analysis</title><article><a href='/guidance'>Guidance</a></article>",
                        ),
                        "/guidance" => (
                            200,
                            "<title>Guidance</title><article><a href='/third'>More</a></article>",
                        ),
                        "/" => (200, "<title>Publisher</title>"),
                        _ => (404, "<title>Page not found</title>"),
                    };
                    stream.write_all(format!("HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
                });
            }
        });
        let root = Batch(std::env::temp_dir().join(format!(
            "article-capture-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos()
        )));
        std::fs::create_dir_all(&root.0).unwrap();
        let mut previous = Archive::default();
        previous
            .append(
                &root.0.join("references.warc.gz"),
                &format!("{origin}/reviewdog"),
                &fictionet_extras::warc::Response {
                    status: http::StatusCode::NOT_FOUND,
                    headers: Default::default(),
                    body: "Missing".into(),
                },
            )
            .unwrap();
        let source = format!("{origin}/incident");
        research(&root.0, std::slice::from_ref(&source))
            .await
            .unwrap();
        server.abort();
        let archive = Archive::directory(&root.0).unwrap();
        for path in ["/incident", "/reviewdog", "/guidance", "/"] {
            verify(&archive, &format!("{origin}{path}")).unwrap();
        }
        assert!(!archive.contains(&format!("{origin}/third")));
        assert_eq!(
            not_found(&archive, &format!("{origin}/404"))
                .unwrap()
                .status,
            404
        );
        let pages = std::sync::Arc::new(
            web_world::pages::Pages::copied(
                web_world::pages::Seed::builtin("security").unwrap(),
                &root.0,
                &[source],
                None,
            )
            .unwrap(),
        );
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                use fictionet_extras::models::Engine;
                for path in ["/reviewdog", "/guidance", "/"] {
                    let page = pages
                        .clone()
                        .fetch(cx.clone(), format!("{origin}{path}"))
                        .await?;
                    assert!(!page.title.is_empty());
                    assert!(!page.body.is_empty());
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn publishing_keeps_existing_worlds_and_git_paths_on_their_batch() {
        let root = Batch(std::env::temp_dir().join(format!(
                "package-publication-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )));
        let corpus = root.0.join("security");
        std::fs::create_dir_all(&corpus).unwrap();
        let mut archive = Archive::default();
        archive
            .append(
                &corpus.join("research.warc.gz"),
                "https://source.org/",
                &fictionet_extras::warc::Response {
                    status: http::StatusCode::OK,
                    headers: http::HeaderMap::from_iter([(
                        http::header::CONTENT_TYPE,
                        "text/html".parse().unwrap(),
                    )]),
                    body: "<title>Source</title><p>Research</p>".into(),
                },
            )
            .unwrap();
        let write_batch = |path: &Path, body: &'static str| {
            std::fs::create_dir_all(path.join("git/psf/requests.git")).unwrap();
            std::fs::write(path.join("git/psf/requests.git/HEAD"), body).unwrap();
            Archive::default()
                .append(
                    &path.join("distributions.warc.gz"),
                    "https://files.pythonhosted.org/tool.whl",
                    &fictionet_extras::warc::Response {
                        status: http::StatusCode::OK,
                        headers: Default::default(),
                        body: body.into(),
                    },
                )
                .unwrap();
        };
        let open = || {
            std::sync::Arc::new(
                web_world::pages::Pages::copied(
                    web_world::pages::Seed::builtin("web").unwrap(),
                    &corpus,
                    &["https://source.org/".into()],
                    None,
                )
                .unwrap(),
            )
        };
        let destination = corpus.join("packages");
        write_batch(&destination, "legacy");
        let legacy = open();
        let first = root.0.join("first");
        write_batch(&first, "first");
        publish(&first, &destination).unwrap();
        let first_path = package_root(&destination).unwrap();
        let first = open();
        let second = root.0.join("second");
        write_batch(&second, "second");
        publish(&second, &destination).unwrap();
        let second = open();
        assert_eq!(
            std::fs::read_to_string(destination.join("git/psf/requests.git/HEAD")).unwrap(),
            "legacy"
        );
        assert_eq!(
            std::fs::read_to_string(first_path.join("git/psf/requests.git/HEAD")).unwrap(),
            "first"
        );
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |cx| async move {
                for (pages, expected) in [(legacy, "legacy"), (first, "first"), (second, "second")]
                {
                    let answer = pages
                        .handle(&cx, "GET", "files.pythonhosted.org", "/tool.whl", None)
                        .await;
                    assert_eq!(answer.status, 200);
                    assert_eq!(answer.body, expected.as_bytes());
                }
                Ok(())
            },
        ))
        .unwrap();
    }

    #[test]
    fn captured_responses_follow_redirects_and_preserve_site_errors() {
        let path = std::env::temp_dir().join(format!(
            "capture-responses-{}-{}.warc.gz",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut archive = Archive::default();
        for (url, status, location, body) in [
            ("https://source.org/404", 301u16, Some("/en/404"), ""),
            (
                "https://source.org/en/404",
                404,
                None,
                "Page not found | Source",
            ),
        ] {
            let mut response = fictionet_extras::warc::Response {
                status: status.try_into().unwrap(),
                headers: Default::default(),
                body: body.as_bytes().to_vec().into(),
            };
            if let Some(location) = location {
                response
                    .headers
                    .insert("location", location.parse().unwrap());
            }
            archive.append(&path, url, &response).unwrap();
        }
        let response = captured(&archive, "https://source.org/404").unwrap();
        assert_eq!(response.status, 404);
        assert_eq!(response.body, "Page not found | Source");
        assert!(verify(&archive, "https://source.org/404").is_err());
        assert!(captured(&archive, "https://source.org/missing").is_err());
        let origin = url::Url::parse("https://source.org/").unwrap().origin();
        assert_eq!(
            site_not_found(&archive, &origin).unwrap().unwrap().status,
            404
        );
        assert!(
            site_not_found(
                &archive,
                &url::Url::parse("https://other.org/").unwrap().origin()
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            not_found(&archive, "https://source.org/404")
                .unwrap()
                .status,
            404
        );
        for status in [200, 401, 403, 429] {
            archive
                .append(
                    &path,
                    "https://source.org/wrong-status",
                    &fictionet_extras::warc::Response {
                        status: http::StatusCode::from_u16(status).unwrap(),
                        headers: Default::default(),
                        body: "Unavailable".into(),
                    },
                )
                .unwrap();
            assert!(not_found(&archive, "https://source.org/wrong-status").is_err());
            assert_eq!(
                captured(&archive, "https://source.org/wrong-status")
                    .unwrap()
                    .status,
                status
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}
