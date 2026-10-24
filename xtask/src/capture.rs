//! Capture the research web and Python distributions at their original URLs.

use crate::Result;
use fictionet_extras::{capture::BROWSER, warc::Archive};
use serde::Deserialize;
use std::{collections::BTreeSet, path::Path, time::SystemTime};
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

impl Drop for Batch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn wget(root: &Path, name: &str, urls: &[String], requisites: bool) -> Result {
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
    download(root, name, &pending, requisites).await
}

async fn download(root: &Path, name: &str, urls: &[String], requisites: bool) -> Result {
    if urls.is_empty() {
        return Ok(());
    }
    let batch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let staging = Batch(root.join(format!(".download-{}-{batch}", std::process::id())));
    std::fs::create_dir_all(&staging.0)?;
    let prefix = staging.0.join(format!("{name}-{batch}"));
    let log = prefix.with_extension("log");
    let mut command = Command::new("wget");
    command.kill_on_drop(true).args([
        "--compression=auto",
        "--delete-after",
        "--content-on-error",
        "--inet4-only",
        "--no-http-keep-alive",
        "--timeout=20",
        "--tries=2",
        "--header=Accept: text/html",
        "--user-agent",
        BROWSER,
    ]);
    if requisites {
        command.args(["--page-requisites", "--span-hosts"]);
    }
    let mut child = command
        .arg(format!("--warc-file={}", prefix.display()))
        .arg(format!(
            "--directory-prefix={}",
            prefix.with_extension("files").display()
        ))
        .arg(format!("--output-file={}", log.display()))
        .args(urls)
        .spawn()?;
    let deadline = std::time::Duration::from_secs((60 * urls.len() as u64).min(180));
    let status = match tokio::time::timeout(deadline, child.wait()).await {
        Ok(status) => status?,
        Err(_) => {
            child.kill().await?;
            std::fs::rename(&log, root.join(log.file_name().unwrap()))?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "capture exceeded its deadline",
            )
            .into());
        }
    };
    let published_log = root.join(log.file_name().unwrap());
    std::fs::rename(&log, &published_log)?;
    // Optional page assets and missing-page captures may return HTTP errors.
    // Required documents and distributions are verified from the archive below.
    if !status.success() && !matches!(status.code(), Some(4 | 8)) {
        return Err(format!("wget failed: {status}; see {}", published_log.display()).into());
    }
    if status.code() == Some(4) {
        eprintln!(
            "Some downloads were unreachable; required responses will be verified. See {}",
            published_log.display()
        );
    }
    let archive = prefix.with_extension("warc.gz");
    std::fs::rename(&archive, root.join(archive.file_name().unwrap()))?;
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

async fn missing_pages(root: &Path, sources: &[String]) -> Result {
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
                Err(error) => failures.push(error.to_string()),
            }
        }
        if !failures.is_empty() {
            return Err(failures.join("\n").into());
        }
    }
    let mut assets = BTreeSet::new();
    for url in urls {
        if let Some(response) = missing.get(&url)? {
            assets.extend(fictionet_extras::capture::links(&url, &response)?.assets);
        }
    }
    wget(
        root,
        "missing-assets",
        &assets.into_iter().collect::<Vec<_>>(),
        true,
    )
    .await
}

async fn documents(root: &Path, name: &str, urls: &[String]) -> Result {
    for group in urls.chunks(4) {
        let mut jobs = tokio::task::JoinSet::new();
        for url in group {
            let root = root.to_owned();
            let name = name.to_owned();
            let url = url.clone();
            jobs.spawn(async move {
                match download(&root, &name, std::slice::from_ref(&url), false).await {
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut) =>
                    {
                        eprintln!("Capture timed out: {url}");
                        Ok(())
                    }
                    result => result,
                }
            });
        }
        while let Some(result) = jobs.join_next().await {
            result??;
        }
    }
    Ok(())
}

async fn research(root: &Path, sources: &[String]) -> Result {
    wget(root, "research", sources, true).await?;
    let archive = Archive::directory(root)?;
    let mut references = BTreeSet::new();
    for url in sources {
        verify(&archive, url)?;
        let (url, response) = captured_at(&archive, url)?;
        references.extend(
            fictionet_extras::capture::references(&url, &response)?
                .into_iter()
                .take(32),
        );
    }
    let references: Vec<_> = references.into_iter().collect();
    let mut pending = Vec::new();
    for url in &references {
        if !archive.contains(url) {
            pending.push(url.clone());
        }
    }
    println!(
        "Capturing {} article references ({} already present)",
        references.len(),
        references.len() - pending.len()
    );
    // Only the source articles discover navigation. References are documents,
    // so third-party application assets cannot expand the capture recursively.
    documents(root, "references", &pending).await?;
    let archive = Archive::directory(root)?;
    let mut origins = sources.to_vec();
    for url in references {
        if captured(&archive, &url).is_ok_and(|response| response.status.is_success()) {
            origins.push(url);
        } else {
            eprintln!("Reference unavailable: {url}");
        }
    }
    missing_pages(root, &origins).await
}

fn package_root(root: &Path) -> std::io::Result<std::path::PathBuf> {
    if root.join("current").try_exists()? {
        std::fs::canonicalize(root.join("current"))
    } else {
        Ok(root.to_owned())
    }
}

fn publish(packages: &Path, destination: &Path) -> Result {
    std::fs::create_dir_all(destination)?;
    let name = format!(
        "batch-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos()
    );
    std::fs::rename(packages, destination.join(&name))?;
    let pointer = destination.join(format!(".{name}"));
    std::os::unix::fs::symlink(&name, &pointer)?;
    std::fs::rename(pointer, destination.join("current"))?;
    // Published batches remain immutable, including paths held by older worlds.
    Ok(())
}

pub async fn run(downloads: &Path, python: &Path) -> Result {
    let seed = web_world::pages::Seed::builtin("security")?;
    let corpus = seed.corpus.ok_or("missing corpus declaration")?;
    let root = downloads.join(&corpus.directory);
    std::fs::create_dir_all(&root)?;
    let root = std::fs::canonicalize(root)?;
    let capture = std::fs::File::open(&root)?;
    capture
        .try_lock()
        .map_err(|error| format!("cannot own corpus capture: {error}"))?;
    research(&root, &corpus.urls).await?;

    // Resolve and capture into an empty batch. Mutable indexes and their complete
    // dependency closure are published together only after an offline install.
    let stamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let batch = Batch(downloads.join(format!(".capture-{}-{stamp}", std::process::id())));
    let staged_corpus = batch.0.join(&corpus.directory);
    std::fs::create_dir_all(&staged_corpus)?;
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        if entry.path().to_string_lossy().ends_with(".warc.gz") {
            std::os::unix::fs::symlink(entry.path(), staged_corpus.join(entry.file_name()))?;
        }
    }
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
    wget(&packages, "distributions", &urls, false).await?;
    let sources = Archive::directory(&packages)?
        .urls()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    missing_pages(&packages, &sources).await?;
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
