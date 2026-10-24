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

async fn wget(root: &Path, name: &str, urls: &[String], requisites: bool) -> Result {
    std::fs::create_dir_all(root)?;
    let archive = if std::fs::read_dir(root)?
        .any(|entry| entry.is_ok_and(|entry| entry.path().to_string_lossy().ends_with(".warc.gz")))
    {
        Some(Archive::directory(root)?)
    } else {
        None
    };
    let urls: Vec<_> = urls
        .iter()
        .filter(|url| {
            archive
                .as_ref()
                .is_none_or(|archive| !archive.contains(url))
        })
        .collect();
    if urls.is_empty() {
        return Ok(());
    }
    let batch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();
    let prefix = root.join(format!("{name}-{batch}"));
    let mut command = Command::new("wget");
    command.args([
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
    let status = command
        .arg(format!("--warc-file={}", prefix.display()))
        .arg(format!(
            "--directory-prefix={}",
            prefix.with_extension("files").display()
        ))
        .arg(format!(
            "--output-file={}",
            prefix.with_extension("log").display()
        ))
        .args(urls)
        .status()
        .await?;
    // Optional page assets and missing-page captures may return HTTP errors.
    // Required documents and distributions are verified from the archive below.
    if !status.success() && !matches!(status.code(), Some(4 | 8)) {
        return Err(format!(
            "wget failed: {status}; see {}",
            prefix.with_extension("log").display()
        )
        .into());
    }
    if status.code() == Some(4) {
        eprintln!(
            "Some downloads were unreachable; required responses will be verified. See {}",
            prefix.with_extension("log").display()
        );
    }
    Ok(())
}

fn verify(archive: &Archive, url: &str) -> Result {
    let mut url = url::Url::parse(url)?;
    for _ in 0..10 {
        let response = archive
            .get(url.as_str())?
            .ok_or_else(|| format!("missing capture: {url}"))?;
        if response.status.is_success() {
            return Ok(());
        }
        if !response.status.is_redirection() {
            return Err(format!("capture {url}: {}", response.status).into());
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
    wget(root, "missing", &urls, false).await?;
    let archive = Archive::directory(root)?;
    let mut assets = BTreeSet::new();
    for url in urls {
        if let Some(response) = archive.get(&url)? {
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

pub async fn run(downloads: &Path, python: &Path) -> Result {
    let seed = web_world::pages::Seed::builtin("security")?;
    let corpus = seed.corpus.ok_or("missing corpus declaration")?;
    let root = downloads.join(corpus.directory);
    std::fs::create_dir_all(&root)?;
    let root = std::fs::canonicalize(root)?;
    wget(&root, "research", &corpus.urls, true).await?;
    let archive = Archive::directory(&root)?;
    for url in &corpus.urls {
        verify(&archive, url)?;
    }
    missing_pages(&root, &corpus.urls).await?;

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
        required.extend([index, distribution.download_info.url, metadata]);
    }
    for repo in [
        "psf/requests/archive/refs/tags/v2.32.3",
        "networkx/networkx/archive/refs/tags/networkx-3.4.2",
        "pallets/click/archive/refs/tags/8.1.8",
    ] {
        for extension in ["tar.gz", "zip"] {
            let url = format!("https://github.com/{repo}.{extension}");
            urls.push(url.clone());
            required.push(url);
        }
    }
    let root = root.join("packages");
    wget(&root, "distributions", &urls, false).await?;
    let sources = Archive::directory(&root)?
        .urls()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    missing_pages(&root, &sources).await?;
    let archive = Archive::directory(&root)?;
    for url in required {
        verify(&archive, &url)?;
    }
    println!(
        "Captured research sources and package distributions in {}",
        root.parent().unwrap().display()
    );
    Ok(())
}
