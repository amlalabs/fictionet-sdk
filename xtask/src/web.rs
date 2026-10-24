//! Download and prepare the offline reference web.

use crate::Result;
use fictionet_extras::{
    capture,
    warc::{Archive, Response},
};
use std::{os::unix::fs::FileExt, path::Path, sync::Arc};

const WIKIPEDIA: &str = "wikipedia_en_all_nopic_2026-06.zim";
const RESERVE: u64 = 60 * 1024 * 1024 * 1024;

pub enum Step {
    All,
    Documents,
    Index,
}

fn space(path: &Path, additional: u64) -> Result {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // The path is NUL terminated and statvfs initializes the output on success.
    if unsafe { libc::statvfs(name.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let stats = unsafe { stats.assume_init() };
    if stats.f_bavail * stats.f_frsize < RESERVE + additional {
        return Err("offline web preparation must leave at least 60 GiB free".into());
    }
    Ok(())
}

async fn fetch(url: url::Url) -> Result<Response> {
    for attempt in 0..3 {
        let result: Result<Response> = async {
            let client = capture::client(&url).await?;
            let response = client
                .get(url.clone())
                .timeout(std::time::Duration::from_secs(15))
                .send()
                .await?;
            if response.status().is_server_error()
                || response.status() == http::StatusCode::TOO_MANY_REQUESTS
            {
                return Err(response.error_for_status().unwrap_err().into());
            }
            Ok(capture::receive(response, Response::DECODED_BYTES).await?)
        }
        .await;
        match result {
            Ok(response) => return Ok(response),
            Err(error) if attempt == 2 => return Err(error),
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await,
        }
    }
    unreachable!()
}

async fn copy_site(root: &Path, name: &str, origin: &str) -> Result {
    use std::collections::{HashSet, VecDeque};
    let destination = root.join(format!("{name}.warc.gz"));
    if destination.exists() {
        return Ok(());
    }
    let temporary = root.join(format!(".{name}.warc.gz"));
    let mut archive = Archive::open(temporary.exists().then_some(temporary.clone()))?;
    let origin = url::Url::parse(origin)?;
    let mut pending = VecDeque::from([origin.to_string()]);
    let mut queued = HashSet::from([origin.to_string()]);
    let mut seen = HashSet::new();
    let mut jobs = tokio::task::JoinSet::new();
    while !pending.is_empty() || !jobs.is_empty() {
        while jobs.len() < 8
            && let Some(url) = pending.pop_front()
        {
            if !seen.insert(url.clone()) {
                continue;
            }
            if seen.len() > 100_000 {
                return Err("documentation capture exceeds page budget".into());
            }
            let cached = archive.get(&url)?.filter(|response| {
                response.status.is_success()
                    || response.status.is_redirection()
                    || response.status == http::StatusCode::NOT_FOUND
            });
            jobs.spawn(async move {
                let response = match cached {
                    Some(response) => response,
                    None => {
                        tokio::time::timeout(
                            std::time::Duration::from_secs(60),
                            fetch(url::Url::parse(&url)?),
                        )
                        .await??
                    }
                };
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((url, response))
            });
        }
        let Some(result) = jobs.join_next().await else {
            continue;
        };
        let (url, response) = result??;
        if !archive.contains(&url) {
            space(root, response.body.len() as u64)?;
            archive.append(&temporary, &url, &response)?;
        }
        let parsed = url::Url::parse(&url)?;
        if response.status.is_redirection() {
            if let Some(next) = response
                .headers
                .get("location")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parsed.join(v).ok())
            {
                let next: String = next.into();
                if queued.insert(next.clone()) {
                    pending.push_back(next);
                }
            }
        } else if response.status.is_success() || response.status == http::StatusCode::NOT_FOUND {
            capture::visit_links(&url, &response, |kind, next| {
                let admitted = kind == capture::LinkKind::Asset
                    || response.status.is_success()
                        && url::Url::parse(&next).is_ok_and(|url| {
                            url.host_str() == origin.host_str()
                                && (url.path() == origin.path()
                                    || url.path().strip_prefix(origin.path()).is_some_and(|tail| {
                                        origin.path().ends_with('/') || tail.starts_with('/')
                                    }))
                                && url.query().is_none()
                        });
                if admitted && queued.insert(next.clone()) {
                    pending.push_back(next);
                }
                Ok(())
            })?;
        }
        if seen.len().is_multiple_of(250) {
            eprintln!("Captured {} documentation URLs for {name}", seen.len());
        }
    }
    let missing_url = origin.join("404")?;
    let missing = match archive
        .get(origin.as_str())?
        .filter(|page| page.status == http::StatusCode::NOT_FOUND)
    {
        Some(page) => page,
        None => fetch(missing_url).await?,
    };
    if missing.status != http::StatusCode::NOT_FOUND {
        return Err(format!("{name} did not return a missing-page response").into());
    }
    let mut missing_url = origin.clone();
    missing_url.set_path("/404");
    archive.append(&temporary, missing_url.as_str(), &missing)?;
    std::fs::rename(temporary, destination)?;
    Ok(())
}

async fn python(root: &Path) -> Result {
    use std::io::Read;
    let destination = root.join("python.warc.gz");
    if destination.exists() {
        return Ok(());
    }
    let url = url::Url::parse("https://docs.python.org/3/archives/python-3.15-docs-html.zip")?;
    let response = capture::client(&url)
        .await?
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    let response = capture::receive(response, 256 * 1024 * 1024).await?;
    space(root, response.body.len() as u64 + 512 * 1024 * 1024)?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(response.body))?;
    let temporary = root.join(".python-archive.warc.gz");
    if temporary.exists() {
        std::fs::remove_file(&temporary)?;
    }
    let mut archive = Archive::default();
    let mut total = 0;
    for entry in 0..zip.len() {
        let mut file = zip.by_index(entry)?;
        if file.is_dir() {
            continue;
        }
        let path = file
            .enclosed_name()
            .ok_or("invalid documentation archive path")?;
        let relative = path.components().skip(1).collect::<std::path::PathBuf>();
        let mut body = Vec::new();
        file.by_ref()
            .take(Response::DECODED_BYTES as u64 + 1)
            .read_to_end(&mut body)?;
        total += body.len();
        if body.len() > Response::DECODED_BYTES || total > 512 * 1024 * 1024 {
            return Err("documentation archive exceeds decoded size budget".into());
        }
        let mime = mime_guess::from_path(&relative)
            .first_or_octet_stream()
            .to_string();
        let url = format!("https://docs.python.org/3/{}", relative.to_string_lossy());
        let response = Response {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([(http::header::CONTENT_TYPE, mime.parse()?)]),
            body: body.into(),
        };
        archive.append(&temporary, &url, &response)?;
        if relative == Path::new("index.html") {
            archive.append(&temporary, "https://docs.python.org/3/", &response)?;
        }
    }
    let missing = fetch(url::Url::parse("https://docs.python.org/3/404")?).await?;
    if missing.status != http::StatusCode::NOT_FOUND {
        return Err("Python did not return its missing-page response".into());
    }
    archive.append(&temporary, "https://docs.python.org/404", &missing)?;
    std::fs::rename(temporary, destination)?;
    eprintln!("Captured the complete Python HTML documentation");
    Ok(())
}

pub async fn build(downloads: &Path, step: Step) -> Result {
    let root = downloads.join("web");
    std::fs::create_dir_all(&root)?;
    space(&root, 0)?;
    let destination = root.join(WIKIPEDIA);
    if matches!(step, Step::All) && !destination.exists() {
        let client = reqwest::Client::builder()
            .user_agent(fictionet_extras::capture::BROWSER)
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(20))
            .build()?;
        let url = format!("https://ftpmirror.your.org/pub/kiwix/zim/wikipedia/{WIKIPEDIA}");
        let headers = client.head(&url).send().await?.error_for_status()?;
        let bytes: u64 = headers
            .headers()
            .get("content-length")
            .ok_or("archive has no length")?
            .to_str()?
            .parse()?;
        if bytes == 0 {
            return Err("archive is empty".into());
        }
        space(&root, bytes)?;
        let url = headers.url().clone();
        let temporary = destination.with_extension("zim.download");
        let file = Arc::new(std::fs::File::create(&temporary)?);
        file.set_len(bytes)?;
        let mut jobs = tokio::task::JoinSet::new();
        let chunk = bytes.div_ceil(16);
        for start in (0..bytes).step_by(chunk as usize) {
            let end = (start + chunk).min(bytes) - 1;
            let client = client.clone();
            let url = url.clone();
            let file = file.clone();
            jobs.spawn(async move {
                let mut response = client
                    .get(url)
                    .header("range", format!("bytes={start}-{end}"))
                    .send()
                    .await?
                    .error_for_status()?;
                if response.status() != reqwest::StatusCode::PARTIAL_CONTENT
                    || response
                        .headers()
                        .get("content-range")
                        .and_then(|v| v.to_str().ok())
                        != Some(format!("bytes {start}-{end}/{bytes}").as_str())
                {
                    return Err("archive server did not honor the requested range".into());
                }
                let mut at = start;
                while let Some(data) = response.chunk().await? {
                    if at + data.len() as u64 > end + 1 {
                        return Err("archive response exceeds range".into());
                    }
                    file.write_all_at(&data, at)?;
                    at += data.len() as u64;
                }
                if at != end + 1 {
                    return Err("incomplete archive range".into());
                }
                eprintln!("Downloaded archive range {} of 16", start / chunk + 1);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
        }
        while let Some(result) = jobs.join_next().await {
            result??;
        }
        file.sync_all()?;
        drop(file);
        eprintln!("Verifying Wikipedia archive…");
        zim::Zim::new(&temporary)?.verify_checksum()?;
        space(&root, 0)?;
        std::fs::rename(temporary, &destination)?;
    }
    if !matches!(step, Step::Index) {
        python(&root).await?;
        for (name, url) in [
            ("mdn", "https://developer.mozilla.org/en-US/docs/"),
            ("github-docs", "https://docs.github.com/en"),
            (
                "wikipedia-missing",
                "https://en.wikipedia.org/wiki/This_article_does_not_exist",
            ),
        ] {
            copy_site(&root, name, url).await?;
        }
    }
    if !matches!(step, Step::Documents) {
        web_world::pages::Pages::prepare_reference(
            web_world::pages::Seed::builtin("security")?,
            downloads,
        )?;
    }
    Ok(())
}
