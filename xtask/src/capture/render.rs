//! Capture a rendered document while the browser itself has no web route.

use crate::Result;
use fictionet_demo::kit::RunDir;
use fictionet_extras::{capture, warc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::os::fd::AsRawFd;
use std::{path::Path, process::Stdio, sync::Arc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

async fn send(writer: &mut OwnedWriteHalf, value: Value) -> Result {
    writer.write_all(value.to_string().as_bytes()).await?;
    writer.write_all(&[0]).await?;
    Ok(())
}

async fn receive(reader: &mut BufReader<OwnedReadHalf>, bytes: &mut Vec<u8>) -> Result<Value> {
    let count = reader.read_until(0, bytes).await?;
    if count == 0 || bytes.last() != Some(&0) {
        return Err("invalid browser message".into());
    }
    let value = serde_json::from_slice(&bytes[..bytes.len() - 1])?;
    bytes.clear();
    Ok(value)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Paused {
    request_id: String,
    request: Request,
}

#[derive(Deserialize)]
struct Request {
    url: url::Url,
    #[serde(deserialize_with = "method")]
    method: http::Method,
    headers: std::collections::HashMap<String, String>,
}

enum Captured {
    Cached(warc::Response),
    Fetched(warc::Response),
}

fn method<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<http::Method, D::Error> {
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}

/// The snapshot and all browser dependencies use the same public-web transport
/// as ordinary captures. Redirects return to interception for fresh admission.
pub(super) async fn document(root: &Path, url: &str, title: &str) -> Result {
    capture::client(&url::Url::parse(url)?).await?;
    render(root, url, Some(title), get).await.map(|_| ())
}

pub(super) async fn requisites(root: &Path, urls: &[String]) -> Result<Vec<String>> {
    let existing = Arc::new(warc::Archive::directory(root)?);
    let mut assets = Vec::new();
    let mut urls = urls
        .iter()
        .cloned()
        .collect::<std::collections::VecDeque<_>>();
    let mut seen = std::collections::HashSet::new();
    let mut pages = tokio::task::JoinSet::new();
    let workers = std::thread::available_parallelism()?.get();
    loop {
        while pages.len() < workers
            && let Some(url) = urls.pop_front()
        {
            if !seen.insert(url.clone()) {
                continue;
            }
            let Some(response) = existing.get(&url)? else {
                continue;
            };
            if response.status.is_redirection() {
                urls.extend(capture::links(&url, &response)?.pages);
                continue;
            }
            if !response
                .headers
                .get(http::header::CONTENT_TYPE)
                .is_some_and(|value| value.as_bytes().starts_with(b"text/html"))
            {
                continue;
            }
            let cache = existing.clone();
            let root = root.to_owned();
            let url = url.clone();
            pages.spawn(async move {
                eprintln!("Rendering requisites: {url}");
                render(&root, &url, None, move |request| {
                    let cache = cache.clone();
                    async move {
                        if let Some(response) = cache.get(request.url.as_str())?
                            && (response.status.is_success() || response.status.is_redirection())
                        {
                            return Ok(Captured::Cached(response));
                        }
                        get(request).await
                    }
                })
                .await
            });
        }
        let Some(result) = pages.join_next().await else {
            break;
        };
        assets.extend(result??);
    }
    Ok(assets)
}

async fn get(request: Request) -> std::io::Result<Captured> {
    let client = capture::client(&request.url).await?;
    let mut headers = http::HeaderMap::new();
    for (name, value) in request.headers {
        headers.insert(
            name.parse::<http::HeaderName>()
                .map_err(std::io::Error::other)?,
            value.parse().map_err(std::io::Error::other)?,
        );
    }
    let response = client
        .get(request.url)
        .headers(headers)
        .send()
        .await
        .map_err(std::io::Error::other)?;
    let mut response = capture::receive(response).await?;
    response.body = response.decoded()?.into();
    response.headers.remove(http::header::CONTENT_ENCODING);
    response.headers.remove(http::header::TRANSFER_ENCODING);
    response
        .headers
        .insert(http::header::CONTENT_LENGTH, response.body.len().into());
    Ok(Captured::Fetched(response))
}

async fn render<F, T>(root: &Path, url: &str, title: Option<&str>, fetch: F) -> Result<Vec<String>>
where
    F: Fn(Request) -> T + Send + Sync + 'static,
    T: std::future::Future<Output = std::io::Result<Captured>> + Send,
{
    let fetch = Arc::new(fetch);
    let profile = RunDir::new(&std::env::temp_dir(), "capture-browser")?;
    let (parent, child) = std::os::unix::net::UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    let descriptor = child.as_raw_fd();
    let mut command = tokio::process::Command::new("unshare");
    command
        .kill_on_drop(true)
        .args(["--user", "--map-root-user", "--net", "chromium"])
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--password-store=basic",
            "--use-mock-keychain",
            "--remote-debugging-pipe",
            "--no-startup-window",
            "--window-size=1440,1000",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The browser has no IP network. Its only host connection is this Unix
    // socket, duplicated onto Chromium's DevTools command and reply descriptors.
    // SAFETY: only async-signal-safe descriptor operations run after fork.
    unsafe {
        command.pre_exec(move || {
            let descriptor = libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 5);
            if descriptor < 0 || libc::dup2(descriptor, 3) < 0 || libc::dup2(descriptor, 4) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut browser = command.spawn()?;
    drop(child);
    let (reader, mut writer) = tokio::net::UnixStream::from_std(parent)?.into_split();
    let mut reader = BufReader::new(reader);
    let mut incoming = Vec::new();
    let work = async {
        let mut id = 0;
        macro_rules! call {
            ($method:expr, $params:expr, $session:expr) => {{
                id += 1;
                let mut command = json!({"id":id,"method":$method,"params":$params});
                if let Some(session) = $session { command["sessionId"] = json!(session); }
                send(&mut writer, command).await?;
                loop {
                    let reply = receive(&mut reader, &mut incoming).await?;
                    if reply["id"] == id {
                        if reply.get("error").is_some() { return Err("capture browser command failed".into()); }
                        break reply["result"].clone();
                    }
                }
            }};
        }
        let target = call!(
            "Target.createTarget",
            json!({"url":"about:blank"}),
            None::<&str>
        );
        let attached = call!(
            "Target.attachToTarget",
            json!({"targetId":target["targetId"],"flatten":true}),
            None::<&str>
        );
        let session = attached["sessionId"]
            .as_str()
            .ok_or("missing browser session")?
            .to_owned();
        call!("Network.enable", json!({}), Some(&session));
        call!("Page.enable", json!({}), Some(&session));
        call!(
            "Page.setLifecycleEventsEnabled",
            json!({"enabled":true}),
            Some(&session)
        );
        let frame =
            call!("Page.getFrameTree", json!({}), Some(&session))["frameTree"]["frame"]["id"]
                .clone();
        call!(
            "Network.setBypassServiceWorker",
            json!({"bypass":true}),
            Some(&session)
        );
        call!(
            "Network.setCacheDisabled",
            json!({"cacheDisabled":true}),
            Some(&session)
        );
        call!(
            "Fetch.enable",
            json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
            Some(&session)
        );
        id += 1;
        send(
            &mut writer,
            json!({"id":id,"sessionId":session,"method":"Page.navigate","params":{"url":url}}),
        )
        .await?;
        let mut archive = warc::Archive::default();
        let staging =
            super::Batch(root.join(format!(".render-{}-{}", std::process::id(), time_stamp())));
        std::fs::create_dir(&staging.0)?;
        let path = staging.0.join(format!("rendered-{}.warc.gz", time_stamp()));
        let mut requests = tokio::task::JoinSet::new();
        let mut urls = Vec::new();
        let mut idle = false;
        let mut evaluation = None;
        let required = serde_json::to_string(&title.unwrap_or_default().to_ascii_lowercase())?;
        let expression = format!(
            r#"(() => {{
            if (!document.title.toLowerCase().includes({required}) || !document.body?.innerText.toLowerCase().includes({required})) return null;
            const html = document.documentElement.outerHTML;
            return {{url:location.href, html}};
        }})()"#
        );
        loop {
            if idle && requests.is_empty() && evaluation.is_none() {
                if title.is_none() {
                    if path.exists() {
                        super::install(&path, root)?;
                    }
                    return Ok(urls);
                }
                id += 1;
                evaluation = Some(id);
                send(&mut writer, json!({"id":id,"sessionId":session,"method":"Runtime.evaluate","params":{"expression":expression,"returnByValue":true}})).await?;
            }
            tokio::select! {
                message = receive(&mut reader, &mut incoming) => {
                    let message = message?;
                    if message["method"] == "Fetch.requestPaused" {
                        let paused: Paused = serde_json::from_value(message["params"].clone())?;
                        urls.push(paused.request.url.to_string());
                        idle = false;
                        let fetch = fetch.clone();
                        requests.spawn(async move {
                            let response = async {
                                if paused.request.method != http::Method::GET { return Err(std::io::Error::other("capture requires a GET response")); }
                                fetch(Request { url: paused.request.url.clone(), method: paused.request.method.clone(), headers: paused.request.headers.clone() }).await
                            };
                            let response = response.await;
                            (paused, response)
                        });
                    } else if message["method"] == "Page.lifecycleEvent" && message["params"]["name"] == "networkIdle" && message["params"]["frameId"] == frame {
                        idle = true;
                    } else if evaluation.is_some() && message.get("id").and_then(Value::as_u64) == evaluation {
                        if message["result"].get("exceptionDetails").is_some() { return Err("rendered document could not be retained".into()); }
                        let value = &message["result"]["result"]["value"];
                        if let (Some(url), Some(html)) = (value["url"].as_str(), value["html"].as_str()) {
                            let mut response = archive.get(url)?.ok_or("rendered document has no captured response")?;
                            if !response.status.is_success() { return Err("rendered document was not a successful response".into()); }
                            response.body = html.to_owned().into();
                            for header in ["etag", "content-md5", "content-length"] { response.headers.remove(header); }
                            response.headers.insert(http::header::CONTENT_LENGTH, response.body.len().into());
                            archive.append(&path, url, &response)?;
                            super::install(&path, root)?;
                            return Ok(urls);
                        }
                        return Err("rendered document does not contain the requested text".into());
                    }
                }
                Some(result) = requests.join_next(), if !requests.is_empty() => {
                    let (paused, response) = result?;
                    id += 1;
                    let (method, params) = if let Ok(captured) = response {
                        let (response, fetched) = match captured {
                            Captured::Cached(response) => (response, false),
                            Captured::Fetched(response) => (response, true),
                        };
                        if fetched {
                            archive.append(&path, paused.request.url.as_str(), &response)?;
                            eprintln!("Rendered requisite {}: {}", response.status, paused.request.url);
                        }
                        let headers = response.headers.iter().map(|(name, value)| json!({"name":name.as_str(),"value":value.to_str().unwrap_or("")})).collect::<Vec<_>>();
                        ("Fetch.fulfillRequest", json!({"requestId":paused.request_id,"responseCode":response.status.as_u16(),"responseHeaders":headers,"body":fictionet::stdlib::codec::base64::encode(&response.body)}))
                    } else {
                        if let Err(error) = response { eprintln!("Rendered requisite unavailable: {}: {error}", paused.request.url); }
                        ("Fetch.failRequest", json!({"requestId":paused.request_id,"errorReason":"BlockedByClient"}))
                    };
                    send(&mut writer, json!({"id":id,"sessionId":session,"method":method,"params":params})).await?;
                }
            }
        }
    };
    let result = work.await;
    let _ = browser.kill().await;
    result
}

fn time_stamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("current clock")
        .as_nanos()
}
