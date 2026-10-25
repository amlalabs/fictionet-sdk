//! The public original behind a page a model writes. The host reads the
//! real document at that address, the way Live copies pages, so a written
//! page for a document that exists matches it. The guest never reaches it.

use super::super::live::{
    Lifetime,
    transport::{Ask, Transport},
};
use super::*;
use fictionet_extras::capture;
use prompts::Original;
use tokio::sync::oneshot;

#[derive(Default)]
pub(super) struct Originals {
    transport: OnceLock<Result<Arc<Transport>, String>>,
    lifetime: Arc<Lifetime>,
}

impl Originals {
    /// Reads `url` on the host, following redirects. `None` when the
    /// address has no readable document.
    pub(super) async fn read(&self, cx: &Cx, url: &str) -> Option<Original> {
        let transport = match self
            .transport
            .get_or_init(|| Transport::new().map(Arc::new))
        {
            Ok(transport) => transport.clone(),
            Err(error) => {
                eprintln!("Original documents are unavailable: {error}");
                return None;
            }
        };
        let (send, receive) = oneshot::channel();
        let lifetime = self.lifetime.clone();
        let url = url.to_owned();
        let thread = cx.clone();
        let runner = transport.clone();
        runner.spawn(async move {
            let _ = send.send(follow(&transport, &thread, &lifetime, &url).await);
        });
        cx.race(None, receive).await.ok()?.ok()?
    }
}

async fn follow(
    transport: &Transport,
    cx: &Cx,
    lifetime: &Lifetime,
    url: &str,
) -> Option<Original> {
    let mut url = url::Url::parse(url).ok()?;
    let mut visited = HashSet::new();
    let response = loop {
        if !visited.insert(url.clone()) {
            return None;
        }
        let response = transport
            .request(cx, lifetime, None, url.as_str(), Ask::Original)
            .await
            .ok()?;
        if response.status.is_redirection() {
            let location = response
                .headers
                .get(http::header::LOCATION)?
                .to_str()
                .ok()?;
            url = url.join(location).ok()?;
            continue;
        }
        break response;
    };
    if response.status != http::StatusCode::OK {
        return None;
    }
    let content_type = response
        .headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let original = transport
        .process(cx, lifetime, move || {
            let body = &response.body;
            Ok(if content_type.starts_with("application/pdf") {
                // A malformed PDF can panic inside the parser; it has no text then.
                std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(&body[..]))
                    .ok()
                    .and_then(Result::ok)
                    .map(|text| Original { title: None, text })
            } else if content_type.starts_with("text/html") {
                capture::page_text(&String::from_utf8_lossy(body))
                    .ok()
                    .map(|text| Original {
                        title: capture::title(&response)
                            .ok()
                            .map(|title| title.trim().to_owned())
                            .filter(|title| !title.is_empty()),
                        text,
                    })
            } else if content_type.starts_with("text/") {
                Some(Original {
                    title: None,
                    text: String::from_utf8_lossy(body).into_owned(),
                })
            } else {
                None
            })
        })
        .await
        .ok()??;
    (!original.text.trim().is_empty()).then_some(original)
}
