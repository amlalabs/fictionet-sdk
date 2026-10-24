//! The public original behind a page a model writes. The host reads the
//! real document at that address, the way Live copies pages, so a written
//! page for a document that exists matches it. The guest never reaches it.

use super::live::{
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
    observer: Mutex<Option<Arc<capture::Observer>>>,
}

impl Originals {
    pub(super) fn observe(&self, observer: Arc<capture::Observer>) {
        *self.observer.lock().unwrap() = Some(observer);
    }

    /// Reads `url` on the host, following redirects. `None` when the address
    /// has no readable public document.
    pub(super) async fn read(&self, cx: &Cx, url: &str) -> Option<Original> {
        let transport = self
            .transport
            .get_or_init(|| Transport::new().map(Arc::new))
            .as_ref()
            .inspect_err(|error| eprintln!("Original documents are unavailable: {error}"))
            .ok()?
            .clone();
        let (send, receive) = oneshot::channel();
        let lifetime = self.lifetime.clone();
        let observer = self.observer.lock().unwrap().clone();
        let url = url.to_owned();
        let thread = cx.clone();
        let runner = transport.clone();
        runner.spawn(async move {
            let _ = send.send(follow(&transport, &thread, &lifetime, observer, url).await);
        });
        cx.race(None, receive).await.ok()?.ok()?
    }
}

async fn follow(
    transport: &Transport,
    cx: &Cx,
    lifetime: &Lifetime,
    observer: Option<Arc<capture::Observer>>,
    url: String,
) -> Option<Original> {
    let mut url = url::Url::parse(&url).ok()?;
    let mut visited = HashSet::new();
    let response = loop {
        if !visited.insert(url.clone()) {
            return None;
        }
        let response = transport
            .request(cx, lifetime, observer.clone(), url.as_str(), Ask::Original)
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
