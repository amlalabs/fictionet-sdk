//! The public original behind a page a model writes. The host reads the
//! real document at that address, the way Live copies pages, so a written
//! page for a document that exists matches it. The guest never reaches it.

use super::live::{
    Lifetime,
    transport::{Ask, Transport},
};
use super::*;
use fictionet_extras::capture;
use prompts::{Original, Reading};
use tokio::sync::oneshot;

#[derive(Default)]
pub(super) struct Originals {
    transport: OnceLock<Result<Arc<Transport>, String>>,
    lifetime: Arc<Lifetime>,
    observer: Mutex<Option<Arc<capture::Observer>>>,
    /// The search provider's key, for originals a site only shows browsers.
    search: Mutex<Option<fictionet_extras::models::Key>>,
}

impl Originals {
    pub(super) fn observe(&self, observer: Arc<capture::Observer>) {
        *self.observer.lock().unwrap() = Some(observer);
    }

    pub(super) fn search_with(&self, key: fictionet_extras::models::Key) {
        *self.search.lock().unwrap() = Some(key);
    }

    /// Reads `url` on the host, following redirects. When the address
    /// cannot be read, its `captured` text stands in; without one, a site
    /// that answers only browsers (a script challenge) is read from the
    /// search provider's copy. `None` when the address has no readable
    /// document.
    pub(super) async fn read(
        &self,
        cx: &Cx,
        url: &str,
        captured: Option<Original>,
    ) -> Option<Original> {
        let transport = match self
            .transport
            .get_or_init(|| Transport::new().map(Arc::new))
        {
            Ok(transport) => transport.clone(),
            Err(error) => {
                eprintln!("Original documents are unavailable: {error}");
                return captured;
            }
        };
        let (send, receive) = oneshot::channel();
        let lifetime = self.lifetime.clone();
        let observer = self.observer.lock().unwrap().clone();
        let search = self.search.lock().unwrap().clone();
        let url = url.to_owned();
        let thread = cx.clone();
        let runner = transport.clone();
        runner.spawn(async move {
            let original =
                match follow(&transport, &thread, &lifetime, observer.clone(), &url).await {
                    Some(original) => Some(original),
                    None => match (captured, search) {
                        (Some(captured), _) => Some(captured),
                        (None, Some(key)) => {
                            contents(&transport, &thread, &lifetime, observer, &key, &url).await
                        }
                        (None, None) => None,
                    },
                };
            let _ = send.send(original);
        });
        cx.race(None, receive).await.ok()?.ok()?
    }
}

/// The search provider's text of `url`. Its title is the document's, not
/// the page's, so the page's own title is left to the site's conventions.
async fn contents(
    transport: &Transport,
    cx: &Cx,
    lifetime: &Lifetime,
    observer: Option<Arc<capture::Observer>>,
    key: &fictionet_extras::models::Key,
    url: &str,
) -> Option<Original> {
    #[derive(Deserialize)]
    struct Reply {
        results: Vec<Item>,
    }
    #[derive(Deserialize)]
    struct Item {
        text: Option<String>,
    }
    let body = json!({"urls": [url], "text": true});
    let response = transport
        .request(
            cx,
            lifetime,
            observer,
            "https://api.exa.ai/contents",
            Ask::Contents(key, &body),
        )
        .await
        .ok()?;
    if !response.status.is_success() {
        return None;
    }
    let reply: Reply = serde_json::from_slice(&response.body).ok()?;
    let text = reply.results.into_iter().next()?.text?;
    (!text.trim().is_empty()).then_some(Original {
        title: None,
        text: key.redact(&text),
        read: Reading::Indexed,
    })
}

async fn follow(
    transport: &Transport,
    cx: &Cx,
    lifetime: &Lifetime,
    observer: Option<Arc<capture::Observer>>,
    url: &str,
) -> Option<Original> {
    let mut url = url::Url::parse(url).ok()?;
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
                    .map(|text| Original {
                        title: None,
                        text,
                        read: Reading::Served,
                    })
            } else if content_type.starts_with("text/html") {
                capture::page_text(&String::from_utf8_lossy(body))
                    .ok()
                    .map(|text| Original {
                        title: capture::title(&response)
                            .ok()
                            .map(|title| title.trim().to_owned())
                            .filter(|title| !title.is_empty()),
                        text,
                        read: Reading::Served,
                    })
            } else if content_type.starts_with("text/") {
                Some(Original {
                    title: None,
                    text: String::from_utf8_lossy(body).into_owned(),
                    read: Reading::Served,
                })
            } else {
                None
            })
        })
        .await
        .ok()??;
    (!original.text.trim().is_empty()).then_some(original)
}
