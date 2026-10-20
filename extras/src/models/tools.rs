//! Search and page access shared with a world's browser sites.
use super::*;

/// An asynchronous answer from the world's search or page handler.
pub type Answer<T> = Pin<Box<dyn Future<Output = fictionet::Result<T>> + Send>>;

/// The same search results and pages that the world serves to its browsers.
pub trait Engine: Send + Sync {
    /// Searches the world's pages. Domain restrictions are applied by the model site.
    fn search(self: Arc<Self>, cx: Cx, query: String) -> Answer<Vec<crate::search::Result>>;
    /// Reads a page through the world's handler, without a host internet request.
    fn fetch(self: Arc<Self>, cx: Cx, url: String) -> Answer<Page>;
    /// Whether the world serves a hostname.
    fn serves(&self, host: &str) -> bool;
}

/// A page returned by a world's own handler.
#[derive(Clone, Debug)]
pub struct Page {
    /// Page title.
    pub title: String,
    /// Media type, without parameters.
    pub media_type: String,
    /// Text or PDF bytes. HTML is converted to text by the model site.
    pub body: Vec<u8>,
}

pub(super) fn host(url: &str) -> Option<String> {
    let url = url::Url::parse(url).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.host_str().map(str::to_owned)
}
pub(super) fn allowed(tool: &Value, url: &str) -> bool {
    let Some(host) = host(url) else {
        return false;
    };
    let matches = |domain: &Value| {
        domain.as_str().is_some_and(|d| {
            let domain = d.trim_start_matches('.').to_ascii_lowercase();
            host == domain
                || host
                    .strip_suffix(&domain)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    };
    !tool["blocked_domains"]
        .as_array()
        .is_some_and(|ds| ds.iter().any(matches))
        && tool["allowed_domains"]
            .as_array()
            .is_none_or(|ds| ds.iter().any(matches))
}
