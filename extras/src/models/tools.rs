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
/// Elements that end a line of text, as a browser lays them out.
const BLOCKS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
];
/// A page's readable text: HTML without scripts and styles, or plain text.
/// Blank lines and indentation are dropped. Other media types have none.
pub(super) fn text(page: &Page) -> Option<String> {
    let text = if page.media_type == "text/html" {
        use kuchiki::iter::NodeEdge;
        use kuchiki::traits::TendrilSink;
        let doc = kuchiki::parse_html().one(String::from_utf8_lossy(&page.body).into_owned());
        if let Ok(nodes) = doc.select("head,script,style,noscript,template") {
            for node in nodes.collect::<Vec<_>>() {
                node.as_node().detach();
            }
        }
        let block = |node: &kuchiki::NodeRef| {
            node.as_element()
                .is_some_and(|e| BLOCKS.contains(&&*e.name.local))
        };
        let mut text = String::new();
        for edge in doc.traverse() {
            match edge {
                NodeEdge::Start(node) | NodeEdge::End(node) if block(&node) => text.push('\n'),
                NodeEdge::Start(node) => {
                    if let Some(chunk) = node.as_text() {
                        text.push_str(&chunk.borrow());
                    }
                }
                NodeEdge::End(_) => {}
            }
        }
        text
    } else if page.media_type.starts_with("text/") {
        String::from_utf8_lossy(&page.body).into_owned()
    } else {
        return None;
    };
    Some(
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
    )
}
