//! Search and page access shared with a world's browser sites.
use super::*;

/// An asynchronous answer from the world's search or page handler.
pub type Answer<T> = Pin<Box<dyn Future<Output = fictionet::Result<T>> + Send>>;

/// The same search results and pages that the world serves to its browsers.
pub trait Engine: Send + Sync {
    /// Searches the world's pages, with the tool's domain restrictions for accurate observation.
    /// The model site also enforces those restrictions on the returned results.
    fn search(
        self: Arc<Self>,
        cx: Cx,
        query: String,
        domains: Domains,
    ) -> Answer<Vec<crate::search::Result>>;
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
    // `example.com.` names the same host as `example.com`.
    url.host_str()
        .map(|host| host.strip_suffix('.').unwrap_or(host).to_owned())
}
/// Domain restrictions on a world's search and fetch results.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Domains {
    /// Permitted domains and their subdomains; absent means unrestricted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    /// Excluded domains and their subdomains, even when otherwise permitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_domains: Option<Vec<String>>,
}
/// Whether the tool's domain restrictions permit this HTTP URL.
pub fn allowed(domains: &Domains, url: &str) -> bool {
    let Some(host) = host(url) else {
        return false;
    };
    let matches = |domain: &String| {
        let domain = domain.trim_matches('.').to_ascii_lowercase();
        host == domain
            || host
                .strip_suffix(&domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
    };
    !domains
        .blocked_domains
        .as_ref()
        .is_some_and(|ds| ds.iter().any(matches))
        && domains
            .allowed_domains
            .as_ref()
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
