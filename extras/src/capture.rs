//! Host side HTTP capture and discovery of page requisites.

mod transport;

pub use transport::{client, public_address, receive};

use crate::warc;
use kuchiki::traits::TendrilSink;
use regex::Regex;
use std::io;
use url::Url;

/// Maximum decoded input passed to HTML, CSS and search-response parsers.
pub const PARSE_BYTES: usize = 2 * 1024 * 1024;

/// An ordinary desktop browser identity for host side live copies.
pub const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

/// The reason for one host HTTP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Query the configured search provider.
    Search,
    /// Copy a reached page, redirect or dependency.
    Capture,
}

/// A credential-free lifecycle event for a host request.
#[derive(Clone, Debug)]
pub struct Event {
    /// Correlates the attempt and its terminal outcome.
    pub attempt: u64,
    /// Destination without user information, query or fragment.
    pub url: Url,
    /// HTTP method sent to the destination.
    pub method: http::Method,
    /// Why the host is making this request.
    pub purpose: Purpose,
    /// Attempt or terminal outcome.
    pub phase: crate::models::UpstreamPhase,
    /// Status only when response headers arrived.
    pub status: Option<http::StatusCode>,
}

/// Observes actual host transport operations, excluding payloads and credentials.
pub type Observer = dyn Fn(&fictionet::Cx, &Event) + Send + Sync;

/// URLs discovered in a response, separated by navigation and page requisites.
#[derive(Default, Debug)]
pub struct Links {
    /// Navigable links. The caller enforces site and depth restrictions.
    pub pages: Vec<String>,
    /// CSS, scripts, images, fonts and nested CSS requisites.
    pub assets: Vec<String>,
}

/// Read document metadata without constructing a tree from untrusted markup.
pub fn title(response: &warc::Response) -> io::Result<String> {
    use html5ever::tokenizer::{TagKind, Token};
    let bytes = response.decoded()?;
    let mut title = String::new();
    let (mut inside, mut finished) = (false, false);
    tokens(&String::from_utf8_lossy(&bytes), |token| {
        match token {
            Token::TagToken(tag) if tag.name.as_ref() == "title" && !finished => {
                inside = tag.kind == TagKind::StartTag;
                finished = !inside;
            }
            Token::CharacterTokens(text) if inside => {
                if title.len() + text.len() > 4096 {
                    return Err(io::Error::other("document title exceeds size limit"));
                }
                title.push_str(&text);
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(title)
}

/// Article references, including the publisher's own pages and cited site roots.
pub fn references(url: &str, response: &warc::Response) -> io::Result<Vec<String>> {
    if !response.status.is_success()
        || !response
            .headers
            .get("content-type")
            .is_some_and(|value| value.as_bytes().starts_with(b"text/html"))
    {
        return Ok(Vec::new());
    }
    let decoded = response.decoded_with_limit(PARSE_BYTES)?;
    let dom = kuchiki::parse_html().one(String::from_utf8_lossy(&decoded).into_owned());
    for node in dom
        .select("nav, header, footer, aside, [role=navigation]")
        .unwrap()
        .collect::<Vec<_>>()
    {
        node.as_node().detach();
    }
    let mut original = Url::parse(url).map_err(io::Error::other)?;
    original.set_fragment(None);
    let base = dom
        .select_first("base[href]")
        .ok()
        .and_then(|node| original.join(node.attributes.borrow().get("href")?).ok())
        .unwrap_or_else(|| original.clone());
    let article = dom
        .select_first("article")
        .or_else(|_| dom.select_first("main"));
    let content = article.map(|node| node.as_node().clone()).unwrap_or(dom);
    let mut seen = std::collections::HashSet::new();
    let mut references = Vec::new();
    for url in content
        .select("a[href], area[href]")
        .unwrap()
        .filter_map(|node| {
            let url = base.join(node.attributes.borrow().get("href")?).ok()?;
            warc::key(url.as_str())
        })
        .filter(|url| url != original.as_str() && seen.insert(url.clone()))
    {
        if references.len() >= 2048 || url.len() > 8192 {
            return Err(io::Error::other("capture discovery exceeds link limit"));
        }
        references.push(url);
    }
    Ok(references)
}

/// A discovered navigation or static dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// A navigable page.
    Page,
    /// A document prerequisite.
    Asset,
}

/// Collect bounded discovery for request-time capture.
pub fn links(url: &str, response: &warc::Response) -> io::Result<Links> {
    let mut links = Links::default();
    visit_links(url, response, |kind, url| {
        let out = match kind {
            LinkKind::Page => &mut links.pages,
            LinkKind::Asset => &mut links.assets,
        };
        if out.len() >= 2048 {
            return Err(io::Error::other("capture discovery exceeds link limit"));
        }
        out.push(url);
        Ok(())
    })?;
    links.assets.sort();
    links.assets.dedup();
    Ok(links)
}

fn link(base: &Url, value: &str, out: &mut dyn FnMut(String) -> io::Result<()>) -> io::Result<()> {
    let Some(url) = base.join(value).ok().and_then(|u| warc::key(u.as_str())) else {
        return Ok(());
    };
    if url.len() > 8192 {
        return Err(io::Error::other("capture discovery exceeds link limit"));
    }
    out(url)
}

fn css(text: &str, base: &Url, out: &mut dyn FnMut(String) -> io::Result<()>) -> io::Result<()> {
    static URLS: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let regex = URLS.get_or_init(|| {
        Regex::new(r#"(?i)url\(\s*["']?([^\s\)"']+)|@import\s+["']([^"']+)"#).unwrap()
    });
    for captures in regex.captures_iter(text) {
        if let Some(value) = captures.get(1).or_else(|| captures.get(2)) {
            link(base, value.as_str(), out)?;
        }
    }
    Ok(())
}

fn srcset(
    mut input: &str,
    base: &Url,
    out: &mut dyn FnMut(String) -> io::Result<()>,
) -> io::Result<()> {
    while !input.is_empty() {
        input = input.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
        if input.is_empty() {
            break;
        }
        let end = input.find(char::is_whitespace).unwrap_or(input.len());
        let candidate = &input[..end];
        input = &input[end..];
        if !candidate.ends_with(',') {
            input = input.split_once(',').map_or("", |(_, rest)| rest);
        }
        link(base, candidate.trim_end_matches(','), out)?;
    }
    Ok(())
}

/// Discover static dependencies using the response's base URL and HTML base tag.
pub fn visit_links(
    url: &str,
    response: &warc::Response,
    mut visit: impl FnMut(LinkKind, String) -> io::Result<()>,
) -> io::Result<()> {
    let base = Url::parse(url).map_err(io::Error::other)?;
    if response.status.is_redirection() {
        if let Some(next) = response
            .headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| base.join(v).ok())
            .and_then(|u| warc::key(u.as_str()))
        {
            visit(LinkKind::Page, next)?;
        }
        return Ok(());
    }
    let content_type = response
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !(content_type.starts_with("text/html") || content_type.starts_with("text/css")) {
        return Ok(());
    }
    let decoded = response.decoded_with_limit(PARSE_BYTES)?;
    let text = String::from_utf8_lossy(&decoded);
    if content_type.starts_with("text/css") {
        css(&text, &base, &mut |url| visit(LinkKind::Asset, url))?;
        return Ok(());
    }
    // Discovery needs tokens, not a DOM. Deeply nested hostile markup cannot
    // grow a tree or turn navigation discovery into quadratic tree building.
    use html5ever::tokenizer::{TagKind, Token};
    let mut document_base = None;
    tokens(&text, |token| {
        if let Token::TagToken(tag) = token
            && tag.kind == TagKind::StartTag
            && tag.name.as_ref() == "base"
            && document_base.is_none()
        {
            document_base = tag
                .attrs
                .iter()
                .find(|attr| attr.name.local.as_ref() == "href")
                .and_then(|attr| base.join(&attr.value).ok());
        }
        Ok(())
    })?;
    let base = document_base.unwrap_or(base);
    if base.as_str().len() > 8192 {
        return Err(io::Error::other("capture discovery exceeds link limit"));
    }
    let mut picture = 0usize;
    let mut style = None;
    tokens(&text, |token| {
        let tag = match token {
            Token::CharacterTokens(text) => {
                if let Some(style) = &mut style {
                    String::push_str(style, &text);
                }
                return Ok(());
            }
            Token::TagToken(tag) => tag,
            _ => return Ok(()),
        };
        let name = tag.name.as_ref();
        if tag.kind == TagKind::EndTag {
            if name == "picture" {
                picture = picture.saturating_sub(1);
            }
            if name == "style"
                && let Some(text) = style.take()
            {
                css(&text, &base, &mut |url| visit(LinkKind::Asset, url))?;
            }
            return Ok(());
        }
        let attr = |name| {
            tag.attrs
                .iter()
                .find(|attr| attr.name.local.as_ref() == name)
                .map(|attr| attr.value.as_ref())
        };
        if name == "picture" {
            picture += 1;
        }
        if matches!(name, "a" | "area")
            && let Some(value) = attr("href")
        {
            link(&base, value, &mut |url| visit(LinkKind::Page, url))?;
        }
        if let Some(value) = attr("poster") {
            link(&base, value, &mut |url| visit(LinkKind::Asset, url))?;
        }
        if matches!(name, "audio" | "video" | "track" | "iframe")
            || (name == "source" && picture == 0)
        {
            return Ok(());
        }
        for name in ["src", "data"] {
            if let Some(value) = attr(name) {
                link(&base, value, &mut |url| visit(LinkKind::Asset, url))?;
            }
        }
        if let Some(value) = attr("srcset") {
            srcset(value, &base, &mut |url| visit(LinkKind::Asset, url))?;
        }
        if name == "link"
            && attr("rel").is_some_and(|r| {
                r.split_whitespace()
                    .any(|v| matches!(v, "stylesheet" | "icon" | "preload" | "modulepreload"))
            })
            && let Some(value) = attr("href")
        {
            link(&base, value, &mut |url| visit(LinkKind::Asset, url))?;
        }
        if let Some(value) = attr("style") {
            css(value, &base, &mut |url| visit(LinkKind::Asset, url))?;
        }
        if name == "style" {
            style = Some(String::new());
        }
        Ok(())
    })?;
    if let Some(text) = style {
        css(&text, &base, &mut |url| visit(LinkKind::Asset, url))?;
    }
    Ok(())
}

fn tokens(
    text: &str,
    visit: impl FnMut(html5ever::tokenizer::Token) -> io::Result<()>,
) -> io::Result<()> {
    use html5ever::tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, states::RawKind,
    };
    struct Sink<F>(F, io::Result<()>);
    impl<F: FnMut(Token) -> io::Result<()>> TokenSink for Sink<F> {
        type Handle = ();
        fn process_token(&mut self, token: Token, _: u64) -> TokenSinkResult<()> {
            let next = match &token {
                Token::TagToken(tag) if tag.kind == TagKind::StartTag => match tag.name.as_ref() {
                    "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                    "style" | "xmp" | "iframe" | "noembed" | "noframes" => {
                        TokenSinkResult::RawData(RawKind::Rawtext)
                    }
                    "textarea" | "title" => TokenSinkResult::RawData(RawKind::Rcdata),
                    "plaintext" => TokenSinkResult::Plaintext,
                    _ => TokenSinkResult::Continue,
                },
                _ => TokenSinkResult::Continue,
            };
            if self.1.is_ok() {
                self.1 = (self.0)(token);
            }
            next
        }
    }
    let mut tokenizer = Tokenizer::new(Sink(visit, Ok(())), Default::default());
    let mut input = BufferQueue::new();
    input.push_back(text.into());
    let _ = tokenizer.feed(&mut input);
    tokenizer.end();
    tokenizer.sink.1
}
