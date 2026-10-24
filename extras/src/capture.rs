//! Host side HTTP capture and discovery of page requisites.

mod transport;

pub use transport::{Pool, client, public_address, receive};

use crate::warc;
use kuchiki::traits::TendrilSink;
use std::io;
use url::Url;

/// An ordinary desktop browser identity for host side live copies.
pub const BROWSER: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

/// The reason for one host HTTP request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Query the configured search provider.
    Search,
    /// Copy a reached page, redirect or dependency.
    Capture,
    /// Copy a package index or file a copied mirror lacks.
    Package,
}

/// Whether a response was reached as a page or as one of its dependencies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Resource {
    /// A page reached directly or through a navigation redirect.
    Document,
    /// A stylesheet, script, font, image or other page dependency.
    Requisite,
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
    /// The page this request fetches a dependency of, when it is one.
    pub page: Option<Url>,
}

/// Observes actual host transport operations, excluding payloads and credentials.
pub type Observer = dyn Fn(&fictionet::Cx, &Event) + Send + Sync;

/// Read article text in a single pass for offline indexing.
pub fn page_text(html: &str) -> io::Result<String> {
    use html5ever::tokenizer::{TagKind, Token};
    let mut text = String::new();
    let mut hidden = Vec::new();
    tokens(html, |token| {
        match token {
            Token::TagToken(tag) => {
                let name = tag.name.as_ref();
                let excluded = matches!(
                    name,
                    "head"
                        | "script"
                        | "style"
                        | "noscript"
                        | "nav"
                        | "header"
                        | "footer"
                        | "aside"
                ) || tag.attrs.iter().any(|attribute| {
                    &*attribute.name.local == "role"
                        && attribute
                            .value
                            .split_whitespace()
                            .any(|role| role.eq_ignore_ascii_case("navigation"))
                });
                let void = matches!(
                    name,
                    "area"
                        | "base"
                        | "br"
                        | "col"
                        | "embed"
                        | "hr"
                        | "img"
                        | "input"
                        | "link"
                        | "meta"
                        | "param"
                        | "source"
                        | "track"
                        | "wbr"
                );
                match tag.kind {
                    TagKind::StartTag
                        if (excluded || !hidden.is_empty()) && !tag.self_closing && !void =>
                    {
                        hidden.push(tag.name.clone())
                    }
                    TagKind::EndTag => {
                        if let Some(at) = hidden.iter().rposition(|name| *name == tag.name) {
                            hidden.truncate(at);
                        }
                    }
                    _ => {}
                }
                if hidden.is_empty() {
                    text.push(' ');
                }
            }
            Token::CharacterTokens(value) if hidden.is_empty() => text.push_str(&value),
            _ => {}
        }
        Ok(())
    })?;
    Ok(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// URLs discovered in a response, separated by navigation and page requisites.
#[derive(Default, Debug)]
pub struct Links {
    /// Navigable links. The caller enforces site restrictions.
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
            Token::TagToken(tag) if &*tag.name == "title" && !finished => {
                inside = tag.kind == TagKind::StartTag;
                finished = !inside;
            }
            Token::CharacterTokens(text) if inside => {
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
    let decoded = response.decoded()?;
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
    Ok(content
        .select("a[href], area[href]")
        .unwrap()
        .filter_map(|node| {
            let url = base.join(node.attributes.borrow().get("href")?).ok()?;
            warc::key(url.as_str())
        })
        .filter(|url| url != original.as_str() && seen.insert(url.clone()))
        .collect())
}

/// A discovered navigation or static dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// A navigable page.
    Page,
    /// A document prerequisite.
    Asset,
}

/// Collect navigation and static dependencies for capture.
pub fn links(url: &str, response: &warc::Response) -> io::Result<Links> {
    let mut links = Links::default();
    visit_links(url, response, |kind, url| {
        let out = match kind {
            LinkKind::Page => &mut links.pages,
            LinkKind::Asset => &mut links.assets,
        };
        out.push(url);
        Ok(())
    })?;
    links.assets.sort();
    links.assets.dedup();
    Ok(links)
}

fn link(base: &Url, value: &str, out: &mut dyn FnMut(String) -> io::Result<()>) -> io::Result<()> {
    if value.trim().is_empty() || value.trim_start().starts_with('#') {
        return Ok(());
    }
    let Some(url) = base.join(value).ok().and_then(|u| warc::key(u.as_str())) else {
        return Ok(());
    };
    out(url)
}

fn css(text: &str, base: &Url, out: &mut dyn FnMut(String) -> io::Result<()>) -> io::Result<()> {
    css_tokens(&mut cssparser::Parser::new(text), base, out, false)
}

fn css_tokens(
    input: &mut cssparser::Parser<'_>,
    base: &Url,
    out: &mut dyn FnMut(String) -> io::Result<()>,
    strings: bool,
) -> io::Result<()> {
    use cssparser::Token;
    let mut result = Ok(());
    while result.is_ok()
        && let Ok(token) = input.next().cloned()
    {
        match token {
            Token::UnquotedUrl(value) => result = link(base, &value, out),
            Token::QuotedString(value) if strings => result = link(base, &value, out),
            Token::AtKeyword(name) if name.eq_ignore_ascii_case("import") => {
                if let Ok(value) = input.try_parse(|input| input.expect_string_cloned()) {
                    result = link(base, &value, out);
                }
            }
            Token::Function(name) if name.eq_ignore_ascii_case("url") => {
                let _: Result<_, cssparser::ParseError<()>> = input.parse_nested_block(|input| {
                    if let Ok(value) = input.expect_string() {
                        result = link(base, value, out);
                    }
                    Ok(())
                });
            }
            Token::Function(name)
                if name.eq_ignore_ascii_case("image-set")
                    || name.eq_ignore_ascii_case("-webkit-image-set") =>
            {
                let _: Result<_, cssparser::ParseError<()>> = input.parse_nested_block(|input| {
                    result = css_tokens(input, base, out, true);
                    Ok(())
                });
            }
            Token::Function(_)
            | Token::ParenthesisBlock
            | Token::SquareBracketBlock
            | Token::CurlyBracketBlock => {
                let _: Result<_, cssparser::ParseError<()>> = input.parse_nested_block(|input| {
                    result = css_tokens(input, base, out, false);
                    Ok(())
                });
            }
            _ => {}
        }
    }
    result
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

/// Follow dependencies and redirects without expanding HTML returned in place
/// of a stylesheet, script, font or image. SPA fallbacks are still archived.
pub fn requisites(
    url: &str,
    response: &warc::Response,
    resource: Resource,
) -> io::Result<Vec<(String, Resource)>> {
    if resource == Resource::Requisite
        && !response.status.is_redirection()
        && response
            .headers
            .get(http::header::CONTENT_TYPE)
            .is_some_and(|value| value.as_bytes().starts_with(b"text/html"))
    {
        return Ok(Vec::new());
    }
    let links = links(url, response)?;
    let mut next = links
        .assets
        .into_iter()
        .map(|url| (url, Resource::Requisite))
        .collect::<Vec<_>>();
    if response.status.is_redirection() {
        next.extend(links.pages.into_iter().map(|url| (url, resource)));
    }
    Ok(next)
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
    let decoded = response.decoded()?;
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
            && &*tag.name == "base"
            && document_base.is_none()
        {
            document_base = tag
                .attrs
                .iter()
                .find(|attr| &*attr.name.local == "href")
                .and_then(|attr| base.join(&attr.value).ok());
        }
        Ok(())
    })?;
    let base = document_base.unwrap_or(base);
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
                .find(|attr| &*attr.name.local == name)
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
        for name in ["src", "data-src", "data-lazy-src", "data-original"] {
            if let Some(value) = attr(name) {
                link(&base, value, &mut |url| visit(LinkKind::Asset, url))?;
            }
        }
        if name == "object"
            && let Some(value) = attr("data")
        {
            link(&base, value, &mut |url| visit(LinkKind::Asset, url))?;
        }
        for name in ["srcset", "data-srcset", "data-lazy-srcset"] {
            if let Some(value) = attr(name) {
                srcset(value, &base, &mut |url| visit(LinkKind::Asset, url))?;
            }
        }
        if matches!(name, "image" | "use")
            && let Some(value) = attr("href")
        {
            link(&base, value, &mut |url| visit(LinkKind::Asset, url))?;
        }
        if name == "link"
            && attr("rel").is_some_and(|r| {
                r.split_whitespace().any(|value| {
                    ["stylesheet", "icon", "preload", "modulepreload"]
                        .iter()
                        .any(|rel| value.eq_ignore_ascii_case(rel))
                })
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
    struct Sink<F>(std::cell::RefCell<(F, io::Result<()>)>);
    impl<F: FnMut(Token) -> io::Result<()>> TokenSink for Sink<F> {
        type Handle = ();
        fn process_token(&self, token: Token, _: u64) -> TokenSinkResult<()> {
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
            let mut state = self.0.borrow_mut();
            if state.1.is_ok() {
                state.1 = (state.0)(token);
            }
            next
        }
    }
    let tokenizer = Tokenizer::new(
        Sink(std::cell::RefCell::new((visit, Ok(())))),
        Default::default(),
    );
    let input = BufferQueue::default();
    input.push_back(text.into());
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    tokenizer.sink.0.into_inner().1
}
