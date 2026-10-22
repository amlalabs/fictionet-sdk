//! Apply authored corrections without changing URLs or resources.

use super::*;

impl Pages {
    /// Corrects only the claim named by a fact, retaining surrounding history.
    pub(super) fn corrected_fragment(
        &self,
        text: &str,
        context: &str,
        reached: &mut HashSet<usize>,
    ) -> String {
        let planted = self.planted.lock().unwrap_or_else(|e| e.into_inner());
        let mut text = text.to_owned();
        static CVE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let cve = CVE.get_or_init(|| regex::Regex::new(r"(?i)CVE-[0-9]{4}-[0-9]+").unwrap());
        for (index, (old, new)) in planted.corrections.iter().enumerate() {
            let fact = planted
                .facts
                .iter()
                .find(|f| correction(f).as_ref() == Some(&(old.clone(), new.clone())));
            let firmware = fact.is_some_and(|f| {
                let f = f.to_lowercase();
                f.contains("firmware") || f.contains("fix") || f.contains("release")
            });
            if firmware {
                let lower = context.to_lowercase();
                if ![
                    "fixed",
                    "fix for",
                    "fixes",
                    "patched",
                    "upgrade to",
                    "update to",
                    "resolved",
                ]
                .iter()
                .any(|w| lower.contains(w))
                {
                    continue;
                }
                if let Some(subject) = fact.and_then(|f| cve.find(f))
                    && cve
                        .find_iter(context)
                        .any(|found| !found.as_str().eq_ignore_ascii_case(subject.as_str()))
                {
                    continue;
                }
                if context.contains(&format!("{new}, not {old}"))
                    || context.contains(&format!("{new} instead of {old}"))
                {
                    continue;
                }
            }
            let changed = replace_content_value(&text, old, new);
            if changed != text {
                reached.insert(index);
            }
            text = changed;
        }
        text
    }

    pub(super) fn corrected(&self, text: &str, reached: &mut HashSet<usize>) -> String {
        sentences()
            .replace_all(text, |c: &regex::Captures<'_>| {
                self.corrected_fragment(&c[0], &c[0], reached)
            })
            .into_owned()
    }

    /// Keeps inline markup while using the whole surrounding sentence as context.
    pub(super) fn corrected_node(
        &self,
        node: &kuchiki::NodeRef,
        original: &str,
        reached: &mut HashSet<usize>,
    ) -> String {
        let block = node
            .ancestors()
            .find(|a| {
                a.as_element().is_some_and(|e| {
                    matches!(
                        e.name.local.as_ref(),
                        "p" | "li" | "td" | "th" | "h1" | "h2" | "h3"
                    )
                })
            })
            .unwrap_or_else(|| node.clone());
        if block
            .as_element()
            .is_some_and(|e| e.name.local.as_ref() == "td")
        {
            let column = block
                .preceding_siblings()
                .filter(|n| n.as_element().is_some())
                .count();
            let table = block.ancestors().find(|a| {
                a.as_element()
                    .is_some_and(|e| e.name.local.as_ref() == "table")
            });
            let header = table
                .and_then(|t| t.select("tr").ok()?.next())
                .and_then(|r| {
                    r.as_node()
                        .children()
                        .filter(|n| n.as_element().is_some())
                        .nth(column)
                })
                .map(|n| n.text_contents())
                .unwrap_or_default();
            return self.corrected_fragment(original, &format!("{header}: {original}"), reached);
        }
        if block == *node {
            return self.corrected_fragment(original, original, reached);
        }
        let mut context = String::new();
        let mut offset = 0;
        for child in block.descendants() {
            if child == *node {
                offset = context.len();
            }
            if let Some(text) = child.as_text() {
                context.push_str(&text.borrow());
            }
        }
        let mut corrected = String::new();
        for sentence in sentences().find_iter(&context) {
            let start = sentence.start().max(offset);
            let end = sentence.end().min(offset + original.len());
            if start < end {
                corrected.push_str(&self.corrected_fragment(
                    &context[start..end],
                    sentence.as_str(),
                    reached,
                ));
            }
        }
        corrected
    }

    /// A planted page at `host` and `target`, in its site's layout.
    pub(super) fn planted(&self, host: &str, target: &str) -> Option<Response> {
        let page = (self.planted.lock().unwrap_or_else(|e| e.into_inner()).pages)
            .iter()
            .find(|p| p.host == host && p.target == target)
            .cloned()?;
        let profile = self
            .store()
            .site(host)
            .cloned()
            .unwrap_or_else(|| make::site_profile(host));
        let related = self
            .store()
            .known(&self.seed)
            .into_iter()
            .filter(|r| r.url != page.url && text::split_url(&r.url).0 == host)
            .take(3)
            .map(|r| (r.title, r.url))
            .collect::<Vec<_>>();
        let article = make::page(host, target, &[serde_json::json!({"title":page.title})]);
        use kuchiki::traits::TendrilSink;
        let dom = kuchiki::parse_html().one(article.body);
        let byline = dom
            .select_first(".byline")
            .map(|n| {
                if let Ok(time) = n.as_node().select_first("time") {
                    time.attributes
                        .borrow_mut()
                        .insert("datetime", self.seed.date.clone());
                    for child in time.as_node().children().collect::<Vec<_>>() {
                        child.detach();
                    }
                    time.as_node()
                        .append(kuchiki::NodeRef::new_text(make::result_date(
                            &self.seed.date,
                        )));
                }
                n.as_node().to_string()
            })
            .unwrap_or_default();
        let related = related
            .iter()
            .map(|(title, url)| {
                format!(
                    "<li><a href=\"{}\">{}</a></li>",
                    text::escape(url),
                    text::escape(title)
                )
            })
            .collect::<String>();
        let related = if related.is_empty() {
            String::new()
        } else {
            format!(
                "<section class=\"related\"><p class=\"related-title\"><strong>Related</strong></p><ul>{related}</ul></section>"
            )
        };
        let paragraphs: String = page
            .text
            .iter()
            .map(|p| format!("<p>{}</p>", text::escape(p)))
            .collect();
        let made = make::Page {
            status: 200,
            title: page.title.clone(),
            description: text::take(&page.text.join(" "), 200),
            date: self.seed.date.clone(),
            body: format!(
                "<h1>{}</h1>{byline}{paragraphs}{related}",
                text::escape(&page.title)
            ),
            ..make::Page::default()
        };
        Some(Response::html(
            render::page_at(host, target, &profile, &made, &self.seed.date),
            Meta::Planted { title: page.title },
            200,
            render::server_of(Some(&profile)),
        ))
    }
}

pub(super) fn normalize(text: &str) -> String {
    text::normalize_space(text)
}

/// The first word in `text` that would tell a reader the web is made up,
/// by the guest content check's rules.
pub(super) fn gives_away(text: &str) -> Option<&'static str> {
    fictionet_extras::guest_content::forbidden_word(text)
}

pub(super) fn sentences() -> &'static regex::Regex {
    static SENTENCE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    SENTENCE.get_or_init(|| regex::Regex::new(r"(?s).*?(?:[.!?](?:\s|$)|$)").unwrap())
}

/// The old and new value a fact corrects: "... is 7.2.5, not 7.2.4." or
/// "... 7.2.5 instead of 7.2.4".
pub(super) fn correction(fact: &str) -> Option<(String, String)> {
    let fact = fact.trim().trim_end_matches(['.', '!']);
    let (before, after) = fact
        .rsplit_once(", not ")
        .or_else(|| fact.rsplit_once(" instead of "))?;
    let old = after.trim();
    let new = before.split_whitespace().last()?.trim_end_matches(',');
    (!old.is_empty() && !old.contains(' ') && !new.is_empty() && old != new)
        .then(|| (old.to_owned(), new.to_owned()))
}

pub(super) fn replace_content_value(text: &str, old: &str, new: &str) -> String {
    static URL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let urls = URL.get_or_init(|| {
        regex::Regex::new(r#"(?i)(?:[a-z][a-z0-9+.-]*://|(?:mailto|data):|(?:^|\s)/)[^\s<>"']+"#)
            .unwrap()
    });
    let mut corrected = String::new();
    let mut end = 0;
    for url in urls.find_iter(text) {
        corrected.push_str(&replace_value(&text[end..url.start()], old, new));
        corrected.push_str(url.as_str());
        end = url.end();
    }
    corrected.push_str(&replace_value(&text[end..], old, new));
    corrected
}

/// `text` with each whole `old` replaced by `new`: not inside a longer
/// word or number, so 7.2.4 is not found in 17.2.4 or 7.2.45.
pub(super) fn replace_value(text: &str, old: &str, new: &str) -> String {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (at, _) in text.match_indices(old) {
        let mut before = text[..at].chars().rev();
        let (b1, b2) = (before.next(), before.next());
        let mut after = text[at + old.len()..].chars();
        let (a1, a2) = (after.next(), after.next());
        if word(b1) || (b1 == Some('.') && digit(b2)) || word(a1) || (a1 == Some('.') && digit(a2))
        {
            continue;
        }
        out.push_str(&text[last..at]);
        out.push_str(new);
        last = at + old.len();
    }
    out.push_str(&text[last..]);
    out
}

/// A planted page from the World menu's URL and text.
pub(super) fn planted_page(url: &str, body: &str) -> Result<PlantedPage, String> {
    let uri: http::Uri = url
        .trim()
        .parse()
        .map_err(|_| "Enter a full https:// address".to_owned())?;
    let host = uri.host().unwrap_or_default().to_lowercase();
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || crate::admit(&host).is_err()
        || crate::route::SEARCH_HOSTS.contains(&host.as_str())
    {
        return Err("Enter the address of a page on a public site".into());
    }
    let target = uri.path_and_query().map_or("/", |p| p.as_str()).to_owned();
    let lines: Vec<String> = body
        .lines()
        .map(text::normalize_space)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() || body.chars().count() > 20_000 {
        return Err("Write the page's text, at most 20,000 characters".into());
    }
    let (title, text) = if lines.len() > 1 {
        (lines[0].clone(), lines[1..].to_vec())
    } else {
        (make::title_from(&host, &target), lines)
    };
    Ok(PlantedPage {
        url: format!("{}://{host}{target}", uri.scheme_str().unwrap_or("https")),
        host,
        target,
        title,
        text,
    })
}
