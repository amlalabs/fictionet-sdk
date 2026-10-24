//! Normalize authored page text while preserving URLs and inline markup.

/// Formats dates while keeping the writer's author identities intact.
pub(crate) fn normalize_page(html: &str, wiki_date: Option<&str>) -> Option<String> {
    use kuchiki::traits::TendrilSink;
    use regex::Regex;
    use std::sync::OnceLock;
    static DATE: OnceLock<Regex> = OnceLock::new();
    let date =
        DATE.get_or_init(|| Regex::new(r"(?i)https?://[^\s<>]+|\b\d{4}-\d{2}-\d{2}\b").unwrap());
    let dom = kuchiki::parse_html().one(html);
    let mut changed = false;
    for node in dom.descendants() {
        if let Some(text) = node.as_text()
            && !node.ancestors().any(|a| {
                a.as_element().is_some_and(|e| {
                    matches!(
                        e.name.local.as_ref(),
                        "script" | "style" | "template" | "code" | "pre"
                    )
                })
            })
        {
            let original = text.borrow().to_string();
            let formatted = date.replace_all(&original, |c: &regex::Captures<'_>| {
                super::seed::parse_date(&c[0])
                    .map(super::make::short_date)
                    .unwrap_or_else(|_| c[0].to_owned())
            });
            if formatted != original {
                *text.borrow_mut() = formatted.into_owned();
                changed = true;
            }
        }
    }
    if let Some(date) = wiki_date.and_then(|d| super::seed::parse_date(d).ok())
        && let Ok(footer) = dom.select_first("footer")
    {
        let line = format!(
            "This page was last edited on {} {} {}",
            date.day(),
            date.month(),
            date.year()
        );
        if !footer.text_contents().contains(&line) {
            let fragment = kuchiki::parse_html().one(format!("<p>{line}</p>"));
            if let Ok(p) = fragment.select_first("p") {
                if let Ok(old) = footer
                    .as_node()
                    .select_first(".page-date, #footer-info-lastmod")
                {
                    for child in old.as_node().children() {
                        child.detach();
                    }
                    old.as_node().append(kuchiki::NodeRef::new_text(line));
                } else {
                    footer.as_node().append(p.as_node().clone());
                }
            }
            changed = true;
        }
    }
    changed.then(|| dom.to_string())
}
