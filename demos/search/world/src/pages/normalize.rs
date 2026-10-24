//! Normalize authored page text while preserving URLs and inline markup.

use super::text::escape as e;

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

/// Dates the next revision and describes the corrections it contains.
pub(crate) fn revise(dom: &kuchiki::NodeRef, date: &str, facts: &[String]) {
    use kuchiki::traits::TendrilSink;
    let date = super::make::result_date(date);
    let mut revision = 1;
    for row in dom.select("tr").unwrap() {
        if row.as_node().select_first("th").is_ok_and(|h| {
            h.text_contents()
                .trim()
                .eq_ignore_ascii_case("Last updated")
        }) && let Ok(cell) = row.as_node().select_first("td")
        {
            let original = cell.text_contents();
            if let Some((_, tail)) = original.rsplit_once("revision ") {
                revision = tail.trim_end_matches(')').parse::<usize>().unwrap_or(0) + 1;
            }
            for child in cell.as_node().children() {
                child.detach();
            }
            cell.as_node().append(kuchiki::NodeRef::new_text(format!(
                "{date} (revision {})",
                revision + facts.len().saturating_sub(1)
            )));
        }
    }
    for heading in dom.select("h2, h3").unwrap() {
        if heading
            .text_contents()
            .eq_ignore_ascii_case("Revision history")
            && let Some(list) = heading.as_node().following_siblings().find(|n| {
                n.as_element()
                    .is_some_and(|e| e.name.local.as_ref() == "ul")
            })
        {
            for (index, fact) in facts.iter().enumerate().rev() {
                let revision = revision + index;
                let fragment = kuchiki::parse_html().one(format!(
                    "<ul><li>Revision {revision}, {date}: {}</li></ul>",
                    e(&format!(
                        "{}.",
                        fact.split_once(", not ")
                            .or_else(|| fact.split_once(" instead of "))
                            .map_or(fact.trim_end_matches('.'), |(claim, _)| claim)
                    ))
                ));
                if let Ok(li) = fragment.select_first("li") {
                    list.prepend(li.as_node().clone());
                }
            }
        }
    }
}
