//! Normalize authored page text while preserving URLs and inline markup.

use super::text::{escape as e, normalize_space};

/// Changes a text range without changing links or inline elements.
fn replace_text(node: &kuchiki::NodeRef, start: usize, end: usize, replacement: &str) {
    let mut offset = 0;
    let mut inserted = false;
    for child in node.descendants() {
        if let Some(text) = child.as_text() {
            let original = text.borrow().to_string();
            let next = offset + original.len();
            let from = start.max(offset);
            let to = end.min(next);
            if from < to {
                let value = if inserted { "" } else { replacement };
                *text.borrow_mut() = format!(
                    "{}{value}{}",
                    &original[..from - offset],
                    &original[to - offset..]
                );
                inserted = true;
            }
            offset = next;
        }
    }
}

/// Whether an attribution names a person rather than a handle or organization.
pub(crate) fn person_name(name: &str, site: &str) -> bool {
    let words: Vec<_> = name.split_whitespace().collect();
    (2..=3).contains(&words.len())
        && !normalize_space(name).eq_ignore_ascii_case(&normalize_space(site))
        && words.iter().all(|word| {
            word.chars().next().is_some_and(char::is_uppercase)
                && word.chars().all(|c| c.is_alphabetic() || "-'’‐‑.".contains(c))
                && !"Team Staff Desk News Editors Editorial Systems Security Support PSIRT Research Labs Lab Inc Corp Agency Office Center Centre Community Admin Moderator Press Media Group Foundation Project Wire Reporter Reporters Contributor Contributors"
                    .split_whitespace()
                    .any(|organization| word.split(|c: char| !c.is_alphabetic())
                        .any(|part| part.eq_ignore_ascii_case(organization)))
        })
}

/// Keeps people already named by the world.
pub(crate) fn invented_name(name: &str, cast: &[crate::pages::prompts::Person]) -> bool {
    super::make::AUTHORS.contains(&name)
        || super::make::USERS.contains(&name)
        || cast.iter().any(|person| person.name == name)
        || name.split_once(' ').is_some_and(|(first, last)| {
            super::make::AUTHORS
                .iter()
                .any(|name| name.split_once(' ').is_some_and(|(f, _)| f == first))
                && super::make::AUTHORS
                    .iter()
                    .any(|name| name.split_once(' ').is_some_and(|(_, l)| l == last))
        })
}

/// Applies the world's author and date styles to visible page content.
pub(crate) fn normalize_page(
    html: &str,
    url: &str,
    site: &str,
    cast: &[crate::pages::prompts::Person],
    wiki_date: Option<&str>,
) -> Option<String> {
    use kuchiki::traits::TendrilSink;
    use regex::Regex;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::OnceLock;
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    static END: OnceLock<Regex> = OnceLock::new();
    static DATE: OnceLock<Regex> = OnceLock::new();
    let prefix = PREFIX.get_or_init(|| {
        Regex::new(r"(?i)\b(?:(?:posted|written|answered|reviewed)\s+by|by|author:)\s+").unwrap()
    });
    let end = END.get_or_init(|| {
        Regex::new(
            r"(?i)\s*[·|•\n(,]|\s+[-–—]\s+|\s+(?:published|updated|on\s+\d+|\d{4}-\d{2}-\d{2})\b",
        )
        .unwrap()
    });
    let date =
        DATE.get_or_init(|| Regex::new(r"(?i)https?://[^\s<>]+|\b\d{4}-\d{2}-\d{2}\b").unwrap());
    let dom = kuchiki::parse_html().one(html);
    let mut changed = false;
    let mut bylines = Vec::new();
    let mut ranges = Vec::new();
    let mut metadata = Vec::new();
    let mut names = BTreeSet::new();
    for node in dom.descendants() {
        let Some(element) = node.as_element() else {
            continue;
        };
        let attributes = element.attributes.borrow();
        let dedicated = attributes
            .get("class")
            .unwrap_or("")
            .split_whitespace()
            .any(|c| c.contains("byline") || c.contains("author"));
        let name = element.name.local.as_ref();
        let text = node.text_contents();
        let label = prefix.find_iter(&text).find(|m| {
            let before = text[..m.start()].trim_end();
            dedicated
                || (text.split_whitespace().count() <= 20
                    && (before.is_empty() || before.ends_with(['.', '!', '?'])))
        });
        let attribution = matches!(
            name,
            "p" | "span"
                | "div"
                | "small"
                | "address"
                | "li"
                | "h2"
                | "h3"
                | "h4"
                | "h5"
                | "h6"
                | "a"
                | "strong"
                | "em"
        );
        let excluded = node.ancestors().chain(node.descendants()).any(|a| {
            a.as_element().is_some_and(|e| {
                matches!(
                    e.name.local.as_ref(),
                    "blockquote" | "q" | "pre" | "code" | "script" | "style" | "template"
                )
            })
        });
        if !excluded
            && (dedicated || (attribution && label.is_some()))
            && !bylines
                .iter()
                .any(|parent| node.ancestors().any(|a| &a == parent))
        {
            let start = label.map_or_else(|| text.len() - text.trim_start().len(), |m| m.end());
            let tail = &text[start..];
            let stop = end.find(tail).map_or(tail.len(), |m| m.start());
            let stop = start + tail[..stop].trim_end().trim_end_matches('.').len();
            let name = normalize_space(&text[start..stop]);
            if person_name(&name, site) {
                names.insert(name.clone());
                ranges.push((node.clone(), start, stop, name));
                bylines.push(node.clone());
            }
        }
        if name == "meta"
            && ["name", "property", "itemprop"].iter().any(|key| {
                attributes.get(*key).is_some_and(|v| {
                    v.rsplit([':', '.', '-']).next().is_some_and(|name| {
                        name.eq_ignore_ascii_case("author") || name.eq_ignore_ascii_case("creator")
                    })
                })
            })
            && let Some(content) = attributes.get("content")
        {
            let name = normalize_space(content);
            if person_name(&name, site) {
                names.insert(name.clone());
                metadata.push((node.clone(), name));
            }
        }
    }
    let mut used: BTreeSet<String> = names
        .iter()
        .filter(|name| invented_name(name, cast))
        .cloned()
        .collect();
    let mut pairs = Vec::new();
    for first in super::make::AUTHORS {
        for last in super::make::AUTHORS {
            let pair = format!(
                "{} {}",
                first.split_once(' ').unwrap().0,
                last.split_once(' ').unwrap().1
            );
            if !super::make::AUTHORS.contains(&pair.as_str())
                && !cast.iter().any(|person| person.name == pair)
            {
                pairs.push(pair);
            }
        }
    }
    let mut replacements = BTreeMap::new();
    for name in names.iter().filter(|name| !invented_name(name, cast)) {
        let key = format!("{url}\n{name}");
        let offset = super::make::hash(&key) % super::make::AUTHORS.len();
        let author = super::make::AUTHORS
            .iter()
            .cycle()
            .skip(offset)
            .take(super::make::AUTHORS.len())
            .map(|name| (*name).to_owned())
            .chain(cast.iter().map(|person| person.name.clone()))
            .find(|candidate| !used.contains(candidate))
            .or_else(|| {
                pairs
                    .iter()
                    .cycle()
                    .skip(super::make::hash(&key) % pairs.len().max(1))
                    .take(pairs.len())
                    .find(|candidate| !used.contains(*candidate))
                    .cloned()
            })
            .unwrap_or_else(|| super::make::AUTHORS[offset].to_owned());
        used.insert(author.clone());
        replacements.insert(name.clone(), author);
    }
    for (node, start, stop, name) in ranges {
        if let Some(author) = replacements.get(&name) {
            replace_text(&node, start, stop, author);
            changed = true;
        }
    }
    for (node, name) in metadata {
        if let Some(author) = replacements.get(&name) {
            node.as_element()
                .unwrap()
                .attributes
                .borrow_mut()
                .insert("content", author.clone());
            changed = true;
        }
    }
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
