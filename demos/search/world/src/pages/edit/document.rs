//! The text a reader sees on an HTML page, mapped back to the bytes it
//! came from. An edit to a passage of that text splices only those bytes:
//! tags, attributes, scripts and every other byte of the page stay as the
//! site sent them.

use super::Edit;
use std::collections::HashMap;
use std::ops::Range;

/// Elements whose content a reader never sees as text.
const HIDDEN: [&str; 12] = [
    "script", "style", "noscript", "template", "svg", "math", "iframe", "textarea", "xmp",
    "noembed", "noframes", "object",
];

/// Elements that start a new line of text.
const BLOCKS: [&str; 44] = [
    "address",
    "article",
    "aside",
    "blockquote",
    "body",
    "br",
    "button",
    "caption",
    "dd",
    "details",
    "dialog",
    "div",
    "dl",
    "dt",
    "fieldset",
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
    "head",
    "header",
    "hr",
    "html",
    "li",
    "main",
    "nav",
    "ol",
    "option",
    "p",
    "pre",
    "section",
    "summary",
    "table",
    "td",
    "th",
    "title",
    "tr",
    "ul",
];

/// How an edited passage is shown on the host's own copy of the page.
const MARK: &str = "<mark style=\"background:#ffd84d;color:#1b1b1b;border-radius:2px;\
box-shadow:0 0 0 2px #ffd84d\">";

/// A page's text, one line per block, with the source bytes behind each
/// character.
pub(super) struct Document<'a> {
    source: &'a str,
    /// The page's text: runs of whitespace are one space, or one line
    /// break where a block starts.
    text: String,
    /// The source bytes each character stands for.
    spans: Vec<Range<usize>>,
    /// Further whitespace a collapsed space absorbed across tags.
    absorbed: HashMap<usize, Vec<Range<usize>>>,
    /// The `text` the page's search compares: quotes, dashes and line
    /// breaks folded, one character for each character of `text`.
    folded: String,
    /// The byte offset in `folded` where each character starts.
    starts: Vec<usize>,
    /// The source bytes of the page's `<title>` text.
    title: Option<Range<usize>>,
}

/// One edit that cannot be made, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Problem {
    /// The passage is empty once its whitespace is trimmed.
    EmptyPassage { edit: usize },
    /// The passage is not in the text.
    NotFound { edit: usize },
    /// The replacement is the passage itself.
    Unchanged { edit: usize },
    /// Two edits change the same words.
    Overlap { first: usize, second: usize },
}

/// One run of source bytes an edit replaces, with the edit's index.
struct Splice {
    bytes: Range<usize>,
    /// The replacement goes here; other runs of the same passage are removed.
    first: bool,
    edit: usize,
}

/// The page with its edits made: what the guest is served, and the host's
/// copy with each change marked.
pub(super) struct Edited {
    pub served: String,
    pub marked: String,
}

impl<'a> Document<'a> {
    /// Reads `source` as a browser shows its text.
    pub(super) fn html(source: &'a str) -> Self {
        let mut reader = Reader::default();
        let bytes = source.as_bytes();
        let mut at = 0;
        while at < source.len() {
            if bytes[at] == b'<'
                && let Some(next) = reader.tag(source, at)
            {
                at = next;
                continue;
            }
            if bytes[at] == b'&'
                && let Some((character, length)) = reference(&source[at..])
            {
                reader.character(character, at..at + length);
                at += length;
                continue;
            }
            let character = source[at..].chars().next().expect("a character");
            reader.character(character, at..at + character.len_utf8());
            at += character.len_utf8();
        }
        let mut folded = String::with_capacity(reader.text.len());
        let mut starts = Vec::with_capacity(reader.spans.len());
        for character in reader.text.chars() {
            starts.push(folded.len());
            folded.push(fold(character));
        }
        Self {
            source,
            text: reader.text,
            starts,
            spans: reader.spans,
            absorbed: reader.absorbed,
            folded,
            title: reader.title,
        }
    }

    /// The page's text, one line per block.
    pub(super) fn text(&self) -> &str {
        &self.text
    }

    /// Whether `passage` appears in the text.
    pub(super) fn contains(&self, passage: &str) -> bool {
        let passage = normalized(passage);
        !passage.is_empty() && self.folded.contains(&passage)
    }

    /// The character ranges where `passage` appears.
    fn occurrences(&self, passage: &str) -> Vec<Range<usize>> {
        let passage = normalized(passage);
        if passage.is_empty() {
            return Vec::new();
        }
        let character = |byte: usize| self.starts.partition_point(|start| *start < byte);
        self.folded
            .match_indices(&passage)
            .map(|(byte, found)| character(byte)..character(byte + found.len()))
            .collect()
    }

    /// Checks `edits` against the text: every passage found, changed, and
    /// apart from the others.
    pub(super) fn check(&self, edits: &[Edit]) -> Result<(), Vec<Problem>> {
        self.splices(edits).map(|_| ())
    }

    /// Makes `edits`: every occurrence of each passage is replaced.
    pub(super) fn apply(&self, edits: &[Edit]) -> Result<Edited, Vec<Problem>> {
        let splices = self.splices(edits)?;
        let mut served = String::with_capacity(self.source.len());
        let mut marked = String::with_capacity(self.source.len());
        let mut at = 0;
        for splice in splices {
            let kept = &self.source[at..splice.bytes.start];
            served.push_str(kept);
            marked.push_str(kept);
            if splice.first {
                let replacement = escape(&edits[splice.edit].replacement);
                served.push_str(&replacement);
                let in_title = self
                    .title
                    .as_ref()
                    .is_some_and(|title| title.contains(&splice.bytes.start));
                if in_title {
                    marked.push_str(&replacement);
                } else {
                    marked.push_str(MARK);
                    marked.push_str(&replacement);
                    marked.push_str("</mark>");
                }
            }
            at = splice.bytes.end;
        }
        served.push_str(&self.source[at..]);
        marked.push_str(&self.source[at..]);
        Ok(Edited { served, marked })
    }

    fn splices(&self, edits: &[Edit]) -> Result<Vec<Splice>, Vec<Problem>> {
        let mut problems = Vec::new();
        let mut splices = Vec::new();
        for (index, edit) in edits.iter().enumerate() {
            if normalized(&edit.passage).is_empty() {
                problems.push(Problem::EmptyPassage { edit: index });
                continue;
            }
            if normalized(&edit.passage) == normalized(&edit.replacement) {
                problems.push(Problem::Unchanged { edit: index });
                continue;
            }
            let found = self.occurrences(&edit.passage);
            if found.is_empty() {
                problems.push(Problem::NotFound { edit: index });
            }
            for characters in found {
                splices.extend(self.runs(characters).into_iter().enumerate().map(
                    |(run, bytes)| Splice {
                        bytes,
                        first: run == 0,
                        edit: index,
                    },
                ));
            }
        }
        splices.sort_by_key(|splice| splice.bytes.start);
        for pair in splices.windows(2) {
            if pair[1].bytes.start < pair[0].bytes.end {
                let (first, second) = (
                    pair[0].edit.min(pair[1].edit),
                    pair[0].edit.max(pair[1].edit),
                );
                let overlap = Problem::Overlap { first, second };
                if !problems.contains(&overlap) {
                    problems.push(overlap);
                }
            }
        }
        if problems.is_empty() {
            Ok(splices)
        } else {
            Err(problems)
        }
    }

    /// The runs of source text behind the characters `characters`: the
    /// bytes between runs are tags, which stay.
    fn runs(&self, characters: Range<usize>) -> Vec<Range<usize>> {
        let mut bytes: Vec<Range<usize>> = characters
            .flat_map(|character| {
                std::iter::once(self.spans[character].clone())
                    .chain(self.absorbed.get(&character).into_iter().flatten().cloned())
            })
            .filter(|range| !range.is_empty())
            .collect();
        bytes.sort_by_key(|range| range.start);
        let mut runs: Vec<Range<usize>> = Vec::new();
        for range in bytes {
            match runs.last_mut() {
                Some(last) if last.end == range.start => last.end = range.end,
                _ => runs.push(range),
            }
        }
        runs
    }
}

/// Builds a document's text one source character at a time.
#[derive(Default)]
struct Reader {
    text: String,
    spans: Vec<Range<usize>>,
    absorbed: HashMap<usize, Vec<Range<usize>>>,
    /// Whitespace not yet written: its source bytes, and whether a block
    /// starts within it.
    pending: Option<(Vec<Range<usize>>, bool)>,
    title: Option<Range<usize>>,
    /// Where the open `<title>`'s text starts.
    title_start: Option<usize>,
}

impl Reader {
    fn character(&mut self, character: char, bytes: Range<usize>) {
        if character.is_whitespace() {
            let (runs, _) = self.pending.get_or_insert_with(|| (Vec::new(), false));
            match runs.last_mut() {
                Some(last) if last.end == bytes.start => last.end = bytes.end,
                _ => runs.push(bytes),
            }
            return;
        }
        if let Some((mut runs, block)) = self.pending.take()
            && !self.text.is_empty()
        {
            let first = runs.remove(0);
            if !runs.is_empty() {
                self.absorbed.insert(self.spans.len(), runs);
            }
            self.push(if block { '\n' } else { ' ' }, first);
        }
        self.push(character, bytes);
    }

    fn push(&mut self, character: char, bytes: Range<usize>) {
        self.text.push(character);
        self.spans.push(bytes);
    }

    fn block(&mut self, at: usize) {
        let (runs, block) = self.pending.get_or_insert_with(|| (Vec::new(), false));
        if runs.is_empty() {
            runs.push(at..at);
        }
        *block = true;
    }

    /// Reads the tag, comment or declaration at `at` and returns where the
    /// text after it starts, or `None` when `<` starts no tag.
    fn tag(&mut self, source: &str, at: usize) -> Option<usize> {
        let rest = &source[at..];
        if let Some(comment) = rest.strip_prefix("<!--") {
            return Some(
                comment
                    .find("-->")
                    .map_or(source.len(), |end| at + 4 + end + 3),
            );
        }
        let after = rest[1..].chars().next()?;
        if after == '!' || after == '?' {
            return Some(rest.find('>').map_or(source.len(), |end| at + end + 1));
        }
        let closing = after == '/';
        let name_start = at + 1 + usize::from(closing);
        let name: String = source[name_start..]
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if name.is_empty() || !name.starts_with(|character: char| character.is_ascii_alphabetic()) {
            return None;
        }
        let end = tag_end(source, name_start + name.len());
        if !closing && HIDDEN.contains(&name.as_str()) {
            return Some(element_end(source, end, &name));
        }
        if BLOCKS.contains(&name.as_str()) {
            self.block(at);
        }
        if name == "title" {
            if closing {
                if let Some(start) = self.title_start.take() {
                    self.title.get_or_insert(start..at);
                }
            } else {
                self.title_start = Some(end);
            }
        }
        Some(end)
    }
}

/// Where the tag whose attributes start at `at` ends, after its `>`.
fn tag_end(source: &str, at: usize) -> usize {
    let mut quote = None;
    for (offset, byte) in source.as_bytes()[at..].iter().enumerate() {
        match (quote, byte) {
            (None, b'"' | b'\'') => quote = Some(*byte),
            (Some(open), _) if open == *byte => quote = None,
            (None, b'>') => return at + offset + 1,
            _ => {}
        }
    }
    source.len()
}

/// Where the hidden element `name` whose content starts at `at` ends,
/// after its closing tag.
fn element_end(source: &str, at: usize, name: &str) -> usize {
    let closing = format!("</{name}");
    let lower = source[at..].to_ascii_lowercase();
    match lower.find(&closing) {
        Some(found) => tag_end(source, at + found + closing.len()),
        None => source.len(),
    }
}

/// The character a character reference at the start of `text` names, and
/// its length in bytes.
fn reference(text: &str) -> Option<(char, usize)> {
    let body = &text[1..];
    if let Some(number) = body.strip_prefix('#') {
        let (digits, radix, prefix) = match number.strip_prefix(['x', 'X']) {
            Some(hex) => (hex, 16, 2),
            None => (number, 10, 1),
        };
        let length = digits
            .chars()
            .take_while(|character| character.is_digit(radix))
            .count();
        if length == 0 {
            return None;
        }
        let code = u32::from_str_radix(&digits[..length], radix).ok()?;
        let character = char::from_u32(code)
            .filter(|character| *character != '\0')
            .unwrap_or('\u{fffd}');
        let terminated = usize::from(digits[length..].starts_with(';'));
        return Some((character, 1 + prefix + length + terminated));
    }
    let length = body
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric())
        .count();
    if !body[length..].starts_with(';') {
        return None;
    }
    let decoded = crate::pages::text::named(&body[..length])?;
    let mut characters = decoded.chars();
    let character = characters.next()?;
    characters
        .next()
        .is_none()
        .then_some((character, length + 2))
}

/// The character the page's search compares for `character`: curly
/// quotes as straight ones, dashes as hyphens and any whitespace as a
/// space, so a passage copied with plain punctuation still matches.
fn fold(character: char) -> char {
    match character {
        '‘' | '’' | '‚' | '‛' | '′' => '\'',
        '“' | '”' | '„' | '‟' | '″' => '"',
        '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' => '-',
        character if character.is_whitespace() => ' ',
        character => character,
    }
}

/// `passage` as the page's search compares it.
fn normalized(passage: &str) -> String {
    passage
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .map(fold)
        .collect()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
