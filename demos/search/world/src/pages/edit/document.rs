//! The text a reader sees on an HTML page, mapped back to the bytes it
//! came from. An edit to a passage of that text splices only those bytes:
//! tags, scripts and every other byte of the page stay as the site sent
//! them. The page's summaries in `<meta>` tags are read as text too, since
//! readers see them in search results and link previews.

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

/// The `<meta>` tags whose content a reader sees as the page's title or
/// summary: in search results, link previews and shared cards.
const SUMMARIES: [&str; 5] = [
    "description",
    "og:title",
    "og:description",
    "twitter:title",
    "twitter:description",
];

/// How a document's source is written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Markup {
    /// HTML: tags stay, text is escaped.
    Html,
    /// Plain text, such as a search result's title.
    Plain,
}

/// A document's text, one line per block, with the source bytes behind
/// each character.
pub(super) struct Document<'a> {
    source: &'a str,
    markup: Markup,
    /// The document's text: runs of whitespace are one space, or one line
    /// break where a block starts.
    text: String,
    /// The source bytes each character stands for.
    spans: Vec<Range<usize>>,
    /// Further whitespace a collapsed space absorbed across tags.
    absorbed: HashMap<usize, Vec<Range<usize>>>,
    /// The `text` the document's search compares: quotes, dashes and line
    /// breaks folded, one character for each character of `text`.
    folded: String,
    /// The byte offset in `folded` where each character starts.
    starts: Vec<usize>,
    /// Source bytes whose text is never marked on the host's copy: the
    /// `<title>` and the summaries in `<meta>` content.
    unmarked: Vec<Range<usize>>,
    /// Source bytes that are attribute values, whose replacements escape
    /// quotes too.
    attributes: Vec<Range<usize>>,
}

/// A run of the text read on its own: its character range and its text.
pub(super) struct Section {
    pub chars: Range<usize>,
    pub text: String,
}

/// An edit to make, and the characters of the text it was asked about.
/// It is made in every place its passage appears in `within`, or anywhere
/// in the text when its passage is not in `within`.
pub(super) struct Scoped<'e> {
    pub edit: &'e Edit,
    pub within: Range<usize>,
}

/// What became of one edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Made,
    /// The passage is empty once its whitespace is trimmed.
    EmptyPassage,
    /// The replacement is the passage itself.
    Unchanged,
    /// The passage is not in the text.
    NotFound,
    /// Every place it appears is inside a longer edit's passage, which was
    /// made instead.
    Covered,
}

/// One run of source bytes an edit replaces, with the edit's index.
struct Splice {
    bytes: Range<usize>,
    /// The replacement goes here; other runs of the same passage are removed.
    first: bool,
    edit: usize,
}

/// The document with its edits made: what the guest is served, the host's
/// copy with each change marked, and what became of each edit.
pub(super) struct Edited {
    pub served: String,
    pub marked: String,
    pub outcomes: Vec<Outcome>,
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
        Self::read(source, Markup::Html, reader)
    }

    /// Reads `source` as plain text.
    pub(super) fn plain(source: &'a str) -> Self {
        let mut reader = Reader::default();
        for (at, character) in source.char_indices() {
            reader.character(character, at..at + character.len_utf8());
        }
        Self::read(source, Markup::Plain, reader)
    }

    fn read(source: &'a str, markup: Markup, reader: Reader) -> Self {
        let mut folded = String::with_capacity(reader.text.len());
        let mut starts = Vec::with_capacity(reader.spans.len());
        for character in reader.text.chars() {
            starts.push(folded.len());
            folded.push(fold(character));
        }
        let mut unmarked = reader.attributes.clone();
        unmarked.extend(reader.title);
        Self {
            source,
            markup,
            text: reader.text,
            starts,
            spans: reader.spans,
            absorbed: reader.absorbed,
            folded,
            unmarked,
            attributes: reader.attributes,
        }
    }

    /// The document's text, one line per block.
    pub(super) fn text(&self) -> &str {
        &self.text
    }

    /// The text in runs of whole lines of about `size` characters each; a
    /// line longer than that is a run of its own.
    pub(super) fn sections(&self, size: usize) -> Vec<Section> {
        let mut sections = Vec::new();
        let (mut start, mut text) = (0, String::new());
        let mut at = 0;
        for line in self.text.split_inclusive('\n') {
            let length = line.chars().count();
            if !text.is_empty() && text.chars().count() + length > size {
                sections.push(Section {
                    chars: start..at,
                    text: std::mem::take(&mut text),
                });
                start = at;
            }
            text.push_str(line);
            at += length;
        }
        if !text.trim().is_empty() {
            sections.push(Section {
                chars: start..at,
                text,
            });
        }
        sections
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

    /// Makes `edits`: each in every place its passage appears in its
    /// scope. Where two edits' passages share words, the longer passage is
    /// made there and the shorter one is not, so the edits never collide.
    pub(super) fn apply(&self, edits: &[Scoped<'_>]) -> Edited {
        let mut outcomes = vec![Outcome::NotFound; edits.len()];
        // Each place an edit could be made, longest passage first.
        let mut places: Vec<(usize, Range<usize>)> = Vec::new();
        for (index, scoped) in edits.iter().enumerate() {
            let edit = scoped.edit;
            if normalized(&edit.passage).is_empty() {
                outcomes[index] = Outcome::EmptyPassage;
                continue;
            }
            if normalized(&edit.passage) == normalized(&edit.replacement) {
                outcomes[index] = Outcome::Unchanged;
                continue;
            }
            let found = self.occurrences(&edit.passage);
            let within: Vec<_> = found
                .iter()
                .filter(|place| {
                    scoped.within.start <= place.start && place.end <= scoped.within.end
                })
                .cloned()
                .collect();
            let found = if within.is_empty() { found } else { within };
            places.extend(
                found
                    .into_iter()
                    .filter(|place| self.one_field(place))
                    .map(|place| (index, place)),
            );
        }
        places.sort_by_key(|(index, place)| (std::cmp::Reverse(place.len()), *index, place.start));
        let mut taken: Vec<Range<usize>> = Vec::new();
        let mut splices = Vec::new();
        for (index, place) in places {
            if taken
                .iter()
                .any(|other| other.start < place.end && place.start < other.end)
            {
                if outcomes[index] == Outcome::NotFound {
                    outcomes[index] = Outcome::Covered;
                }
                continue;
            }
            outcomes[index] = Outcome::Made;
            splices.extend(
                self.runs(place.clone())
                    .into_iter()
                    .enumerate()
                    .map(|(run, bytes)| Splice {
                        bytes,
                        first: run == 0,
                        edit: index,
                    }),
            );
            taken.push(place);
        }
        splices.sort_by_key(|splice| splice.bytes.start);
        let mut served = String::with_capacity(self.source.len());
        let mut marked = String::with_capacity(self.source.len());
        let mut at = 0;
        for splice in splices {
            let kept = &self.source[at..splice.bytes.start];
            served.push_str(kept);
            marked.push_str(kept);
            if splice.first {
                let replacement = &edits[splice.edit].edit.replacement;
                let replacement = match self.markup {
                    Markup::Html => crate::pages::text::escape(replacement),
                    Markup::Plain => replacement.clone(),
                };
                served.push_str(&replacement);
                let inside = |ranges: &[Range<usize>]| {
                    ranges
                        .iter()
                        .any(|range| range.contains(&splice.bytes.start))
                };
                if self.markup == Markup::Plain || inside(&self.unmarked) {
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
        Edited {
            served,
            marked,
            outcomes,
        }
    }

    /// Whether the characters `place` lie in one field: all in the same
    /// attribute value, or all in the page's text.
    fn one_field(&self, place: &Range<usize>) -> bool {
        let field = |character: usize| {
            let byte = self.spans[character].start;
            self.attributes
                .iter()
                .position(|range| range.contains(&byte))
        };
        let first = field(place.start);
        place.clone().all(|character| field(character) == first)
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
    /// The `<meta>` summaries read as text, by their source bytes.
    attributes: Vec<Range<usize>>,
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
        if name == "meta" && !closing {
            self.summary(source, name_start + name.len(), end);
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

impl Reader {
    /// Reads a `<meta>` tag's content as a line of text when it is one of
    /// the page's [`SUMMARIES`]; its attributes run from `at` to `end`.
    fn summary(&mut self, source: &str, at: usize, end: usize) {
        let attributes = attributes(source, at, end);
        let names = |key: &str| {
            attributes
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(key))
                .map(|(_, value)| source[value.clone()].trim().to_ascii_lowercase())
        };
        let summary = names("name")
            .into_iter()
            .chain(names("property"))
            .any(|name| SUMMARIES.contains(&name.as_str()));
        let Some((_, value)) = attributes
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content"))
        else {
            return;
        };
        if !summary || source[value.clone()].trim().is_empty() {
            return;
        }
        self.block(value.start);
        let mut at = value.start;
        while at < value.end {
            if source.as_bytes()[at] == b'&'
                && let Some((character, length)) = reference(&source[at..value.end])
            {
                self.character(character, at..at + length);
                at += length;
                continue;
            }
            let character = source[at..].chars().next().expect("a character");
            self.character(character, at..at + character.len_utf8());
            at += character.len_utf8();
        }
        self.block(value.end);
        self.attributes.push(value.clone());
    }
}

/// The attributes of the tag whose attributes run from `at` to `end`
/// (after its `>`): each name with the source bytes of its value.
fn attributes(source: &str, at: usize, end: usize) -> Vec<(&str, Range<usize>)> {
    let bytes = source.as_bytes();
    let end = end.min(source.len());
    let mut found = Vec::new();
    let mut at = at;
    let space = |byte: u8| byte.is_ascii_whitespace() || byte == b'/';
    while at < end {
        while at < end && space(bytes[at]) {
            at += 1;
        }
        let name_start = at;
        while at < end && !space(bytes[at]) && !matches!(bytes[at], b'=' | b'>') {
            at += 1;
        }
        let name = &source[name_start..at];
        if name.is_empty() {
            break;
        }
        while at < end && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at >= end || bytes[at] != b'=' {
            continue;
        }
        at += 1;
        while at < end && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        let value = match bytes.get(at) {
            Some(quote @ (b'"' | b'\'')) => {
                let start = at + 1;
                let stop = source[start..end]
                    .find(*quote as char)
                    .map_or(end, |offset| start + offset);
                at = (stop + 1).min(end);
                start..stop
            }
            _ => {
                let start = at;
                while at < end && !bytes[at].is_ascii_whitespace() && bytes[at] != b'>' {
                    at += 1;
                }
                start..at
            }
        };
        found.push((name, value));
    }
    found
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
