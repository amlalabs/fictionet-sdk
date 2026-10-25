//! The text a reader sees in a document, mapped back to the bytes it came
//! from. An edit to a passage of that text splices only those bytes: tags,
//! code and every other byte stay as the site sent them.
//!
//! An HTML page's text is what a browser shows, with the page's summaries
//! in `<meta>` tags (readers see them in search results and link
//! previews) and the strings in its scripts' data, which a reader of the
//! page's source sees. JSON is read as its string values, each under the
//! keys that hold it; plain text line by line; XML and feeds as the text
//! of their elements.

use super::Edit;
use super::literal::{self, Code, Literal};
use std::collections::HashMap;
use std::ops::Range;
use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

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

/// A line repeated with at least this many words is one text shown twice
/// (a page's data holding the paragraph it shows, say): it is read once and
/// edited the same way everywhere.
const REPEATED_WORDS: usize = 3;

/// How a document is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::pages) enum Format {
    /// An HTML page.
    Html,
    /// JSON data.
    Json,
    /// A plain text file, line by line.
    Text,
    /// XML, such as a feed.
    Xml,
    /// One line of plain text, such as a search result's title.
    Line,
}

impl Format {
    /// The format of a response whose media type is `content_type`, when
    /// its text can be edited.
    pub(in crate::pages) fn of(content_type: &str) -> Option<Self> {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let (kind, subtype) = media.split_once('/')?;
        Some(match (kind, subtype) {
            ("text", "html") | ("application", "xhtml+xml") => Self::Html,
            (_, "json") | (_, "ld+json") => Self::Json,
            (_, subtype) if subtype.ends_with("+json") => Self::Json,
            ("text", "xml") | ("application", "xml") => Self::Xml,
            ("application", subtype) if subtype.ends_with("+xml") => Self::Xml,
            ("text", "plain" | "markdown" | "x-markdown" | "csv" | "x-rst") => Self::Text,
            _ => return None,
        })
    }
}

/// Where in the source a run of text sits, which decides how a
/// replacement is written there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    /// A `<meta>` summary's attribute value.
    Summary,
    /// A string in JSON or a script, quoted with `quote`, held in `holder`.
    Literal { quote: u8, holder: Holder },
    /// An XML `CDATA` section.
    CData,
}

/// What holds a string of data, which decides how a replacement in it is
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Holder {
    /// A JSON document.
    Data,
    /// A page's `<script>`, which a closing tag in it would end.
    Script,
    /// A page's `data-` attribute holding JSON, written with references.
    Attribute,
}

/// A document's text, one line per block, with the source bytes behind
/// each character.
pub(super) struct Document<'a> {
    source: &'a str,
    format: Format,
    /// The document's text: runs of whitespace are one space, or one line
    /// break where a block starts.
    text: String,
    /// The source bytes each character stands for.
    spans: Vec<Range<usize>>,
    /// Further whitespace a collapsed space absorbed across tags.
    absorbed: HashMap<usize, Vec<Range<usize>>>,
    /// The `text` the document's search compares: quotes, dashes, accents
    /// and line breaks folded, with where each character of `text` starts.
    folded: String,
    starts: Vec<usize>,
    /// The page's `<title>` text, which is never marked on the host's copy.
    title: Option<Range<usize>>,
    /// Source bytes that are not page text, and how replacements are
    /// written in them.
    fields: Vec<(Range<usize>, Field)>,
    /// Characters that name the keys a value sits under (`events.fixed: `):
    /// read with the value, never edited.
    labels: Vec<Range<usize>>,
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
    /// The replacement would turn one value of data, or a summary, into
    /// several lines.
    Lines,
}

/// One place an edit is made: its characters and the words that replace
/// them there.
struct Place {
    edit: usize,
    chars: Range<usize>,
    replacement: String,
}

/// One run of source bytes an edit replaces.
struct Splice {
    bytes: Range<usize>,
    /// The replacement as written in the source, on the first run of a
    /// place; the other runs are removed.
    written: Option<String>,
    /// Whether the host's copy marks it.
    marked: bool,
}

/// The document with its edits made: what the guest is served, the host's
/// copy with each change marked, and what became of each edit.
pub(super) struct Edited {
    pub served: String,
    pub marked: String,
    pub outcomes: Vec<Outcome>,
    /// Each change as made: the words of the text it replaced and what
    /// replaced them, the page's text first and its data after.
    pub changes: Vec<Edit>,
}

impl<'a> Document<'a> {
    /// Reads `source`, written in `format`.
    pub(super) fn new(source: &'a str, format: Format) -> Self {
        match format {
            Format::Html => Self::markup(source, Format::Html),
            Format::Xml => Self::markup(source, Format::Xml),
            Format::Json => Self::json(source),
            Format::Text => Self::plain(source, true),
            Format::Line => Self::plain(source, false),
        }
    }

    /// Reads HTML as a browser shows its text, or XML as its elements' text.
    fn markup(source: &'a str, format: Format) -> Self {
        let mut reader = Reader {
            xml: format == Format::Xml,
            ..Reader::default()
        };
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
        for value in std::mem::take(&mut reader.deferred) {
            reader.literal(&value, Holder::Attribute);
        }
        Self::read(source, format, reader)
    }

    /// Reads JSON as its string values, one per line under its keys.
    fn json(source: &'a str) -> Self {
        let mut reader = Reader::default();
        for value in literal::values(source, 0..source.len(), Code::Json) {
            if readable(&value, Code::Json) {
                reader.literal(&value, Holder::Data);
            }
        }
        Self::read(source, Format::Json, reader)
    }

    /// Reads `source` as plain text; with `lines`, each line break starts
    /// a line of the text.
    fn plain(source: &'a str, lines: bool) -> Self {
        let mut reader = Reader::default();
        for (at, character) in source.char_indices() {
            reader.character(character, at..at + character.len_utf8());
            if lines && character == '\n' {
                reader.block(at);
            }
        }
        Self::read(
            source,
            if lines { Format::Text } else { Format::Line },
            reader,
        )
    }

    fn read(source: &'a str, format: Format, reader: Reader) -> Self {
        let mut folded = String::with_capacity(reader.text.len());
        let mut starts = Vec::with_capacity(reader.spans.len());
        for character in reader.text.chars() {
            starts.push(folded.len());
            folded.extend(fold(character));
        }
        let mut fields = reader.fields;
        fields.sort_by_key(|(range, _)| range.start);
        Self {
            source,
            format,
            text: reader.text,
            starts,
            spans: reader.spans,
            absorbed: reader.absorbed,
            folded,
            title: reader.title,
            fields,
            labels: reader.labels,
        }
    }

    /// The document's text, one line per block.
    pub(super) fn text(&self) -> &str {
        &self.text
    }

    /// The text in runs of whole lines of about `size` characters each; a
    /// line longer than that is a run of its own. A repeated line is read
    /// only where it first appears: its edits are made everywhere it does.
    pub(super) fn sections(&self, size: usize) -> Vec<Section> {
        let mut sections = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let (mut start, mut text) = (0, String::new());
        let mut at = 0;
        for line in self.text.split_inclusive('\n') {
            let length = line.chars().count();
            let repeated = repeatable(line) && !seen.insert(line.trim_end());
            if !repeated {
                if !text.is_empty() && text.chars().count() + length > size {
                    sections.push(Section {
                        chars: start..at,
                        text: std::mem::take(&mut text),
                    });
                    start = at;
                }
                text.push_str(line);
            }
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
        let found: Vec<Range<usize>> = self
            .folded
            .match_indices(&passage)
            .map(|(byte, found)| character(byte)..character(byte + found.len()))
            .collect();
        if !found.is_empty() {
            return found;
        }
        // Text with stray spaces in words (`t hat w indy`, as some
        // snippets have) is matched by a passage copied with the words
        // whole: both are compared without their spaces.
        let mut squeezed = String::with_capacity(self.folded.len());
        let mut starts = Vec::new();
        let mut origins = Vec::new();
        for (index, character) in self.text.chars().enumerate() {
            if let Some(folded) = fold(character)
                && !folded.is_whitespace()
            {
                starts.push(squeezed.len());
                origins.push(index);
                squeezed.push(folded);
            }
        }
        let passage: String = passage.chars().filter(|c| !c.is_whitespace()).collect();
        if passage.is_empty() {
            return Vec::new();
        }
        let position = |byte: usize| starts.partition_point(|start| *start < byte);
        squeezed
            .match_indices(&passage)
            .map(|(byte, found)| {
                let first = position(byte);
                let last = position(byte + found.len()) - 1;
                origins[first]..origins[last] + 1
            })
            .collect()
    }

    /// Makes `edits`: each in every place its passage appears in its
    /// scope, and in every repeat of the line it is made in. Where two
    /// edits' passages share words, the longer passage is made there and
    /// the shorter one is not, so the edits never collide.
    pub(super) fn apply(&self, edits: &[Scoped<'_>]) -> Edited {
        let mut outcomes = vec![Outcome::NotFound; edits.len()];
        let repeats = self.repeats();
        let mut places: Vec<Place> = Vec::new();
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
            // A passage copied with its escapes written out (`–`,
            // `&ndash;`) is the text they stand for.
            let mut readings = vec![(edit.passage.clone(), edit.replacement.clone())];
            if let Some(passage) = unescaped(&edit.passage) {
                let replacement = unescaped(&edit.replacement).unwrap_or(edit.replacement.clone());
                readings.push((passage, replacement));
            }
            let Some((found, replacement)) =
                readings.into_iter().find_map(|(passage, replacement)| {
                    let found = self.occurrences(&passage);
                    (!found.is_empty()).then_some((found, replacement))
                })
            else {
                continue;
            };
            let within: Vec<_> = found
                .iter()
                .filter(|place| {
                    scoped.within.start <= place.start && place.end <= scoped.within.end
                })
                .cloned()
                .collect();
            let found = if within.is_empty() { found } else { within };
            let pieces = found
                .into_iter()
                .flat_map(|place| self.lines_of(place, &replacement));
            for (place, replacement) in pieces {
                let Some((chars, replacement)) = self.unlabeled(place, &replacement) else {
                    continue;
                };
                for chars in std::iter::once(chars.clone()).chain(self.repeated(&repeats, &chars)) {
                    if !self.one_field(&chars) {
                        continue;
                    }
                    // One value of data stays one value: no edit adds lines to it.
                    if self.field(self.spans[chars.start].start).is_some()
                        && replacement.contains('\n')
                    {
                        outcomes[index] = Outcome::Lines;
                        continue;
                    }
                    places.push(Place {
                        edit: index,
                        chars,
                        replacement: replacement.clone(),
                    });
                }
            }
        }
        places.sort_by_key(|place| {
            (
                std::cmp::Reverse(place.chars.len()),
                place.edit,
                place.chars.start,
            )
        });
        let mut taken: Vec<Range<usize>> = Vec::new();
        let mut splices = Vec::new();
        let mut changes = Vec::new();
        for place in places {
            if taken
                .iter()
                .any(|other| other.start < place.chars.end && place.chars.start < other.end)
            {
                if outcomes[place.edit] == Outcome::NotFound {
                    outcomes[place.edit] = Outcome::Covered;
                }
                continue;
            }
            outcomes[place.edit] = Outcome::Made;
            let first = self.spans[place.chars.start].start;
            let field = self.field(first);
            let words: String = self
                .text
                .chars()
                .skip(place.chars.start)
                .take(place.chars.len())
                .collect();
            let change = Edit {
                passage: words,
                replacement: place.replacement.clone(),
            };
            changes.push((field.is_some(), place.edit, place.chars.start, change));
            let written = self.written(&place.replacement, field);
            let marked = self.format == Format::Html
                && field.is_none()
                && !self
                    .title
                    .as_ref()
                    .is_some_and(|title| title.contains(&first));
            for (run, bytes) in self.runs(place.chars.clone()).into_iter().enumerate() {
                splices.push(Splice {
                    bytes,
                    written: (run == 0).then(|| written.clone()),
                    marked,
                });
            }
            taken.push(place.chars);
        }
        splices.sort_by_key(|splice| splice.bytes.start);
        let mut served = String::with_capacity(self.source.len());
        let mut marked = String::with_capacity(self.source.len());
        let mut at = 0;
        for splice in splices {
            let kept = &self.source[at..splice.bytes.start];
            served.push_str(kept);
            marked.push_str(kept);
            if let Some(written) = &splice.written {
                served.push_str(written);
                if splice.marked {
                    marked.push_str(MARK);
                    marked.push_str(written);
                    marked.push_str("</mark>");
                } else {
                    marked.push_str(written);
                }
            }
            at = splice.bytes.end;
        }
        served.push_str(&self.source[at..]);
        marked.push_str(&self.source[at..]);
        changes.sort_by_key(|(data, edit, start, _)| (*data, *edit, *start));
        let mut listed: Vec<Edit> = Vec::new();
        for (_, _, _, change) in changes {
            if !listed.contains(&change) {
                listed.push(change);
            }
        }
        Edited {
            served,
            marked,
            outcomes,
            changes: listed,
        }
    }

    /// `replacement` as written in the source where `field` is.
    fn written(&self, replacement: &str, field: Option<Field>) -> String {
        match field {
            Some(Field::Summary) => crate::pages::text::escape(replacement),
            Some(Field::Literal { quote, holder }) => {
                let escaped = literal::escaped(replacement, quote, holder == Holder::Script);
                match holder {
                    Holder::Attribute => crate::pages::text::escape(&escaped),
                    Holder::Data | Holder::Script => escaped,
                }
            }
            Some(Field::CData) => replacement.replace("]]>", "]]]]><![CDATA[>"),
            None => match self.format {
                Format::Html | Format::Xml => crate::pages::text::escape(replacement),
                Format::Json | Format::Text | Format::Line => replacement.to_owned(),
            },
        }
    }

    /// The field the source byte `byte` is in, if it is not page text.
    fn field(&self, byte: usize) -> Option<Field> {
        let index = self
            .fields
            .partition_point(|(range, _)| range.start <= byte);
        let (range, field) = self.fields.get(index.checked_sub(1)?)?;
        (range.contains(&byte) || range.start == byte).then_some(*field)
    }

    /// The field index the source byte `byte` is in.
    fn field_index(&self, byte: usize) -> Option<usize> {
        let index = self
            .fields
            .partition_point(|(range, _)| range.start <= byte);
        let found = index.checked_sub(1)?;
        let (range, _) = &self.fields[found];
        (range.contains(&byte) || range.start == byte).then_some(found)
    }

    /// A place that runs over several lines (table cells, values of data)
    /// with a replacement of as many lines, as one edit per line that
    /// changes, so each line keeps its own place; otherwise the place as
    /// it is.
    fn lines_of(&self, place: Range<usize>, replacement: &str) -> Vec<(Range<usize>, String)> {
        let breaks: Vec<usize> = place
            .clone()
            .zip(self.text.chars().skip(place.start))
            .filter(|(_, character)| *character == '\n')
            .map(|(index, _)| index)
            .collect();
        let lines: Vec<&str> = replacement.split('\n').collect();
        if breaks.is_empty() || lines.len() != breaks.len() + 1 {
            return vec![(place, replacement.to_owned())];
        }
        let starts = std::iter::once(place.start).chain(breaks.iter().map(|at| at + 1));
        let ends = breaks.iter().copied().chain(std::iter::once(place.end));
        starts
            .zip(ends)
            .zip(lines)
            .filter(|((start, end), line)| {
                let real: String = self.text.chars().skip(*start).take(end - start).collect();
                normalized(&real) != normalized(line)
            })
            .map(|((start, end), line)| (start..end, line.to_owned()))
            .collect()
    }

    /// `place` without the key names it starts with, and `replacement`
    /// without the same names; `None` when the place reaches into names
    /// any other way, since names are never edited.
    fn unlabeled(&self, place: Range<usize>, replacement: &str) -> Option<(Range<usize>, String)> {
        let Some(label) = self
            .labels
            .iter()
            .find(|label| label.start < place.end && place.start < label.end)
        else {
            return Some((place, replacement.to_owned()));
        };
        if place.start < label.start || place.end <= label.end {
            return None;
        }
        let names: String = self
            .text
            .chars()
            .skip(place.start)
            .take(label.end - place.start)
            .collect();
        let names = normalized(names.trim_end());
        let mut rest = replacement.trim_start();
        let mut matched = String::new();
        while normalized(&matched) != names {
            let character = rest.chars().next()?;
            matched.push(character);
            rest = &rest[character.len_utf8()..];
            if normalized(&matched).len() > names.len() {
                return None;
            }
        }
        Some((label.end..place.end, rest.trim_start().to_owned()))
    }

    /// The lines of the text worth editing alike wherever they repeat: each
    /// such line's text with the character ranges of its lines.
    fn repeats(&self) -> HashMap<&str, Vec<Range<usize>>> {
        let mut lines: HashMap<&str, Vec<Range<usize>>> = HashMap::new();
        let mut at = 0;
        for line in self.text.split('\n') {
            let length = line.chars().count();
            if repeatable(line) {
                lines.entry(line).or_default().push(at..at + length);
            }
            at += length + 1;
        }
        lines.retain(|_, places| places.len() > 1);
        lines
    }

    /// `place` in every other line that repeats the line it is in.
    fn repeated(
        &self,
        repeats: &HashMap<&str, Vec<Range<usize>>>,
        place: &Range<usize>,
    ) -> Vec<Range<usize>> {
        let Some(lines) = repeats.values().find(|lines| {
            lines
                .iter()
                .any(|line| line.start <= place.start && place.end <= line.end)
        }) else {
            return Vec::new();
        };
        let line = lines
            .iter()
            .find(|line| line.start <= place.start && place.end <= line.end)
            .expect("the place's line");
        lines
            .iter()
            .filter(|other| other.start != line.start)
            .map(|other| {
                other.start + (place.start - line.start)..other.start + (place.end - line.start)
            })
            .collect()
    }

    /// Whether the characters `place` lie in one field: all in the same
    /// attribute value or string, or all in the page's text.
    fn one_field(&self, place: &Range<usize>) -> bool {
        let field = |character: usize| self.field_index(self.spans[character].start);
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

/// Whether `line` is long enough that a repeat of it is the same text.
fn repeatable(line: &str) -> bool {
    line.split_whitespace().count() >= REPEATED_WORDS
}

/// Whether a string value reads as text worth editing: not an address, a
/// path, a hash or a token. In a page's scripts, also not a bare word,
/// which is almost always a name in the code.
fn readable(value: &Literal, code: Code) -> bool {
    let text: String = value
        .characters
        .iter()
        .map(|(character, _)| *character)
        .collect();
    let text = text.trim();
    let spaced = text.contains(char::is_whitespace);
    if text
        .chars()
        .filter(|character| character.is_alphanumeric())
        .count()
        < 2
    {
        return false;
    }
    let address = ["http://", "https://", "//", "data:", "mailto:", "blob:"]
        .iter()
        .any(|prefix| text.starts_with(prefix));
    if address || (!spaced && (text.starts_with(['/', '#', '.']) || text.chars().count() > 40)) {
        return false;
    }
    match code {
        Code::Json => true,
        // A word with no spaces is a figure (`1889`, `2.0.1`, `[,2.0)`) when it
        // has digits and hardly any letters; otherwise it names something in
        // the code (`cite_note-20`, `mwDAM`).
        Code::Script => {
            spaced
                || (text.contains(|character: char| character.is_ascii_digit())
                    && text.chars().filter(char::is_ascii_alphabetic).count() <= 1)
        }
    }
}

/// Builds a document's text one source character at a time.
#[derive(Default)]
struct Reader {
    /// Whether the source is XML: every element is a block and no element
    /// hides its text.
    xml: bool,
    text: String,
    spans: Vec<Range<usize>>,
    absorbed: HashMap<usize, Vec<Range<usize>>>,
    /// Whitespace not yet written: its source bytes, and whether a block
    /// starts within it.
    pending: Option<(Vec<Range<usize>>, bool)>,
    title: Option<Range<usize>>,
    /// Where the open `<title>`'s text starts.
    title_start: Option<usize>,
    fields: Vec<(Range<usize>, Field)>,
    labels: Vec<Range<usize>>,
    /// Strings in tags' `data-` attributes, read after the page's text so
    /// they never break a sentence that runs past a tag.
    deferred: Vec<Literal>,
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
        self.flush();
        self.push(character, bytes);
    }

    /// Writes the whitespace not yet written, as one space or line break.
    fn flush(&mut self) {
        if let Some((mut runs, block)) = self.pending.take()
            && !self.text.is_empty()
        {
            let first = runs.remove(0);
            if !runs.is_empty() {
                self.absorbed.insert(self.spans.len(), runs);
            }
            self.push(if block { '\n' } else { ' ' }, first);
        }
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

    /// A string value on a line of its own, after the keys it sits under.
    fn literal(&mut self, value: &Literal, holder: Holder) {
        let at = value.content.start;
        self.block(at);
        if !value.label.is_empty() {
            self.flush();
            let start = self.spans.len();
            for character in value.label.chars().chain(": ".chars()) {
                self.push(character, at..at);
            }
            self.labels.push(start..self.spans.len());
        }
        for (character, bytes) in &value.characters {
            self.character(*character, bytes.clone());
        }
        self.block(value.content.end);
        self.fields.push((
            value.content.clone(),
            Field::Literal {
                quote: value.quote,
                holder,
            },
        ));
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
        if self.xml
            && let Some(data) = rest.strip_prefix("<![CDATA[")
        {
            let start = at + 9;
            let end = data.find("]]>").map_or(source.len(), |end| start + end);
            self.block(at);
            for (offset, character) in source[start..end].char_indices() {
                let byte = start + offset;
                self.character(character, byte..byte + character.len_utf8());
            }
            self.fields.push((start..end, Field::CData));
            self.block(end);
            return Some((end + 3).min(source.len()));
        }
        let after = rest[1..].chars().next()?;
        if after == '!' || after == '?' {
            return Some(rest.find('>').map_or(source.len(), |end| at + end + 1));
        }
        let closing = after == '/';
        let name_start = at + 1 + usize::from(closing);
        let name: String = source[name_start..]
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric()
                    || (self.xml && matches!(character, ':' | '-' | '_' | '.'))
            })
            .collect::<String>()
            .to_ascii_lowercase();
        if name.is_empty() || !name.starts_with(|character: char| character.is_ascii_alphabetic()) {
            return None;
        }
        let end = tag_end(source, name_start + name.len());
        if self.xml {
            self.block(at);
            return Some(end);
        }
        if !closing && name == "script" {
            return Some(self.script(source, name_start + name.len(), end));
        }
        if !closing && HIDDEN.contains(&name.as_str()) {
            return Some(element_end(source, end, &name));
        }
        if BLOCKS.contains(&name.as_str()) {
            self.block(at);
        }
        if name == "meta" && !closing {
            self.summary(source, name_start + name.len(), end);
        }
        if !closing {
            self.data(source, name_start + name.len(), end);
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

    /// Reads the strings in the data of the `<script>` whose attributes run
    /// from `at` to `end`, and returns where the text after it starts.
    fn script(&mut self, source: &str, at: usize, end: usize) -> usize {
        let after = element_end(source, end, "script");
        let content_end = source[end..after]
            .to_ascii_lowercase()
            .rfind("</script")
            .map_or(after, |offset| end + offset);
        let kind = attributes(source, at, end)
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("type"))
            .map(|(_, value)| source[value].trim().to_ascii_lowercase());
        let code = match kind.as_deref() {
            None
            | Some(
                ""
                | "module"
                | "text/javascript"
                | "application/javascript"
                | "text/ecmascript"
                | "application/ecmascript",
            ) => Code::Script,
            Some(kind) if kind.ends_with("json") => Code::Json,
            Some(_) => return after,
        };
        for value in literal::values(source, end..content_end, code) {
            if readable(&value, Code::Script) {
                self.literal(&value, Holder::Script);
            }
        }
        after
    }

    /// Reads the strings in the JSON a tag's `data-` attributes hold (a
    /// page's template source, say); its attributes run from `at` to `end`.
    fn data(&mut self, source: &str, at: usize, end: usize) {
        for (name, value) in attributes(source, at, end) {
            let opens = source[value.clone()].trim_start().starts_with(['{', '[']);
            if !name.to_ascii_lowercase().starts_with("data-") || !opens {
                continue;
            }
            // The value as written, with its references decoded, and where
            // each decoded byte's character starts and ends in the source.
            let mut decoded = String::new();
            let mut starts = Vec::new();
            let mut ends = Vec::new();
            let mut byte = value.start;
            while byte < value.end {
                let (character, length) = if source.as_bytes()[byte] == b'&' {
                    reference(&source[byte..value.end])
                } else {
                    None
                }
                .unwrap_or_else(|| {
                    let character = source[byte..].chars().next().expect("a character");
                    (character, character.len_utf8())
                });
                starts.resize(decoded.len() + 1, byte);
                decoded.push(character);
                ends.resize(decoded.len() + 1, byte + length);
                byte += length;
            }
            starts.resize(decoded.len() + 1, value.end);
            for found in literal::values(&decoded, 0..decoded.len(), Code::Json) {
                let value = Literal {
                    content: starts[found.content.start]..starts[found.content.end],
                    quote: found.quote,
                    characters: found
                        .characters
                        .iter()
                        .map(|(character, bytes)| {
                            (*character, starts[bytes.start]..ends[bytes.end])
                        })
                        .collect(),
                    label: found.label,
                };
                if readable(&value, Code::Script) {
                    self.deferred.push(value);
                }
            }
        }
    }

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
        self.fields.push((value.clone(), Field::Summary));
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

/// `text` with the escapes a model may copy literally decoded: JSON and
/// script escapes (`–`, `\"`) and HTML references (`&ndash;`). `None`
/// when it has none.
fn unescaped(text: &str) -> Option<String> {
    let mut decoded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(character) = rest.chars().next() {
        if character == '\\' {
            let escape = &rest[1..];
            let hex = escape
                .strip_prefix('u')
                .and_then(|digits| digits.get(..4))
                .and_then(|digits| u32::from_str_radix(digits, 16).ok());
            if let Some(code) = hex {
                decoded.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                rest = &rest[6..];
                continue;
            }
            if let Some(next) = escape.chars().next()
                && matches!(next, 'n' | 't' | 'r' | '"' | '\'' | '\\' | '/')
            {
                decoded.push(match next {
                    'n' | 't' | 'r' => ' ',
                    other => other,
                });
                rest = &escape[1..];
                continue;
            }
        }
        if character == '&'
            && let Some((decoded_character, length)) = reference(rest)
        {
            decoded.push(decoded_character);
            rest = &rest[length..];
            continue;
        }
        decoded.push(character);
        rest = &rest[character.len_utf8()..];
    }
    (decoded != text).then_some(decoded)
}

/// The character the document's search compares for `character`: curly
/// quotes as straight ones, dashes as hyphens, any whitespace as a space
/// and letters without their accents, so a passage copied with plain
/// punctuation or another Unicode form still matches. Combining accents
/// compare as nothing.
fn fold(character: char) -> Option<char> {
    Some(match character {
        '‘' | '’' | '‚' | '‛' | '′' => '\'',
        '“' | '”' | '„' | '‟' | '″' => '"',
        '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' => '-',
        character if character.is_whitespace() => ' ',
        character if is_combining_mark(character) => return None,
        character => character
            .nfd()
            .find(|part| !is_combining_mark(*part))
            .unwrap_or(character),
    })
}

/// `passage` as the document's search compares it.
fn normalized(passage: &str) -> String {
    passage
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter_map(fold)
        .collect()
}
