//! Typeset authored documents at PDF addresses.
//!
//! Text is set in the standard Times and Courier faces with WinAnsi encoding,
//! the way common PDF libraries write it, so every reader recovers the words
//! straight from the page content. Characters outside that encoding are set
//! in an embedded Liberation Serif subset that carries its own Unicode map.

use kuchiki::traits::TendrilSink;
use pdf_writer::{
    Filter, Finish, Name, Pdf, Rect, Ref, Str, TextStr,
    types::{CidFontType, FontFlags, SystemInfo, UnicodeCmap},
};
use std::{io::Write, sync::OnceLock};

const REGULAR: &[u8] = include_bytes!("fonts/LiberationSerif-Regular.ttf");
const BOLD: &[u8] = include_bytes!("fonts/LiberationSerif-Bold.ttf");
const PAGE: (f32, f32) = (612.0, 792.0);
const LEFT: f32 = 72.0;
const WIDTH: f32 = 468.0;
const TOP: f32 = 72.0;
const BOTTOM: f32 = 720.0;
const FOOTER: f32 = 756.0;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Style {
    Regular,
    Bold,
    Mono,
}

impl Style {
    /// The standard face that sets this style's encodable text.
    fn standard(self) -> &'static [u8] {
        match self {
            Style::Regular => b"Times-Roman",
            Style::Bold => b"Times-Bold",
            Style::Mono => b"Courier",
        }
    }
    /// The embedded face for characters the standard face cannot encode.
    fn fallback(self) -> Fallback {
        match self {
            Style::Bold => Fallback::Bold,
            Style::Regular | Style::Mono => Fallback::Regular,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fallback {
    Regular,
    Bold,
}

impl Fallback {
    const ALL: [Fallback; 2] = [Fallback::Regular, Fallback::Bold];
    fn data(self) -> &'static [u8] {
        match self {
            Fallback::Regular => REGULAR,
            Fallback::Bold => BOLD,
        }
    }
    fn face(self) -> &'static ttf_parser::Face<'static> {
        static FACES: OnceLock<[ttf_parser::Face<'static>; 2]> = OnceLock::new();
        let faces = FACES.get_or_init(|| {
            [REGULAR, BOLD].map(|data| ttf_parser::Face::parse(data, 0).expect("bundled font"))
        });
        &faces[self as usize]
    }
    fn resource(self) -> &'static [u8] {
        match self {
            Fallback::Regular => b"F4",
            Fallback::Bold => b"F5",
        }
    }
    fn base_font(self) -> &'static [u8] {
        match self {
            Fallback::Regular => b"AAAAAA+LiberationSerif",
            Fallback::Bold => b"AAAAAB+LiberationSerif-Bold",
        }
    }
}

/// The WinAnsi code for `c`, when the standard faces can set it.
fn win_ansi(c: char) -> Option<u8> {
    let code = u32::from(c);
    if (0x20..0x7f).contains(&code) || (0xa0..=0xff).contains(&code) {
        return Some(code as u8);
    }
    Some(match c {
        '€' => 0x80,
        '‚' => 0x82,
        'ƒ' => 0x83,
        '„' => 0x84,
        '…' => 0x85,
        '†' => 0x86,
        '‡' => 0x87,
        'ˆ' => 0x88,
        '‰' => 0x89,
        'Š' => 0x8a,
        '‹' => 0x8b,
        'Œ' => 0x8c,
        'Ž' => 0x8e,
        '‘' => 0x91,
        '’' => 0x92,
        '“' => 0x93,
        '”' => 0x94,
        '•' => 0x95,
        '–' => 0x96,
        '—' => 0x97,
        '˜' => 0x98,
        '™' => 0x99,
        'š' => 0x9a,
        '›' => 0x9b,
        'œ' => 0x9c,
        'ž' => 0x9e,
        'Ÿ' => 0x9f,
        _ => return None,
    })
}

/// The width of `c` at `size` points. Times shares Liberation Serif's
/// metrics; Courier is fixed width.
fn advance(style: Style, c: char, size: f32) -> f32 {
    if style == Style::Mono && win_ansi(c).is_some() {
        return 0.6 * size;
    }
    let face = style.fallback().face();
    let glyph = face.glyph_index(c).unwrap_or(ttf_parser::GlyphId(0));
    f32::from(face.glyph_hor_advance(glyph).unwrap_or(0)) * size / f32::from(face.units_per_em())
}

fn width(text: &str, style: Style, size: f32) -> f32 {
    text.chars().map(|c| advance(style, c, size)).sum()
}

struct Line {
    text: String,
    size: f32,
    style: Style,
    /// Space after the line, in points.
    space: f32,
    /// A heading stays on the page of the line after it.
    keep: bool,
    /// A table row's cells, by their offset from the left margin.
    cells: Vec<(f32, String)>,
}

/// Breaks `text` into lines no wider than the column. Words wrap at spaces;
/// a word wider than the column wraps between characters, without losing any.
fn wrap(text: &str, size: f32, style: Style, lines: &mut Vec<Line>) {
    let push = |lines: &mut Vec<Line>, text: String| {
        lines.push(Line {
            text,
            size,
            style,
            space: 0.0,
            keep: style == Style::Bold,
            cells: Vec::new(),
        })
    };
    let mut line = String::new();
    for word in text.split_whitespace() {
        let joined = if line.is_empty() {
            word.into()
        } else {
            format!("{line} {word}")
        };
        if width(&joined, style, size) > WIDTH && !line.is_empty() {
            push(lines, std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        for c in word.chars() {
            if width(&line, style, size) + advance(style, c, size) > WIDTH && !line.is_empty() {
                push(lines, std::mem::take(&mut line));
            }
            line.push(c);
        }
    }
    if !line.is_empty() {
        push(lines, line);
    }
}

/// Preformatted text keeps its own lines and spacing.
fn wrap_preformatted(text: &str, lines: &mut Vec<Line>) {
    let (size, style) = (9.0, Style::Mono);
    for source in text.trim_matches('\n').lines() {
        let mut line = String::new();
        for c in source.replace('\t', "    ").chars() {
            if width(&line, style, size) + advance(style, c, size) > WIDTH && !line.is_empty() {
                lines.push(Line {
                    text: std::mem::take(&mut line),
                    size,
                    style,
                    space: 0.0,
                    keep: false,
                    cells: Vec::new(),
                });
            }
            line.push(c);
        }
        lines.push(Line {
            text: line,
            size,
            style,
            space: 0.0,
            keep: false,
            cells: Vec::new(),
        });
    }
}

/// Text a reader would see: invisible and control characters removed.
fn visible(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{ad}' | '\u{200b}'..='\u{200f}' | '\u{2060}' | '\u{feff}'
            ) && (!c.is_control() || matches!(c, '\n' | '\t'))
        })
        .collect()
}

/// A table: rows in columns when they fit the page, else each row as text.
fn table(node: &kuchiki::NodeRef, lines: &mut Vec<Line>) {
    const SIZE: f32 = 10.0;
    const GAP: f32 = 18.0;
    let rows = node
        .select("tr")
        .expect("table selector")
        .map(|row| {
            let cells = row
                .as_node()
                .select("th,td")
                .expect("table selector")
                .map(|cell| normalize(&visible(&cell.text_contents())))
                .collect::<Vec<_>>();
            (row.as_node().select_first("th").is_ok(), cells)
        })
        .filter(|(_, cells)| !cells.is_empty())
        .collect::<Vec<_>>();
    let columns = rows.iter().map(|(_, cells)| cells.len()).max().unwrap_or(0);
    let widths = (0..columns)
        .map(|column| {
            rows.iter()
                .filter_map(|(header, cells)| {
                    let style = if *header { Style::Bold } else { Style::Regular };
                    cells.get(column).map(|cell| width(cell, style, SIZE))
                })
                .fold(0.0, f32::max)
        })
        .collect::<Vec<_>>();
    let fits = widths.iter().sum::<f32>() + GAP * columns.saturating_sub(1) as f32 <= WIDTH;
    for (header, cells) in rows {
        let style = if header { Style::Bold } else { Style::Regular };
        if fits {
            let mut offset = 0.0;
            let mut placed = Vec::new();
            for (cell, width) in cells.into_iter().zip(&widths) {
                placed.push((offset, cell));
                offset += width + GAP;
            }
            lines.push(Line {
                text: String::new(),
                size: SIZE,
                style,
                space: 4.0,
                keep: header,
                cells: placed,
            });
        } else {
            wrap(&cells.join("   "), SIZE, style, lines);
            if let Some(line) = lines.last_mut() {
                line.space = 4.0;
                line.keep = header;
            }
        }
    }
}

fn normalize(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn lines_of(markup: &str) -> Vec<Line> {
    let dom = kuchiki::parse_html().one(markup);
    let mut lines = Vec::new();
    let blocks = dom
        .select("h1,h2,h3,h4,p,li,pre,table,blockquote,figcaption,dt,dd")
        .expect("document selector");
    for block in blocks {
        let node = block.as_node();
        if node.ancestors().skip(1).any(|parent| {
            parent.as_element().is_some_and(|e| {
                matches!(
                    e.name.local.as_ref(),
                    "p" | "li" | "pre" | "table" | "blockquote" | "figcaption" | "dt" | "dd"
                )
            })
        }) {
            continue;
        }
        let tag = block.name.local.as_ref();
        let first = lines.len();
        match tag {
            "pre" => wrap_preformatted(&visible(&node.text_contents()), &mut lines),
            "table" => table(node, &mut lines),
            "li" => {
                let marker = match node.parent().and_then(|p| {
                    p.as_element()
                        .map(|e| (e.name.local.as_ref() == "ol", p.clone()))
                }) {
                    Some((true, list)) => {
                        let index = list
                            .children()
                            .filter(|n| {
                                n.as_element()
                                    .is_some_and(|e| e.name.local.as_ref() == "li")
                            })
                            .position(|n| n == *node)
                            .unwrap_or(0);
                        format!("{}.", index + 1)
                    }
                    _ => "•".to_owned(),
                };
                wrap(
                    &format!("{marker} {}", visible(&node.text_contents())),
                    11.0,
                    Style::Regular,
                    &mut lines,
                );
            }
            _ => {
                let (size, style) = match tag {
                    "h1" => (18.0, Style::Bold),
                    "h2" => (14.0, Style::Bold),
                    "h3" | "h4" => (12.0, Style::Bold),
                    _ => (11.0, Style::Regular),
                };
                wrap(&visible(&node.text_contents()), size, style, &mut lines);
            }
        }
        // Rows of a table and items of a list sit close together.
        let space = match tag {
            "li" => 3.0,
            "h1" => 10.0,
            _ => 8.0,
        };
        if lines.len() > first
            && let Some(line) = lines.last_mut()
        {
            line.space = space;
        }
    }
    lines
}

/// Glyphs of one embedded face used by the document, renumbered for its subset.
struct Subset {
    remapper: subsetter::GlyphRemapper,
    /// Width and text of each subset glyph, by its new number.
    glyphs: Vec<(f32, Option<char>)>,
}

impl Subset {
    fn new() -> Self {
        let mut subset = Self {
            remapper: subsetter::GlyphRemapper::new(),
            glyphs: Vec::new(),
        };
        subset.remapper.remap(0);
        subset.glyphs.push((0.0, None));
        subset
    }
    fn glyph(&mut self, fallback: Fallback, c: char) -> u16 {
        let face = fallback.face();
        let glyph = face.glyph_index(c).unwrap_or(ttf_parser::GlyphId(0));
        let new = self.remapper.remap(glyph.0);
        if usize::from(new) == self.glyphs.len() {
            let width = f32::from(face.glyph_hor_advance(glyph).unwrap_or(0)) * 1000.0
                / f32::from(face.units_per_em());
            self.glyphs.push((width, Some(c)));
        }
        new
    }
}

/// Writes one line of text: encodable runs in the standard face as literal
/// strings, the rest in the embedded face by glyph. The text position
/// advances by each run's widths.
fn show(content: &mut Vec<u8>, line: &Line, x: f32, y: f32, subsets: &mut [Option<Subset>; 2]) {
    if !line.cells.is_empty() {
        for (offset, cell) in &line.cells {
            let cell = Line {
                text: cell.clone(),
                cells: Vec::new(),
                ..*line
            };
            show(content, &cell, x + offset, y, subsets);
        }
        return;
    }
    let _ = writeln!(content, "BT\n1 0 0 1 {x:.2} {:.2} Tm", PAGE.1 - y);
    let mut run = Vec::new();
    let mut encoded = true;
    let flush = |content: &mut Vec<u8>, run: &mut Vec<u8>, encoded: bool| {
        if run.is_empty() {
            return;
        }
        let font = if encoded {
            match line.style {
                Style::Regular => "F1",
                Style::Bold => "F2",
                Style::Mono => "F3",
            }
        } else {
            std::str::from_utf8(line.style.fallback().resource()).expect("resource name")
        };
        let _ = writeln!(content, "/{font} {} Tf", line.size);
        if encoded {
            content.push(b'(');
            for &byte in run.iter() {
                match byte {
                    b'(' | b')' | b'\\' => content.extend([b'\\', byte]),
                    0x20..0x7f => content.push(byte),
                    _ => {
                        let _ = write!(content, "\\{byte:03o}");
                    }
                }
            }
            content.extend(b") Tj\n");
        } else {
            content.push(b'<');
            for byte in run.iter() {
                let _ = write!(content, "{byte:02X}");
            }
            content.extend(b"> Tj\n");
        }
        run.clear();
    };
    for c in line.text.chars() {
        let code = win_ansi(c);
        if code.is_some() != encoded {
            flush(content, &mut run, encoded);
            encoded = code.is_some();
        }
        match code {
            Some(code) => run.push(code),
            // A character neither face can draw is left out, as a viewer would.
            None if line.style.fallback().face().glyph_index(c).is_none() => {}
            None => {
                let fallback = line.style.fallback();
                let glyph = subsets[fallback as usize]
                    .get_or_insert_with(Subset::new)
                    .glyph(fallback, c);
                run.extend(glyph.to_be_bytes());
            }
        }
    }
    flush(content, &mut run, encoded);
    content.extend(b"ET\n");
}

fn compressed(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("compress in memory");
    encoder.finish().expect("compress in memory")
}

pub(super) fn render(title: &str, markup: &str) -> Result<Vec<u8>, String> {
    let mut lines = lines_of(markup);
    if lines.is_empty() {
        wrap(
            &visible(&super::text::text_of(markup)),
            11.0,
            Style::Regular,
            &mut lines,
        );
    }
    // Lay the lines out on pages; a heading never ends a page.
    let mut pages: Vec<Vec<(f32, &Line)>> = vec![Vec::new()];
    let mut y = TOP;
    for (index, line) in lines.iter().enumerate() {
        let height = line.size * 1.25;
        let next = lines
            .get(index + 1)
            .filter(|_| line.keep)
            .map_or(0.0, |next| next.size * 1.25 + line.space);
        let page = pages.last_mut().expect("a page");
        if !page.is_empty() && y + height + next > BOTTOM {
            pages.push(Vec::new());
            y = TOP;
        }
        y += line.size;
        pages.last_mut().expect("a page").push((y, line));
        y += line.size * 0.25 + line.space;
    }
    let mut subsets: [Option<Subset>; 2] = [None, None];
    let footer = Line {
        text: String::new(),
        size: 9.0,
        style: Style::Regular,
        space: 0.0,
        keep: false,
        cells: Vec::new(),
    };
    let count = pages.len();
    let contents = pages
        .iter()
        .enumerate()
        .map(|(index, page)| {
            let mut content = Vec::new();
            for (y, line) in page {
                show(&mut content, line, LEFT, *y, &mut subsets);
            }
            let number = Line {
                text: (index + 1).to_string(),
                cells: Vec::new(),
                ..footer
            };
            let x = (PAGE.0 - width(&number.text, Style::Regular, number.size)) / 2.0;
            show(&mut content, &number, x, FOOTER, &mut subsets);
            content
        })
        .collect::<Vec<_>>();

    let mut pdf = Pdf::new();
    let mut next = Ref::new(1);
    let mut alloc = || next.bump();
    let catalog = alloc();
    let tree = alloc();
    let info = alloc();
    let standard = [alloc(), alloc(), alloc()];
    let fallbacks = Fallback::ALL.map(|_| alloc());
    let page_ids = (0..count).map(|_| alloc()).collect::<Vec<_>>();
    pdf.catalog(catalog).pages(tree);
    pdf.pages(tree)
        .kids(page_ids.iter().copied())
        .count(count as i32);
    pdf.document_info(info).title(TextStr(title));
    for (id, style) in standard
        .iter()
        .zip([Style::Regular, Style::Bold, Style::Mono])
    {
        pdf.type1_font(*id)
            .base_font(Name(style.standard()))
            .encoding_predefined(Name(b"WinAnsiEncoding"));
    }
    for (page_id, content) in page_ids.iter().zip(&contents) {
        // Page text stays uncompressed, as common PDF libraries leave it.
        let content_id = alloc();
        pdf.stream(content_id, content);
        let mut page = pdf.page(*page_id);
        page.parent(tree)
            .media_box(Rect::new(0.0, 0.0, PAGE.0, PAGE.1))
            .contents(content_id);
        let mut resources = page.resources();
        let mut fonts = resources.fonts();
        for (name, id) in [b"F1", b"F2", b"F3"].iter().zip(standard) {
            fonts.pair(Name(name.as_slice()), id);
        }
        for (fallback, id) in Fallback::ALL.iter().zip(fallbacks) {
            if subsets[*fallback as usize].is_some() {
                fonts.pair(Name(fallback.resource()), id);
            }
        }
    }
    for (fallback, id) in Fallback::ALL.iter().zip(fallbacks) {
        let Some(subset) = &subsets[*fallback as usize] else {
            continue;
        };
        let (cid, descriptor, file, cmap) = (alloc(), alloc(), alloc(), alloc());
        let face = fallback.face();
        let scale = 1000.0 / f32::from(face.units_per_em());
        let data = subsetter::subset(fallback.data(), 0, &subset.remapper)
            .map_err(|error| format!("Cannot embed the document font: {error:?}"))?;
        let system = SystemInfo {
            registry: Str(b"Adobe"),
            ordering: Str(b"Identity"),
            supplement: 0,
        };
        pdf.type0_font(id)
            .base_font(Name(fallback.base_font()))
            .encoding_predefined(Name(b"Identity-H"))
            .descendant_font(cid)
            .to_unicode(cmap);
        let mut font = pdf.cid_font(cid);
        font.subtype(CidFontType::Type2)
            .base_font(Name(fallback.base_font()))
            .system_info(system)
            .font_descriptor(descriptor)
            .default_width(0.0)
            .cid_to_gid_map_predefined(Name(b"Identity"));
        font.widths()
            .consecutive(0, subset.glyphs.iter().map(|(width, _)| *width));
        font.finish();
        let bbox = face.global_bounding_box();
        pdf.font_descriptor(descriptor)
            .name(Name(fallback.base_font()))
            .flags(FontFlags::SERIF | FontFlags::SYMBOLIC)
            .bbox(Rect::new(
                f32::from(bbox.x_min) * scale,
                f32::from(bbox.y_min) * scale,
                f32::from(bbox.x_max) * scale,
                f32::from(bbox.y_max) * scale,
            ))
            .italic_angle(0.0)
            .ascent(f32::from(face.ascender()) * scale)
            .descent(f32::from(face.descender()) * scale)
            .cap_height(f32::from(face.capital_height().unwrap_or(face.ascender())) * scale)
            .stem_v(if *fallback == Fallback::Bold {
                140.0
            } else {
                80.0
            })
            .font_file2(file);
        let packed = compressed(&data);
        pdf.stream(file, &packed)
            .filter(Filter::FlateDecode)
            .pair(Name(b"Length1"), data.len() as i32);
        let mut map = UnicodeCmap::new(Name(b"Custom"), system);
        for (glyph, (_, c)) in subset.glyphs.iter().enumerate() {
            if let Some(c) = c {
                map.pair(glyph as u16, *c);
            }
        }
        let map = map.finish();
        pdf.cmap(cmap, &map)
            .name(Name(b"Custom"))
            .system_info(system);
    }
    Ok(pdf.finish())
}
