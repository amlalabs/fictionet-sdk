//! Typeset authored documents at PDF addresses with embedded Unicode fonts.

use krilla::{
    Document,
    geom::Point,
    metadata::Metadata,
    page::PageSettings,
    text::{Font, TextDirection},
};
use kuchiki::traits::TendrilSink;
use std::sync::OnceLock;

const REGULAR: &[u8] = include_bytes!("fonts/LiberationSerif-Regular.ttf");
const BOLD: &[u8] = include_bytes!("fonts/LiberationSerif-Bold.ttf");
const WIDTH: f32 = 468.0;

struct Line {
    text: String,
    size: f32,
    bold: bool,
    space: f32,
}

fn width(text: &str, size: f32, bold: bool) -> f32 {
    let face = rustybuzz::Face::from_slice(if bold { BOLD } else { REGULAR }, 0)
        .expect("bundled document font");
    let mut buffer = rustybuzz::UnicodeBuffer::new();
    buffer.push_str(text);
    buffer.guess_segment_properties();
    let shaped = rustybuzz::shape(&face, &[], buffer);
    shaped
        .glyph_positions()
        .iter()
        .map(|p| p.x_advance as f32)
        .sum::<f32>()
        * size
        / face.units_per_em() as f32
}

fn wrap(text: &str, size: f32, bold: bool, lines: &mut Vec<Line>) {
    let mut line = String::new();
    for word in text.split_whitespace() {
        let candidate = if line.is_empty() {
            word.into()
        } else {
            format!("{line} {word}")
        };
        if width(&candidate, size, bold) > WIDTH && !line.is_empty() {
            lines.push(Line {
                text: std::mem::take(&mut line),
                size,
                bold,
                space: 0.0,
            });
        }
        if !line.is_empty() {
            line.push(' ');
        }
        // Long URLs and identifiers wrap too, without dropping characters.
        for c in word.chars() {
            let candidate = format!("{line}{c}");
            if width(&candidate, size, bold) > WIDTH && !line.is_empty() {
                lines.push(Line {
                    text: std::mem::take(&mut line),
                    size,
                    bold,
                    space: 0.0,
                });
            }
            line.push(c);
        }
    }
    if !line.is_empty() {
        lines.push(Line {
            text: line,
            size,
            bold,
            space: 8.0,
        });
    }
}

pub(super) fn render(title: &str, markup: &str) -> Result<Vec<u8>, String> {
    static FONTS: OnceLock<(Font, Font)> = OnceLock::new();
    let fonts = FONTS.get_or_init(|| {
        (
            Font::new(REGULAR.to_vec().into(), 0).expect("bundled document font"),
            Font::new(BOLD.to_vec().into(), 0).expect("bundled document font"),
        )
    });
    let dom = kuchiki::parse_html().one(markup);
    let mut lines = Vec::new();
    let blocks = dom
        .select("h1,h2,h3,p,li,pre,tr,blockquote")
        .expect("document selector");
    for block in blocks {
        if block.as_node().ancestors().skip(1).any(|parent| {
            parent.as_element().is_some_and(|e| {
                matches!(
                    e.name.local.as_ref(),
                    "p" | "li" | "pre" | "tr" | "blockquote"
                )
            })
        }) {
            continue;
        }
        let tag = block.name.local.as_ref();
        let (size, bold) = match tag {
            "h1" => (20.0, true),
            "h2" => (14.0, true),
            "h3" => (12.0, true),
            _ => (11.0, false),
        };
        let text = if tag == "tr" {
            block
                .as_node()
                .select("th,td")
                .expect("table selector")
                .map(|cell| cell.text_contents())
                .collect::<Vec<_>>()
                .join("   ")
        } else {
            block.text_contents()
        };
        wrap(&text, size, bold, &mut lines);
    }
    if lines.is_empty() {
        wrap(&super::text::text_of(markup), 11.0, false, &mut lines);
    }
    let mut document = Document::new();
    document.set_metadata(Metadata::new().title(title.to_owned()));
    let mut remaining = lines.as_slice();
    let mut number = 1;
    while !remaining.is_empty() {
        let mut page =
            document.start_page_with(PageSettings::from_wh(612.0, 792.0).expect("letter page"));
        let mut surface = page.surface();
        let mut y = 60.0;
        let mut count = 0;
        for line in remaining {
            if y + line.size * 1.4 > 726.0 {
                break;
            }
            y += line.size;
            surface.draw_text(
                Point::from_xy(72.0, y),
                if line.bold {
                    fonts.1.clone()
                } else {
                    fonts.0.clone()
                },
                line.size,
                &line.text,
                false,
                TextDirection::Auto,
            );
            y += line.size * 0.4 + line.space;
            count += 1;
        }
        surface.draw_text(
            Point::from_xy(302.0, 756.0),
            fonts.0.clone(),
            9.0,
            &number.to_string(),
            false,
            TextDirection::Auto,
        );
        surface.finish();
        page.finish();
        remaining = &remaining[count..];
        number += 1;
    }
    document
        .finish()
        .map_err(|error| format!("Cannot typeset document: {error:?}"))
}
