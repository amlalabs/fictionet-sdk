//! A bounded reader for the XML subset used by schema files.
//!
//! It accepts an XML declaration, comments, elements with namespace
//! prefixes, attributes, text, and predefined or numeric character
//! references. DTDs, entity declarations, processing instructions after
//! the declaration, and CDATA are refused. Input size, nesting, element
//! count, attribute count, and name length are bounded.
use crate::{Error, ErrorKind, ir::*};
use std::collections::BTreeMap;

/// One element. Children are indexes into [`Document::nodes`].
#[derive(Debug)]
pub(crate) struct Node {
    /// Local name, without any namespace prefix.
    pub(crate) tag: String,
    pub(crate) attrs: BTreeMap<String, String>,
    /// All character data directly inside the element, concatenated.
    pub(crate) text: String,
    pub(crate) children: Vec<usize>,
    /// Byte offset of the element in the input.
    pub(crate) at: usize,
}
impl Node {
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.get(name).map(String::as_str)
    }
}
/// A parsed document. The root element is node 0.
pub(crate) struct Document {
    pub(crate) nodes: Vec<Node>,
}
fn syntax(at: usize, message: &str) -> Error {
    Error::new(ErrorKind::XmlSyntax, format!("byte {at}"), message)
}
fn limit(at: usize, message: &str) -> Error {
    Error::new(ErrorKind::InputLimit, format!("byte {at}"), message)
}
struct Reader<'a> {
    input: &'a str,
    at: usize,
    nodes: Vec<Node>,
}
impl<'a> Reader<'a> {
    fn rest(&self) -> &'a str {
        self.input.get(self.at..).unwrap_or_default()
    }
    fn ws(&mut self) {
        while self
            .rest()
            .as_bytes()
            .first()
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at += 1;
        }
    }
    fn take(&mut self, s: &str) -> bool {
        if self.rest().starts_with(s) {
            self.at += s.len();
            true
        } else {
            false
        }
    }
    fn name(&mut self) -> Result<String, Error> {
        let start = self.at;
        let first = self.rest().as_bytes().first().copied();
        if !first.is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') {
            return Err(syntax(start, "expected a name"));
        }
        while self
            .rest()
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
        {
            self.at += 1;
        }
        if self.at - start > MAX_NAME {
            return Err(limit(start, "XML name exceeds MAX_NAME"));
        }
        let name = self
            .input
            .get(start..self.at)
            .ok_or_else(|| syntax(start, "expected a name"))?;
        if name.matches(':').count() > 1 || name.ends_with(':') {
            return Err(syntax(start, "invalid qualified name"));
        }
        Ok(name.to_owned())
    }
    fn comment(&mut self) -> Result<(), Error> {
        let n = self
            .rest()
            .find("-->")
            .ok_or_else(|| syntax(self.at, "unterminated comment"))?;
        let content = self.rest().get(..n).unwrap_or_default();
        if content.contains("--") || content.ends_with('-') {
            return Err(syntax(self.at, "invalid comment"));
        }
        self.at += n + 3;
        Ok(())
    }
    fn element(&mut self, depth: usize) -> Result<usize, Error> {
        if depth > MAX_XML_DEPTH {
            return Err(limit(self.at, "XML nesting exceeds MAX_XML_DEPTH"));
        }
        if self.nodes.len() >= MAX_XML_ELEMENTS {
            return Err(limit(self.at, "XML element count exceeds MAX_XML_ELEMENTS"));
        }
        let at = self.at;
        if !self.take("<") {
            return Err(syntax(self.at, "expected an element"));
        }
        let qualified = self.name()?;
        let tag = qualified.rsplit(':').next().unwrap_or_default().to_owned();
        let mut attrs = BTreeMap::new();
        let empty;
        loop {
            let before = self.at;
            self.ws();
            if self.take("/>") {
                empty = true;
                break;
            }
            if self.take(">") {
                empty = false;
                break;
            }
            if before == self.at {
                return Err(syntax(self.at, "expected whitespace before an attribute"));
            }
            if attrs.len() >= MAX_XML_ATTRIBUTES {
                return Err(limit(self.at, "attribute count exceeds MAX_XML_ATTRIBUTES"));
            }
            let name = self.name()?;
            self.ws();
            if !self.take("=") {
                return Err(syntax(self.at, "expected '='"));
            }
            self.ws();
            let quote = self
                .rest()
                .chars()
                .next()
                .filter(|c| *c == '\'' || *c == '"')
                .ok_or_else(|| syntax(self.at, "expected a quoted value"))?;
            self.at += 1;
            let len = self
                .rest()
                .find(quote)
                .ok_or_else(|| syntax(self.at, "unterminated attribute"))?;
            let raw = self.rest().get(..len).unwrap_or_default();
            if raw.contains('<') {
                return Err(syntax(self.at, "'<' in attribute value"));
            }
            let value = text(raw, self.at)?;
            self.at += len + 1;
            if attrs.insert(name, value).is_some() {
                return Err(syntax(self.at, "duplicate attribute"));
            }
        }
        let id = self.nodes.len();
        self.nodes.push(Node {
            tag,
            attrs,
            text: String::new(),
            children: Vec::new(),
            at,
        });
        if empty {
            return Ok(id);
        }
        loop {
            if self.take("</") {
                if self.name()? != qualified {
                    return Err(syntax(self.at, "mismatched closing tag"));
                }
                self.ws();
                if !self.take(">") {
                    return Err(syntax(self.at, "expected '>'"));
                }
                break;
            }
            if self.take("<!--") {
                self.comment()?;
                continue;
            }
            if self.rest().starts_with("<!") || self.rest().starts_with("<?") {
                return Err(syntax(self.at, "unsupported markup"));
            }
            if self.rest().starts_with('<') {
                let child = self.element(depth + 1)?;
                if let Some(node) = self.nodes.get_mut(id) {
                    node.children.push(child);
                }
            } else {
                let len = self
                    .rest()
                    .find('<')
                    .ok_or_else(|| syntax(self.at, "unterminated element"))?;
                let raw = self.rest().get(..len).unwrap_or_default();
                if raw.contains("]]>") {
                    return Err(syntax(self.at, "']]>' in text"));
                }
                let content = text(raw, self.at)?;
                if let Some(node) = self.nodes.get_mut(id) {
                    node.text.push_str(&content);
                }
                self.at += len;
            }
        }
        Ok(id)
    }
}
fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}
fn text(raw: &str, at: usize) -> Result<String, Error> {
    let mut out = String::new();
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(rest.get(..i).unwrap_or_default());
        rest = rest.get(i + 1..).unwrap_or_default();
        let end = rest
            .find(';')
            .ok_or_else(|| syntax(at, "unterminated reference"))?;
        let token = rest.get(..end).unwrap_or_default();
        let c = match token {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let n = if let Some(hex) = token.strip_prefix("#x") {
                    u32::from_str_radix(hex, 16).ok()
                } else {
                    token.strip_prefix('#').and_then(|s| s.parse::<u32>().ok())
                };
                n.and_then(char::from_u32)
                    .filter(|c| xml_char(*c))
                    .ok_or_else(|| syntax(at, "unknown or invalid reference"))?
            }
        };
        out.push(c);
        rest = rest.get(end + 1..).unwrap_or_default();
    }
    out.push_str(rest);
    Ok(out)
}
/// Parses one document. `input` is already bounded by [`MAX_INPUT`].
pub(crate) fn parse(input: &[u8]) -> Result<Document, Error> {
    if input.len() > MAX_INPUT {
        return Err(limit(0, "input exceeds MAX_INPUT"));
    }
    let input = std::str::from_utf8(input).map_err(|e| syntax(e.valid_up_to(), "invalid UTF-8"))?;
    if let Some((at, _)) = input.char_indices().find(|(_, c)| !xml_char(*c)) {
        return Err(syntax(at, "character not allowed in XML"));
    }
    let mut xml = Reader {
        input,
        at: 0,
        nodes: Vec::new(),
    };
    xml.take("\u{feff}");
    if xml.take("<?xml") {
        let before = xml.at;
        xml.ws();
        if before == xml.at {
            return Err(syntax(xml.at, "malformed XML declaration"));
        }
        let len = xml
            .rest()
            .find("?>")
            .ok_or_else(|| syntax(xml.at, "unterminated XML declaration"))?;
        // The declaration's attributes use the same bounded tokenizer.
        let declaration = format!(
            "<declaration {}/>",
            xml.rest().get(..len).unwrap_or_default()
        );
        let mut d = Reader {
            input: &declaration,
            at: 0,
            nodes: Vec::new(),
        };
        d.element(1)
            .map_err(|_| syntax(xml.at, "malformed XML declaration"))?;
        let valid = d.nodes.first().is_some_and(|node| {
            node.attr("version") == Some("1.0")
                && node
                    .attr("encoding")
                    .is_none_or(|s| s.eq_ignore_ascii_case("UTF-8"))
                && node
                    .attrs
                    .keys()
                    .all(|s| matches!(s.as_str(), "version" | "encoding" | "standalone"))
                && node
                    .attr("standalone")
                    .is_none_or(|s| s == "yes" || s == "no")
        });
        if !valid {
            return Err(syntax(xml.at, "unsupported XML declaration"));
        }
        xml.at += len + 2;
    }
    loop {
        xml.ws();
        if !xml.take("<!--") {
            break;
        }
        xml.comment()?;
    }
    xml.element(1)?;
    loop {
        xml.ws();
        if !xml.take("<!--") {
            break;
        }
        xml.comment()?;
    }
    if !xml.rest().is_empty() {
        return Err(syntax(xml.at, "content after the root element"));
    }
    Ok(Document { nodes: xml.nodes })
}
