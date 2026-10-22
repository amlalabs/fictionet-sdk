//! JSON text for packet presentation.

use std::fmt::Write;

/// Appends `s` as a JSON string, quotes included.
pub(crate) fn string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // `<` too, so a string can never close a script element.
            c if (c as u32) < 0x20 || c == '<' || c == '\u{2028}' || c == '\u{2029}' => {
                #[expect(
                    clippy::let_underscore_must_use,
                    reason = "fmt::Write for String never returns Err"
                )]
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
pub(super) use objects::{Object, array};

#[cfg(test)]
mod objects {
    use super::*;
    /// `s` as a JSON string.
    pub(crate) fn quote(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        string(&mut out, s);
        out
    }

    /// An object written field by field.
    pub(crate) struct Object {
        out: String,
        first: bool,
    }

    impl Object {
        pub(crate) fn new() -> Object {
            Object {
                out: String::from("{"),
                first: true,
            }
        }

        fn key(&mut self, k: &str) {
            if !self.first {
                self.out.push(',');
            }
            self.first = false;
            string(&mut self.out, k);
            self.out.push(':');
        }

        pub(crate) fn str(mut self, k: &str, v: &str) -> Object {
            self.key(k);
            string(&mut self.out, v);
            self
        }

        pub(crate) fn opt_str(self, k: &str, v: Option<&str>) -> Object {
            match v {
                Some(v) => self.str(k, v),
                None => self.raw(k, "null"),
            }
        }

        pub(crate) fn num(mut self, k: &str, v: impl std::fmt::Display) -> Object {
            self.key(k);
            #[expect(
                clippy::let_underscore_must_use,
                reason = "fmt::Write for String never returns Err"
            )]
            let _ = write!(self.out, "{v}");
            self
        }

        pub(crate) fn bool(self, k: &str, v: bool) -> Object {
            self.raw(k, if v { "true" } else { "false" })
        }

        /// A value that is JSON already.
        pub(crate) fn raw(mut self, k: &str, v: &str) -> Object {
            self.key(k);
            self.out.push_str(v);
            self
        }

        pub(crate) fn done(mut self) -> String {
            self.out.push('}');
            self.out
        }
    }

    /// An array of values that are JSON already.
    pub(crate) fn array<I: IntoIterator<Item = S>, S: AsRef<str>>(items: I) -> String {
        let mut out = String::from("[");
        for (i, item) in items.into_iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(item.as_ref());
        }
        out.push(']');
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn strings_are_escaped() {
            assert_eq!(
                quote("a\"b\\c\n</script>\u{1}"),
                r#""a\"b\\c\n\u003c/script>\u0001""#
            );
        }

        #[test]
        fn objects_and_arrays() {
            let o = Object::new()
                .str("id", "t1")
                .num("line", 5)
                .bool("ok", true)
                .opt_str("p", None)
                .done();
            assert_eq!(o, r#"{"id":"t1","line":5,"ok":true,"p":null}"#);
            assert_eq!(array(["1", "2"]), "[1,2]");
        }
    }
}
