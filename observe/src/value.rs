use crate::json::Parser;

/// One whole value of a reply: its chunks joined.
#[derive(Debug)]
pub struct Value {
    /// The request this value answers.
    pub id: u32,
    /// The original bytes, without normalization or interpretation.
    pub bytes: Vec<u8>,
    /// The value is binary rather than JSON.
    pub binary: bool,
    /// No more replies come for this id.
    pub end: bool,
}

/// An observer event or error, inspected without changing the raw value.
#[derive(Debug, PartialEq, Eq)]
pub enum Envelope<'a> {
    /// A stream event with a string name and any JSON data.
    Event {
        /// The decoded event name.
        name: String,
        /// The exact JSON text of the data value, borrowed from the reply.
        data: &'a str,
    },
    /// The world's decoded error message.
    Error(String),
}

impl Value {
    /// Inspects a JSON event (`event` and `data`) or error (`error`).
    /// Field order, whitespace and string escapes do not affect inspection.
    /// Unknown fields are ignored. Names and errors must be strings; event
    /// data may be any JSON value. Duplicate envelope fields and objects
    /// mixing an error with event fields are not recognized.
    ///
    /// Recognition does not depend on size, element count or nesting depth.
    /// Data and unknown fields are validated without building a JSON tree.
    /// Returns `None` for binary values, other replies, invalid envelopes,
    /// invalid JSON or invalid UTF-8. The original bytes and flags are
    /// unchanged, including when inspection fails.
    pub fn envelope(&self) -> Option<Envelope<'_>> {
        if self.binary {
            return None;
        }
        let text = std::str::from_utf8(&self.bytes).ok()?;
        let mut p = Parser {
            b: text.as_bytes(),
            i: 0,
        };
        p.ws();
        p.eat(b'{')?;
        let (mut event, mut data, mut error) = (None, None, None);
        loop {
            p.ws();
            let key = p.string(true)?;
            p.ws();
            p.eat(b':')?;
            p.ws();
            match key.as_str() {
                "event" | "error" => {
                    let slot = if key == "event" {
                        &mut event
                    } else {
                        &mut error
                    };
                    if slot.replace(p.string(true)?).is_some() {
                        return None;
                    }
                }
                "data" => {
                    let start = p.i;
                    p.skip_value()?;
                    if data.replace(&text[start..p.i]).is_some() {
                        return None;
                    }
                }
                _ => p.skip_value()?,
            }
            p.ws();
            if p.eat(b'}').is_some() {
                break;
            }
            p.eat(b',')?;
        }
        p.ws();
        if p.i != text.len() {
            return None;
        }
        match (event, data, error) {
            (Some(name), Some(data), None) => Some(Envelope::Event { name, data }),
            (None, None, Some(error)) => Some(Envelope::Error(error)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(bytes: &[u8]) -> Value {
        Value {
            id: 7,
            bytes: bytes.to_vec(),
            binary: false,
            end: true,
        }
    }

    #[test]
    fn envelopes_ignore_json_formatting_and_keep_raw_values() {
        for (bytes, data) in [
            (
                br#"{"event":"ended","data":{"n":1}}"#.as_slice(),
                r#"{"n":1}"#,
            ),
            (
                b" \n{ \"data\": { \"n\": 1 }, \"extra\": true, \"event\": \"ended\" }\t",
                r#"{ "n": 1 }"#,
            ),
            (
                br#"{"d\u0061ta":{"n":1},"ev\u0065nt":"end\u0065d"}"#,
                r#"{"n":1}"#,
            ),
        ] {
            let value = value(bytes);
            assert_eq!(
                value.envelope(),
                Some(Envelope::Event {
                    name: "ended".into(),
                    data,
                })
            );
            assert_eq!(value.bytes, bytes);
            assert_eq!(value.id, 7);
            assert!(!value.binary);
            assert!(value.end);
        }
        for bytes in [
            br#"{"error":"not found"}"#.as_slice(),
            b" \n{ \"extra\": 1, \"err\\u006fr\": \"not found\" }\n",
        ] {
            assert_eq!(
                value(bytes).envelope(),
                Some(Envelope::Error("not found".into()))
            );
        }
        assert!(matches!(
            value(br#"{"event":"custom","data":null}"#).envelope(),
            Some(Envelope::Event { data: "null", .. })
        ));
    }

    #[test]
    fn envelopes_validate_data_and_unknown_fields() {
        for data in [
            "null",
            "true",
            "false",
            "0",
            "-0",
            "1.25e+1234567890",
            r#""\"\\\/\b\f\n\r\t\u0000\uD83D\uDE00é""#,
            r#"[0, {"x": [true, false, null, [], {}]}, "text"]"#,
            r#"{ "x": 1, "x": 2 }"#,
        ] {
            let bytes = format!(r#"{{"extra":{data},"event":"custom","data": {data} }}"#);
            assert_eq!(
                value(bytes.as_bytes()).envelope(),
                Some(Envelope::Event {
                    name: "custom".into(),
                    data,
                })
            );
        }
        assert_eq!(
            value(br#"{"err\u006fr":"\uD83D\uDE00\n"}"#).envelope(),
            Some(Envelope::Error("😀\n".into())),
        );
        for data in [
            "01",
            "-01",
            "+1",
            ".1",
            "1.",
            "1e",
            "1e+",
            "--1",
            "NaN",
            "True",
            "nul",
            "[1,]",
            "[,1]",
            "[1 2]",
            "[}",
            "{]",
            r#"{"x" 1}"#,
            r#"{"x":1,}"#,
            r#"{1:2}"#,
            r#"{"x":}"#,
            r#""\x00""#,
            r#""\u+123""#,
            r#""\uD83D""#,
            r#""\uDE00""#,
            r#""\uD83D\u0041""#,
            "\"raw\nline\"",
        ] {
            for bytes in [
                format!(r#"{{"event":"custom","data":{data}}}"#),
                format!(r#"{{"error":"x","extra":{data}}}"#),
            ] {
                assert_eq!(value(bytes.as_bytes()).envelope(), None, "{bytes}");
            }
        }
    }

    #[test]
    fn envelopes_recognize_large_data_without_copying_it() {
        let data = format!("[{}0]", "0,      ".repeat(150_000));
        assert!(data.len() > 1024 * 1024);
        let bytes = format!(r#"{{"event":"snapshot","data":{data}}}"#);
        let value = value(bytes.as_bytes());
        let Some(Envelope::Event { name, data: raw }) = value.envelope() else {
            panic!("large snapshot was not recognized");
        };
        assert_eq!(name, "snapshot");
        assert_eq!(raw, data);
        assert!(value.bytes.as_ptr_range().contains(&raw.as_ptr()));
    }

    #[test]
    fn envelopes_handle_deep_data_without_recursion() {
        let data = format!("{}0{}", "[".repeat(200_000), "]".repeat(200_000));
        let bytes = format!(r#"{{"data":{data},"event":"snapshot"}}"#);
        assert_eq!(
            value(bytes.as_bytes()).envelope(),
            Some(Envelope::Event {
                name: "snapshot".into(),
                data: &data,
            })
        );
        let bytes = format!(r#"{{"data":{data},"extra":[{data},],"event":"snapshot"}}"#);
        assert_eq!(value(bytes.as_bytes()).envelope(), None);
    }

    #[test]
    fn invalid_envelopes_and_binary_values_are_not_inspected() {
        for bytes in [
            br#"{"event":"ended","data":}"#.as_slice(),
            br#"{"error":"truncated""#,
            br#"{"event":"ended","data":{}} false"#,
            br#"{"event":"ended"}"#,
            br#"{"event":false,"data":{}}"#,
            br#"{"error":null}"#,
            br#"{"event":"ended","data":{},"error":"x"}"#,
            br#"{"event":"ended","event":"node","data":{}}"#,
            br#"{"event":"ended","data":{},"d\u0061ta":null}"#,
            br#"{"error":"x","error":"y"}"#,
            br#"{"error":"x","data":null}"#,
            br#"{"event":"ended","data":{},}"#,
            br#"{"event":"\uD800","data":{}}"#,
            br#"{"error":"\uDC00"}"#,
            br#"{"error":"x","\uD800":0}"#,
            br#"{"nested":{"event":"ended","data":{}}}"#,
            br#"[{"error":"x"}]"#,
            b"{\"error\":\"\xff\"}",
            b"{\"error\":\"x\",\"extra\":\"\xff\"}",
        ] {
            assert_eq!(value(bytes).envelope(), None, "{bytes:?}");
        }
        let mut binary = value(br#"{"error":"x"}"#);
        binary.binary = true;
        assert_eq!(binary.envelope(), None);
        assert_eq!(binary.bytes, br#"{"error":"x"}"#);
    }
}
