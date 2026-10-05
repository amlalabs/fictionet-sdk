//! XML documents, as a world serving SOAP or XMPP reads them, and the
//! writer given whatever text the agent sent.
#![no_main]
#![allow(deprecated)] // This target also checks the compatibility API.

use std::sync::Arc;

use fictionet::stdlib::xml::{Attribute, Error, ErrorKind, Event, Name, Parser, Start, Writer, XMLNS_NAMESPACE, parse};
use libfuzzer_sys::fuzz_target;
use fictionet::stdlib::codec::contract;

/// Feeds `chunks` in order, then finishes: the events and the error, if
/// any.
fn run<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> (Vec<Event>, Option<Error>) {
    let mut p = Parser::new();
    let mut events = Vec::new();
    let drain = |p: &mut Parser, events: &mut Vec<Event>| -> Option<Error> {
        while let Some(ev) = p.next_event() {
            match ev {
                Ok(e) => events.push(e),
                Err(e) => return Some(e),
            }
        }
        None
    };
    for c in chunks {
        p.feed(c);
        if let Some(e) = drain(&mut p, &mut events) {
            return (events, Some(e));
        }
    }
    p.finish();
    let err = drain(&mut p, &mut events);
    assert_eq!(err.is_none(), p.is_done());
    (events, err)
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode(fictionet::stdlib::xml::Frames::new, data);
    contract::check_wire::<fictionet::stdlib::xml::Frame>(data);
    contract::check_wire_value(&fictionet::stdlib::xml::Frame { data: data.to_vec() });
    // The document, split two ways: all at once, and a byte at a time.
    let whole = run([data]);
    let bytewise = run(data.chunks(1));
    assert_eq!(whole, bytewise);

    // A document read can be written, and reads back the same.
    if let (events, None) = &whole {
        let mut w = Writer::new();
        let mut written = true;
        for e in events {
            match w.event(e) {
                Ok(()) => {}
                // Escaping can grow a document past the size limit.
                Err(ErrorKind::TooLarge) => {
                    written = false;
                    break;
                }
                Err(e) => panic!("{e}"),
            }
        }
        if written {
            let out = w.finish().unwrap();
            assert_eq!(&parse(out.as_bytes()).unwrap(), events);
        }
    }

    // Whatever a writer accepts, a parser reads.
    let s = String::from_utf8_lossy(data);
    let mut w = Writer::new();
    let _ = w.comment(&s);
    let _ = w.start("r", &[("v", &s), ("xmlns:q", &s)]);
    let _ = w.start(&s, &[(&s, "x")]);
    let _ = w.text(&s);
    let _ = w.cdata(&s);
    let _ = w.pi(&s, &s);
    // A writer keeps room for its end tags, so closing never fails.
    while w.depth() > 0 {
        w.end().unwrap();
    }
    let _ = w.text(&s);
    if let Ok(out) = w.finish() {
        assert!(parse(out.as_bytes()).is_ok());
    }

    // Events built from the input, names and namespaces chosen from small
    // sets so they collide: what a writer accepts reads back with the same
    // tags, namespaces included.
    events(data);
});

fn events(data: &[u8]) {
    let uris = [None, Some(Arc::<str>::from("urn:a")), Some(Arc::<str>::from("urn:b"))];
    let prefixes = [None, Some("p"), Some("q")];
    let name = |b: u8| Name {
        prefix: prefixes[usize::from(b % 3)].map(String::from),
        local: ["a", "b"][usize::from(b / 3 % 2)].to_string(),
        namespace: uris[usize::from(b / 6 % 3)].clone(),
    };
    let xmlns = Some(Arc::<str>::from(XMLNS_NAMESPACE));
    let mut w = Writer::new();
    let mut tags = Vec::new();
    let mut open: Vec<Name> = Vec::new();
    for op in data.chunks(3) {
        let [kind, a, b] = [op[0], *op.get(1).unwrap_or(&0), *op.get(2).unwrap_or(&0)];
        let event = match kind % 4 {
            0 | 1 => {
                let mut attributes = Vec::new();
                if a & 1 != 0 {
                    // A declaration of a prefix, or of the default namespace.
                    let local = ["xmlns", "p", "q"][usize::from(a / 2 % 3)];
                    let prefix = (local != "xmlns").then(|| "xmlns".to_string());
                    let value = ["", "urn:a", "urn:b"][usize::from(a / 6 % 3)].to_string();
                    attributes.push(Attribute {
                        name: Name { prefix, local: local.into(), namespace: xmlns.clone() },
                        value,
                    });
                }
                if a & 64 != 0 {
                    attributes.push(Attribute { name: name(b / 2), value: "v".into() });
                }
                Event::Start(Start { name: name(b), attributes })
            }
            2 => match open.last() {
                Some(n) if a % 4 != 0 => Event::End(n.clone()),
                _ => Event::End(name(b)),
            },
            _ => Event::Text("t".into()),
        };
        if w.event(&event).is_ok() {
            match &event {
                Event::Start(s) => {
                    open.push(s.name.clone());
                    tags.push(event.clone());
                }
                Event::End(_) => {
                    open.pop();
                    tags.push(event.clone());
                }
                _ => {}
            }
        }
    }
    while let Some(n) = open.pop() {
        w.event(&Event::End(n.clone())).unwrap();
        tags.push(Event::End(n));
    }
    if let Ok(out) = w.finish() {
        let read = parse(out.as_bytes()).unwrap();
        let read: Vec<Event> = read.into_iter().filter(|e| matches!(e, Event::Start(_) | Event::End(_))).collect();
        assert_eq!(read, tags, "{out}");
    }
}
