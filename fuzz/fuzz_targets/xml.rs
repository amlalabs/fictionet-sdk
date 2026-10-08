//! XML documents, as a world serving SOAP or XMPP reads them, and the
//! writer given whatever text the agent sent.
#![no_main]

use std::sync::Arc;

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::test_support::contract;

use fictionet::stdlib::test_support::decode_all;
use fictionet::stdlib::xml::{
    Attribute, Builder, Document, ErrorKind, Event, Events, Name, Start, XMLNS_NAMESPACE,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(
        Events::new,
        data,
        2 * (fictionet::stdlib::xml::MAX_DOCUMENT + 1),
    );
    contract::check_wire::<fictionet::stdlib::xml::Document>(data);
    contract::check_wire_value(&fictionet::stdlib::xml::Document {
        data: data.to_vec(),
    });
    let whole = decode_all(Events::new, data);

    // A document read can be written, and reads back the same.
    if let (events, None) = &whole
        && !events.is_empty()
    {
        let mut w = Builder::new();
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
            let out = w.build().unwrap();
            let bytes = out.to_bytes().unwrap();
            assert_eq!(decode_all(Events::new, &bytes), (events.clone(), None));
        }
    }

    // Whatever a writer accepts, a parser reads.
    let s = String::from_utf8_lossy(data);
    let mut w = Builder::new();
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
    if let Ok(out) = w.build() {
        contract::check_wire_value(&out);
        assert!(Document::parse(&out.to_bytes().unwrap()).is_ok());
    }

    // Events built from the input, names and namespaces chosen from small
    // sets so they collide: what a writer accepts reads back with the same
    // tags, namespaces included.
    events(data);
});

fn events(data: &[u8]) {
    let uris = [
        None,
        Some(Arc::<str>::from("urn:a")),
        Some(Arc::<str>::from("urn:b")),
    ];
    let prefixes = [None, Some("p"), Some("q")];
    let name = |b: u8| Name {
        prefix: prefixes[usize::from(b % 3)].map(String::from),
        local: ["a", "b"][usize::from(b / 3 % 2)].to_string(),
        namespace: uris[usize::from(b / 6 % 3)].clone(),
    };
    let xmlns = Some(Arc::<str>::from(XMLNS_NAMESPACE));
    let mut w = Builder::new();
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
                        name: Name {
                            prefix,
                            local: local.into(),
                            namespace: xmlns.clone(),
                        },
                        value,
                    });
                }
                if a & 64 != 0 {
                    attributes.push(Attribute {
                        name: name(b / 2),
                        value: "v".into(),
                    });
                }
                Event::Start(Start {
                    name: name(b),
                    attributes,
                })
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
    if let Ok(out) = w.build() {
        let bytes = out.to_bytes().unwrap();
        let (read, error) = decode_all(Events::new, &bytes);
        assert_eq!(error, None);
        let read: Vec<Event> = read
            .into_iter()
            .filter(|e| matches!(e, Event::Start(_) | Event::End(_)))
            .collect();
        assert_eq!(read, tags, "{out:?}");
    }
}
