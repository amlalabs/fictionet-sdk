//! XML documents, as a world serving SOAP or XMPP reads them, and the
//! writer given whatever text the agent sent.
#![no_main]

use fictionet::stdlib::xml::{Error, ErrorKind, Event, Parser, Writer, parse};
use libfuzzer_sys::fuzz_target;

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
    while w.depth() > 0 {
        w.end().unwrap();
    }
    let _ = w.text(&s);
    if let Ok(out) = w.finish() {
        assert!(parse(out.as_bytes()).is_ok());
    }
});
