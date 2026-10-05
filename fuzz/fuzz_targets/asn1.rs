//! ASN.1 BER and DER, as a world reads them from an LDAP stream or a
//! certificate the agent sends, and writes them back.
#![no_main]

use fictionet::stdlib::asn1::{
    Class, Decoder, Element, Error, Oid, Reader, Rules, StringKind, Tag, Writer, check_generalized_time,
    check_utc_time, element_len,
};
use libfuzzer_sys::fuzz_target;

const KINDS: [StringKind; 11] = [
    StringKind::Utf8,
    StringKind::Numeric,
    StringKind::Printable,
    StringKind::Teletex,
    StringKind::Videotex,
    StringKind::Ia5,
    StringKind::Graphic,
    StringKind::Visible,
    StringKind::General,
    StringKind::Universal,
    StringKind::Bmp,
];

/// Every element the decoder gives, and the error that ended the stream.
fn split(data: &[u8], rules: Rules, bytewise: bool) -> (Vec<Vec<u8>>, Option<Error>) {
    let mut d = Decoder::new(rules);
    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = if bytewise { data.chunks(1).collect() } else { vec![data] };
    for chunk in chunks {
        d.feed(chunk);
        while let Some(r) = d.next_element() {
            match r {
                Ok(e) => out.push(e),
                Err(e) => return (out, Some(e)),
            }
        }
    }
    (out, None)
}

/// Calls every value reader on `e` and its children.
fn walk(e: Element<'_>) {
    let _ = e.boolean();
    if let Ok(i) = e.integer() {
        let _ = (i.to_i64(), i.to_u64(), i.to_i128(), i.to_u128(), i.unsigned_bytes());
    }
    let _ = e.null();
    if let Ok(o) = e.oid() {
        assert_eq!(Oid::from_arcs(&o.arcs()).as_ref(), Ok(&o));
        assert_eq!(o.to_string().parse::<Oid>(), Ok(o));
    }
    let _ = e.octet_string();
    if let Ok(b) = e.bit_string() {
        let _ = b.bit(b.len().saturating_sub(1));
    }
    for kind in KINDS {
        if let Ok(s) = e.text(kind) {
            assert_eq!(kind.encode(&s).ok().as_deref(), e.string_bytes(kind).ok().as_deref());
        }
    }
    let _ = (e.utc_time(), e.generalized_time(), e.set_reader().is_ok(), e.set_of_reader().is_ok());
    if let Ok(r) = e.reader() {
        for child in r {
            let Ok(c) = child else { break };
            walk(c);
        }
    }
}

fn children(e: Element<'_>) -> Option<Vec<Element<'_>>> {
    e.reader().ok()?.collect::<Result<Vec<_>, _>>().ok()
}

fn copy_all(kids: Vec<Element<'_>>, w: &mut Writer) -> Option<()> {
    kids.into_iter().try_for_each(|k| copy(k, w))
}

/// Writes `e` again, if the writer has a method for every value in it.
fn copy(e: Element<'_>, w: &mut Writer) -> Option<()> {
    let t = e.tag();
    let mut ok = Some(());
    if t.class != Class::Universal {
        if t.constructed {
            let kids = children(e)?;
            w.constructed(t, |w| ok = copy_all(kids, w));
        } else {
            w.primitive(t, e.contents());
        }
        return ok;
    }
    match t.number {
        1 => w.boolean(e.boolean().ok()?),
        2 => w.integer_bytes(e.integer().ok()?.as_bytes()),
        3 => w.bit_string_value(&e.bit_string().ok()?),
        4 => w.octet_string(&e.octet_string().ok()?),
        5 => {
            e.null().ok()?;
            w.null();
        }
        6 => w.oid(&e.oid().ok()?),
        10 => w.enumerated(e.integer().ok()?.to_i64()?),
        16 => {
            let kids = children(e)?;
            w.sequence(|w| ok = copy_all(kids, w));
        }
        17 => {
            let kids = children(e)?;
            let mut tags: Vec<_> = kids.iter().map(|k| (k.tag().class, k.tag().number)).collect();
            tags.sort();
            let distinct = tags.windows(2).all(|p| p[0] != p[1]);
            if distinct && e.set_reader().is_ok() {
                w.set(|w| ok = copy_all(kids, w));
            } else if e.set_of_reader().is_ok() {
                w.set_of(|w| ok = copy_all(kids, w));
            } else {
                return None;
            }
        }
        23 => {
            let s = e.utc_time().ok()?;
            check_utc_time(s.as_bytes(), Rules::Der).ok()?;
            w.utc_time(&s);
        }
        24 => {
            let s = e.generalized_time().ok()?;
            check_generalized_time(s.as_bytes(), Rules::Der).ok()?;
            w.generalized_time(&s);
        }
        n => {
            let kind = StringKind::from_tag(Tag::universal(n))?;
            w.string_bytes(kind, &e.string_bytes(kind).ok()?);
        }
    }
    ok
}

fuzz_target!(|data: &[u8]| {
    // The stream, split two ways: all at once, and a byte at a time.
    for rules in [Rules::Ber, Rules::Der] {
        assert_eq!(split(data, rules, false), split(data, rules, true));
    }
    // DER is BER: what DER frames, BER frames the same.
    if let Ok(Some(n)) = element_len(data, Rules::Der) {
        assert_eq!(element_len(data, Rules::Ber), Ok(Some(n)));
    }
    for rules in [Rules::Ber, Rules::Der] {
        for e in Reader::new(data, rules) {
            let Ok(e) = e else { break };
            walk(e);
            // What `Writer::encoded` takes, it writes as is, and DER reads.
            let mut w = Writer::new();
            w.encoded(e.raw());
            if let Ok(out) = w.finish() {
                assert_eq!(out, e.raw());
                let mut r = Reader::new(&out, Rules::Der);
                walk(r.read().unwrap());
                assert!(r.is_empty());
            }
            let mut w = Writer::new();
            if copy(e, &mut w).is_none() {
                continue;
            }
            let out = match w.finish() {
                Ok(out) => out,
                Err(err) => {
                    assert_eq!(err, Error::TooLong);
                    continue;
                }
            };
            // DER has one encoding per value, so a copy is the same bytes.
            if rules == Rules::Der {
                assert_eq!(out, e.raw());
            }
            // What a writer writes reads under DER, and copies the same.
            let mut r = Reader::new(&out, Rules::Der);
            let back = r.read().unwrap();
            assert!(r.is_empty());
            let mut again = Writer::new();
            copy(back, &mut again).unwrap();
            assert_eq!(again.finish().unwrap(), out);
            // And `Writer::encoded` takes it back unchanged.
            let mut whole = Writer::new();
            whole.encoded(&out);
            assert_eq!(whole.finish().unwrap(), out);
        }
    }
});
