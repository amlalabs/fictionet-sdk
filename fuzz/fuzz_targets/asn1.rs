//! ASN.1 BER and DER, as a world reads them from an LDAP stream or a
//! certificate the agent sends, and writes them back.
#![no_main]

use fictionet::stdlib::asn1::{
    Class, Decoder, Element, Elements, Error, Frame, MAX_INPUT, Oid, Reader, Rules, StringKind, Tag, Writer,
    check_generalized_time, check_utc_time, element_len,
};
use fictionet::stdlib::codec::contract;
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
    for mut chunk in chunks {
        // Feed, take out, and feed the rest, as a world's read loop does.
        loop {
            let n = d.feed(chunk);
            chunk = &chunk[n..];
            assert!(d.buffered() <= MAX_INPUT);
            while let Some(r) = d.next_element() {
                match r {
                    Ok(e) => out.push(e),
                    Err(e) => return (out, Some(e)),
                }
            }
            if chunk.is_empty() {
                break;
            }
            assert!(n > 0, "a full decoder must give an element or an error");
        }
    }
    (out, None)
}

/// Runs writer calls named by the bytes of `ops`, from the front, until
/// they run out or say to stop. Closures get scripts of their own, some of
/// which write nothing or several elements, replace the writer they are
/// given, or take it out.
fn script(ops: &mut &[u8], w: &mut Writer, level: usize) {
    while let Some((&op, rest)) = ops.split_first() {
        *ops = rest;
        let arg = ops.first().copied().unwrap_or(0);
        if level > 40 {
            return;
        }
        match op % 13 {
            0 => w.null(),
            1 => {
                let n = usize::from(arg % 20).min(ops.len());
                w.integer_unsigned(&ops[..n]);
                *ops = &ops[n..];
            }
            2 => w.explicit(u32::from(arg % 4), |w| script(ops, w, level + 1)),
            3 => w.implicit(Tag::context(u32::from(arg % 4)), |w| script(ops, w, level + 1)),
            4 => w.sequence(|w| script(ops, w, level + 1)),
            5 => w.set(|w| script(ops, w, level + 1)),
            6 => w.set_of(|w| script(ops, w, level + 1)),
            7 => {
                let mut other = Writer::new();
                script(ops, &mut other, level + 1);
                *w = other;
            }
            8 => drop(std::mem::take(w)),
            9 => {
                let s: String = ops.iter().take(8).map(|&b| char::from(b)).collect();
                w.text(StringKind::Bmp, &s);
            }
            10 => w.bit_string(&ops[..ops.len().min(3)], arg % 9),
            11 => w.constructed(Tag::application(u32::from(arg % 4)), |w| script(ops, w, level + 1)),
            _ => return,
        }
    }
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
    contract::check_decode(|| Elements::new(Rules::Ber), data);
    contract::check_decode(|| Elements::new(Rules::Der), data);
    contract::check_wire::<Frame>(data);
    contract::check_wire_value(&Frame(data.get(..MAX_INPUT + 1).unwrap_or(data).to_vec()));

    // The stream, split two ways: all at once, and a byte at a time.
    for rules in [Rules::Ber, Rules::Der] {
        assert_eq!(split(data, rules, false), split(data, rules, true));
    }
    // Fed again and again without taking anything out, a decoder holds
    // no more than MAX_INPUT bytes.
    let mut d = Decoder::new(Rules::Ber);
    for _ in 0..4 {
        let _ = d.feed(data);
        assert!(d.buffered() <= MAX_INPUT);
    }
    // Whatever a script of writer calls does, the writer does not panic,
    // and what it finishes with reads under DER, element by element, with
    // every value checked.
    let mut w = Writer::new();
    script(&mut &data[..], &mut w, 0);
    if let Ok(out) = w.finish() {
        for e in Reader::new(&out, Rules::Der) {
            let e = e.unwrap();
            let mut again = Writer::new();
            again.encoded(e.raw());
            assert_eq!(again.finish().unwrap(), e.raw());
        }
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
