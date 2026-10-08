//! ASN.1 BER and DER, as a world reads them from an LDAP stream or a
//! certificate the agent sends, and writes them back.
#![no_main]

use fictionet::stdlib::asn1::harness::check;
use fictionet::stdlib::asn1::{Frame, MAX_INPUT, Reader, Rules, StringKind, Tag, Writer};
use fictionet::stdlib::test_support::contract;
use libfuzzer_sys::fuzz_target;

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
            3 => w.implicit(Tag::context(u32::from(arg % 4)), |w| {
                script(ops, w, level + 1)
            }),
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
            11 => w.constructed(Tag::application(u32::from(arg % 4)), |w| {
                script(ops, w, level + 1)
            }),
            _ => return,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    contract::check_wire_value(&Frame(data.get(..MAX_INPUT + 1).unwrap_or(data).to_vec()));

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
});
