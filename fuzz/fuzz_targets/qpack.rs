//! QPACK encoder streams, decoder streams and field sections, as a world
//! playing an HTTP/3 server reads them.
#![no_main]

use fictionet::stdlib::qpack::{
    Decoder, DecoderInstruction, Encoder, EncoderInstruction, Field, MAX_STRING, Representation, Section,
    huffman_decode, huffman_encode,
};
use libfuzzer_sys::fuzz_target;

/// Every byte of a decoder stream must read as whole instructions.
fn assert_whole_instructions(mut b: &[u8]) {
    while !b.is_empty() {
        let Ok(Some((_, used))) = DecoderInstruction::parse(b) else { panic!("bad decoder stream {b:?}") };
        b = &b[used..];
    }
}

fuzz_target!(|data: &[u8]| {
    // The first byte splits the rest, in proportion: an encoder stream, then
    // field sections.
    let Some((&split, rest)) = data.split_first() else { return };
    let (stream, section) = rest.split_at(usize::from(split) * rest.len() / 255);

    // The encoder stream, split two ways: all at once, and a byte at a time.
    let mut whole = Decoder::new(4096, 4, 16 << 10);
    let r1 = whole.feed_encoder_stream(stream);
    let mut bytewise = Decoder::new(4096, 4, 16 << 10);
    let mut r2 = Ok(());
    for b in stream {
        r2 = bytewise.feed_encoder_stream(std::slice::from_ref(b));
        if r2.is_err() {
            break;
        }
    }
    assert_eq!(r1, r2);
    assert_eq!(whole.table(), bytewise.table());

    // The field section against that table. Fields read can be written
    // again, and read back the same.
    if let Ok(Section::Fields(fields)) = whole.decode_section(0, section) {
        let mut encoder = Encoder::new(0, 16 << 10);
        let bytes = encoder.encode_section(0, &fields).unwrap();
        let back = Decoder::new(0, 0, 16 << 10).decode_section(0, &bytes).unwrap();
        assert_eq!(back, Section::Fields(fields));
    }
    let _ = whole.unblocked();
    assert_whole_instructions(&whole.take_decoder_stream());

    // In steps: half the encoder stream, then the sections split in four
    // over two streams, which may block, then the other half, then the
    // released sections taken out one at a time. Each stream's sections
    // come out in the order they went in, and the decoder stream reads.
    let mut d = Decoder::new(4096, 2, 16 << 10);
    let (early, late) = stream.split_at(stream.len() / 2);
    if d.feed_encoder_stream(early).is_ok() {
        let mut sent: [Vec<usize>; 2] = [Vec::new(), Vec::new()];
        let mut ok = true;
        for (i, piece) in section.chunks(section.len().div_ceil(4).max(1)).enumerate() {
            match d.decode_section((i % 2) as u64 * 4, piece) {
                Ok(Section::Blocked) => sent[i % 2].push(i),
                Ok(Section::Fields(_)) => assert!(sent[i % 2].is_empty(), "a section passed one held on its stream"),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && d.feed_encoder_stream(late).is_ok() {
            let mut taken = [0usize; 2];
            while let Some((s, _)) = d.next_unblocked() {
                let k = usize::try_from(s / 4).unwrap();
                taken[k] += 1;
                assert!(taken[k] <= sent[k].len());
            }
            assert_eq!(d.blocked_streams(), (0..2).filter(|&k| taken[k] < sent[k].len()).count());
        }
        let _ = d.cancel_stream(4);
        assert_whole_instructions(&d.take_decoder_stream());
    }

    // Any bytes as one item of each kind.
    if let Ok((rep, _)) = Representation::parse(data) {
        let bytes = rep.to_bytes();
        assert_eq!(Representation::parse(&bytes), Ok((rep, bytes.len())));
    }
    if let Ok(Some((ins, _))) = EncoderInstruction::parse(data) {
        let bytes = ins.to_bytes();
        assert_eq!(EncoderInstruction::parse(&bytes), Ok(Some((ins, bytes.len()))));
    }
    if let Ok(Some((ins, _))) = DecoderInstruction::parse(data) {
        let bytes = ins.to_bytes();
        assert_eq!(DecoderInstruction::parse(&bytes), Ok(Some((ins, bytes.len()))));
    }
    if let Ok(s) = huffman_decode(data) {
        assert_eq!(huffman_decode(&huffman_encode(&s)), Ok(s));
    }
    // Any bytes, Huffman-coded and read back, cut as the writers cut them.
    let cut = &data[..data.len().min(MAX_STRING)];
    assert_eq!(huffman_decode(&huffman_encode(data)).as_deref(), Ok(cut));
    // Any bytes as a field value, written and read back.
    let rep = Representation::LiteralName { never_index: false, name: b"x".to_vec(), value: cut.to_vec() };
    assert_eq!(Representation::parse(&rep.to_bytes()).map(|(r, _)| r), Ok(rep));

    // Any bytes as a decoder stream, read by an encoder that has inserted
    // two entries, had them acknowledged, and sent sections that use them
    // on streams 0 and 4, so acknowledgments have sections to match.
    let mut encoder = Encoder::new(4096, 16 << 10);
    encoder.set_capacity(4096).unwrap();
    encoder.insert(b"x-a", b"1").unwrap();
    encoder.insert(b"x-b", b"2").unwrap();
    encoder.feed_decoder_stream(&[0x02]).unwrap();
    for stream in [0, 4, 4] {
        encoder.encode_section(stream, &[Field::new("x-a", "1"), Field::new("x-b", "2")]).unwrap();
    }
    let mut e2 = encoder.clone();
    let r1 = encoder.feed_decoder_stream(data);
    let mut r2 = Ok(());
    for b in data {
        r2 = e2.feed_decoder_stream(std::slice::from_ref(b));
        if r2.is_err() {
            break;
        }
    }
    assert_eq!(r1, r2);
    assert_eq!(encoder.known_received_count(), e2.known_received_count());
});
