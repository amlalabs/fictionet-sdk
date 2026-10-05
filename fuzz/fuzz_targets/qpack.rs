//! QPACK encoder streams, decoder streams and field sections, as a world
//! playing an HTTP/3 server reads them.
#![no_main]

use fictionet::stdlib::qpack::{
    Decoder, DecoderInstruction, Encoder, EncoderInstruction, Representation, Section, huffman_decode, huffman_encode,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first byte splits the rest: an encoder stream, then a field section.
    let Some((&split, rest)) = data.split_first() else { return };
    let (stream, section) = rest.split_at(usize::from(split).min(rest.len()));

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
    let _ = whole.take_decoder_stream();

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

    // Any bytes as a decoder stream, read by an encoder that has inserted
    // two entries.
    let mut encoder = Encoder::new(4096, 16 << 10);
    encoder.set_capacity(4096).unwrap();
    encoder.insert(b"x-a", b"1").unwrap();
    encoder.insert(b"x-b", b"2").unwrap();
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
