//! Bounded buffer proofs for TLS and STARTTLS. These call the real Chunk
//! methods from layer/carrier.rs:74-91. TLS advances partially admitted
//! input at services/tls/layer.rs:371-391 and writes at :456-462. A switch
//! transfers the remaining owned chunk, not its consumed prefix.
//!
//! Four arbitrary bytes and two arbitrary partial admissions include zero,
//! full consumption, and every split. Cryptography and unbounded allocation
//! are outside this proof. The negative harnesses replace one real method
//! with its broken version, leaving the property and inputs unchanged.

use fictionet::stdlib::layer::Chunk;

fn partial_admissions() {
    let bytes: [u8; 4] = kani::any();
    let mut chunk = Chunk::unpaid(bytes.to_vec());
    let mut consumed = 0;
    for _ in 0..2 {
        let accepted: usize = kani::any();
        kani::assume(accepted <= 4 - consumed);
        chunk.advance(accepted);
        consumed += accepted;
        assert_eq!(chunk.len(), 4 - consumed, "only unread bytes remain");
        for i in 0..4 {
            if i < chunk.len() {
                assert_eq!(chunk[i], bytes[consumed + i], "the suffix stays ordered");
            }
        }
    }
}

fn switch_suffix() {
    let bytes: [u8; 4] = kani::any();
    let boundary: usize = kani::any();
    kani::assume(boundary <= 4);
    let mut secure = Chunk::unpaid(bytes.to_vec());
    let plain = secure.split_to(boundary);
    assert_eq!(plain.len(), boundary, "plaintext ends at the switch");
    assert_eq!(
        secure.len(),
        4 - boundary,
        "the secure suffix excludes plaintext"
    );
    for i in 0..4 {
        if i < boundary {
            assert_eq!(plain[i], bytes[i]);
        } else {
            assert_eq!(secure[i - boundary], bytes[i]);
        }
    }
}

#[kani::proof]
#[kani::unwind(6)]
fn tls_partial_admissions_preserve_the_suffix() {
    partial_admissions();
}

#[kani::proof]
#[kani::unwind(6)]
fn starttls_split_excludes_the_plaintext_prefix() {
    switch_suffix();
}

fn keep_cursor(_: &mut Chunk, _: usize) {}

fn replay_prefix(chunk: &mut Chunk, n: usize) -> Chunk {
    Chunk::unpaid(chunk[..n].to_vec())
}

#[kani::proof]
#[kani::unwind(6)]
#[kani::stub(Chunk::advance, keep_cursor)]
fn without_consuming_tls_input() {
    partial_admissions();
}

#[kani::proof]
#[kani::unwind(6)]
#[kani::stub(Chunk::split_to, replay_prefix)]
fn without_excluding_the_plaintext_prefix() {
    switch_suffix();
}
