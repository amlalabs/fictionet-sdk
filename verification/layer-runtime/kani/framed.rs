//! `Framed` (src/stdlib/layer/framed.rs:41-213) over two decoders: `Units`,
//! which keeps the `Decode` contract with a capacity of three, the
//! smallest at which the buffer can grow past its limit; and `Steps`,
//! whose every step the solver chooses. The real `Stream`, `Buffer`,
//! `Budget`, `Charge`, `Chunk` and `Driver` run underneath.
//!
//! | Harness | Property |
//! | --- | --- |
//! | `the_buffer_is_charged_before_bytes_are_taken_A_B` | two pushes of `A` and `B` bytes (each 1 to 3, the bytes any), with up to two items taken between: after each, `Framed`'s charge covers the decoder's input storage and held state and is all the budget holds, and what the push hands back (`Partial` or `Blocked`) is exactly the bytes it did not take |
//! | `every_charge_comes_back_*` | under a budget of 0, 6, 8, 13 or 14 bytes, two bytes from the peer and a value from above, then two of an end, a reset, an end from above, a taken event, a taken write and its delivery, in ten orders: a budget refusal takes no byte, the budget holds exactly what `Framed` and the chunk in flight are charged, never past its limit, a written value is charged at least its length, and nothing once they are dropped |
//! | `units_come_up_in_order_and_the_rest_is_handed_back_odd_first_cut_3` | a three-byte unit (its payload any) and then a one-byte one, in two pushes, then the end: each unit comes up once, in order, then `Ended`. The cuts that make a push hand bytes back, and a trailing partial unit, did not fit in 10 GiB with the bytes handed back offered again; `Partial` is covered by the line above, the reassembly after it by `StreamRunner.tla` (`InputKept`) and the unit test `every_cut_of_the_input_gets_every_frame_back_in_order` |
//! | `a_decoder_failure_comes_up_once_then_ended` | against any decoder items, ends, needs and failures, through any three of input, end, reset and taken events, then three more taken events: no item after a failure; a failure comes up once and `Ended` right after it; nothing after `Ended`; once either came up, input is over, and input offered after its end is refused as `Closed` and changes nothing |

extern crate alloc;

use super::super::{BoundedDecode, BoundedWire, Framed, FramedError, Owned};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use fictionet::Entropy;
use fictionet::stdlib::codec::{Decode, Fail, Step, Wire};
use fictionet::stdlib::layer::{
    Admit, Budget, Chunk, Driver, Layer, MessageCommand, MessageEvent, StreamCommand, StreamEvent,
};
use fictionet::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bad;
impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bad")
    }
}
impl core::error::Error for Bad {}

/// What the layer above writes: one length byte and its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Blob(Vec<u8>);
impl Wire for Blob {
    type ParseError = Bad;
    type WriteError = Bad;
    fn parse(b: &[u8]) -> Result<Self, Bad> {
        match b.split_first() {
            Some((&n, rest)) if usize::from(n) == rest.len() => Ok(Blob(rest.to_vec())),
            _ => Err(Bad),
        }
    }
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Bad> {
        let n = u8::try_from(self.0.len()).map_err(|_| Bad)?;
        out.push(n);
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

/// A decoder with a capacity of four whose every step the solver chooses:
/// any item, the end, a need for more, or a failure. It keeps no contract
/// (an item may consume any part of the input, a need may come with a full
/// buffer), so what `Framed` promises against it holds for every decoder
/// whose steps are among these. Skips are left out: they loop inside
/// `Stream::next`, which the codec proofs cover, and never reach `Framed`.
struct Steps;
impl Decode for Steps {
    type Item = u8;
    type Error = Bad;
    const NAME: &'static str = "steps";
    fn capacity(&self) -> usize {
        4
    }
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<u8>, Bad> {
        let n: usize = kani::any();
        kani::assume(n <= input.len());
        Ok(match kani::any::<u8>() {
            0 => return Err(Bad),
            1 => Step::Item(kani::any(), n),
            2 => Step::End,
            _ => Step::Need,
        })
    }
}

/// A decoder that keeps the `Decode` contract with a capacity of three: an
/// even first byte is a one-byte unit, an odd one starts a three-byte
/// unit. It frames like `Frames<Blob>` without building a value per
/// unit, so the solver spends its effort on the buffer and the charges.
struct Units;
impl Decode for Units {
    type Item = u8;
    type Error = Bad;
    const NAME: &'static str = "units";
    fn capacity(&self) -> usize {
        3
    }
    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<u8>, Bad> {
        Ok(match input.first() {
            None => Step::Need,
            Some(&b) if b % 2 == 0 => Step::Item(b, 1),
            Some(&b) if input.len() >= 3 => Step::Item(b, 3),
            Some(_) => Step::Need,
        })
    }
}

impl BoundedDecode for Units {
    fn allocation_bound(&self) -> usize {
        0
    }
}
impl BoundedDecode for Steps {
    fn allocation_bound(&self) -> usize {
        0
    }
}
impl BoundedWire for Blob {
    fn write_bounded(&self, out: &mut super::super::BoundedWriter<'_>) -> Result<(), Bad> {
        let n = u8::try_from(self.0.len()).map_err(|_| Bad)?;
        out.push(n);
        out.extend_from_slice(&self.0);
        Ok(())
    }

    fn write_bound(&self) -> Result<usize, Bad> {
        u8::try_from(self.0.len()).map_err(|_| Bad)?;
        Ok(1 + self.0.len())
    }
}

struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill_random(&self, out: &mut [u8]) {
        out.fill(0);
    }
}

fn driver<D: BoundedDecode>(decoder: D, budget: &Budget) -> Driver<Framed<D, Blob>>
where
    D::Error: Clone,
{
    Driver::new(
        Framed::new(decoder),
        Arc::new(NoEntropy),
        budget.clone(),
        Instant::ZERO,
    )
}

/// What `Framed` holds as charged for its buffer, by its own fields.
fn buffer_charge<D: Decode>(f: &Framed<D, Blob>) -> usize {
    f.charge.as_ref().map_or(0, |c| c.bytes())
}

/// What one event says, without its payload.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    Item,
    Failure,
    End,
}

fn seen<T, E>(event: &MessageEvent<Result<T, E>>) -> Seen {
    match event {
        MessageEvent::Message(Ok(_)) => Seen::Item,
        MessageEvent::Message(Err(_)) => Seen::Failure,
        MessageEvent::Ended => Seen::End,
    }
}

/// A chunk of exactly `N` symbolic bytes. Separate fixed lengths keep
/// allocation sizes concrete while covering every byte value.
fn fixed<const N: usize>() -> Chunk {
    Chunk::new(kani::any::<[u8; N]>().to_vec())
}

/// What a push of `offered` hands back is exactly the bytes it did not take.
fn suffix_kept(offered: &[u8], admit: Admit<StreamEvent>) {
    match admit {
        Admit::Taken => {}
        Admit::Partial(StreamEvent::Data(rest)) => {
            assert!(!rest.is_empty() && rest.len() < offered.len());
            assert!(rest[..] == offered[offered.len() - rest.len()..]);
        }
        Admit::Blocked(StreamEvent::Data(rest)) => assert!(rest[..] == offered[..]),
        _ => panic!("open input is never closed"),
    }
}

/// Two pushes of `A` and `B` bytes, with whatever the layer above takes
/// between them, against the charge, and what each push hands back. One
/// harness per pair of lengths.
fn charged_across<const A: usize, const B: usize>() {
    let budget = Budget::unlimited();
    let mut d = driver(Units, &budget);
    let check = |d: &Driver<Framed<Units, Blob>>| {
        let f = d.layer();
        assert!(
            buffer_charge(f) >= f.stream.allocated() + f.stream.held(),
            "the decoder's storage is charged"
        );
        assert_eq!(budget.used(), buffer_charge(f));
    };
    let first = kani::any::<[u8; A]>();
    suffix_kept(
        &first,
        d.deliver(StreamEvent::Data(Chunk::new(first.to_vec())))
            .unwrap(),
    );
    check(&d);
    let takes: u8 = kani::any();
    kani::assume(takes <= 2);
    for _ in 0..takes {
        let _ = d.layer_mut().take_event();
    }
    let second = kani::any::<[u8; B]>();
    suffix_kept(
        &second,
        d.deliver(StreamEvent::Data(Chunk::new(second.to_vec())))
            .unwrap(),
    );
    check(&d);
}

macro_rules! charged {
    ($($name:ident: $a:literal, $b:literal;)*) => {$(
        #[kani::proof]
        #[kani::unwind(7)]
        fn $name() {
            charged_across::<$a, $b>();
        }
    )*};
}

charged! {
    the_buffer_is_charged_before_bytes_are_taken_1_1: 1, 1;
    the_buffer_is_charged_before_bytes_are_taken_1_2: 1, 2;
    the_buffer_is_charged_before_bytes_are_taken_1_3: 1, 3;
    the_buffer_is_charged_before_bytes_are_taken_2_1: 2, 1;
    the_buffer_is_charged_before_bytes_are_taken_2_2: 2, 2;
    the_buffer_is_charged_before_bytes_are_taken_2_3: 2, 3;
    the_buffer_is_charged_before_bytes_are_taken_3_1: 3, 1;
    the_buffer_is_charged_before_bytes_are_taken_3_2: 3, 2;
    the_buffer_is_charged_before_bytes_are_taken_3_3: 3, 3;
}

/// The budget holds exactly what `Framed` and the chunk in flight are
/// charged, never past its limit.
fn accounted(budget: &Budget, d: &Driver<Framed<Units, Blob>>, flying: &Option<Chunk>) {
    let f = d.layer();
    let out = f.out.as_ref().map_or(0, Chunk::charged);
    let held = flying.as_ref().map_or(0, Chunk::charged);
    assert_eq!(budget.used(), buffer_charge(f) + out + held);
    assert!(budget.used() <= budget.limit());
}

/// Under a budget of `LIMIT` bytes: two bytes from the peer and one value
/// from above, each of which the budget may refuse, then the steps `S1`
/// and `S2`: 0 the peer ends, 1 the peer resets, 2 the layer above ends, 3
/// an event is taken, 4 the transport takes the write it holds, 5 the
/// transport takes the next write.
/// The fixed limits exercise refusal, the input reservation alone, and
/// combined input and output with several amounts of spare capacity.
/// Output now reserves its declared encoded bound before allocation.
fn charges_come_back<const LIMIT: usize, const S1: u8, const S2: u8>() {
    let budget = Budget::new(LIMIT);
    let mut d = driver(Units, &budget);
    // Output the transport has not taken yet.
    let mut flying: Option<Chunk> = None;
    if d.deliver(StreamEvent::Data(fixed::<2>())).is_err() {
        // A budget refusal takes no byte.
        assert_eq!(d.layer().stream.allocated(), 0);
        assert_eq!(d.layer().stream.buffered(), 0);
    }
    accounted(&budget, &d, &flying);
    let _ = d.command(MessageCommand::Send(Owned::new(
        Blob(alloc::vec![kani::any()]),
        Budget::unlimited().charge(1).unwrap(),
    )));
    accounted(&budget, &d, &flying);
    for step in [S1, S2] {
        match step {
            0 => {
                let _ = d.deliver(StreamEvent::Ended);
            }
            1 => {
                let _ = d.deliver(StreamEvent::Reset);
            }
            2 => {
                let _ = d.command(MessageCommand::End);
            }
            3 => {
                let _ = d.layer_mut().take_event();
            }
            4 => {
                // The transport takes what it held.
                flying = None;
            }
            _ => {
                if flying.is_none()
                    && let Some(StreamCommand::Write(chunk)) = d.layer_mut().take_command()
                {
                    assert!(chunk.charged() >= chunk.len(), "a write carries its charge");
                    flying = Some(chunk);
                }
            }
        }
        accounted(&budget, &d, &flying);
    }
    drop(flying);
    drop(d);
    assert_eq!(budget.used(), 0, "every charge comes back");
}

macro_rules! charges {
    ($($name:ident: $limit:literal, $s1:literal, $s2:literal;)*) => {$(
        #[kani::proof]
        #[kani::unwind(7)]
        fn $name() {
            charges_come_back::<$limit, $s1, $s2>();
        }
    )*};
}

charges! {
    every_charge_comes_back_14_write_then_delivered: 14, 5, 4;
    every_charge_comes_back_14_write_then_reset: 14, 5, 1;
    every_charge_comes_back_14_reset_then_write: 14, 1, 5;
    every_charge_comes_back_14_ended_then_end: 14, 0, 2;
    every_charge_comes_back_14_event_then_write: 14, 3, 5;
    every_charge_comes_back_14_end_then_write: 14, 2, 5;
    every_charge_comes_back_13_write_then_reset: 13, 5, 1;
    every_charge_comes_back_8_write_then_reset: 8, 5, 1;
    every_charge_comes_back_6_write_then_reset: 6, 5, 1;
    every_charge_comes_back_0_write_then_reset: 0, 5, 1;
}

/// Units on the wire in a fixed shape (`ODD_FIRST`: a three-byte unit,
/// then a one-byte one; otherwise a one-byte unit, a three-byte one and a
/// trailing odd byte that never completes), cut once at `CUT`. A unit's
/// first byte fixes its length; its other bytes are any. Offered as a peer
/// would: what a push hands back is offered again once the layer above
/// has taken what it can.
fn in_order<const ODD_FIRST: bool, const CUT: usize>() {
    // The first byte of each unit says its length, so it is fixed by the
    // shape; the other bytes of a three-byte unit are the solver's.
    let (p, q): (u8, u8) = (kani::any(), kani::any());
    let odd = [5, p, q, 2];
    let even = [2, 5, p, q, 7];
    let wire: &[u8] = if ODD_FIRST { &odd } else { &even };
    let units = if ODD_FIRST { [5, 2] } else { [2, 5] };
    let partial = !ODD_FIRST;
    let budget = Budget::unlimited();
    let mut d = driver(Units, &budget);
    let mut items = 0;
    let mut failures = 0;
    let mut ended = false;
    // Takes what the layer has for the layer above; three is more than it
    // can hold.
    let mut take = |d: &mut Driver<Framed<Units, Blob>>| {
        for _ in 0..3 {
            let Some(event) = d.layer_mut().take_event() else {
                break;
            };
            assert!(!ended, "nothing comes up after Ended");
            match event {
                MessageEvent::Message(Ok(unit)) => {
                    assert!(failures == 0);
                    assert!(items < 2);
                    assert!(*unit == units[items], "in order, each once");
                    items += 1;
                }
                MessageEvent::Message(Err(fail)) => {
                    assert!(fail == Fail::Truncated { unread: 1 });
                    failures += 1;
                }
                MessageEvent::Ended => ended = true,
            }
        }
    };
    for (from, to) in [(0, CUT), (CUT, wire.len())] {
        let mut offer = Some(Chunk::new(&wire[from..to]));
        for _ in 0..3 {
            let Some(chunk) = offer.take() else {
                break;
            };
            match d.deliver(StreamEvent::Data(chunk)).unwrap() {
                Admit::Taken => {}
                Admit::Partial(StreamEvent::Data(rest))
                | Admit::Blocked(StreamEvent::Data(rest)) => {
                    // What comes back is exactly the bytes not taken.
                    assert!(rest[..] == wire[to - rest.len()..to]);
                    // Offered again as the same bytes, fresh, so the solver need not
                    // carry the returned chunk across rounds.
                    offer = Some(Chunk::new(&wire[to - rest.len()..to]));
                }
                _ => panic!("open input is never closed"),
            }
            take(&mut d);
        }
        assert!(offer.is_none(), "every byte offered is taken in the end");
    }
    let _ = d.deliver(StreamEvent::Ended).unwrap();
    take(&mut d);
    assert!(items == 2, "every unit comes up");
    assert!(failures == usize::from(partial));
    assert!(ended);
}

macro_rules! in_order {
    ($($name:ident: $odd:literal, $cut:literal;)*) => {$(
        #[kani::proof]
        #[kani::unwind(4)]
        fn $name() {
            in_order::<$odd, $cut>();
        }
    )*};
}

in_order! {
    units_come_up_in_order_and_the_rest_is_handed_back_odd_first_cut_3: true, 3;
}

#[kani::proof]
#[kani::unwind(7)]
#[kani::solver(minisat)]
fn a_decoder_failure_comes_up_once_then_ended() {
    let budget = Budget::unlimited();
    let mut d = driver(Steps, &budget);
    let mut log = [Seen::Item; 7];
    let mut n = 0;
    for _ in 0..3 {
        match kani::any::<u8>() {
            0 => {
                let over = d.layer().input_over || d.layer().stream.is_eof();
                let buffered = d.layer().stream.buffered();
                let admit = d.deliver(StreamEvent::Data(fixed::<2>()));
                if over {
                    assert!(
                        matches!(admit, Ok(Admit::Closed(_))),
                        "input after its end is refused"
                    );
                    assert_eq!(d.layer().stream.buffered(), buffered);
                }
            }
            1 => {
                let _ = d.deliver(StreamEvent::Ended).unwrap();
            }
            2 => {
                let _ = d.deliver(StreamEvent::Reset).unwrap();
            }
            _ => {
                if let Some(event) = d.layer_mut().take_event() {
                    log[n] = seen(&event);
                    n += 1;
                }
            }
        }
        if log[..n].iter().any(|s| *s != Seen::Item) {
            assert!(
                d.layer().input_over,
                "after a failure or the end, input is over"
            );
        }
    }
    // Then everything still to come.
    for _ in 0..3 {
        if let Some(event) = d.layer_mut().take_event() {
            log[n] = seen(&event);
            n += 1;
        }
    }
    let log = &log[..n];
    for (i, s) in log.iter().enumerate() {
        match s {
            Seen::Item => assert!(
                !log[..i].contains(&Seen::Failure),
                "no item after a failure"
            ),
            Seen::Failure => {
                assert!(
                    !log[..i].contains(&Seen::Failure),
                    "a failure comes up once"
                );
                assert!(
                    i + 1 == log.len() || log[i + 1] == Seen::End,
                    "Ended follows a failure at once"
                );
            }
            Seen::End => assert_eq!(i + 1, log.len(), "nothing after Ended"),
        }
    }
    if log.last() == Some(&Seen::Failure) {
        assert!(matches!(
            d.layer_mut().take_event(),
            Some(MessageEvent::Ended)
        ));
    }
}

#[kani::proof]
#[kani::unwind(5)]
fn encoding_is_not_called_without_its_reservation() {
    struct Large;
    impl Wire for Large {
        type ParseError = Bad;
        type WriteError = Bad;
        fn parse(_: &[u8]) -> Result<Self, Bad> {
            Ok(Self)
        }
        fn write(&self, _: &mut Vec<u8>) -> Result<(), Bad> {
            panic!("an unreserved writer must not run")
        }
    }
    impl BoundedWire for Large {
        fn write_bounded(&self, _: &mut super::super::BoundedWriter<'_>) -> Result<(), Bad> {
            panic!("an unreserved writer must not run")
        }

        fn write_bound(&self) -> Result<usize, Bad> {
            Ok(64)
        }
    }
    let limit: u8 = kani::any();
    kani::assume(limit < 64);
    let budget = Budget::new(usize::from(limit));
    let mut d = Driver::new(
        Framed::<_, Large>::new(Units),
        Arc::new(NoEntropy),
        budget.clone(),
        Instant::ZERO,
    );
    let value = Owned::new(Large, budget.charge(0).unwrap());
    assert!(matches!(
        d.command(MessageCommand::Send(value)),
        Err(FramedError::Budget)
    ));
    assert_eq!(budget.used(), 0);
}

#[kani::proof]
#[kani::unwind(6)]
fn a_decoded_allocation_keeps_its_charge_outside_the_layer() {
    struct Allocates;
    impl Decode for Allocates {
        type Item = Vec<u8>;
        type Error = Bad;
        const NAME: &'static str = "owned";
        fn capacity(&self) -> usize {
            1
        }
        fn decode(&mut self, input: &[u8], _: bool) -> Result<Step<Vec<u8>>, Bad> {
            Ok(if input.is_empty() {
                Step::Need
            } else {
                Step::Item(input[..1].to_vec(), 1)
            })
        }
    }
    impl BoundedDecode for Allocates {
        fn allocation_bound(&self) -> usize {
            1
        }
    }
    let budget = Budget::new(8);
    let mut d = driver(Allocates, &budget);
    assert!(matches!(
        d.deliver(StreamEvent::Data(fixed::<1>())).unwrap(),
        Admit::Taken
    ));
    let MessageEvent::Message(Ok(value)) = d.layer_mut().take_event().unwrap() else {
        panic!("one item")
    };
    assert!(value.charged() >= value.capacity());
    drop(d);
    assert_eq!(budget.used(), value.charged());
    drop(value);
    assert_eq!(budget.used(), 0);
}

/// Any split of a short encoding either fits in the fixed destination or
/// reports exhaustion. Writes after exhaustion cannot make it successful.
#[kani::proof]
#[kani::unwind(6)]
fn a_bounded_writer_refuses_every_encoding_past_its_capacity() {
    let input: [u8; 4] = kani::any();
    let length: usize = kani::any();
    let cut: usize = kani::any();
    kani::assume(length <= input.len() && cut <= length);
    let mut storage = [0u8; 3];
    let mut writer = super::super::BoundedWriter::new(&mut storage);
    writer.extend_from_slice(&input[..cut]);
    writer.extend_from_slice(&input[cut..length]);
    let result = writer.finish();
    assert_eq!(result.is_ok(), length <= storage.len());
    if let Ok(written) = result {
        assert_eq!(written, length);
        assert_eq!(&storage[..written], &input[..length]);
    }
}
