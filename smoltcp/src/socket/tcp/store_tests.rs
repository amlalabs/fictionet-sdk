//! The stores against the byte ring the socket kept before: the same
//! segments and reads, the same bytes read in the same order, the same
//! window, and the stores' own bounds at every step.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use fictionet_buf::{Budget, Chunk};

use super::rx::{RxStore, SEGMENTS, SLOT, SMALL};
use super::tx::{HEADROOM, TxStore};
use crate::storage::{Assembler, RingBuffer};

const MSS: usize = 1460;

/// What a store may keep alive receiving with `capacity`: twice the window
/// in gathered blocks, and a slot or a segment for each chunk it keeps.
fn rx_bound(capacity: usize) -> usize {
    2 * capacity + SEGMENTS * SLOT.max(MSS)
}

/// The same for sending, where every block the store makes has headroom.
fn tx_bound(capacity: usize) -> usize {
    capacity + SLOT + SEGMENTS * (SLOT - 1)
}

#[test]
fn transmit_compaction_stays_within_one_window_of_payload() {
    let capacity = 1024 * 1024;
    let mut store = TxStore::new(capacity, Budget::unlimited());
    for _ in 0..2 * SEGMENTS {
        store.push(paid(&vec![0; capacity / (2 * SEGMENTS)])).unwrap();
        assert!(store.held() <= tx_bound(capacity));
    }
}

#[test]
fn a_partial_ack_does_not_pin_an_extra_window_on_the_next_write() {
    let capacity = 1024 * 1024;
    let mut store = TxStore::new(capacity, Budget::unlimited());
    let bytes: Vec<_> = (0..capacity).map(byte).collect();
    let mut chunk = Chunk::block(&Budget::unlimited(), HEADROOM, HEADROOM + bytes.len()).unwrap();
    chunk.extend_within(&bytes).unwrap();
    store.push(chunk).unwrap();
    let packet = store.piece(0, capacity).unwrap().in_place(40, |p| p[..40].fill(0)).unwrap();
    store.ack(capacity - SMALL);
    store.push(paid(&bytes[..capacity - SMALL])).unwrap();
    assert!(store.held() <= tx_bound(capacity));
    assert_eq!(store.bytes(0, SMALL), &bytes[capacity - SMALL..]);
    let mut offset = SMALL;
    while offset < capacity {
        let piece = store.bytes(offset, MSS);
        assert_eq!(piece, &bytes[offset - SMALL..offset - SMALL + piece.len()]);
        offset += piece.len();
    }
    assert_eq!(&packet[40..], bytes);
}

#[test]
fn writes_refused_for_retention_keep_ownership_and_bytes() {
    let capacity = 1024 * 1024;
    let budget = Budget::new(capacity);
    let mut store = TxStore::new(capacity, budget.clone());
    store.push(paid(&vec![1; capacity])).unwrap();
    store.ack(capacity - SMALL);
    let blocked = budget.charge(budget.limit()).unwrap();
    let write = paid(&vec![2; capacity - SMALL]);
    let original = write.clone();
    let refused = store.push(write).unwrap_err();
    assert!(refused.shares(&original));
    assert_eq!(store.len(), SMALL);
    assert_eq!(store.bytes(0, SMALL), &[1; SMALL]);
    drop(blocked);
    store.push(refused).unwrap();
    assert!(store.held() <= tx_bound(capacity));
}

#[test]
fn unpaid_writes_are_charged_before_retention() {
    let budget = Budget::new(0);
    let mut store = TxStore::new(4 * SLOT, budget);
    let write = Chunk::unpaid(vec![1; SMALL]);
    let original = write.clone();
    let refused = store.push(write).unwrap_err();
    assert!(refused.shares(&original));
    assert!(store.is_empty());
}

#[test]
fn a_piece_request_can_extend_past_the_address_space() {
    let mut store = TxStore::new(SLOT, Budget::unlimited());
    let bytes: Vec<_> = (0..SMALL).map(byte).collect();
    store.push(paid(&bytes)).unwrap();
    for offset in 1..bytes.len() {
        assert_eq!(store.bytes(offset, usize::MAX), &bytes[offset..]);
        assert_eq!(store.piece(offset, usize::MAX).unwrap().bytes(), &bytes[offset..]);
    }
}

/// `bytes` paid for by a budget of their own, as a segment comes from the
/// layer below.
fn paid(bytes: &[u8]) -> Chunk {
    Chunk::copy_of(&Budget::unlimited(), bytes).unwrap()
}

/// The byte of the peer's stream at `seq`: what every copy of it carries.
fn byte(seq: usize) -> u8 {
    (seq ^ (seq >> 8) ^ (seq >> 16)) as u8
}

/// What a segment-options hook makes of a byte, wherever it falls.
fn edit(byte: u8) -> u8 {
    byte ^ 0x5a
}

/// Receiving, both ways: the store with its assembler and the ring with
/// its own, fed the same segments of one stream.
struct Receiver {
    store: RxStore,
    ring: RingBuffer<'static>,
    store_holes: Assembler,
    ring_holes: Assembler,
    /// The stream position of the first byte not yet ready.
    edge: usize,
    edits: bool,
    store_read: Vec<u8>,
    ring_read: Vec<u8>,
}

impl Receiver {
    fn new(capacity: usize, edits: bool) -> Receiver {
        Receiver {
            store: RxStore::new(capacity, Budget::unlimited()),
            ring: RingBuffer::new(vec![0; capacity]),
            store_holes: Assembler::new(),
            ring_holes: Assembler::new(),
            edge: 0,
            edits,
            store_read: Vec::new(),
            ring_read: Vec::new(),
        }
    }

    /// The segment carrying `len` bytes from `offset` past the edge, as a
    /// socket hands it on: clipped to the window. Returns whether the
    /// store took it.
    fn segment(&mut self, offset: usize, len: usize) -> bool {
        let window = self.store.window();
        if offset >= window {
            return false;
        }
        let len = len.min(window - offset);
        let bytes: Vec<u8> = (0..len).map(|i| byte(self.edge + offset + i)).collect();
        // A segment arrives in a packet: its payload is a piece of it.
        let mut packet = Chunk::unpaid([&[0xee; 40][..], &bytes].concat());
        packet.advance(40);

        let before = self.store_holes.clone();
        let Ok(contiguous) = self.store_holes.add_then_remove_front(offset, len) else {
            assert!(self.ring_holes.add_then_remove_front(offset, len).is_err());
            return false;
        };
        if self.store.insert(offset, &packet).is_err() {
            self.store_holes = before;
            return false;
        }
        drop(packet);
        assert_eq!(
            self.ring_holes.add_then_remove_front(offset, len),
            Ok(contiguous)
        );
        assert_eq!(self.ring.write_unallocated(offset, &bytes), len);

        let mut taken = 0;
        while taken < contiguous {
            let mut chunk = self.store.take_contiguous().expect("contiguous bytes held");
            taken += chunk.len();
            if self.edits {
                for b in chunk.make_mut(&Budget::unlimited()).unwrap() {
                    *b = edit(*b);
                }
            }
            self.store.commit(chunk);
        }
        assert_eq!(taken, contiguous);
        if self.edits {
            for i in 0..contiguous {
                let mut b = [0];
                self.ring.read_unallocated(i, &mut b);
                assert_eq!(self.ring.write_unallocated(i, &[edit(b[0])]), 1);
            }
        }
        self.ring.enqueue_unallocated(contiguous);
        self.edge += contiguous;
        true
    }

    fn read(&mut self, most: usize) {
        let mut want = most.min(self.store.len());
        let before = self.store_read.len();
        while want > 0 {
            let chunk = self.store.pop(want).expect("ready bytes");
            want -= chunk.len();
            self.store_read.extend_from_slice(&chunk);
        }
        let n = self.store_read.len() - before;
        let mut bytes = vec![0; n];
        assert_eq!(self.ring.dequeue_slice(&mut bytes), n);
        self.ring_read.extend_from_slice(&bytes);
    }

    fn check(&self) {
        assert_eq!(self.store.window(), self.ring.window());
        assert_eq!(self.store.len(), self.ring.len());
        assert_eq!(self.store_holes, self.ring_holes);
        assert_eq!(self.store_read, self.ring_read);
        assert!(self.store.descriptors() <= SEGMENTS);
        let capacity = self.store.capacity();
        assert!(self.store.held() <= rx_bound(capacity));
        // What waits out of order is what the assembler says arrived.
        let waiting: Vec<_> = self
            .store
            .waiting()
            .map(|(o, b)| (o, o + b.len()))
            .collect();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in waiting {
            match merged.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => merged.push((start, end)),
            }
        }
        let assembled: Vec<_> = self.store_holes.iter_data().collect();
        assert_eq!(merged, assembled);
        for (offset, bytes) in self.store.waiting() {
            for (i, b) in bytes.iter().enumerate() {
                assert_eq!(*b, byte(self.edge + offset + i));
            }
        }
    }
}

/// Random segments of one stream, reordered, duplicated and overlapping,
/// from a byte to a full MSS, and random reads, some of them none while
/// the window closes, against the ring.
#[test]
fn receiving_matches_the_ring() {
    for seed in 0..48 {
        let mut rng = StdRng::seed_from_u64(seed);
        let capacity = [4096, 65536, 256 * 1024][seed as usize % 3];
        let mut rx = Receiver::new(capacity, seed % 2 == 1);
        for _ in 0..3000 {
            match rng.gen_range(0..10) {
                0..=6 => {
                    let len = match rng.gen_range(0..4) {
                        0 => rng.gen_range(1..SMALL),
                        _ => rng.gen_range(SMALL..=MSS),
                    };
                    let window = rx.store.window().max(1);
                    let offset = match rng.gen_range(0..3) {
                        0 => 0,
                        _ => rng.gen_range(0..window.min(16 * MSS)),
                    };
                    rx.segment(offset, len);
                }
                // A slow reader: the window closes, segments are clipped,
                // and those past it are dropped.
                7 => rx.read(rng.gen_range(0..64)),
                _ => rx.read(rng.gen_range(0..4 * MSS)),
            }
            rx.check();
        }
        rx.read(usize::MAX);
        rx.check();
        assert!(!rx.store_read.is_empty());
    }
}

/// A window of MSS segments in order with no reads holds far more
/// segments than chunks: the store joins neighbors and keeps every byte.
#[test]
fn a_slow_reader_s_window_fits_in_bounded_chunks() {
    for capacity in [256 * 1024, 2 * 1024 * 1024] {
        let mut rx = Receiver::new(capacity, false);
        while rx.store.window() > 0 {
            assert!(rx.segment(0, MSS));
            rx.check();
        }
        assert!(rx.store.descriptors() <= SEGMENTS);
        rx.read(usize::MAX);
        rx.check();
        assert_eq!(rx.store_read.len(), capacity);
    }
}

/// Where a segment overlaps bytes held out of order and carries other
/// bytes there, the store keeps the first copy.
#[test]
fn overlapping_bytes_keep_the_first_copy() {
    let mut store = RxStore::new(64, Budget::unlimited());
    store.insert(2, &Chunk::unpaid(b"XY".to_vec())).unwrap();
    store.insert(0, &Chunk::unpaid(b"abcdef".to_vec())).unwrap();
    let mut read = Vec::new();
    while let Some(chunk) = store.take_contiguous() {
        read.extend_from_slice(&chunk);
    }
    assert_eq!(read, b"abXYef");
}

/// A segment of at least SMALL bytes is kept as the chunk it came in, not
/// copied, while chunks are free; shorter ones are gathered.
#[test]
fn a_segment_is_kept_without_a_copy() {
    let mut store = RxStore::new(64 * 1024, Budget::unlimited());
    let segment = paid(&[7; MSS]);
    store.insert(0, &segment).unwrap();
    let kept = store.take_contiguous().unwrap();
    assert!(kept.shares(&segment));
    store.commit(kept);
    let read = store.pop(usize::MAX).unwrap();
    assert!(read.shares(&segment));

    let short = paid(&[1; SMALL - 1]);
    store.insert(0, &short).unwrap();
    let kept = store.take_contiguous().unwrap();
    store.commit(kept);
    assert!(!store.pop(usize::MAX).unwrap().shares(&short));
}

/// Bytes that come paid keep their payment; bytes nothing pays for are
/// charged to the store's budget, and refused when it has no room.
#[test]
fn what_the_store_keeps_is_paid_for() {
    let budget = Budget::new(SMALL);
    let mut store = RxStore::new(64 * 1024, budget.clone());
    store.insert(0, &paid(&[1; MSS])).unwrap();
    assert_eq!(budget.used(), 0);
    assert!(store.insert(MSS, &Chunk::unpaid(vec![2; MSS])).is_err());
    assert_eq!(store.descriptors(), 1);
    store.insert(MSS, &Chunk::unpaid(vec![3; SMALL])).unwrap();
    assert!(budget.used() >= SMALL);
    while let Some(chunk) = store.take_contiguous() {
        assert!(chunk.charged() >= chunk.len());
        store.commit(chunk);
    }
    while store.pop(usize::MAX).is_some() {}
    assert_eq!(budget.used(), 0);
}

/// Overlapping packets clipped at the window's edge must not each pin a
/// large reassembly allocation for the few new bytes they contribute.
#[test]
fn clipped_waiting_pieces_do_not_pin_large_packets() {
    for piece_length in [1, SMALL, 2 * SMALL] {
        let capacity = 2 * SMALL * SEGMENTS;
        let mut store = RxStore::new(capacity, Budget::unlimited());
        for count in 1..=SEGMENTS {
            let length = count * piece_length;
            let offset = capacity - length;
            let bytes: Vec<_> = (offset..offset + 32 * SLOT).map(byte).collect();
            let packet = paid(&bytes);
            store.insert(offset, &packet.slice(0..length)).unwrap();
            assert!(store.held() <= rx_bound(capacity));
            assert!(store.descriptors() <= SEGMENTS);
            for (at, kept) in store.waiting() {
                assert!(kept.iter().enumerate().all(|(i, &b)| b == byte(at + i)));
            }
        }
        assert_eq!(store.waiting().map(|(_, bytes)| bytes.len()).sum::<usize>(), SEGMENTS * piece_length);
    }
}

/// Detaching several new pieces is atomic if the budget fits the first
/// copy but refuses another one from the same overlapping segment.
#[test]
fn a_refused_detachment_keeps_all_waiting_bytes_unchanged() {
    let budget = Budget::new(2);
    let mut store = RxStore::new(16, budget.clone());
    store.insert(2, &paid(&[byte(2)])).unwrap();
    let before: Vec<_> = store.waiting().map(|(at, bytes)| (at, bytes.to_vec())).collect();
    let bytes: Vec<_> = (0..2 * SLOT).map(byte).collect();
    let packet = paid(&bytes);
    assert!(store.insert(0, &packet.slice(0..4)).is_err());
    let after: Vec<_> = store.waiting().map(|(at, bytes)| (at, bytes.to_vec())).collect();
    assert_eq!(after, before);
    assert_eq!(budget.used(), 0);
}

/// A store whose budget refuses the block it needs to make room refuses
/// the segment and changes no byte it holds.
#[test]
fn a_refused_block_refuses_the_segment() {
    let budget = Budget::new(0);
    let mut store = RxStore::new(1 << 20, budget);
    for i in 0..SEGMENTS {
        let piece = paid(&[i as u8; SMALL]);
        store.insert(1 + SMALL * i, &piece).unwrap();
    }
    let before: Vec<(usize, Vec<u8>)> = store.waiting().map(|(o, b)| (o, b.to_vec())).collect();
    let one_more = paid(&[9; SMALL]);
    assert!(store.insert(1 + SMALL * SEGMENTS, &one_more).is_err());
    let after: Vec<(usize, Vec<u8>)> = store.waiting().map(|(o, b)| (o, b.to_vec())).collect();
    assert_eq!(before, after);
}

/// Sending, both ways: the store and the ring, fed the same writes and
/// acknowledgements.
#[test]
fn sending_matches_the_ring() {
    for seed in 0..48 {
        let mut rng = StdRng::seed_from_u64(seed);
        let capacity = [4096, 65536, 256 * 1024][seed as usize % 3];
        let mut store = TxStore::new(capacity, Budget::unlimited());
        let mut ring = RingBuffer::new(vec![0; capacity]);
        let mut written = 0usize;
        let mut acked = 0usize;
        for _ in 0..3000 {
            match rng.gen_range(0..10) {
                0..=5 => {
                    let len = match rng.gen_range(0..3) {
                        0 => rng.gen_range(1..SMALL),
                        _ => rng.gen_range(SMALL..=4 * MSS),
                    };
                    let bytes: Vec<u8> = (0..len).map(|i| byte(written + i)).collect();
                    let fits = len <= ring.window();
                    // A writer's block has headroom, as the writers' do.
                    let mut chunk =
                        Chunk::block(&Budget::unlimited(), HEADROOM, HEADROOM + len).unwrap();
                    chunk.extend_within(&bytes).unwrap();
                    assert_eq!(store.push(chunk).is_ok(), fits);
                    if fits {
                        assert_eq!(ring.enqueue_slice(&bytes), len);
                        written += len;
                    }
                }
                6..=7 if !ring.is_empty() => {
                    let n = rng.gen_range(1..=ring.len());
                    store.ack(n);
                    ring.dequeue_allocated(n);
                    acked += n;
                }
                _ if !ring.is_empty() => {
                    let offset = rng.gen_range(0..ring.len());
                    let len = rng.gen_range(1..=MSS);
                    let piece = store.bytes(offset, len).to_vec();
                    let slice = ring.get_allocated(offset, len);
                    for (bytes, at) in [(&piece[..], offset), (slice, offset)] {
                        assert!(!bytes.is_empty() && bytes.len() <= len);
                        for (i, b) in bytes.iter().enumerate() {
                            assert_eq!(*b, byte(acked + at + i));
                        }
                    }
                    let ends: Vec<usize> = store.ends().collect();
                    let stop = offset + piece.len();
                    assert!(ends.iter().all(|&end| end <= offset || end >= stop));
                    let whole = store.piece(offset, len).unwrap();
                    assert_eq!(whole.bytes(), &piece[..]);
                }
                _ => {}
            }
            assert_eq!(store.len(), ring.len());
            assert_eq!(store.window(), ring.window());
            assert!(store.descriptors() <= SEGMENTS);
            assert!(store.held() <= tx_bound(capacity));
        }
    }
}

/// A chunk with headroom that the store alone holds goes out with the
/// header written in front of it and no copy; while that packet is still
/// held elsewhere, the next send of it gets nothing and is copied; once it
/// is dropped, the next is in place again.
#[test]
fn a_unique_chunk_is_sent_in_place_and_a_shared_one_is_not() {
    let mut store = TxStore::new(64 * 1024, Budget::unlimited());
    let mut chunk = Chunk::block(&Budget::unlimited(), HEADROOM, HEADROOM + 1000).unwrap();
    chunk.extend_within(&[3; 1000]).unwrap();
    store.push(chunk).unwrap();

    let header = 40;
    let packet = store
        .piece(0, MSS)
        .unwrap()
        .in_place(header, |bytes| bytes[..header].fill(0xab))
        .expect("unique, with headroom");
    assert_eq!(packet.len(), header + 1000);
    assert!(packet[..header].iter().all(|&b| b == 0xab));
    assert!(packet[header..].iter().all(|&b| b == 3));
    assert_eq!(store.bytes(0, MSS), &[3; 1000][..]);

    let mut called = false;
    let again = store
        .piece(0, MSS)
        .unwrap()
        .in_place(header, |_| called = true);
    assert!(
        again.is_none() && !called,
        "the first packet still holds it"
    );
    drop(packet);
    assert!(
        store
            .piece(0, MSS)
            .unwrap()
            .in_place(header, |_| ())
            .is_some()
    );

    // Part of a chunk, or a chunk without the headroom, is copied.
    assert!(
        store
            .piece(0, 10)
            .unwrap()
            .in_place(header, |_| ())
            .is_none()
    );
    let mut tight = TxStore::new(64 * 1024, Budget::unlimited());
    tight.push(Chunk::unpaid(vec![1; 500])).unwrap();
    assert!(
        tight
            .piece(0, MSS)
            .unwrap()
            .in_place(header, |_| ())
            .is_none()
    );
}

/// More writes than chunks: neighbors are joined and every byte stays, in
/// order, until it is acknowledged.
#[test]
fn many_writes_fit_in_bounded_chunks() {
    let mut store = TxStore::new(1 << 20, Budget::unlimited());
    let mut model = Vec::new();
    for i in 0..400 {
        let bytes: Vec<u8> = (0..SMALL + i).map(|j| byte(model.len() + j)).collect();
        store.push(Chunk::unpaid(bytes.clone())).unwrap();
        model.extend_from_slice(&bytes);
        assert!(store.descriptors() <= SEGMENTS);
    }
    let mut offset = 0;
    while offset < model.len() {
        let bytes = store.bytes(offset, usize::MAX);
        assert_eq!(bytes, &model[offset..offset + bytes.len()]);
        offset += bytes.len();
    }
    store.ack(model.len());
    assert!(store.is_empty() && store.descriptors() == 0);
}

/// Sending a short write must leave its gathering block writable while
/// the packet is in flight, so subsequent short writes can share the tail.
#[test]
fn short_writes_gather_while_packets_are_in_flight() {
    let mut store = TxStore::new(4 * SLOT, Budget::unlimited());
    let mut packets = Vec::new();
    let mut expected = Vec::new();
    for i in 0..SEGMENTS {
        let bytes = vec![byte(i); 7];
        let offset = expected.len();
        store.push(paid(&bytes)).unwrap();
        expected.extend_from_slice(&bytes);
        let mut piece = store.piece(offset, bytes.len()).unwrap();
        let packet = piece
            .in_place(40, |packet| packet[..40].fill(0))
            .unwrap_or_else(|| paid(piece.bytes()));
        packets.push(packet);
        assert!(store.descriptors() <= expected.len().div_ceil(SLOT));
    }
    let mut actual = Vec::new();
    while actual.len() < store.len() {
        actual.extend_from_slice(store.bytes(actual.len(), MSS));
    }
    assert_eq!(actual, expected);
    assert_eq!(
        packets.iter().map(|p| p.len()).sum::<usize>(),
        expected.len()
    );
}
