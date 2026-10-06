use super::{Decoded, Layer};
use crate::stdlib::codec::{Decode, Fail, Spans, Stream};

/// What a decoder shows for one item. Ranges supplied by [`fields`](Self::fields)
/// are relative to the item's raw bytes, before placement in a packet.
///
/// Implement this trait on a copied protocol decoder or on your own decoder.
/// Register it with [`Registry::register`](super::Registry::register).
/// Driving it through [`Observed`] or a registry requires `Self::Error: Clone`.
/// The stream retains a terminal error while reporting it once to the caller.
///
/// ```
/// use fictionet::observe::{Layer, Present, Registry, Selection, Match, Transport};
/// use fictionet::stdlib::codec::{Decode, Step};
/// use std::convert::Infallible;
/// struct Bytes;
/// impl Decode for Bytes {
///     type Item = u8;
///     type Error = Infallible;
///     const NAME: &'static str = "Byte protocol";
///     fn capacity(&self) -> usize { 1 }
///     fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<u8>, Infallible> {
///         Ok(b.first().map_or(Step::Need, |v| Step::Item(*v, 1)))
///     }
/// }
/// impl Present for Bytes {
///     fn summary(item: &u8) -> String { format!("Byte {item}") }
///     fn fields(item: &u8, _: &[u8], layer: &mut Layer) {
///         layer.field("Value", item.to_string(), (0, 1));
///     }
/// }
/// let mut registry = Registry::default();
/// registry.register("bytes", |s: Selection<'_>| {
///     if s.transport == Transport::Tcp && s.ports.1 == 9000 {
///         Match::Yes
///     } else { Match::No }
/// }, |_| [Bytes, Bytes]);
/// ```
pub trait Present: Decode {
    /// The item's one-line description.
    fn summary(item: &Self::Item) -> String;

    /// Adds fields with ranges relative to `bytes`. Notes have no range.
    fn fields(item: &Self::Item, bytes: &[u8], layer: &mut Layer);

    /// Adds an item to a packet. Override to add several layers, tags, or
    /// a packet summary that differs from the layer summary.
    fn present(
        item: &Self::Item,
        bytes: &[u8],
        start: u64,
        place: &Placement,
        packet: &mut Decoded,
    ) {
        let mut layer = Layer::new(Self::NAME, 0, (0, bytes.len()));
        layer.summary = Self::summary(item);
        Self::fields(item, bytes, &mut layer);
        packet.application(2, Self::NAME, &layer.summary);
        place.push(packet, start, bytes, Self::NAME, layer);
    }

    /// Reports a terminal framing error. The driver calls this once.
    fn error(error: &Fail<Self::Error>, packet: &mut Decoded) {
        packet.tag("malformed");
        packet.info = format!("{}: {error}", Self::NAME);
    }

    /// Supplies the packet's remaining display budget before decoding the
    /// next item. Changes affect presentation limits only, not wire validity.
    fn prepare(&mut self, _packet: &Decoded) {}

    /// Whether a header-only item still has payload bytes to skip.
    /// This preserves the packet's partial-message annotation while skipping.
    fn pending(&self) -> bool {
        false
    }

    /// Clears protocol state after missing bytes. The input buffer is
    /// discarded separately. The default suits a stateless decoder.
    fn reset(&mut self) {}
}

/// A run of stream bytes in one buffer of the current packet.
/// An absent offset means the bytes came from an earlier packet.
#[derive(Clone, Copy, Debug, Default)]
pub struct Place {
    /// Offset of the first byte in the stream.
    pub stream_start: u64,
    /// Buffer index in [`Decoded`]. Zero is the captured packet.
    pub buf: usize,
    /// Start in that buffer, or `None` for bytes held from another packet.
    pub offset: Option<usize>,
    /// Number of bytes in this run.
    pub len: usize,
}

impl Place {
    /// Locates an item, or gives it a reassembly buffer when it crosses
    /// this run's boundary. All returned ranges use checked arithmetic.
    pub fn locate(
        &self,
        packet: &mut Decoded,
        start: u64,
        bytes: &[u8],
        name: &str,
    ) -> (usize, usize) {
        let direct = (|| {
            let delta = usize::try_from(start.checked_sub(self.stream_start)?).ok()?;
            if delta.checked_add(bytes.len())? > self.len {
                return None;
            }
            let base = self.offset?.checked_add(delta)?;
            base.checked_add(bytes.len())?;
            Some((self.buf, base))
        })();
        direct.unwrap_or_else(|| (packet.buffer(name, bytes.to_vec()), 0))
    }
}

/// Maps item offsets through zero or more [`Spans`] to the current packet.
/// Hops run from the innermost stream outward. Only exact byte mappings
/// can point into a packet. Transformed bytes, gaps, and expired spans use
/// a named reassembly buffer instead.
#[derive(Clone, Debug, Default)]
pub struct Placement {
    at: Place,
    hops: Vec<Spans>,
}

impl Placement {
    /// Creates a direct stream-to-packet placement.
    pub fn new(at: Place) -> Self {
        Self {
            at,
            hops: Vec::new(),
        }
    }

    /// Adds an outward hop. Returns false past 16 hops or a retention limit
    /// above 256 spans per hop. Use [`Spans::push_exact`] for unchanged
    /// payload bytes.
    pub fn through(&mut self, spans: Spans) -> bool {
        if self.hops.len() >= 16 || spans.keep() > 256 {
            return false;
        }
        self.hops.push(spans);
        true
    }

    /// Accesses an outward hop, numbered from the innermost stream at zero.
    /// Record each new payload before feeding its bytes to [`Observed::data`].
    /// Replacements must keep the same stream offset coordinates.
    pub fn hop_mut(&mut self, index: usize) -> Option<&mut Spans> {
        self.hops.get_mut(index)
    }

    /// Changes the terminal packet run without changing the span chain.
    pub fn packet(&mut self, at: Place) {
        self.at = at;
    }

    /// Locates exact bytes in the current packet, or creates a named
    /// buffer containing those bytes. A coarse span never implies identity.
    pub fn locate(
        &self,
        packet: &mut Decoded,
        start: u64,
        bytes: &[u8],
        name: &str,
    ) -> (usize, usize) {
        let direct = (|| {
            let mut range = start..start.checked_add(u64::try_from(bytes.len()).ok()?)?;
            for spans in &self.hops {
                range = spans.locate_exact(range)?;
            }
            Some(range.start)
        })();
        match direct {
            Some(start) => self.at.locate(packet, start, bytes, name),
            None => (packet.buffer(name, bytes.to_vec()), 0),
        }
    }

    /// Places a layer whose ranges are relative to `bytes` and adds it.
    /// Invalid field ranges lose their byte reference. Invalid layer
    /// ranges become empty. Notes remain unchanged.
    pub fn push(
        &self,
        packet: &mut Decoded,
        start: u64,
        bytes: &[u8],
        name: &str,
        mut layer: Layer,
    ) {
        let (buf, base) = self.locate(packet, start, bytes, name);
        let shift = |(a, b): (usize, usize)| {
            if a > b || b > bytes.len() {
                return None;
            }
            Some((base.checked_add(a)?, base.checked_add(b)?))
        };
        layer.buf = buf;
        layer.range = shift(layer.range).unwrap_or((base, base));
        for field in &mut layer.fields {
            field.range = field.range.and_then(shift);
        }
        packet.push(layer);
    }
}

/// One observed direction: a bounded [`Stream`] and its byte placement.
///
/// Call [`data`](Self::data) for ordered bytes and [`end`](Self::end) at
/// EOF. The same adapter drives registered built-in and user decoders.
/// Messages spanning packets receive a reassembly buffer on completion.
pub struct Observed<D: Present> {
    stream: Stream<D>,
    place: Placement,
    origin: Option<u64>,
    pending: bool,
    limit: usize,
    refused: Option<Fail<D::Error>>,
}

impl<D: Present> std::fmt::Debug for Observed<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observed")
            .field("protocol", &D::NAME)
            .field("buffered", &self.stream.buffered())
            .field("held", &self.stream.held())
            .field("place", &self.place)
            .field("origin", &self.origin)
            .field("done", &self.is_done())
            .finish()
    }
}

impl<D: Present> Observed<D> {
    /// Starts a direction with the decoder's input capacity.
    pub fn new(decoder: D) -> Self {
        Self::with_buffer(decoder, 0)
    }

    /// Allows bounded read-ahead beyond the decoder's minimum capacity.
    /// Capture framers can show a complete large frame when it is already
    /// in the current packet, while skipping one still arriving in pieces.
    pub fn with_buffer(decoder: D, limit: usize) -> Self {
        Self {
            stream: Stream::with_buffer(decoder, limit),
            place: Placement::default(),
            origin: None,
            pending: false,
            limit,
            refused: None,
        }
    }

    /// Whether input or a skipped payload is waiting for more bytes.
    pub fn waiting(&self) -> bool {
        !self.is_done() && (self.stream.buffered() != 0 || self.pending)
    }

    /// Accesses the placement chain, for nested byte streams. On first use,
    /// the innermost hop must end at the end of the supplied byte chunk.
    pub fn placement(&mut self) -> &mut Placement {
        &mut self.place
    }

    /// Accesses decoder modes between items, as with [`Stream::decoder`].
    pub fn decoder(&mut self) -> &mut D {
        self.stream.decoder()
    }

    /// Unread bytes waiting for another input chunk.
    pub fn buffered(&self) -> usize {
        self.stream.buffered()
    }

    /// Whether decoding has stopped, including after an error or refused input.
    pub fn is_done(&self) -> bool {
        self.refused.is_some() || self.stream.is_done()
    }

    /// The terminal error, if any.
    pub fn failed(&self) -> Option<&Fail<D::Error>> {
        self.refused.as_ref().or_else(|| self.stream.failed())
    }

    /// Drops unread input and resets protocol state after a gap. Keeps the
    /// placement hops and starts at the innermost hop's next byte offset.
    /// Call this before recording the next payload's spans.
    pub fn reset(self) -> Self {
        let (_, mut decoder) = self.stream.into_parts();
        decoder.reset();
        Self {
            origin: self.place.hops.first().map(Spans::inner_offset),
            place: self.place,
            ..Self::with_buffer(decoder, self.limit)
        }
    }
}

impl<D: Present> Observed<D>
where
    D::Error: Clone,
{
    /// Feeds ordered bytes and adds all completed items to `packet`.
    /// `at` describes this chunk in the current packet, even if the chunk
    /// completes an item that started in a previous packet. Refused buffer
    /// input marks the direction lost until [`reset`](Self::reset).
    pub fn data(&mut self, bytes: &[u8], at: Place, packet: &mut Decoded) {
        self.data_with(bytes, at, packet, |item, raw, start, place, packet| {
            D::present(&item, raw, start, place, packet);
        });
    }

    /// Feeds bytes while a session supplies item presentation. The callback
    /// runs before raw bytes are consumed and receives their stream offset
    /// and placement. This supports session state shared across directions.
    pub fn data_with(
        &mut self,
        mut bytes: &[u8],
        at: Place,
        packet: &mut Decoded,
        mut present: impl FnMut(D::Item, &[u8], u64, &Placement, &mut Decoded),
    ) {
        if self.refused.is_some() {
            return;
        }
        self.place.packet(at);
        let origin = *self.origin.get_or_insert_with(|| {
            self.place.hops.first().map_or(at.stream_start, |spans| {
                spans.inner_offset().saturating_sub(bytes.len() as u64)
            })
        });
        loop {
            let n = self.stream.push(bytes);
            bytes = bytes.get(n..).unwrap_or_default();
            loop {
                self.stream.decoder().prepare(packet);
                let Some(result) = self.stream.with_next(|item, raw, range| {
                    present(
                        item,
                        raw,
                        range.start.saturating_add(origin),
                        &self.place,
                        packet,
                    );
                }) else { break };
                if let Err(error) = result {
                    D::error(&error, packet);
                }
            }
            self.pending = self.stream.decoder().pending();
            if bytes.is_empty() || self.stream.is_done() {
                break;
            }
            if n == 0 {
                // Refused input (including allocation failure) breaks framing.
                // Stop until reset rather than joining across missing bytes.
                self.refuse(packet);
                break;
            }
        }
    }

    fn refuse(&mut self, packet: &mut Decoded) {
        let error = Fail::Stuck {
            unread: self.stream.buffered(),
            capacity: self.stream.decoder().capacity(),
        };
        D::error(&error, packet);
        self.refused = Some(error);
    }

    /// Marks EOF and presents any final item. Partial input uses
    /// [`Present::error`]. Pass the packet used by the last `data` call,
    /// or clear its placement first if EOF arrives in a later packet.
    pub fn end(&mut self, packet: &mut Decoded) {
        if self.refused.is_some() {
            return;
        }
        self.stream.end();
        loop {
            self.stream.decoder().prepare(packet);
            let Some(result) = self.stream.with_next(|item, raw, range| {
                D::present(
                    &item,
                    raw,
                    range.start.saturating_add(self.origin.unwrap_or(0)),
                    &self.place,
                    packet,
                );
            }) else { break };
            if let Err(error) = result {
                D::error(&error, packet);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_rejects_hops_that_can_outgrow_the_bound() {
        let mut placement = Placement::default();
        assert!(!placement.through(Spans::new(usize::MAX)));
        assert!(placement.through(Spans::new(256)));
        for i in 0..40_000 {
            let hop = placement.hop_mut(0).unwrap();
            hop.skip(1);
            hop.push_exact(1);
            assert!(hop.len() <= 256);
            assert_eq!(hop.locate_exact(i..i + 1), Some(2 * i + 1..2 * i + 2));
        }
    }

    struct QuietRefusal;
    impl Decode for QuietRefusal {
        type Item = ();
        type Error = std::convert::Infallible;
        const NAME: &'static str = "Quiet refusal";
        fn capacity(&self) -> usize {
            1
        }
        fn decode(
            &mut self,
            _: &[u8],
            _: bool,
        ) -> Result<crate::stdlib::codec::Step<()>, Self::Error> {
            Ok(crate::stdlib::codec::Step::Need)
        }
    }
    impl Present for QuietRefusal {
        fn summary(_: &()) -> String {
            String::new()
        }
        fn fields(_: &(), _: &[u8], _: &mut Layer) {}
        fn error(_: &Fail<Self::Error>, packet: &mut Decoded) {
            packet.info.push_str("refused");
        }
    }

    #[test]
    fn refused_input_uses_the_presenters_error_policy_and_retains_failure() {
        let mut observed = Observed::new(QuietRefusal);
        let mut packet = Decoded::default();
        // Exercise refusal without depending on an allocator failure.
        observed.refuse(&mut packet);
        assert!(packet.tags.is_empty());
        assert!(matches!(observed.failed(), Some(Fail::Stuck { .. })));
        assert!(observed.is_done());
        assert!(!observed.waiting());
        observed.data(b"y", Place::default(), &mut packet);
        observed.end(&mut packet);
        assert_eq!(packet.info, "refused");
        assert!(observed.reset().failed().is_none());
    }

    struct Refused;
    impl Decode for Refused {
        type Item = ();
        type Error = std::fmt::Error;
        const NAME: &'static str = "Refused";
        fn capacity(&self) -> usize {
            1
        }
        fn decode(
            &mut self,
            _: &[u8],
            _: bool,
        ) -> Result<crate::stdlib::codec::Step<()>, Self::Error> {
            Err(std::fmt::Error)
        }
    }
    impl Present for Refused {
        fn summary(_: &()) -> String {
            String::new()
        }
        fn fields(_: &(), _: &[u8], _: &mut Layer) {}
    }

    #[test]
    fn a_terminal_error_is_tagged_once_and_stops_the_direction() {
        let mut observed = Observed::new(Refused);
        let mut packet = Decoded::default();
        observed.data(
            b"x",
            Place {
                offset: Some(0),
                len: 1,
                ..Place::default()
            },
            &mut packet,
        );
        assert_eq!(packet.tags, ["malformed"]);
        assert!(packet.info.starts_with("Refused: decoder error:"));
        assert!(observed.failed().is_some());
        assert!(!observed.waiting());
        let mut later = Decoded::default();
        observed.data(b"y", Place::default(), &mut later);
        assert!(later.tags.is_empty());
        assert!(later.info.is_empty());
    }

    struct Two;
    impl Decode for Two {
        type Item = ();
        type Error = std::convert::Infallible;
        const NAME: &'static str = "Two";
        fn capacity(&self) -> usize {
            2
        }
        fn decode(
            &mut self,
            input: &[u8],
            _: bool,
        ) -> Result<crate::stdlib::codec::Step<()>, Self::Error> {
            Ok(if input.len() >= 2 {
                crate::stdlib::codec::Step::Item((), 2)
            } else {
                crate::stdlib::codec::Step::Need
            })
        }
    }
    impl Present for Two {
        fn summary(_: &()) -> String {
            "two bytes".into()
        }
        fn fields(_: &(), _: &[u8], _: &mut Layer) {}
    }

    #[test]
    fn reset_keeps_hops_and_uses_the_next_inner_offset() {
        let mut spans = Spans::new(8);
        spans.skip(4);
        spans.push_exact(2);
        let mut observed = Observed::new(Two);
        assert!(observed.placement().through(spans));
        let at = Place {
            offset: Some(0),
            len: 6,
            ..Place::default()
        };
        let mut packet = Decoded::default();
        observed.data(b"ab", at, &mut packet);
        assert_eq!((packet.layers[0].buf, packet.layers[0].range), (0, (4, 6)));
        observed = observed.reset();
        let mut packet = Decoded::default();
        observed.data(
            b"cd",
            Place {
                stream_start: 6,
                ..at
            },
            &mut packet,
        );
        // Without a fresh mapping the next item must get its own bytes.
        assert_eq!((packet.layers[0].buf, packet.layers[0].range), (1, (0, 2)));
        assert_eq!(packet.extra[0].1, b"cd");
    }

    #[test]
    fn live_hops_keep_mapping_payloads_after_reset() {
        let mut observed = Observed::new(Two);
        assert!(observed.placement().through(Spans::new(8)));
        for stream_start in [0, 6, 12] {
            let spans = observed.placement().hop_mut(0).unwrap();
            spans.skip(4);
            spans.push_exact(2);
            let mut packet = Decoded::default();
            observed.data(
                b"ab",
                Place {
                    stream_start,
                    offset: Some(0),
                    len: 6,
                    ..Place::default()
                },
                &mut packet,
            );
            assert_eq!((packet.layers[0].buf, packet.layers[0].range), (0, (4, 6)));
            assert!(packet.extra.is_empty());
            observed = observed.reset();
        }
        assert!(observed.placement().hop_mut(1).is_none());
    }

    #[test]
    fn first_use_starts_at_the_current_inner_run() {
        let mut spans = Spans::new(8);
        spans.skip(4);
        spans.push_exact(2);
        spans.skip(4);
        spans.push_exact(2);
        let mut observed = Observed::new(Two);
        assert!(observed.placement().through(spans));
        let mut packet = Decoded::default();
        observed.data(
            b"cd",
            Place {
                stream_start: 6,
                offset: Some(0),
                len: 6,
                ..Place::default()
            },
            &mut packet,
        );
        assert_eq!((packet.layers[0].buf, packet.layers[0].range), (0, (4, 6)));
    }

    #[test]
    fn placement_follows_several_exact_hops_and_partial_spans() {
        let mut inner = Spans::new(8);
        inner.skip(2);
        inner.push_exact(4);
        inner.push_exact(4);
        let mut outer = Spans::new(8);
        outer.skip(20);
        outer.push_exact(10);
        let mut place = Placement::new(Place {
            stream_start: 0,
            buf: 0,
            offset: Some(40),
            len: 30,
        });
        assert!(place.through(inner));
        assert!(place.through(outer));
        let mut packet = Decoded::default();
        assert_eq!(place.locate(&mut packet, 1, b"abcde", "inner"), (0, 63));
        assert!(packet.extra.is_empty());
        let mut layer = Layer::new("inner", 0, (0, 5));
        layer.field("part", "bcd", (1, 4));
        place.push(&mut packet, 1, b"abcde", "inner", layer);
        assert_eq!(packet.layers[0].range, (63, 68));
        assert_eq!(packet.layers[0].fields[0].range, Some((64, 67)));
    }

    #[test]
    fn gaps_coarse_mappings_and_expired_spans_get_their_own_bytes() {
        for coarse in [false, true] {
            let mut spans = Spans::new(2);
            if coarse {
                spans.push(4, 4);
            } else {
                spans.push_exact(2);
                spans.skip(1);
                spans.push_exact(2);
            }
            let mut place = Placement::new(Place {
                offset: Some(40),
                len: 20,
                ..Place::default()
            });
            assert!(place.through(spans));
            let mut packet = Decoded::default();
            assert_eq!(place.locate(&mut packet, 0, b"abcd", "joined"), (1, 0));
            assert_eq!(packet.extra, [("joined".into(), b"abcd".to_vec())]);
        }
        let mut spans = Spans::new(1);
        spans.push_exact(2);
        spans.push_exact(2);
        let mut place = Placement::new(Place {
            offset: Some(0),
            len: 4,
            ..Place::default()
        });
        assert!(place.through(spans));
        assert_eq!(
            place.locate(&mut Decoded::default(), 0, b"ab", "expired"),
            (1, 0)
        );
    }

    #[test]
    fn packet_boundaries_and_overflow_do_not_create_invalid_ranges() {
        let at = Place {
            stream_start: 3,
            offset: Some(40),
            len: 5,
            ..Place::default()
        };
        for (start, raw) in [(0, &b"abc"[..]), (7, &b"abc"[..]), (u64::MAX, &b"a"[..])] {
            assert_eq!(
                at.locate(&mut Decoded::default(), start, raw, "split"),
                (1, 0)
            );
        }
        let place = Placement::new(Place {
            offset: Some(usize::MAX),
            len: 1,
            ..Place::default()
        });
        let mut packet = Decoded::default();
        let mut layer = Layer::new("x", 0, (0, 1));
        layer.field("bad", "range", (1, usize::MAX));
        place.push(&mut packet, 0, b"a", "x", layer);
        assert_eq!(packet.layers[0].range, (0, 1));
        assert_eq!(packet.layers[0].fields[0].range, None);
    }
}
