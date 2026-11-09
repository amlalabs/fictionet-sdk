use fictionet::stdlib::dissect::{Decoded, Match, Place, Protocol, Registry, Selection};
use fictionet::stdlib::layer::Termination;
use fictionet::stdlib::network::Transport;

/// Selects and drives one ordered byte conversation in both directions.
/// Direction zero sends from the first port to the second. TCP callers use
/// endpoints sorted by address and port; nested streams keep that order.
///
/// Holds at most 64 prefix bytes per direction until a protocol is chosen.
/// Selection flushes both prefixes through the selected public [`Protocol`].
/// Eight unmatched bytes reject the conversation permanently. A matcher still
/// returning [`Match::More`] at 64 bytes also rejects it; lower-priority
/// matchers do not run. Undecided and rejected conversations are not waiting.
pub struct Conversation {
    ports: (u16, u16),
    alpn: Option<String>,
    name: Option<String>,
    registry: Registry,
    protocol: Option<Box<dyn Protocol>>,
    prefix: [Vec<u8>; 2],
    prefix_start: [u64; 2],
    /// Bytes were lost in this direction before a protocol was chosen.
    lost_early: [bool; 2],
    /// This direction ended cleanly before a protocol was chosen.
    ended_early: [bool; 2],
    rejected: bool,
}

impl Conversation {
    /// Starts automatic or explicit selection using the supplied registry.
    pub fn with_registry(port_a: u16, port_b: u16, registry: Registry) -> Self {
        Self {
            ports: (port_a, port_b),
            name: None,
            alpn: None,
            registry,
            protocol: None,
            prefix: [Vec::new(), Vec::new()],
            prefix_start: [0; 2],
            lost_early: [false; 2],
            ended_early: [false; 2],
            rejected: false,
        }
    }

    /// Supplies the service protocol before bytes arrive.
    pub fn with_protocol(mut self, name: Option<&str>) -> Self {
        self.name = name.map(str::to_owned);
        self
    }

    /// Supplies the negotiated ALPN to matchers for a nested stream.
    /// Call this before feeding any bytes. It does not choose a protocol.
    pub fn with_alpn(mut self, alpn: Option<String>) -> Self {
        self.alpn = alpn;
        self
    }

    /// Whether a chosen protocol holds part of a message in this direction.
    pub fn waiting(&self, dir: bool) -> bool {
        self.protocol.as_ref().is_some_and(|p| p.waiting(dir))
    }

    /// Discards this direction's prefix and tells the selected protocol about
    /// missing bytes. Before selection, the protocol chosen later is told
    /// first. A rejected conversation stays rejected.
    pub fn lost(&mut self, dir: bool) {
        if let Some(protocol) = &mut self.protocol {
            protocol.lost(dir);
        } else if let Some(lost) = self.lost_early.get_mut(usize::from(dir)) {
            *lost = true;
        }
        if let Some(prefix) = self.prefix.get_mut(usize::from(dir)) {
            prefix.clear();
        }
    }

    /// Tells the selected protocol how this direction ended, and appends
    /// what that completes to `d`. Before selection, an end that is not
    /// clean discards the prefix, as [`lost`](Self::lost) does; a clean end
    /// keeps it, and the protocol chosen later is told of the end after
    /// the prefix, so what the end completes is shown then.
    pub fn end(&mut self, dir: bool, how: Termination, d: &mut Decoded) {
        match &mut self.protocol {
            Some(protocol) => protocol.end(dir, how, d),
            None if !how.is_clean() => self.lost(dir),
            None => {
                if let Some(ended) = self.ended_early.get_mut(usize::from(dir)) {
                    *ended = true;
                }
            }
        }
    }

    /// Processes ordered bytes and appends completed messages to `d`.
    /// `place` locates this chunk in the current packet. Earlier prefix bytes
    /// receive reassembly buffers. TLS reads its keys from the registry's
    /// [`KeyLog`](super::KeyLog).
    pub fn data(&mut self, dir: bool, bytes: &[u8], place: Place, d: &mut Decoded) {
        if self.rejected {
            return;
        }
        if let Some(protocol) = &mut self.protocol {
            protocol.data(dir, bytes, place, d);
            return;
        }
        let i = usize::from(dir);
        let Some(prefix) = self.prefix.get_mut(i) else {
            return;
        };
        let old = prefix.len();
        if old == 0 {
            self.prefix_start[i] = place.stream_start;
        }
        prefix.extend_from_slice(
            bytes
                .get(..bytes.len().min(64usize.saturating_sub(old)))
                .unwrap_or_default(),
        );
        match self.registry.open(Selection {
            transport: Transport::Tcp,
            ports: self.ports,
            first: prefix,
            protocol: self.name.as_deref(),
            alpn: self.alpn.as_deref(),
        }) {
            Ok(mut protocol) => {
                prefix.truncate(old);
                // Selection applies to both directions. Flush every earlier
                // prefix now, including a peer that may never send again.
                for j in [1 - i, i] {
                    if self.lost_early[j] {
                        protocol.lost(j != 0);
                    }
                    let held = &mut self.prefix[j];
                    if !held.is_empty() {
                        protocol.data(
                            j != 0,
                            held,
                            Place {
                                stream_start: self.prefix_start[j],
                                len: held.len(),
                                ..Place::default()
                            },
                            d,
                        );
                        held.clear();
                    }
                    if self.ended_early[j] {
                        protocol.end(j != 0, Termination::Fin, d);
                    }
                }
                protocol.data(dir, bytes, place, d);
                self.protocol = Some(protocol);
            }
            Err(decision) => {
                if prefix.len() >= 64 || (decision == Match::No && prefix.len() >= 8) {
                    self.rejected = true;
                    self.prefix.iter_mut().for_each(Vec::clear);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::dissect::{Layer, Present};

    #[test]
    fn more_at_the_prefix_limit_rejects_without_falling_through() {
        let mut registry = Registry::new();
        registry.register("fallback", |_| Match::Yes, |_| [Tiny, Tiny]);
        registry.register("pending", |_| Match::More, |_| [Tiny, Tiny]);
        let mut conversation = Conversation::with_registry(1, 2, registry);
        let mut packet = Decoded::default();
        for _ in 0..64 {
            conversation.data(false, b"x", Place::default(), &mut packet);
            assert!(!conversation.waiting(false));
        }
        assert!(conversation.rejected);
        conversation.data(true, b"\x01x", Place::default(), &mut packet);
        assert!(packet.layers.is_empty());
        assert!(conversation.prefix.iter().all(Vec::is_empty));
    }
    struct Tiny;
    impl fictionet::stdlib::codec::Decode for Tiny {
        type Item = Vec<u8>;
        type Error = std::convert::Infallible;
        const NAME: &'static str = "Tiny";
        fn capacity(&self) -> usize {
            256
        }
        fn decode(
            &mut self,
            input: &[u8],
            _: bool,
        ) -> Result<fictionet::stdlib::codec::Step<Vec<u8>>, Self::Error> {
            use fictionet::stdlib::codec::Step;
            let Some(&len) = input.first() else {
                return Ok(Step::Need);
            };
            let end = 1 + usize::from(len);
            Ok(match input.get(1..end) {
                Some(bytes) => Step::Item(bytes.to_vec(), end),
                None => Step::Need,
            })
        }
    }
    impl Present for Tiny {
        fn summary(item: &Vec<u8>) -> String {
            String::from_utf8_lossy(item).into_owned()
        }
        fn fields(_: &Vec<u8>, _: &[u8], _: &mut Layer) {}
    }

    struct Feeder {
        c: Conversation,
        at: [u64; 2],
    }

    impl Feeder {
        fn send(&mut self, dir: bool, bytes: &[u8], chunk: usize) -> Decoded {
            let mut d = Decoded::default();
            for piece in bytes.chunks(chunk) {
                d = Decoded::default();
                let place = Place {
                    stream_start: self.at[dir as usize],
                    buf: 0,
                    offset: Some(0),
                    len: piece.len(),
                };
                self.c.data(dir, piece, place, &mut d);
                self.at[dir as usize] += piece.len() as u64;
            }
            d
        }
    }
    #[test]
    fn selection_flushes_the_other_directions_prefix() {
        for partial in [false, true] {
            let mut registry = Registry::new();
            registry.register(
                "tiny",
                |s| {
                    if s.first == b"\x01b" {
                        Match::Yes
                    } else {
                        Match::More
                    }
                },
                |_| [Tiny, Tiny],
            );
            let mut f = Feeder {
                c: Conversation::with_registry(1, 2, registry),
                at: [0, 0],
            };
            let prefix: &[u8] = if partial { b"\x05he" } else { b"\x01a" };
            f.send(false, prefix, prefix.len());
            assert!(!f.c.waiting(false));
            let packet = f.send(true, b"\x01b", 2);
            assert!(f.c.prefix.iter().all(Vec::is_empty));
            assert_eq!(f.c.waiting(false), partial);
            if partial {
                assert_eq!(f.send(false, b"llo", 3).info, "hello");
                assert!(!f.c.waiting(false));
            } else {
                assert_eq!(packet.info, "a, b");
                assert_eq!(packet.extra[0].1, prefix);
            }
        }
    }

    /// A message read to the end of its stream: it completes only at the
    /// end.
    struct ToEnd;
    impl fictionet::stdlib::codec::Decode for ToEnd {
        type Item = Vec<u8>;
        type Error = std::convert::Infallible;
        const NAME: &'static str = "To end";
        fn capacity(&self) -> usize {
            256
        }
        fn decode(
            &mut self,
            input: &[u8],
            eof: bool,
        ) -> Result<fictionet::stdlib::codec::Step<Vec<u8>>, Self::Error> {
            use fictionet::stdlib::codec::Step;
            Ok(match (eof, input.len()) {
                (false, _) => Step::Need,
                (true, 0) => Step::End,
                (true, n) => Step::Item(input.to_vec(), n),
            })
        }
    }
    impl Present for ToEnd {
        fn summary(item: &Vec<u8>) -> String {
            String::from_utf8_lossy(item).into_owned()
        }
        fn fields(_: &Vec<u8>, _: &[u8], _: &mut Layer) {}
    }

    /// A direction that ends with a FIN before either direction chose a
    /// protocol is finished once the other direction chooses one: its
    /// prefix goes to the protocol, then its end, so a message the FIN
    /// completes is shown and nothing is left waiting.
    #[test]
    fn a_fin_before_the_choice_finishes_the_prefix_after_it() {
        let mut registry = Registry::new();
        registry.register(
            "to-end",
            |s| {
                if s.first.starts_with(b"go") {
                    Match::Yes
                } else {
                    Match::More
                }
            },
            |_| [ToEnd, ToEnd],
        );
        let mut f = Feeder {
            c: Conversation::with_registry(1, 2, registry),
            at: [0, 0],
        };
        f.send(false, b"bye", 3);
        let mut fin = Decoded::default();
        f.c.end(false, Termination::Fin, &mut fin);
        assert!(fin.layers.is_empty());
        let chosen = f.send(true, b"go", 2);
        let layer = chosen
            .layers
            .iter()
            .find(|l| l.summary == "bye")
            .expect("the FIN completes the message");
        assert_eq!(chosen.extra[layer.buf - 1].1, b"bye");
        assert!(!f.c.waiting(false));
        assert!(f.c.waiting(true));
    }
}
