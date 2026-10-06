use super::{Decoded, KeyLine, Observed, Place, Present};
use std::sync::Arc;

/// The transport carrying an application conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// An ordered TCP byte stream.
    Tcp,
    /// One UDP datagram. The selected decoder receives EOF after it.
    Udp,
}

/// Inputs to a protocol matcher. TCP ports are in conversation order;
/// UDP ports are source then destination. `first` is a bounded prefix.
#[derive(Clone, Copy, Debug)]
pub struct Selection<'a> {
    /// The transport carrying these bytes.
    pub transport: Transport,
    /// The conversation's two ports. TCP endpoints sort by address, then
    /// port. Direction zero sends from the first port to the second.
    pub ports: (u16, u16),
    /// First bytes of the direction currently being identified.
    pub first: &'a [u8],
    /// The negotiated TLS ALPN, when these bytes came from a TLS session.
    pub alpn: Option<&'a str>,
}

/// A protocol matcher's decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// Select this protocol.
    Yes,
    /// More prefix bytes could identify this protocol. UDP treats this
    /// as `No` because a datagram cannot grow.
    More,
    /// This protocol does not match.
    No,
}

/// A selected conversation. Implement this only for protocols needing
/// shared session state or typed inputs, such as TLS. Byte decoders use
/// [`Registry::register`] and [`Observed`] directly.
pub trait Protocol: Send {
    /// Processes ordered bytes in one direction. `reverse` selects the
    /// second direction. Keys are TLS secrets supplied by the capture owner.
    fn data(
        &mut self,
        reverse: bool,
        bytes: &[u8],
        at: Place,
        packet: &mut Decoded,
        keys: &[KeyLine],
    );
    /// Whether this direction holds part of a message.
    fn waiting(&self, reverse: bool) -> bool;
    /// Discards state invalidated by missing bytes in this direction.
    fn lost(&mut self, reverse: bool);
    /// Finishes a datagram or stream. The default has no final output.
    fn end(&mut self, _reverse: bool, _packet: &mut Decoded) {}
}

type Matcher = dyn Fn(Selection<'_>) -> Match + Send + Sync;
type Factory = dyn Fn(Selection<'_>, &Registry) -> Box<dyn Protocol> + Send + Sync;
struct Entry {
    name: String,
    matches: Box<Matcher>,
    make: Box<Factory>,
}

/// Protocol factories used by a [`Dissector`](super::Dissector) or a live
/// world's [`Cx::observe_protocols`](crate::Cx::observe_protocols).
///
/// `default()` registers the built-ins. `new()` starts empty. Later
/// registrations take precedence. A matcher returning [`Match::More`]
/// postpones lower-priority TCP matchers. [`Conversation`](super::Conversation)
/// rejects the conversation if that matcher still returns `More` at 64
/// prefix bytes in a direction. It does not fall through to other matchers.
/// For UDP it acts as `No`: a datagram cannot grow. Explicit selection
/// bypasses matchers only for the chosen transport.
#[derive(Clone)]
pub struct Registry {
    entries: Vec<Arc<Entry>>,
    choice: [Option<String>; 2],
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("names", &self.entries.iter().map(|e| &e.name).collect::<Vec<_>>())
            .field("choice", &self.choice)
            .finish()
    }
}

impl Default for Registry {
    fn default() -> Self {
        let mut registry = Self::new();
        super::app::register(&mut registry);
        registry
    }
}

impl Registry {
    /// Creates a registry with no protocols.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            choice: [None, None],
        }
    }

    /// Registers a byte decoder pair. Both directions use the same public
    /// adapter. The factory runs once per conversation or UDP datagram.
    pub fn register<D>(
        &mut self,
        name: &str,
        matches: impl Fn(Selection<'_>) -> Match + Send + Sync + 'static,
        make: impl Fn(Selection<'_>) -> [D; 2] + Send + Sync + 'static,
    ) where
        D: Present + Send + 'static,
        D::Error: Clone + Send,
    {
        self.register_with_buffer(name, matches, 0, make);
    }

    /// Registers a decoder pair with bounded input read-ahead. This is
    /// useful for capture framers that can display a complete large item
    /// already in a packet. A zero limit uses each decoder's capacity.
    pub fn register_with_buffer<D>(
        &mut self,
        name: &str,
        matches: impl Fn(Selection<'_>) -> Match + Send + Sync + 'static,
        limit: usize,
        make: impl Fn(Selection<'_>) -> [D; 2] + Send + Sync + 'static,
    ) where
        D: Present + Send + 'static,
        D::Error: Clone + Send,
    {
        self.register_protocol(name, matches, move |selection, _| {
            Box::new(Pair {
                dirs: make(selection).map(|d| Some(Observed::with_buffer(d, limit))),
            })
        });
    }

    /// Registers a session factory through the same selection mechanism
    /// as a byte decoder. A duplicate name replaces its earlier factory.
    /// The factory receives this registry, including all user registrations.
    /// Clone it to select protocols inside a session such as TLS.
    pub fn register_protocol(
        &mut self,
        name: &str,
        matches: impl Fn(Selection<'_>) -> Match + Send + Sync + 'static,
        make: impl Fn(Selection<'_>, &Registry) -> Box<dyn Protocol> + Send + Sync + 'static,
    ) {
        self.entries.retain(|entry| entry.name != name);
        self.entries.push(Arc::new(Entry {
            name: name.to_owned(),
            matches: Box::new(matches),
            make: Box::new(make),
        }));
    }

    /// Selects a registered name for subsequent conversations on `transport`.
    /// Returns false for an unknown name and leaves the choice unchanged.
    pub fn choose(&mut self, transport: Transport, name: &str) -> bool {
        if !self.entries.iter().any(|entry| entry.name == name) {
            return false;
        }
        self.choice[transport as usize] = Some(name.to_owned());
        true
    }

    /// Restores selection by matchers for `transport`.
    pub fn automatic(&mut self, transport: Transport) {
        self.choice[transport as usize] = None;
    }

    /// Returns the selected name, or the decision to wait or reject.
    pub fn select(&self, input: Selection<'_>) -> Result<&str, Match> {
        if let Some(name) = &self.choice[input.transport as usize] {
            return Ok(name);
        }
        for entry in self.entries.iter().rev() {
            match (entry.matches)(input) {
                Match::Yes => return Ok(&entry.name),
                Match::More if input.transport == Transport::Tcp => return Err(Match::More),
                Match::More | Match::No => {}
            }
        }
        Err(Match::No)
    }

    /// Instantiates the selected conversation. Returns `More` while a
    /// TCP matcher needs prefix bytes, or `No` when nothing matches.
    pub fn open(&self, input: Selection<'_>) -> Result<Box<dyn Protocol>, Match> {
        let name = self.select(input)?;
        self.entries
            .iter()
            .find(|e| e.name == name)
            .map(|e| (e.make)(input, self))
            .ok_or(Match::No)
    }
}

struct Pair<D: Present> {
    dirs: [Option<Observed<D>>; 2],
}

impl<D: Present + Send> Protocol for Pair<D>
where
    D::Error: Clone + Send,
{
    fn data(
        &mut self,
        reverse: bool,
        bytes: &[u8],
        at: Place,
        packet: &mut Decoded,
        _: &[KeyLine],
    ) {
        if let Some(dir) = self
            .dirs
            .get_mut(usize::from(reverse))
            .and_then(Option::as_mut)
        {
            dir.data(bytes, at, packet);
        }
    }
    fn waiting(&self, reverse: bool) -> bool {
        self.dirs
            .get(usize::from(reverse))
            .and_then(Option::as_ref)
            .is_some_and(Observed::waiting)
    }
    fn lost(&mut self, reverse: bool) {
        if let Some(slot) = self.dirs.get_mut(usize::from(reverse)) {
            *slot = slot.take().map(Observed::reset);
        }
    }
    fn end(&mut self, reverse: bool, packet: &mut Decoded) {
        if let Some(dir) = self
            .dirs
            .get_mut(usize::from(reverse))
            .and_then(Option::as_mut)
        {
            dir.end(packet);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::protocols::Modbus;

    fn input(ports: (u16, u16), first: &[u8]) -> Selection<'_> {
        Selection {
            transport: Transport::Tcp,
            ports,
            first,
            alpn: None,
        }
    }

    #[test]
    fn selects_ports_prefixes_and_an_explicit_name() {
        let mut registry = Registry::new();
        registry.register(
            "port",
            |s| {
                if s.ports.0 == 42 || s.ports.1 == 42 {
                    Match::Yes
                } else {
                    Match::No
                }
            },
            |_| [Modbus::new(true), Modbus::new(false)],
        );
        registry.register(
            "prefix",
            |s| {
                if s.first.starts_with(b"tiny") {
                    Match::Yes
                } else if b"tiny".starts_with(s.first) {
                    Match::More
                } else {
                    Match::No
                }
            },
            |_| [Modbus::new(true), Modbus::new(false)],
        );
        assert_eq!(registry.select(input((9, 42), b"other")), Ok("port"));
        assert_eq!(registry.select(input((9, 10), b"tiny!")), Ok("prefix"));
        assert_eq!(registry.select(input((9, 42), b"ti")), Err(Match::More));
        assert_eq!(registry.select(input((9, 10), b"other")), Err(Match::No));
        assert!(registry.choose(Transport::Tcp, "port"));
        assert_eq!(registry.select(input((9, 10), b"tiny!")), Ok("port"));
        assert!(!registry.choose(Transport::Tcp, "missing"));
        assert_eq!(registry.select(input((9, 10), b"tiny!")), Ok("port"));
        registry.automatic(Transport::Tcp);
        assert_eq!(registry.select(input((9, 10), b"tiny!")), Ok("prefix"));
    }

    #[test]
    fn transport_choices_and_incomplete_tcp_matchers_do_not_hide_datagrams() {
        let mut registry = Registry::default();
        assert!(registry.choose(Transport::Tcp, "http1"));
        registry.register(
            "short-prefix",
            |_| Match::More,
            |_| [Modbus::new(true), Modbus::new(false)],
        );
        for (ports, name) in [((40000, 53), "dns"), ((67, 68), "dhcp")] {
            let selection = Selection {
                transport: Transport::Udp,
                ..input(ports, &[0])
            };
            assert_eq!(registry.select(selection), Ok(name));
        }
        assert_eq!(registry.select(input((40000, 53), &[0])), Ok("http1"));
        assert!(registry.choose(Transport::Udp, "dns"));
        let selection = Selection {
            transport: Transport::Udp,
            ..input((67, 68), &[0])
        };
        assert_eq!(registry.select(selection), Ok("dns"));
        registry.automatic(Transport::Udp);
        assert_eq!(registry.select(selection), Ok("dhcp"));
        registry.automatic(Transport::Tcp);
        assert_eq!(registry.select(input((40000, 53), &[0])), Err(Match::More));
    }

    #[test]
    fn user_registration_can_replace_a_builtin() {
        let mut registry = Registry::default();
        registry.register(
            "modbus",
            |_| Match::Yes,
            |_| [Modbus::new(true), Modbus::new(false)],
        );
        assert_eq!(registry.select(input((12, 13), b"")), Ok("modbus"));
        assert_eq!(
            registry
                .entries
                .iter()
                .filter(|e| e.name == "modbus")
                .count(),
            1
        );
    }
}
