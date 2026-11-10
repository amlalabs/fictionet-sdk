//! The TCP endpoint as a [layer](fictionet::stdlib::layer): whole IP
//! packets below, one byte-stream child per connection above.
//!
//! [`TcpLayer`] owns everything one machine's TCP keeps: the smoltcp
//! interface and socket set, the listeners with their backlogs and SYN
//! cookies, the handshake answers and segment options a listener supplies,
//! the buffers and their pages, keepalive, retransmission and TIME-WAIT,
//! the orphans of closed connections, and what a closed port or a SYN from
//! port 0 gets. Its time and entropy come from the [`Env`] of each call; it
//! never polls an interface, sleeps, spawns a task or wakes one.
//!
//! The async [`Endpoint`](super::Endpoint) runs one of these behind its
//! handles: its task feeds packets in and sends packets out, and its
//! listeners and connections send commands and read the events that come
//! up. A world can instead put applications straight on the children with
//! [`Children`](fictionet::stdlib::layer::Children).

use super::*;

use core::convert::Infallible;
use std::sync::Weak;

use fictionet::Entropy;
use fictionet::stdlib::layer::{
    Admit, Budget, ByteStream, Charge, ChargedBytes, ChargedVec, Child, ChildId, Chunk, Closing,
    CommandOf, Env, EventOf, Layer, MessageCommand, MessageEvent, Messages, MuxEvent, MuxOp,
    PacketCommand, PacketEvent, Packets, Slots, StreamCommand, StreamEvent,
};
use fictionet::stdlib::network::Transport;
use fictionet::stdlib::network::packet::{CheckedIpPacket, Sort};
use fictionet::stdlib::network::transport::{
    Request, Tcp, TcpControl, TcpNotice, TcpOpening, TcpOrigin,
};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Events waiting for the layer above, past which no new data, connection
/// or packet is taken in until the layer above takes some.
const UP_ROOM: usize = 64;
/// The most bytes one data event carries.
const DATA_MAX: usize = 64 * 1024;
/// Initial socket and listener places, grown together before admitting more.
const STORAGE_FLOOR: usize = 4;

/// An event for the layer above.
type Up = MuxEvent<ByteStream, Messages<TcpNotice, TcpControl>, TcpOpening>;

/// The time smoltcp counts in, from the run's.
pub(super) fn smol(now: Instant) -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros(now.since_start().as_micros() as i64)
}

/// The run's time, from smoltcp's.
fn unsmol(at: smoltcp::time::Instant) -> Instant {
    Instant::from_since_start(Duration::from_micros(at.total_micros().max(0) as u64))
}

/// The first SYN and the listener's accepted reply.
struct Attempt {
    syn: Arc<[TcpOption]>,
    added: Vec<TcpOption>,
    syn_ipv4: Option<Vec<Ipv4Option>>,
    ipv4_reply: Ipv4Reply,
}

/// One arriving segment, as much as a reset in answer to it needs.
#[derive(Clone, Copy)]
struct Arrived {
    /// Its source.
    from: SocketAddr,
    /// Its destination.
    to: SocketAddr,
    seq: u32,
    /// Its acknowledgment number, when the ACK flag is set.
    ack: Option<u32>,
    /// SEG.LEN: its payload bytes, plus one each for SYN and FIN.
    len: u32,
    /// Its payload bytes.
    payload: usize,
}

impl Arrived {
    /// `t`, a segment from `from` to `to` that smoltcp parsed, with
    /// `payload` bytes of data.
    fn of(from: SocketAddr, to: SocketAddr, t: &[u8], payload: usize) -> Arrived {
        let flags = t[13];
        Arrived {
            from,
            to,
            seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
            ack: (flags & 0x10 != 0).then(|| u32::from_be_bytes([t[8], t[9], t[10], t[11]])),
            len: payload as u32 + u32::from(flags & 0x02 != 0) + u32::from(flags & 0x01 != 0),
            payload,
        }
    }

    /// The RST that answers this segment when it may not open or join a
    /// connection (RFC 9293 section 3.10.7.1): with the sequence number
    /// the segment acknowledged, or with sequence number 0 and an ACK of
    /// the segment when it had no ACK. It has window 0 and `options`, whole
    /// options from [`encode`], as its only options.
    fn reset(&self, options: &[u8]) -> Vec<u8> {
        let (seq, ack) = match self.ack {
            Some(ack) => (ack, None),
            None => (0, Some(self.seq.wrapping_add(self.len))),
        };
        segment(self.to, self.from, seq, ack, 0x04, 0, options)
    }
}

/// A TCP segment with no payload from `from` to `to`, in an IP packet with
/// the header [`packet`](fictionet::stdlib::network::ip::packet) writes.
/// `flags` gets ACK added when there is an `ack`, and `options` are whole
/// options, padded here with End of Option List.
fn segment(
    from: SocketAddr,
    to: SocketAddr,
    seq: u32,
    ack: Option<u32>,
    flags: u8,
    window: u16,
    options: &[u8],
) -> Vec<u8> {
    let area = options.len().div_ceil(4) * 4;
    let mut t = vec![0; 20 + area];
    t[0..2].copy_from_slice(&from.port().to_be_bytes());
    t[2..4].copy_from_slice(&to.port().to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.unwrap_or(0).to_be_bytes());
    t[12] = ((20 + area) / 4) as u8 * 16;
    t[13] = flags | if ack.is_some() { 0x10 } else { 0 };
    t[14..16].copy_from_slice(&window.to_be_bytes());
    t[20..20 + options.len()].copy_from_slice(options);
    let sum = transport_checksum(from.ip(), to.ip(), TCP, &t);
    t[16..18].copy_from_slice(&sum.to_be_bytes());
    fictionet::stdlib::network::ip::packet(from.ip(), to.ip(), TCP, &t).0
}

/// An HMAC-SHA256 key of 32 bytes from the run's random stream.
fn secret(entropy: &dyn Entropy) -> ring::hmac::Key {
    let mut key = [0; 32];
    entropy.fill_random(&mut key);
    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key)
}

/// Appends the address and port of each of `ends`.
pub(super) fn put_ends(message: &mut Vec<u8>, ends: [SocketAddr; 2]) {
    for end in ends {
        match end.ip() {
            IpAddr::V4(a) => message.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => message.extend_from_slice(&a.octets()),
        }
        message.extend_from_slice(&end.port().to_be_bytes());
    }
}

/// The key of an endpoint's initial sequence numbers.
struct Sequences(ring::hmac::Key);

impl Sequences {
    /// The initial sequence number of a connection from `local` to
    /// `remote` that starts at `now`, as RFC 6528 section 3 has it: the
    /// first 32 bits of an HMAC-SHA256 of the endpoints, plus a clock that
    /// ticks every 4 microseconds. A peer learns nothing from its own
    /// connections' numbers about those of another address or port, and
    /// a new connection on the same endpoints starts past the old one.
    fn initial(&self, local: SocketAddr, remote: SocketAddr, now: smoltcp::time::Instant) -> u32 {
        let mut message = Vec::with_capacity(36);
        put_ends(&mut message, [local, remote]);
        let tag = ring::hmac::sign(&self.0, &message);
        let t = tag.as_ref();
        let clock = (now.total_micros().max(0) as u64 / 4) as u32;
        u32::from_be_bytes([t[0], t[1], t[2], t[3]]).wrapping_add(clock)
    }
}

/// The packets going into and out of smoltcp.
///
/// A packet's buffer is kept once smoltcp has read it, and the next packet
/// smoltcp sends is written into it: in a steady exchange, the buffers the
/// peer's packets arrived in carry the answers, and the engine allocates
/// none. The kept buffers are bounded in number and size.
#[derive(Default)]
pub(super) struct Dev {
    pub(super) rx: Option<Vec<u8>>,
    /// What smoltcp sent since the endpoint last looked at its packets.
    pub(super) tx: Vec<Vec<u8>>,
    /// Packets the endpoint has looked at, for the layer below to take.
    out: VecDeque<Vec<u8>>,
    /// Buffers of packets smoltcp has read, for the packets it sends.
    spare: Spare,
    /// The buffer of the packet smoltcp is reading, once it is done.
    read: Option<Vec<u8>>,
}

/// The pool of packet buffers an engine keeps: those of the packets it has
/// read, emptied, for the packets it sends. Bounded in number and size, so
/// an engine holds at most `PACKETS * MTU` of them.
#[derive(Default)]
struct Spare(Option<ChargedVec<Vec<u8>>>);

impl Spare {
    /// How many buffers it keeps.
    const PACKETS: usize = EGRESS_PACKETS;

    /// Keeps a buffer, if there is room for one of its size.
    fn keep(&mut self, mut buffer: Vec<u8>) {
        if buffer.capacity() <= MTU
            && let Some(buffers) = &mut self.0
        {
            buffer.clear();
            let _ = buffers.push(buffer);
        }
    }

    /// A zeroed buffer of `len` bytes: a kept one when there is one.
    fn take(&mut self, len: usize) -> Vec<u8> {
        let mut buffer = self
            .0
            .as_mut()
            .and_then(ChargedVec::pop)
            .unwrap_or_default();
        // Resizing a small reused vector geometrically could exceed the MTU.
        if buffer.capacity() < len {
            buffer.reserve_exact(len - buffer.len());
        }
        buffer.resize(len, 0);
        buffer
    }
}

impl Dev {
    /// Whether the output allowance is used up: smoltcp may not send
    /// until the layer below takes some packets.
    fn full(&self) -> bool {
        self.tx.len() + self.out.len() >= EGRESS_PACKETS
    }

    /// Takes back the buffer of the packet smoltcp read, or did not read.
    fn reclaim(&mut self) {
        if let Some(buffer) = self.read.take().or_else(|| self.rx.take()) {
            self.spare.keep(buffer);
        }
    }
}

pub(super) struct Rx<'a> {
    bytes: Vec<u8>,
    read: &'a mut Option<Vec<u8>>,
}

pub(super) struct Tx<'a> {
    tx: &'a mut Vec<Vec<u8>>,
    spare: &'a mut Spare,
}

impl RxToken for Rx<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        let r = f(&self.bytes);
        *self.read = Some(self.bytes);
        r
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = self.spare.take(len);
        let r = f(&mut buf);
        self.tx.push(buf);
        r
    }
}

impl Device for Dev {
    type RxToken<'a> = Rx<'a>;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx<'_>, Tx<'_>)> {
        if self.full() {
            return None;
        }
        let bytes = self.rx.take()?;
        let Dev {
            tx, spare, read, ..
        } = self;
        Some((Rx { bytes, read }, Tx { tx, spare }))
    }

    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        (!self.full()).then_some(Tx {
            tx: &mut self.tx,
            spare: &mut self.spare,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            max_transmission_unit: MTU,
        }
    }
}

/// A socket's name inside [`TcpLayer`]: its slot in the socket set, and
/// the slot's generation when the socket took it.
///
/// A slot is reused once its socket goes, in the next generation, so an
/// id outlives its socket harmlessly: it no longer finds a socket or a
/// connection. Ids order by slot, which is the socket set's own scan
/// order, so every order the engine keeps by id is a function of the
/// sockets' history alone.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) struct Id {
    slot: SocketHandle,
    generation: u64,
}

impl std::hash::Hash for Id {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.generation.rotate_left(32) ^ self.slot.index() as u64);
    }
}

/// What the engine keeps for one slot of the socket set.
#[derive(Default)]
struct Slot {
    /// The generation of the slot's socket, or of the next one while the
    /// slot is empty.
    generation: u64,
    /// The slot holds a socket.
    used: bool,
    /// The connection of the slot's socket. A listening socket has none.
    conn: Option<Conn>,
}

/// The sockets and their connections, in one slab indexed by the socket
/// set's slots. Each slot carries a generation, so a stale [`Id`] finds
/// nothing. Slots are reused lowest first, as the socket set reuses
/// them, and are never moved: the slab grows to the most sockets held at
/// once and keeps its slots. Transport changes and application credit
/// share the socket set's retained queue.
pub(super) struct Sockets {
    set: SocketSet<'static>,
    /// One per slot of `set`, empty slots included.
    slots: Vec<Slot>,
    /// How many slots hold a socket.
    live: usize,
    /// The socket refreshed last, so the next refresh starts after it.
    after: Option<Id>,
}

impl Sockets {
    fn new() -> Self {
        Self {
            set: SocketSet::default(),
            slots: Vec::new(),
            live: 0,
            after: None,
        }
    }

    fn add(&mut self, socket: stcp::Socket<'static>) -> Id {
        let slot = self.set.add(socket);
        if slot.index() == self.slots.len() {
            self.slots.push(Slot::default());
        }
        let entry = &mut self.slots[slot.index()];
        assert!(!entry.used && entry.conn.is_none(), "a free slot");
        entry.used = true;
        self.live += 1;
        Id {
            slot,
            generation: entry.generation,
        }
    }

    /// The slot of `id`, while its socket is there.
    fn slot(&self, id: Id) -> Option<&Slot> {
        self.slots
            .get(id.slot.index())
            .filter(|s| s.used && s.generation == id.generation)
    }

    fn slot_mut(&mut self, id: Id) -> Option<&mut Slot> {
        self.slots
            .get_mut(id.slot.index())
            .filter(|s| s.used && s.generation == id.generation)
    }

    /// Removes the socket of `id` and its connection, if it still has one.
    /// The slot's next socket gets the next generation.
    fn remove(&mut self, id: Id) -> stcp::Socket<'static> {
        let entry = self.slot_mut(id).expect("a live socket");
        entry.used = false;
        entry.conn = None;
        entry.generation += 1;
        self.live -= 1;
        self.set.remove(id.slot)
    }

    /// Whether the socket of `id` is still there.
    fn contains(&self, id: Id) -> bool {
        self.slot(id).is_some()
    }

    /// How many sockets there are.
    fn len(&self) -> usize {
        self.live
    }

    /// The socket set's handle on the socket of `id`.
    fn handle(&self, id: Id) -> SocketHandle {
        assert!(self.contains(id), "a live socket");
        id.slot
    }

    fn get(&self, id: Id) -> &stcp::Socket<'static> {
        self.set.get(self.handle(id))
    }

    fn get_mut(&mut self, id: Id) -> &mut stcp::Socket<'static> {
        assert!(self.contains(id), "a live socket");
        self.set.get_mut(id.slot)
    }

    /// The connection of `id`, while its socket has one.
    fn conn(&self, id: Id) -> Option<&Conn> {
        self.slot(id)?.conn.as_ref()
    }

    fn conn_mut(&mut self, id: Id) -> Option<&mut Conn> {
        self.slot_mut(id)?.conn.as_mut()
    }

    /// Gives the socket of `id` its connection.
    fn insert_conn(&mut self, id: Id, conn: Conn) {
        let entry = self.slot_mut(id).expect("a live socket");
        assert!(entry.conn.is_none(), "one connection per socket");
        entry.conn = Some(conn);
    }

    /// Takes the connection of `id` away, keeping its socket.
    fn take_conn(&mut self, id: Id) -> Option<Conn> {
        self.slot_mut(id)?.conn.take()
    }

    /// The socket of `id` and its connection, together.
    fn socket_and_conn(&mut self, id: Id) -> (&mut stcp::Socket<'static>, &mut Conn) {
        assert!(self.contains(id), "a live socket");
        let conn = self.slots[id.slot.index()]
            .conn
            .as_mut()
            .expect("a connection");
        (self.set.get_mut(id.slot), conn)
    }

    /// Every connection, in slot order.
    fn conns(&self) -> impl Iterator<Item = (Id, &Conn)> {
        self.set.iter().filter_map(|(slot, _)| {
            let conn = self.slots[slot.index()].conn.as_ref()?;
            Some((self.id_of(slot), conn))
        })
    }

    /// The id of the socket in `slot`.
    fn id_of(&self, slot: SocketHandle) -> Id {
        let s = &self.slots[slot.index()];
        assert!(s.used, "a live socket");
        Id {
            slot,
            generation: s.generation,
        }
    }

    fn mark(&mut self, id: Id) {
        assert!(self.contains(id), "a live socket");
        self.set.mark_changed(id.slot);
    }

    fn acknowledge(&mut self, id: Id) {
        if self.contains(id) {
            self.set.acknowledge_changed(id.slot);
        }
    }

    fn pending(&self) -> usize {
        self.set.changed().len()
    }

    fn next(&mut self) -> Option<Id> {
        let id = self.id_of(self.set.changed().next()?);
        self.after = Some(id);
        Some(id)
    }

    /// Orders the pending observations by id, starting after the socket
    /// refreshed last.
    fn prepare_refresh(&mut self) -> usize {
        let (after, slots) = (self.after, &self.slots);
        self.set.order_changed(|slot| {
            let id = Id {
                slot,
                generation: slots[slot.index()].generation,
            };
            (after.is_some_and(|after| id <= after), id)
        });
        self.pending()
    }
}

/// Hashes an [`Id`] by one multiplication. The engine makes the ids
/// itself from its own slots, so a keyed hash defends against nothing
/// here; maps keyed by addresses the peer chooses keep the default one.
#[derive(Default)]
pub(super) struct IdHasher(u64);

/// The hasher of a map keyed by [`Id`].
pub(super) type ById = std::hash::BuildHasherDefault<IdHasher>;

impl std::hash::Hasher for IdHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(b)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0 ^ n).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// One machine's TCP as a layer: `Packets<CheckedIpPacket, Chunk>` below, the
/// [`Tcp`] mux above. See the [module docs](super).
///
/// The endpoint owns the input path and supplies checked packets sorted to TCP.
/// Each independent network has its own IP and TCP layers.
///
/// # The layer above
///
/// Connections are children. A listener ([`TcpControl::Listen`]) takes
/// handshakes into its backlog, and each [`TcpControl::Accept`] lets one
/// that finished open a child, as `accept(2)` would; until then it counts
/// against the backlog, so a host that stops accepting gets SYN cookies or
/// dropped SYNs, as the listener's settings say. A [`TcpControl::Connect`]
/// opens its child at once, with [`TcpOrigin::Connected`]: the child gets
/// credit to write once the handshake is done, and a handshake that fails
/// is reported with [`TcpNotice::ConnectFailed`] and closes the child.
///
/// A child's stream works as a socket does. Data comes up within the
/// credit the layer above grants, straight from the receive buffer, so the
/// window opens only as the layer above reads. Credit for writing is the
/// room in the send buffer, and [`StreamEvent::Written`] says the send
/// buffer took the bytes, nothing more. [`StreamCommand::End`] sends the
/// FIN after every queued byte is acknowledged. [`StreamEvent::Ended`]
/// comes after the peer's FIN and every byte before it, and
/// [`StreamEvent::Reset`] when the connection was reset (at once) or
/// closed (after what was left to read).
///
/// Closing a child is `close(2)`: the connection finishes closing on its
/// own, with a FIN after what was written, or a RST if the layer above
/// left received bytes unread. A connection keeps what [`TcpControl::Hold`]
/// gave it until it is reset, reaches TIME-WAIT, times out or is forgotten,
/// whether or not its child is still open, and then [`TcpNotice::Gone`]
/// names it.
///
/// # Time, entropy and memory
///
/// [`Layer::deadline`] is the earliest retransmission, keepalive,
/// handshake, orphan, TIME-WAIT or page release the endpoint waits for.
/// The endpoint draws from the [`Env`]'s entropy only for each new socket's
/// IPv4 identification, when [`Settings::ipv4_id`] asks for it, and for its
/// keys and first ephemeral port when it is made.
///
/// Each socket's receive and send buffers are charged to the [`Env`]'s
/// budget before the socket is made: a SYN or a cookie that does not fit
/// is dropped, and a connect fails as refused. Data coming up is charged as
/// it is copied out, taking as much as the budget permits. Packet storage
/// and event queues are reserved on the first environment's budget; socket
/// and listener bookkeeping reserves further capacity there before growth.
/// Answers, segment-option callbacks and the cookie codec run inside the endpoint
/// and their allocations are not measured.
pub struct TcpLayer {
    pub(super) addr: IpAddr,
    pub(super) iface: Iface,
    pub(super) sockets: Sockets,
    /// Reclamation handles. Each socket also owns its mapping.
    pub(super) pages: HashMap<Id, Arc<Pages>, ById>,
    /// What each socket's buffers are charged to the budget, given back
    /// when the socket goes.
    reserved: HashMap<Id, Charge, ById>,
    /// Sockets whose buffers may hold pages that could be given back.
    pub(super) dirty: HashSet<Id, ById>,
    /// When `dirty` is next looked at.
    next_release: Option<smoltcp::time::Instant>,
    pub(super) dev: Dev,
    /// Listener maintenance in ascending port order.
    pub(super) listeners: BTreeMap<u16, Listen>,
    /// Connections by (local, remote), to note RSTs and FINs.
    pub(super) by_tuple: HashMap<(SocketAddr, SocketAddr), Id>,
    /// Local ports in use by listeners (counted once) and connections.
    pub(super) ports: HashMap<u16, usize>,
    next_port: u16,
    /// Connections the layer above closed, removed once they close.
    pub(super) orphans: Vec<Id>,
    /// Handshakes that may have left SYN-RECEIVED since housekeeping last
    /// looked: those a segment reached, and those aborted. Only a segment
    /// or an abort moves a handshake on, so housekeeping looks at these
    /// alone, however many handshakes wait.
    pub(super) touched: Vec<Id>,
    /// Retired orphans, in the order housekeeping first saw TIME-WAIT.
    pub(super) time_wait: VecDeque<Id>,
    pub(super) stopped: bool,
    /// Each new socket's receive and send buffer, in bytes.
    buffer: usize,
    /// Connections per listening port not accepted yet: [`Options::backlog`].
    backlog: usize,
    /// The key of this endpoint's SYN cookies.
    cookie_key: [u8; 32],
    pub(super) settings: Settings,
    /// Sources whose ownership the enclosing network verifies.
    isolated_peer: Option<Box<dyn Fn(IpAddr) -> bool + Send>>,
    /// The children: which socket each one is.
    children: Slots<Id>,
    /// Events for the layer above that may pass ones it refused.
    urgent: VecDeque<Up>,
    /// Events for the layer above, in order.
    up: VecDeque<Up>,
    /// Something changed that the next step must look at.
    work: bool,
    /// The interface's clock and the handshake expiry already ran for the
    /// packets of this step.
    primed: bool,
    /// When the last step ran.
    stepped: Option<Instant>,
    /// When the endpoint next needs time.
    next: Option<Instant>,
    /// The output allowance was used up in the last step.
    saturated: bool,
    /// The end went to the layer below.
    ended: bool,
    /// How many sockets and listeners `storage` pays routing for; 0 until
    /// the first budget paid the fixed storage.
    storage_places: usize,
    /// The fixed storage and routing, charged to the first budget the
    /// engine sees. Last, so it is given back after what it pays for.
    storage: Option<Charge>,
}

/// One listening port.
#[derive(Default)]
pub(super) struct Listen {
    /// Connections not accepted yet, including incomplete handshakes.
    pub(super) backlog: usize,
    /// Sockets in LISTEN, waiting for a SYN.
    pub(super) idle: Vec<Id>,
    /// Sockets that got a SYN and wait for the handshake to finish, each
    /// with when it is given up ([`Conn::gives_up`]), soonest first. So the
    /// handshakes due to be dropped are found without looking at the rest.
    pub(super) embryonic: BTreeSet<(smoltcp::time::Instant, Id)>,
    /// Connections ready for `accept`.
    pub(super) ready: VecDeque<Id>,
    /// How many of `embryonic` and `ready` each peer address has.
    pub(super) per_peer: HashMap<IpAddr, usize>,
    /// How many more connections the layer above accepts.
    accept: usize,
    /// Its say in its handshakes: [`Listener::answer`].
    answer: Option<Box<dyn Answer>>,
}

impl Listen {
    /// Where handshake `h` is in `embryonic`, if it is there.
    fn embryo(&self, h: Id, sockets: &Sockets) -> Option<(smoltcp::time::Instant, Id)> {
        let key = (sockets.conn(h)?.gives_up?, h);
        self.embryonic.contains(&key).then_some(key)
    }

    /// Takes handshake `h` out of `embryonic`. Returns whether it was there.
    fn hatch(&mut self, h: Id, sockets: &Sockets) -> bool {
        self.embryo(h, sockets)
            .is_some_and(|key| self.embryonic.remove(&key))
    }

    /// Takes back a socket that left `embryonic` because a RST returned it
    /// from SYN-RECEIVED to LISTEN, and forgets its connection. One spare
    /// listening socket is enough (`ingress` makes one when there is none),
    /// and every socket costs a little on every packet, so a burst of SYNs
    /// must not leave a pool behind. Returns whether the socket is kept as
    /// the spare; otherwise the caller removes it.
    fn relisten(
        &mut self,
        h: Id,
        sockets: &mut Sockets,
        by_tuple: &mut HashMap<(SocketAddr, SocketAddr), Id>,
    ) -> bool {
        if let Some(c) = sockets.take_conn(h) {
            by_tuple.remove(&(c.local, c.remote));
            self.left(c.remote.ip());
        }
        let spare = self.idle.is_empty();
        if spare {
            self.idle.push(h);
        }
        spare
    }

    /// One connection from `peer` left `embryonic` or `ready` for good.
    pub(super) fn left(&mut self, peer: IpAddr) {
        if let Some(n) = self.per_peer.get_mut(&peer) {
            *n -= 1;
            if *n == 0 {
                self.per_peer.remove(&peer);
            }
        }
    }
}

pub(super) struct Conn {
    pub(super) local: SocketAddr,
    pub(super) remote: SocketAddr,
    /// ECN was offered in the SYN.
    ecn: bool,
    /// Echo congestion until the peer acknowledges it with CWR.
    congestion_echo: bool,
    /// A RST arrived for this connection, or this side aborted it, or it
    /// closed while a segment was taken.
    pub(super) rst: bool,
    /// A RST arrived for this connection, or this side aborted it: its
    /// stream was reset.
    reset: bool,
    /// A FIN arrived for this connection.
    pub(super) fin: bool,
    /// This side ended its stream.
    pub(super) shut: bool,
    /// The layer above closed it: the connection is in `orphans`.
    pub(super) orphaned: bool,
    /// Closed by the layer above, and only TIME-WAIT recovery state remains.
    pub(super) retired: bool,
    /// This side connected, so it holds its local port.
    pub(super) side: Side,
    /// Our initial sequence number, from the SYN sent for this attempt.
    pub(super) iss: Option<u32>,
    /// An ICMPv4 destination-unreachable code for this pending connect.
    unreachable: Option<u8>,
    /// What the handshake carried, for a connection a listener took.
    pub(super) handshake: Handshake,
    /// When a handshake still waiting for its last ACK is dropped, or when
    /// an orphan in FIN-WAIT-2 is forgotten.
    pub(super) gives_up: Option<smoltcp::time::Instant>,
    /// Kept until a reset, retirement or socket removal: [`TcpControl::Hold`].
    held: Vec<Box<dyn std::any::Any + Send>>,
    /// Its child, until the connection is gone.
    pub(super) child: Option<ChildId>,
    /// The layer above still holds the child.
    open: bool,
    /// The [`TcpControl::Connect`] that asked for it.
    request: Option<Request>,
    /// The handshake is done: the child's stream carries bytes.
    live: bool,
    /// Bytes the layer above lets come up.
    recv_credit: u64,
    /// The receive window the layer above lent for its child's bytes
    /// ([`MuxOp::Window`]): while it keeps it, they come up made in it,
    /// already paid for on the child's budget, instead of charged to the
    /// endpoint's.
    window: Option<Weak<Charge>>,
    /// Send-buffer room granted to the layer above and not yet used.
    send_granted: u64,
    /// [`StreamEvent::Ended`] went up.
    ended_sent: bool,
    /// [`StreamEvent::Reset`] went up.
    reset_sent: bool,
    /// Its socket reached TIME-WAIT or closed on its own (its timeout, or
    /// the end of TIME-WAIT) while the layer above held the child: what
    /// it held was let go and [`TcpNotice::Gone`] said.
    released: bool,
}

impl Conn {
    pub(super) fn new(local: SocketAddr, remote: SocketAddr, side: Side) -> Conn {
        Conn {
            local,
            remote,
            ecn: false,
            congestion_echo: false,
            rst: false,
            reset: false,
            fin: false,
            shut: false,
            orphaned: false,
            retired: false,
            side,
            iss: None,
            unreachable: None,
            handshake: Handshake::default(),
            gives_up: None,
            held: Vec::new(),
            child: None,
            open: false,
            request: None,
            live: false,
            recv_credit: 0,
            window: None,
            send_granted: 0,
            ended_sent: false,
            reset_sent: false,
            released: false,
        }
    }
}

/// Copies what `socket` received into `into`, up to its capacity, straight
/// out of the socket's ring, which may hand the bytes over in two pieces,
/// into memory nothing zeroed first.
fn recv_into(socket: &mut stcp::Socket<'static>, into: &mut Vec<u8>) {
    while into.len() < into.capacity() && socket.can_recv() {
        let took = socket
            .recv(|data| {
                let take = data.len().min(into.capacity() - into.len());
                into.extend_from_slice(&data[..take]);
                (take, take)
            })
            .unwrap_or(0);
        if took == 0 {
            break;
        }
    }
}

/// A socket's two buffers, in an anonymous mapping of their own.
///
/// smoltcp buffers are fixed slices. Taking them from the heap would keep
/// their pages after the connection goes quiet or closes: the allocator
/// zeroes fresh chunks (so even an idle connection costs its full 512
/// KiB) and keeps freed memory. With a mapping of its own, a page costs
/// memory only once it is written, the pages of an empty buffer can be
/// given back while the connection stays open ([`Pages::release`]), and
/// closing returns all of it.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub(super) struct Pages {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: `Pages` owns its mapping; the raw pointer is only an address.
// Every access goes through the layer that owns it.
#[cfg(not(target_arch = "wasm32"))]
#[allow(unsafe_code, reason = "the owned mapping can move with its socket")]
unsafe impl Send for Pages {}

// SAFETY: shared handles do not expose bytes. The two exclusive halves
// lend disjoint slices, and reclamation requires exclusive socket access.
#[cfg(not(target_arch = "wasm32"))]
#[allow(unsafe_code, reason = "shared ownership of disjoint mapped buffers")]
unsafe impl Sync for Pages {}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
struct MappedHalf {
    pages: Arc<Pages>,
    start: usize,
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(
    unsafe_code,
    reason = "borrow the owned half for the current buffer access"
)]
impl AsRef<[u8]> for MappedHalf {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: construction creates exactly two nonoverlapping halves.
        // The owner keeps the mapping live for this borrow.
        unsafe { std::slice::from_raw_parts(self.pages.ptr.add(self.start), self.pages.len / 2) }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(
    unsafe_code,
    reason = "borrow the owned half for the current buffer access"
)]
impl AsMut<[u8]> for MappedHalf {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: this unique half is exclusively borrowed, its owner is
        // live, and the other half cannot address these bytes.
        unsafe {
            std::slice::from_raw_parts_mut(self.pages.ptr.add(self.start), self.pages.len / 2)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(
    unsafe_code,
    reason = "anonymous mapping ownership and buffer reclamation"
)]
impl Pages {
    /// Maps two buffers of `buffer` bytes, or `None` if the system says no.
    fn map(buffer: usize) -> Option<Pages> {
        let len = buffer.checked_mul(2)?;
        if len == 0 || len > isize::MAX as usize {
            return None;
        }
        // SAFETY: a fresh private anonymous mapping; no existing memory is
        // touched.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        if ptr.is_null() {
            // SAFETY: mmap succeeded, but Rust slices cannot use a null address.
            unsafe { libc::munmap(ptr, len) };
            return None;
        }
        // A huge page can span adjacent socket mappings and make a quiet
        // connection pay for another connection's buffers. Keep these
        // independently reclaimable buffers on ordinary pages.
        #[cfg(target_os = "linux")]
        unsafe {
            // SAFETY: this is the complete, freshly allocated mapping.
            libc::madvise(ptr, len, libc::MADV_NOHUGEPAGE);
        }
        Some(Pages {
            ptr: ptr.cast(),
            len,
        })
    }

    fn socket(buffer: usize) -> Option<(stcp::Socket<'static>, Arc<Pages>)> {
        let pages = Arc::new(Self::map(buffer)?);
        let rx = MappedHalf {
            pages: pages.clone(),
            start: 0,
        };
        let tx = MappedHalf {
            pages: pages.clone(),
            start: buffer,
        };
        let socket = stcp::Socket::new(
            stcp::SocketBuffer::new_owned(rx),
            stcp::SocketBuffer::new_owned(tx),
        );
        Some((socket, pages))
    }

    /// Gives the pages of both halves back to the system. They read as
    /// zeros after, and cost memory again only once written.
    ///
    /// SAFETY: the socket that owns the halves must be exclusively borrowed and
    /// must hold nothing in them: no bytes to read, none to send or
    /// resend, and an empty receive assembler. Check `recv_queue`,
    /// `send_queue`, and `has_pending_recv`. No buffer slices may be borrowed
    /// during reclamation.
    unsafe fn release(&self) {
        // SAFETY: the range is this mapping. MADV_DONTNEED on a private
        // anonymous mapping only makes its pages read as zeros, and the
        // caller has checked that the socket holds no data in them.
        unsafe { libc::madvise(self.ptr.cast(), self.len, libc::MADV_DONTNEED) };
    }

    /// How many of the pages are in memory now.
    #[cfg(test)]
    pub(super) fn resident(&self) -> usize {
        let page = 4096;
        let mut v = vec![0u8; self.len.div_ceil(page)];
        // SAFETY: `v` has one byte per page of the mapping.
        unsafe { libc::mincore(self.ptr.cast(), self.len, v.as_mut_ptr().cast()) };
        v.iter().filter(|b| *b & 1 != 0).count()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unsafe_code, reason = "release the owned anonymous mapping")]
impl Drop for Pages {
    fn drop(&mut self) {
        // SAFETY: this unmaps exactly the mapping made in `map`, after all
        // owning halves and reclamation handles have been dropped.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
    }
}

/// A browser has no `mmap`, so there every socket's buffers come from the
/// heap and no `Pages` is ever made.
#[cfg(target_arch = "wasm32")]
pub(super) enum Pages {}

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code, reason = "matches the unreachable host mapping interface")]
impl Pages {
    fn socket(_buffer: usize) -> Option<(stcp::Socket<'static>, Arc<Pages>)> {
        None
    }

    /// SAFETY: as on a host; no `Pages` exists to call it on.
    unsafe fn release(&self) {
        match *self {}
    }
}

/// A socket with two buffers of `buffer` bytes.
pub(super) fn new_socket(buffer: usize) -> (stcp::Socket<'static>, Option<Arc<Pages>>) {
    let (mut s, pages) = match Pages::socket(buffer) {
        Some((socket, pages)) => (socket, Some(pages)),
        None => (
            stcp::Socket::new(
                stcp::SocketBuffer::new(vec![0; buffer]),
                stcp::SocketBuffer::new(vec![0; buffer]),
            ),
            None,
        ),
    };
    s.set_tsval_generator(Some(|now| (now.total_micros() / 1000) as u32));
    s.set_nagle_enabled(false);
    (s, pages)
}

/// What a read, write or connect on a child would get now, for the async
/// handles that wait on the events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing yet: wait for an event of the child.
    Wait,
    /// Done: the end of the stream, or an open connection.
    Done,
    /// Failed with this.
    Failed(ConnError),
}

impl TcpLayer {
    /// TCP for a machine with address `addr` and `options`, made at `now`.
    /// Draws its keys and first ephemeral port from `entropy`.
    pub fn new(addr: IpAddr, options: Options, entropy: &dyn Entropy, now: Instant) -> TcpLayer {
        let mut dev = Dev::default();
        let mut cookie_key = [0; 32];
        entropy.fill_random(&mut cookie_key);
        let sequences = Sequences(secret(entropy));
        let config = Config {
            initial_seq: Box::new(move |local, remote, now| {
                sequences.initial(local.into(), remote.into(), now)
            }),
            ip_addr: addr.into(),
        };
        let mut iface = Iface::new(config, &mut dev, smol(now));
        iface.set_ignore_malformed_options(options.settings.ignore_malformed_options);
        iface.set_reset_closed_ports(options.settings.closed_port == ClosedPort::Reset);
        TcpLayer {
            storage: None,
            storage_places: 0,
            addr,
            iface,
            sockets: Sockets::new(),
            pages: HashMap::default(),
            reserved: HashMap::default(),
            dirty: HashSet::default(),
            next_release: None,
            dev,
            listeners: BTreeMap::new(),
            by_tuple: HashMap::new(),
            ports: HashMap::new(),
            next_port: EPHEMERAL + entropy.random_below(65536 - EPHEMERAL as u64) as u16,
            orphans: Vec::new(),
            touched: Vec::new(),
            time_wait: VecDeque::new(),
            stopped: false,
            buffer: options.buffer,
            backlog: options.backlog,
            cookie_key,
            settings: options.settings,
            isolated_peer: None,
            children: Slots::new(usize::MAX),
            urgent: VecDeque::new(),
            up: VecDeque::new(),
            work: false,
            primed: false,
            stepped: None,
            next: None,
            saturated: false,
            ended: false,
        }
    }

    /// Keeps per-source flood limits only for sources `isolated` accepts:
    /// those the enclosing network keeps from being spoofed. A peer at its
    /// limit with such an address has its SYNs dropped instead of getting
    /// SYN cookies.
    pub fn limit_isolated_peers(&mut self, isolated: impl Fn(IpAddr) -> bool + Send + 'static) {
        self.isolated_peer = Some(Box::new(isolated));
    }

    /// The machine's address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Charges the buffers of one more socket, or `None` if they do not fit.
    fn reserve(&mut self, budget: &Budget) -> Option<Charge> {
        if !self.reserve_storage(budget) || !self.make_room() {
            return None;
        }
        budget.charge(2 * self.buffer)
    }

    /// Packet buffers and event queues have fixed limits. Socket and listener
    /// routing grows on the same budget; its high water mark remains paid until
    /// the engine drops, including empty hash buckets and reusable socket slots.
    fn storage_bytes(places: usize) -> Option<usize> {
        let fixed =
            2 * UP_ROOM * size_of::<Up>() + 2 * EGRESS_PACKETS * (MTU + size_of::<Vec<u8>>());
        // Include socket scheduling, child slots, connection and listener indexes,
        // and the terminal events a batch of socket removals can produce.
        // Four times the entries covers geometric vector/hash capacity and tree
        // nodes.
        let entry = size_of::<Option<stcp::Socket<'static>>>()
            + size_of::<Slot>()
            + size_of::<Listen>()
            + size_of::<Charge>()
            + size_of::<Arc<Pages>>()
            + size_of::<(SocketAddr, SocketAddr)>()
            + 4 * size_of::<Up>()
            + 32 * size_of::<usize>();
        places.checked_mul(4 * entry)?.checked_add(fixed)
    }

    fn reserve_storage(&mut self, budget: &Budget) -> bool {
        if self.storage_places != 0 {
            return true;
        }
        let charge = self
            .storage
            .get_or_insert_with(|| budget.charge(0).unwrap());
        let places = STORAGE_FLOOR;
        let spare_bytes = Spare::PACKETS * size_of::<Vec<u8>>();
        if !charge.grow_to(Self::storage_bytes(places).unwrap() + spare_bytes) {
            return false;
        }
        let spare = charge.split(spare_bytes).unwrap().into_vec();
        self.dev.spare = Spare(Some(spare));
        self.up.reserve_exact(UP_ROOM);
        self.urgent.reserve_exact(UP_ROOM);
        self.dev.tx.reserve_exact(EGRESS_PACKETS);
        self.dev.out.reserve_exact(EGRESS_PACKETS);
        self.storage_places = places;
        true
    }

    fn make_room(&mut self) -> bool {
        if self.sockets.len() + self.listeners.len() < self.storage_places {
            return true;
        }
        let Some(places) = self.storage_places.checked_mul(2) else {
            return false;
        };
        let Some(bytes) = Self::storage_bytes(places) else {
            return false;
        };
        if !self.storage.as_mut().unwrap().grow_to(bytes) {
            return false;
        }
        self.storage_places = places;
        true
    }

    /// Adds a socket made by [`new_socket`], drawing its IPv4
    /// identification from `entropy` when the settings ask for it.
    pub(super) fn add_socket(
        &mut self,
        entropy: &dyn Entropy,
        (mut s, pages): (stcp::Socket<'static>, Option<Arc<Pages>>),
    ) -> Id {
        s.set_settings(self.settings.socket);
        if let Some(id) = self.settings.ipv4_id {
            s.set_ipv4_identification(id(entropy));
        }
        s.set_timeout(self.settings.timeout.map(Into::into));
        s.set_keep_alive(self.settings.keep_alive.map(Into::into));
        if s.state() != TcpState::SynReceived {
            s.set_tsval_generator(self.settings.timestamp_clock);
        }
        if let (Some(offset), Some(local), Some(remote)) = (
            self.settings.timestamp_offset,
            s.local_endpoint(),
            s.remote_endpoint(),
        ) {
            s.set_timestamp_offset(offset(
                &self.cookie_key,
                SocketAddr::from(local).ip(),
                SocketAddr::from(remote).ip(),
            ));
        }
        let h = self.sockets.add(s);
        if let Some(p) = pages {
            self.pages.insert(h, p);
        }
        h
    }

    /// Removes a socket, then unmaps its buffers and gives back their charge.
    pub(super) fn remove_socket(&mut self, h: Id) {
        self.sockets.remove(h);
        self.pages.remove(&h);
        self.reserved.remove(&h);
        self.dirty.remove(&h);
    }

    /// Notes that a socket's buffers may have pages to give back later.
    fn soiled(&mut self, h: Id) {
        if self.pages.contains_key(&h) {
            self.dirty.insert(h);
        }
    }

    /// Gives back the pages of every noted socket whose buffers are now
    /// empty. Sockets that still hold data stay noted.
    #[allow(unsafe_code, reason = "reclaim empty mapped socket buffers")]
    pub(super) fn release_quiet(&mut self) {
        let dirty: Vec<Id> = self.dirty.iter().copied().collect();
        for h in dirty {
            let s = self.get(h);
            let (rq, sq) = (s.recv_queue(), s.send_queue());
            if rq == 0 && sq == 0 && !s.has_pending_recv() {
                // SAFETY: the socket holds nothing in its buffers, as just
                // checked: nothing to read or send, and nothing out of order.
                unsafe { self.pages[&h].release() };
                self.dirty.remove(&h);
            }
        }
    }

    pub(super) fn sock(&mut self, h: Id) -> &mut stcp::Socket<'static> {
        self.sockets.get_mut(h)
    }

    pub(super) fn get(&self, h: Id) -> &stcp::Socket<'static> {
        self.sockets.get(h)
    }

    /// The connection of `h`. Panics if its socket has none.
    fn conn(&self, h: Id) -> &Conn {
        self.sockets.conn(h).expect("a connection")
    }

    pub(super) fn take_port(&mut self, port: u16) {
        *self.ports.entry(port).or_default() += 1;
    }

    fn free_port(&mut self, port: u16) {
        if let Some(n) = self.ports.get_mut(&port) {
            *n -= 1;
            if *n == 0 {
                self.ports.remove(&port);
            }
        }
    }

    /// Forgets a connection socket entirely.
    pub(super) fn remove_conn(&mut self, h: Id) {
        if let Some(c) = self.sockets.take_conn(h) {
            self.by_tuple.remove(&(c.local, c.remote));
            if c.side == Side::Client {
                self.free_port(c.local.port());
            }
            if let Some(id) = c.child {
                self.children.remove(id);
                self.notice(TcpNotice::Gone(id));
            }
        }
        self.remove_socket(h);
    }

    /// Sends the FIN after every queued byte is acknowledged.
    /// This preserves the endpoint's shutdown packet order.
    pub(super) fn close_if_drained(&mut self, h: Id) {
        if self.conn(h).shut && self.get(h).send_queue() == 0 {
            self.sock(h).close();
        }
    }

    /// Resets the connection and says so, keeping the socket until its RST
    /// can be sent. It is gone: what it held is let go.
    fn abort(&mut self, h: Id) {
        let c = self.sockets.conn_mut(h).unwrap();
        c.rst = true;
        c.reset = true;
        c.held.clear();
        let child = c.child;
        let tell = c.open && c.live && !c.reset_sent;
        if tell {
            c.reset_sent = true;
        }
        self.sock(h).abort();
        self.touched.push(h);
        if let Some(id) = child {
            if tell {
                self.urgent
                    .push_back(MuxEvent::Child(id, StreamEvent::Reset));
            }
            self.notice(TcpNotice::Gone(id));
        }
        self.work = true;
    }

    /// Lets a socket the layer above no longer holds finish closing; it is
    /// removed once it has closed. Unread data means the application lost
    /// bytes, so the peer gets a RST, as from a kernel.
    pub(super) fn orphan(&mut self, h: Id, abort: bool) {
        if let Some(c) = self.sockets.conn_mut(h) {
            c.open = false;
            c.recv_credit = 0;
        }
        if self.stopped {
            self.remove_conn(h);
            return;
        }
        if abort || self.get(h).can_recv() {
            self.abort(h);
        } else {
            self.sockets.conn_mut(h).unwrap().shut = true;
            self.close_if_drained(h);
        }
        // An orphan should not live on keepalives. A peer that never
        // closes its side keeps it only for the configured orphan timeout
        // (tcp_fin_timeout): see `expire_orphans`.
        let timeout = self.settings.orphan_timeout;
        let s = self.sock(h);
        s.set_keep_alive(None);
        s.set_timeout(Some(timeout.into()));
        self.sockets.conn_mut(h).unwrap().orphaned = true;
        self.orphans.push(h);
        self.work = true;
    }

    /// Why a connection can no longer carry bytes, once its socket closed.
    pub(super) fn closed_reason(&self, h: Id) -> ConnError {
        let c = self.conn(h);
        if self.stopped {
            ConnError::Closed
        } else if let Some(code) = c.unreachable {
            ConnError::Unreachable(code)
        } else if c.rst {
            ConnError::Reset
        } else {
            ConnError::TimedOut
        }
    }

    /// Records the sequence number of an outgoing SYN, for ICMP checks, or
    /// of a SYN-ACK, for the connection's [`Handshake`].
    pub(super) fn sent(&mut self, packet: &mut Vec<u8>) {
        let Some(ip) = Header::parse_whole(packet) else {
            return;
        };
        let t = ip.payload(packet);
        if ip.protocol != TCP || t.len() < 20 {
            return;
        }
        let local = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
        let mut destination = ip.dst;
        if destination.is_ipv4() {
            for option in Ipv4Packet::new_unchecked(&*packet)
                .options_iter()
                .expect("validated IPv4 header")
            {
                match option {
                    Ipv4Option::LooseSourceRoute { pointer, routes }
                    | Ipv4Option::StrictSourceRoute { pointer, routes }
                        if usize::from(pointer) <= 3 + routes.len() * 4 =>
                    {
                        destination = (*routes.last().expect("unconsumed route slot")).into();
                        break;
                    }
                    _ => {}
                }
            }
        }
        let remote = SocketAddr::new(destination, u16::from_be_bytes([t[2], t[3]]));
        let mut refreshed = None;
        if let Some(h) = self.by_tuple.get(&(local, remote)) {
            let c = self.sockets.conn_mut(*h).unwrap();
            let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
            match (c.side, t[13] & 0x12) {
                (Side::Client, 0x02) => {
                    c.iss.get_or_insert(seq);
                }
                (Side::Server, 0x12) => {
                    c.handshake.iss = seq;
                    if c.iss.replace(seq).is_some()
                        && local.is_ipv4()
                        && let Some(answer) = self
                            .listeners
                            .get(&local.port())
                            .and_then(|listener| listener.answer.as_ref())
                    {
                        refreshed = answer.retransmit_ipv4_options(&c.handshake);
                    }
                }
                _ => {}
            }
            if c.ecn && t[13] & 0x04 == 0 && (t[13] & 0x12 == 0x12 || c.congestion_echo) {
                let t = &mut packet[ip.payload.clone()];
                t[13] |= 0x40;
                t[16..18].fill(0);
                let sum = transport_checksum(local.ip(), remote.ip(), TCP, t);
                t[16..18].copy_from_slice(&sum.to_be_bytes());
            }
        }
        if let Some(options) = refreshed
            && let Ok(mut bytes) = encode_ipv4_options(&options)
        {
            bytes.resize(bytes.len().div_ceil(4) * 4, 0);
            let header_len = 20 + bytes.len();
            let Ok(length) = u16::try_from(packet.len() + header_len - ip.payload.start) else {
                return;
            };
            packet.splice(20..ip.payload.start, bytes);
            packet[0] = 0x40 | (header_len / 4) as u8;
            packet[2..4].copy_from_slice(&length.to_be_bytes());
            fictionet::stdlib::network::ip::set_header_checksum(&mut packet[..header_len]);
        }
    }

    /// Only the quoted, still-pending attempt can be failed by ICMPv4.
    fn unreachable(&mut self, message: &[u8]) {
        if message.len() < 8
            || message[0] != 3
            || message[1] == 4
            || message[1] > 15
            || checksum(message) != 0
        {
            return;
        }
        let quoted = &message[8..];
        let Some(ip) = Header::parse_truncated(quoted) else {
            return;
        };
        if !ip.src.is_ipv4()
            || ip.protocol != TCP
            || ip.fragment.is_some()
            || !Ipv4Packet::new_unchecked(quoted).verify_checksum()
        {
            return;
        }
        let t = ip.payload(quoted);
        let total = u16::from_be_bytes([quoted[2], quoted[3]]) as usize;
        // The minimum ICMP quote has only the ports and sequence number.
        if t.len() < 8 || total < ip.payload.start + 20 || (t.len() >= 14 && t[13] & 0x17 != 2) {
            return;
        }
        if quoted.len() >= total
            && TcpRepr::parse_with(
                &TcpPacket::new_unchecked(t),
                &ip.src.into(),
                &ip.dst.into(),
                self.settings.ignore_malformed_options,
            )
            .is_err()
        {
            return;
        }
        let local = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
        let remote = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
        let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
        let Some(&h) = self.by_tuple.get(&(local, remote)) else {
            return;
        };
        let c = self.conn(h);
        if c.side != Side::Client
            || c.iss != Some(seq)
            || !matches!(
                self.get(h).state(),
                TcpState::SynSent | TcpState::SynReceived
            )
        {
            return;
        }
        self.sockets.conn_mut(h).unwrap().unreachable = Some(message[1]);
        self.abort(h);
    }

    /// Feeds one whole IP packet into smoltcp, charging new sockets'
    /// buffers to `budget` and drawing their IPv4 identification from
    /// `entropy`. Returns whether it was a TCP segment for this endpoint
    /// that carried data.
    ///
    /// The IP layer has already checked the packet's header and taken out
    /// any IPv6 extension headers ([`IpLayer`](fictionet::stdlib::network::packet::IpLayer)).
    pub(super) fn ingress(
        &mut self,
        entropy: &dyn Entropy,
        budget: &Budget,
        now: smoltcp::time::Instant,
        packet: Vec<u8>,
    ) -> bool {
        // Whatever the packet is, it may be answered directly.
        self.work = true;
        let addr = self.addr;
        let Some(ip) = Header::parse_whole(&packet) else {
            return false;
        };
        if ip.dst != addr {
            return false;
        }
        if ip.protocol == ICMP && addr.is_ipv4() {
            if Ipv4Packet::new_unchecked(&packet).verify_checksum() {
                self.unreachable(ip.payload(&packet));
            }
            return false;
        }
        // smoltcp takes TCP only right after the IPv6 header, as the IP
        // layer leaves it.
        if ip.protocol != TCP
            || ip.payload.len() < 20
            || (ip.dst.is_ipv6() && ip.payload.start != 40)
        {
            return false;
        }
        // Validate before a rejected packet can change connection bookkeeping.
        if ip.src.is_ipv4() && !Ipv4Packet::new_unchecked(&packet).verify_checksum() {
            return false;
        }
        let t = &packet[ip.payload.clone()];
        let Ok(repr) = TcpRepr::parse_with(
            &TcpPacket::new_unchecked(t),
            &ip.src.into(),
            &ip.dst.into(),
            self.settings.ignore_malformed_options,
        ) else {
            // A valid header with an unreadable option suffix gets the reset
            // suggested by RFC 9293 section 3.1. Parsing the prefix still
            // validates the checksum, header length and control flags. No
            // rejected segment may change connection bookkeeping.
            if unicast(ip.src)
                && let Ok(repr) = TcpRepr::parse_with(
                    &TcpPacket::new_unchecked(t),
                    &ip.src.into(),
                    &ip.dst.into(),
                    true,
                )
                && t[13] & 4 == 0
            {
                let src = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
                let dst = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
                self.dev
                    .tx
                    .push(Arrived::of(src, dst, t, repr.payload.len()).reset(&[]));
            }
            return false;
        };
        // A host discards what comes from an address that is not one
        // host's (RFC 1122 section 3.2.1.3), as smoltcp does on its own
        // path. The SYN cookies and refusals here answer before smoltcp
        // sees the segment, so the check comes first.
        if !unicast(ip.src) {
            return false;
        }
        let data = !repr.payload.is_empty();
        let src = SocketAddr::new(ip.src, u16::from_be_bytes([t[0], t[1]]));
        let dst = SocketAddr::new(ip.dst, u16::from_be_bytes([t[2], t[3]]));
        let arrived = Arrived::of(src, dst, t, repr.payload.len());
        let flags = t[13];
        let ip_ecn = if ip.src.is_ipv4() {
            packet[1] & 3
        } else {
            packet[1] >> 4 & 3
        };
        let congestion = ip_ecn == 3;
        let ecn = flags & 0xc0 == 0xc0 && (self.settings.ecn_syn)(ip_ecn, t[12] & 15);
        let (syn, rst, ack) = (flags & 6 == 2, flags & 4 != 0, flags & 16 != 0);
        // A SYN from source port 0 that the settings drop goes before any
        // listener is looked for: nothing is sent and nothing is counted.
        if syn && !ack && src.port() == 0 && self.settings.source_port_zero == SourcePortZero::Drop
        {
            return false;
        }
        if syn
            && !ack
            && !self.by_tuple.contains_key(&(dst, src))
            && !self.listeners.contains_key(&dst.port())
        {
            self.notice(TcpNotice::Refused {
                peer: src,
                local: dst,
            });
        }
        let new =
            !self.by_tuple.contains_key(&(dst, src)) && self.listeners.contains_key(&dst.port());
        // LISTEN ignores segments without SYN, ACK or RST (RFC 9293).
        // Idle sockets are allocated lazily, so handle this before dispatch.
        if new && !syn && !ack && !rst {
            return false;
        }
        // A SYN for a listener that smoltcp is to take: its options, and
        // what the listener's answer adds to the SYN-ACK.
        let mut attempt = None;
        if new && syn && !ack {
            let Some(taken) = self.attempt(
                entropy,
                budget,
                arrived,
                t,
                ecn,
                if src.is_ipv4() {
                    Some(ipv4_options(&packet).expect("validated IPv4 header"))
                } else {
                    None
                },
                now,
            ) else {
                return false;
            };
            attempt = Some(taken);
        }
        if new && ack && !syn && !rst && !self.take_cookie(entropy, budget, arrived, t, now) {
            return false;
        }
        let handle = self.by_tuple.get(&(dst, src)).copied();
        let before = handle.map(|h| self.get(h).state());
        // An ACK that would complete a kept handshake while the connections
        // waiting for accept fill the backlog is dropped, as one returning
        // a cookie is: the socket sends its SYN-ACK again, and the
        // handshake completes once accept has taken one, or is given up.
        if let Some(h) = handle
            && before == Some(TcpState::SynReceived)
            && ack
            && !syn
            && !rst
            && self.conn(h).side == Side::Server
            && self
                .listeners
                .get(&dst.port())
                .is_some_and(|l| l.ready.len() >= l.backlog)
        {
            return false;
        }
        // The options of an ACK that may complete a handshake.
        let completing = (before == Some(TcpState::SynReceived)).then(|| segment_options(t));
        self.dev.rx = Some(packet);
        if let Some(h) = handle {
            let target = self.sockets.handle(h);
            self.iface
                .poll_ingress_targeted(now, &mut self.dev, &mut self.sockets.set, target);
        } else {
            self.iface
                .poll_ingress_single(now, &mut self.dev, &mut self.sockets.set);
        }
        let consumed = self.dev.rx.is_none();
        self.dev.reclaim();
        if let Some(h) = handle {
            if let Some(c) = self.sockets.conn_mut(h)
                && c.ecn
            {
                if flags & 0x80 != 0 {
                    c.congestion_echo = false;
                }
                if congestion {
                    c.congestion_echo = true;
                }
            }
            if before == Some(TcpState::SynReceived) {
                self.touched.push(h);
            }
            let s = self.get(h);
            let after = s.state();
            if consumed && data && (s.recv_queue() != 0 || s.has_pending_recv()) {
                self.soiled(h);
            }
            let c = self.sockets.conn_mut(h).unwrap();
            if (rst || after == TcpState::Closed)
                && before != Some(after)
                && matches!(after, TcpState::Closed | TcpState::Listen)
            {
                c.rst = true;
                c.reset |= rst;
                c.held.clear();
                if let Some(id) = c.child {
                    if rst && c.open && c.live && !c.reset_sent {
                        c.reset_sent = true;
                        self.urgent
                            .push_back(MuxEvent::Child(id, StreamEvent::Reset));
                    }
                    self.notice(TcpNotice::Gone(id));
                }
            }
            let c = self.sockets.conn_mut(h).unwrap();
            if flags & 1 != 0
                && before != Some(after)
                && matches!(
                    after,
                    TcpState::CloseWait | TcpState::Closing | TcpState::TimeWait
                )
            {
                c.fin = true;
                // ACK an accepted FIN immediately, even if the application
                // drops its handle after reading EOF.
                self.sockets.get_mut(h).set_ack_delay(None);
            }
            self.close_if_drained(h);
            // A RST in SYN-RECEIVED put the socket back in LISTEN. It is
            // taken back now: a later SYN in the same batch may land on it,
            // and must not find it still named for the old peer.
            if after == TcpState::Listen
                && let Some(l) = self.listeners.get_mut(&dst.port())
                && l.hatch(h, &self.sockets)
                && !l.relisten(h, &mut self.sockets, &mut self.by_tuple)
            {
                self.remove_socket(h);
            }
            if let Some(ack) = completing
                && !matches!(
                    after,
                    TcpState::SynReceived | TcpState::Listen | TcpState::Closed
                )
                && self.conn(h).side == Side::Server
            {
                self.completed(h, arrived, ack);
            }
        }
        if let Some(Attempt {
            syn,
            added,
            syn_ipv4,
            ipv4_reply,
        }) = attempt
        {
            // At most one idle socket took the SYN.
            let l = self.listeners.get_mut(&dst.port()).unwrap();
            let sockets = &self.sockets;
            if let Some(i) = l
                .idle
                .iter()
                .position(|&h| sockets.get(h).state() == TcpState::SynReceived)
            {
                let h = l.idle.swap_remove(i);
                let gives_up = now + self.settings.handshake_timeout.into();
                l.embryonic.insert((gives_up, h));
                let s = self.sockets.get(h);
                let local = s.local_endpoint().map(SocketAddr::from).unwrap_or(dst);
                let remote = s.remote_endpoint().map(SocketAddr::from).unwrap_or(src);
                *l.per_peer.entry(remote.ip()).or_default() += 1;
                let offset = self.settings.timestamp_offset.map_or(0, |offset| {
                    offset(&self.cookie_key, local.ip(), remote.ip())
                });
                self.sock(h).set_timestamp_offset(offset);
                let wire: Vec<_> = added.iter().filter_map(TcpOption::to_wire).collect();
                self.sock(h)
                    .set_syn_options(&wire)
                    .expect("`attempt` checked that the answer can be sent");
                self.sock(h)
                    .set_syn_ipv4_options(&ipv4_reply.options, ipv4_reply.destination)
                    .expect("attempt checked IPv4 options");
                let mut conn = Conn::new(local, remote, Side::Server);
                conn.ecn = ecn;
                conn.handshake.syn_ipv4 = syn_ipv4.map(Arc::from);
                conn.handshake.syn_ack_ipv4 = local.is_ipv4().then(|| ipv4_reply.options.into());
                conn.handshake.syn = Some(syn);
                conn.handshake.syn_ack = Some(added.into());
                conn.handshake.irs = arrived.seq;
                conn.gives_up = Some(gives_up);
                self.sockets.insert_conn(h, conn);
                self.by_tuple.insert((local, remote), h);
            }
        }
        data
    }

    /// Answers a SYN for a listening port that no connection has. Returns
    /// its options, and what the listener's [`Answer::syn`] adds to the
    /// SYN-ACK, when smoltcp is to take it; a listening socket is ready to.
    /// Otherwise the SYN has been dropped, refused with a RST, or answered
    /// with a SYN cookie here, and smoltcp never sees it.
    #[allow(clippy::too_many_arguments)]
    fn attempt(
        &mut self,
        entropy: &dyn Entropy,
        budget: &Budget,
        arrived: Arrived,
        t: &[u8],
        ecn: bool,
        syn_ipv4: Option<Vec<Ipv4Option>>,
        now: smoltcp::time::Instant,
    ) -> Option<Attempt> {
        let (src, dst) = (arrived.from, arrived.to);
        let l = &self.listeners[&dst.port()];
        let peer_full = self
            .settings
            .backlog_per_peer
            .is_some_and(|limit| l.per_peer.get(&src.ip()).is_some_and(|&n| n >= limit));
        if l.ready.len() >= l.backlog && self.settings.reset_full_queue {
            self.dev.tx.push(arrived.reset(&[]));
            return None;
        }
        if l.ready.len() >= l.backlog
            || (peer_full
                && self
                    .isolated_peer
                    .as_ref()
                    .is_some_and(|isolated| isolated(src.ip())))
        {
            return None;
        }
        let syn = segment_options(t);
        let cookie = l.embryonic.len() + l.ready.len() >= l.backlog || peer_full;
        let asked = Syn {
            options: &syn,
            ipv4_options: syn_ipv4.as_deref().unwrap_or_default(),
            to: dst,
            from: src,
            seq: arrived.seq,
            cookie,
        };
        let added = match l.answer.as_ref().map(|answer| answer.syn(&asked)) {
            None => Vec::new(),
            Some(SynAnswer::Accept(added)) => added,
            Some(SynAnswer::Refuse(refusal)) => {
                // Options that cannot be sent leave a plain RST.
                let options = encode(&refusal).unwrap_or_default();
                self.dev.tx.push(arrived.reset(&options));
                return None;
            }
        };
        let Some(encoded) = encode(&added) else {
            self.dev.tx.push(arrived.reset(&[]));
            return None;
        };
        let ipv4_reply = if dst.is_ipv4() {
            l.answer.as_ref().map_or_else(
                || Some(Ipv4Reply::default()),
                |answer| answer.ipv4_options(&asked),
            )?
        } else {
            Ipv4Reply::default()
        };
        if encode_ipv4_options(&ipv4_reply.options).is_err() {
            self.dev.tx.push(arrived.reset(&[]));
            return None;
        }
        if cookie {
            let codec = self.settings.cookies?;
            let input = CookieInput {
                key: &self.cookie_key,
                local: dst,
                remote: src,
                sequence: arrived.seq,
                now: Duration::from_micros(now.total_micros().max(0) as u64),
                options: &syn,
                ecn,
            };
            let CookieReply {
                sequence: iss,
                options: kept,
                ecn,
            } = codec.issue(&input);
            let timestamps = kept
                .iter()
                .any(|o| matches!(o, TcpOption::Timestamps { .. }));
            let own_mss = MTU - if dst.is_ipv6() { 40 } else { 20 } - 20;
            let mut options = vec![2, 4];
            options.extend_from_slice(&(own_mss as u16).to_be_bytes());
            options.extend_from_slice(&encode(&kept)?);
            options.extend_from_slice(&encoded);
            if options.len() > 40 {
                return None;
            }
            let window = if timestamps {
                self.settings
                    .socket
                    .syn_window_with_timestamps
                    .or(self.settings.socket.syn_window)
            } else {
                self.settings.socket.syn_window
            }
            .unwrap_or(self.buffer.min(usize::from(u16::MAX)) as u16);
            let ack = arrived.seq.wrapping_add(1);
            let reply = segment(
                dst,
                src,
                iss,
                Some(ack),
                0x02 | if ecn { 0x40 } else { 0 },
                window,
                &options,
            );
            let reply = if let (IpAddr::V4(local), IpAddr::V4(peer)) = (dst.ip(), src.ip()) {
                fictionet::stdlib::network::ip::packet_with_ipv4_options(
                    local,
                    ipv4_reply.destination.unwrap_or(peer),
                    TCP,
                    fictionet::stdlib::network::ip::Fields::default(),
                    &ipv4_reply.options,
                    &reply[20..],
                )
                .expect("checked IPv4 reply")
                .0
            } else {
                reply
            };
            self.dev.tx.push(reply);
            return None;
        }
        if l.idle.is_empty() {
            // The listening socket that takes the SYN keeps its buffers for
            // the connection: they are charged before it is made.
            let charge = self.reserve(budget)?;
            let mut s = new_socket(self.buffer);
            s.0.listen(dst.port()).expect("a new socket can listen");
            let h = self.add_socket(entropy, s);
            self.reserved.insert(h, charge);
            self.listeners.get_mut(&dst.port()).unwrap().idle.push(h);
        }
        Some(Attempt {
            syn,
            added,
            syn_ipv4,
            ipv4_reply,
        })
    }

    /// Takes an ACK for a listening port that no connection has. When it
    /// returns a SYN cookie this endpoint made, a connection opens for it in
    /// SYN-RECEIVED, which the ACK then completes. Returns whether to go on
    /// with the ACK: not when it returns a cookie but the connections
    /// waiting for `accept` fill the backlog, or its buffers do not fit
    /// the budget.
    fn take_cookie(
        &mut self,
        entropy: &dyn Entropy,
        budget: &Budget,
        arrived: Arrived,
        t: &[u8],
        now: smoltcp::time::Instant,
    ) -> bool {
        let (src, dst) = (arrived.from, arrived.to);
        let Some(ack) = arrived.ack else {
            return true;
        };
        let (irs, iss) = (arrived.seq.wrapping_sub(1), ack.wrapping_sub(1));
        let Some(codec) = self.settings.cookies else {
            return true;
        };
        let options = segment_options(t);
        let input = CookieInput {
            key: &self.cookie_key,
            local: dst,
            remote: src,
            sequence: irs,
            now: Duration::from_micros(now.total_micros().max(0) as u64),
            options: &options,
            ecn: false,
        };
        let Some(kept) = codec.validate(&input, iss) else {
            return true;
        };
        let l = &self.listeners[&dst.port()];
        if l.ready.len() >= l.backlog
            || (self
                .settings
                .backlog_per_peer
                .is_some_and(|limit| l.per_peer.get(&src.ip()).is_some_and(|&n| n >= limit))
                && self
                    .isolated_peer
                    .as_ref()
                    .is_some_and(|isolated| isolated(src.ip())))
        {
            return false;
        }
        let Some(charge) = self.reserve(budget) else {
            return false;
        };
        let mut s = new_socket(self.buffer);
        s.0.listen(dst.port()).expect("a new socket can listen");
        s.0.accept_syn_cookie(dst.into(), src.into(), irs, iss, kept.mss, now);
        let h = self.add_socket(entropy, s);
        self.reserved.insert(h, charge);
        self.sockets.get_mut(h).restore_cookie_options(
            kept.scale,
            kept.sack,
            kept.timestamp.and_then(|(offset, remote)| {
                self.settings
                    .timestamp_clock
                    .map(|clock| (clock, offset, remote))
            }),
        );
        let l = self.listeners.get_mut(&dst.port()).unwrap();
        let gives_up = now + self.settings.handshake_timeout.into();
        l.embryonic.insert((gives_up, h));
        *l.per_peer.entry(src.ip()).or_default() += 1;
        let mut conn = Conn::new(dst, src, Side::Server);
        conn.gives_up = Some(gives_up);
        conn.ecn = kept.ecn;
        conn.handshake.origin = HandshakeOrigin::Cookie;
        (conn.handshake.irs, conn.handshake.iss) = (irs, iss);
        self.sockets.insert_conn(h, conn);
        self.by_tuple.insert((dst, src), h);
        true
    }

    /// The ACK `arrived`, with options `ack`, completed the handshake of
    /// `h`, a connection a listener took. Its listener's [`Answer::ack`]
    /// says whether it stays. One it takes waits for `accept` from now on,
    /// so the next ACK that returns a SYN cookie counts it. One it refuses
    /// gets a RST in answer to that ACK and is forgotten at once.
    fn completed(&mut self, h: Id, arrived: Arrived, ack: Arc<[TcpOption]>) {
        let port = arrived.to.port();
        let l = self.listeners.get_mut(&port).expect("a listener");
        l.hatch(h, &self.sockets);
        let c = self.sockets.conn_mut(h).expect("a connection");
        c.gives_up = None;
        c.handshake.ack = ack;
        c.handshake.ack_payload = arrived.payload;
        // A SYN cookie's: what the listener kept of the SYN, if anything.
        if c.handshake.syn_ack.is_none()
            && let Some(kept) = l
                .answer
                .as_ref()
                .and_then(|a| a.cookie(arrived.from, &c.handshake))
        {
            c.handshake.syn = Some(kept.syn);
            c.handshake.syn_ack = Some(kept.syn_ack);
            c.handshake.syn_ipv4 = kept.syn_ipv4;
            c.handshake.syn_ack_ipv4 = kept.syn_ack_ipv4;
        }
        let handshake = &self.sockets.conn(h).expect("a connection").handshake;
        let answer = l
            .answer
            .as_ref()
            .map_or(AckAnswer::Accept, |a| a.ack(handshake));
        match answer {
            AckAnswer::Accept => {
                if let Some(segments) = l.answer.as_ref().and_then(|a| a.segments(handshake)) {
                    let wire: Vec<_> = handshake
                        .ack
                        .iter()
                        .filter_map(TcpOption::to_wire)
                        .collect();
                    let options = stcp::encode_options_within(&wire, 40)
                        .expect("received handshake options fit a TCP header");
                    let irs = handshake.irs;
                    let s = self.sockets.get_mut(h);
                    s.set_segment_options(Box::new(SegmentsOnWire(segments)));
                    s.process_handshake_data(irs.wrapping_add(1), &options);
                }
                if arrived.from.port() == 0
                    && self.settings.source_port_zero == SourcePortZero::CloseAfterHandshake
                {
                    // Closed as an application that gets no usable peer
                    // address closes it the moment it is accepted: the
                    // listener never sees it.
                    l.left(arrived.from.ip());
                    self.orphan(h, false);
                    return;
                }
                l.ready.push_back(h);
                self.offer(port);
                return;
            }
            AckAnswer::Refuse(refusal) => {
                // Options that cannot be sent leave a plain RST.
                let options = encode(&refusal).unwrap_or_default();
                self.dev.tx.push(arrived.reset(&options));
            }
            AckAnswer::Drop => {}
        }
        if let Some(c) = self.sockets.take_conn(h) {
            self.by_tuple.remove(&(c.local, c.remote));
            l.left(c.remote.ip());
        }
        self.remove_socket(h);
    }

    /// Drops the handshakes still waiting for their last ACK
    /// [`Settings::handshake_timeout`] after their SYN, without a RST.
    fn expire_handshakes(&mut self, now: smoltcp::time::Instant) {
        let mut gone = Vec::new();
        for l in self.listeners.values_mut() {
            // Only those due, soonest first. One that left SYN-RECEIVED
            // is housekeeping's.
            let due: Vec<_> = l
                .embryonic
                .iter()
                .take_while(|&&(at, _)| at <= now)
                .copied()
                .filter(|&(_, h)| self.sockets.get(h).state() == TcpState::SynReceived)
                .collect();
            for key @ (_, h) in due {
                l.embryonic.remove(&key);
                if let Some(c) = self.sockets.take_conn(h) {
                    self.by_tuple.remove(&(c.local, c.remote));
                    l.left(c.remote.ip());
                }
                gone.push(h);
            }
        }
        for h in gone {
            self.remove_socket(h);
        }
    }

    /// Forgets each orphan [`Settings::orphan_timeout`] after it entered FIN-WAIT-2,
    /// whatever its peer sends meanwhile, without a RST.
    /// Later segments from the peer get a RST, as there is no connection.
    /// Otherwise a peer that acknowledges the FIN and then sends an ACK
    /// now and then would keep the connection forever.
    fn expire_orphans(&mut self, now: smoltcp::time::Instant) {
        let mut i = 0;
        while i < self.orphans.len() {
            let h = self.orphans[i];
            let fin_wait_2 = self.get(h).state() == TcpState::FinWait2;
            let Some(c) = self.sockets.conn_mut(h) else {
                i += 1;
                continue;
            };
            match (fin_wait_2, c.gives_up) {
                (true, Some(at)) if at <= now => {
                    self.orphans.swap_remove(i);
                    self.remove_conn(h);
                    continue;
                }
                (true, None) => c.gives_up = Some(now + self.settings.orphan_timeout.into()),
                (true, Some(_)) => {}
                (false, _) => c.gives_up = None,
            }
            i += 1;
        }
    }

    /// When the next handshake waiting for its last ACK is due to be
    /// dropped, or the next orphan in FIN-WAIT-2 forgotten.
    pub(super) fn next_expiry(&self) -> Option<smoltcp::time::Instant> {
        let handshakes = self
            .listeners
            .values()
            .filter_map(|l| l.embryonic.first().map(|&(at, _)| at));
        let orphans = self
            .orphans
            .iter()
            .filter_map(|h| self.sockets.conn(*h)?.gives_up);
        handshakes.chain(orphans).min()
    }

    /// Moves finished handshakes to the accept queues and removes orphans
    /// that have closed.
    pub(super) fn housekeeping(&mut self) {
        let mut ready = BTreeSet::new();
        let mut gone = Vec::new();
        // Handshakes still to be looked at next turn.
        let mut later = Vec::new();
        for h in std::mem::take(&mut self.touched) {
            let Some(c) = self.sockets.conn(h) else {
                continue;
            };
            let Some(l) = self.listeners.get_mut(&c.local.port()) else {
                continue;
            };
            let Some(key) = l.embryo(h, &self.sockets) else {
                continue;
            };
            let s = self.sockets.get(h);
            match s.state() {
                TcpState::SynReceived => {}
                // An aborted socket keeps its endpoint until smoltcp sends
                // its RST, which the output allowance may leave for the
                // next turn.
                TcpState::Closed if s.remote_endpoint().is_some() => later.push(h),
                // `ingress` takes back a socket a RST returns to LISTEN.
                TcpState::Listen => {
                    l.embryonic.remove(&key);
                    if !l.relisten(h, &mut self.sockets, &mut self.by_tuple) {
                        gone.push(h);
                    }
                }
                TcpState::Closed | TcpState::TimeWait => {
                    l.embryonic.remove(&key);
                    if let Some(c) = self.sockets.take_conn(h) {
                        self.by_tuple.remove(&(c.local, c.remote));
                        l.left(c.remote.ip());
                    }
                    gone.push(h);
                }
                _ => {
                    l.embryonic.remove(&key);
                    l.ready.push_back(h);
                    ready.insert(self.conn(h).local.port());
                }
            }
        }
        self.touched = later;
        for h in gone {
            self.remove_socket(h);
        }
        let mut i = 0;
        while i < self.orphans.len() {
            let h = self.orphans[i];
            let state = self.get(h).state();
            if state == TcpState::Closed && self.get(h).remote_endpoint().is_none() {
                // An aborted socket is already CLOSED, but keeps its
                // endpoint until smoltcp sends the RST. The output
                // allowance may leave that packet for the next turn.
                self.orphans.swap_remove(i);
                self.remove_conn(h);
            } else {
                // smoltcp owns the explicit TIME-WAIT expiry and exposes
                // it through poll_at. Retransmitted FINs restart its ten-
                // second timer; egress moves the socket to CLOSED at expiry.
                // The orphan timeout must not interrupt that with a RST.
                if state == TcpState::TimeWait && !self.conn(h).retired {
                    self.sock(h).set_timeout(None);
                    let c = self.sockets.conn_mut(h).unwrap();
                    c.retired = true;
                    c.held.clear();
                    if let Some(id) = c.child.take() {
                        self.children.remove(id);
                        self.notice(TcpNotice::Gone(id));
                    }
                    self.time_wait.push_back(h);
                }
                i += 1;
            }
        }
        self.time_wait.retain(|h| self.sockets.conn(*h).is_some());
        if self.time_wait.len() > MAX_TIME_WAIT {
            while self.time_wait.len() > MAX_TIME_WAIT {
                let h = self.time_wait.pop_front().unwrap();
                self.remove_conn(h);
            }
            self.orphans.retain(|h| self.sockets.conn(*h).is_some());
        }
        for port in ready {
            self.offer(port);
        }
    }

    /// The endpoint stopped: every socket is aborted, the orphans are
    /// forgotten, and every command after this fails as closed.
    pub(super) fn stop(&mut self) {
        self.stopped = true;
        let handles: Vec<Id> = self.sockets.conns().map(|(h, _)| h).collect();
        for h in handles {
            self.sock(h).abort();
            let c = self.sockets.conn_mut(h).unwrap();
            c.held.clear();
            let child = c.child;
            if let Some(id) = child
                && c.open
                && c.live
                && !c.reset_sent
            {
                c.reset_sent = true;
                self.urgent
                    .push_back(MuxEvent::Child(id, StreamEvent::Reset));
            }
            if let Some(id) = child {
                self.notice(TcpNotice::Gone(id));
            }
        }
        for h in std::mem::take(&mut self.orphans) {
            self.remove_conn(h);
        }
        self.time_wait.clear();
        self.work = true;
    }

    // -----------------------------------------------------------------------
    // The layer above

    /// Says `notice` on the control port.
    fn notice(&mut self, notice: TcpNotice) {
        self.up
            .push_back(MuxEvent::Control(MessageEvent::Message(notice)));
    }

    /// Opens a child for socket `h`, as `origin` made it.
    fn open_child(&mut self, h: Id, origin: TcpOrigin) {
        self.sockets.mark(h);
        let child: Child = self
            .children
            .insert(h)
            .unwrap_or_else(|_| unreachable!("children are bounded by sockets"));
        let c = self.sockets.conn_mut(h).unwrap();
        c.child = Some(child.id());
        c.open = true;
        let opening = TcpOpening {
            local: c.local,
            remote: c.remote,
            origin,
        };
        self.up
            .push_back(MuxEvent::Opened(child, opening, self.buffer as u64));
    }

    /// Opens a child for each connection of `port`'s accept queue that the
    /// layer above accepts, while it has room.
    fn offer(&mut self, port: u16) {
        loop {
            if self.up.len() >= UP_ROOM {
                return;
            }
            let Some(l) = self.listeners.get_mut(&port) else {
                return;
            };
            if l.accept == 0 {
                return;
            }
            let Some(h) = l.ready.pop_front() else {
                return;
            };
            l.accept -= 1;
            let c = self.sockets.conn(h).expect("a connection");
            let (remote, handshake) = (c.remote, c.handshake.clone());
            l.left(remote.ip());
            self.open_child(h, TcpOrigin::Accepted(handshake));
            let c = self.sockets.conn_mut(h).unwrap();
            c.live = true;
            // The peer may have reset it while it waited: its child opens
            // gone, and is told so now rather than when it is closed.
            if let Some(id) = c.child
                && self.gone(id)
            {
                self.notice(TcpNotice::Gone(id));
            }
            self.grant(h);
        }
    }

    /// Grants the child of `h` the send-buffer room it has not been
    /// granted yet, while it may write.
    fn grant(&mut self, h: Id) {
        let s = self.sockets.get(h);
        let writable = matches!(s.state(), TcpState::Established | TcpState::CloseWait);
        let free = (s.send_capacity() - s.send_queue()) as u64;
        let c = self.sockets.conn_mut(h).unwrap();
        let Some(id) = c.child else {
            return;
        };
        if !writable || c.shut {
            c.send_granted = 0;
        } else if free > c.send_granted {
            self.up
                .push_back(MuxEvent::Credit(id, free - c.send_granted));
            c.send_granted = free;
        }
    }

    /// Brings the child of `h` up to date: its connect's outcome, its
    /// write credit, the data it may read, and its end or reset.
    fn refresh(&mut self, budget: &Budget, h: Id) {
        let Some(c) = self.sockets.conn(h) else {
            return;
        };
        let (Some(id), true) = (c.child, c.open) else {
            return;
        };
        let state = self.get(h).state();
        if !c.live {
            match state {
                TcpState::SynSent | TcpState::SynReceived | TcpState::Listen => return,
                TcpState::Closed => return self.connect_failed(h, id),
                _ => self.sockets.conn_mut(h).unwrap().live = true,
            }
        }
        let c = self.sockets.conn_mut(h).unwrap();
        if matches!(state, TcpState::TimeWait | TcpState::Closed) && !c.rst && !c.released {
            // The transport is done with it, whether or not the layer above
            // still holds the child: limits that count it stop counting.
            c.released = true;
            c.held.clear();
            self.notice(TcpNotice::Gone(id));
        }
        if self.conn(h).reset_sent {
            return;
        }
        self.grant(h);
        let (s, c) = self.sockets.socket_and_conn(h);
        let mut moved = false;
        while c.recv_credit > 0 && s.can_recv() && self.up.len() < UP_ROOM {
            let n = (c.recv_credit as usize).min(s.recv_queue()).min(DATA_MAX);
            // In the window the layer above lent, which paid for every
            // byte its credit lets come up. Otherwise charged to the
            // endpoint's budget, taking as much as it has room for.
            let chunk = match c.window.as_ref().and_then(Weak::upgrade) {
                Some(window) => {
                    let mut bytes = Vec::with_capacity(n);
                    recv_into(s, &mut bytes);
                    Chunk::in_window(bytes, window)
                }
                None => {
                    let Some(mut bytes) = ChargedBytes::with_capacity_within(budget, 1..=n) else {
                        break;
                    };
                    bytes
                        .fill(|into| {
                            recv_into(s, into);
                            Ok::<_, Infallible>(())
                        })
                        .expect("a receive stops at the capacity");
                    Chunk::from_bytes(bytes)
                }
            };
            let got = chunk.len();
            if got == 0 {
                break;
            }
            c.recv_credit -= got as u64;
            self.up
                .push_back(MuxEvent::Child(id, StreamEvent::Data(chunk)));
            moved = true;
        }
        if moved {
            // The window opened: tell the peer.
            self.work = true;
        }
        if s.can_recv() {
            return;
        }
        let end = match s.recv_slice(&mut []) {
            Ok(_) => false,
            Err(stcp::RecvError::Finished) => true,
            Err(stcp::RecvError::InvalidState) => c.fin && !c.rst,
        };
        if end && !c.ended_sent {
            c.ended_sent = true;
            self.up.push_back(MuxEvent::Child(id, StreamEvent::Ended));
        }
        if state == TcpState::Closed {
            c.reset_sent = true;
            self.up.push_back(MuxEvent::Child(id, StreamEvent::Reset));
        }
    }

    /// The connect of `h`, with child `id`, failed before its handshake
    /// finished: says why, closes the child, and lets the socket go.
    fn connect_failed(&mut self, h: Id, id: ChildId) {
        let error = match self.closed_reason(h) {
            ConnError::Reset => ConnError::Refused,
            e => e,
        };
        let c = self.sockets.conn_mut(h).unwrap();
        c.child = None;
        c.held.clear();
        let request = c.request;
        self.children.remove(id);
        self.notice(TcpNotice::Gone(id));
        if let Some(request) = request {
            self.notice(TcpNotice::ConnectFailed { request, error });
        }
        self.up.push_back(MuxEvent::Closed(id));
        self.orphan(h, false);
    }

    /// Brings changed children up to date, rotating after the last served child.
    fn refresh_all(&mut self, budget: &Budget) {
        let count = self.sockets.prepare_refresh();
        for _ in 0..count {
            if self.up.len() >= UP_ROOM {
                break;
            }
            let Some(h) = self.sockets.next() else {
                break;
            };
            self.refresh(budget, h);
            self.sockets.acknowledge(h);
            if self
                .sockets
                .conn(h)
                .is_some_and(|c| c.open && c.recv_credit > 0)
                && self.sockets.get(h).can_recv()
            {
                self.sockets.mark(h);
            }
        }
        if self.up.len() < UP_ROOM {
            self.sockets.after = None;
        }
    }

    /// Opens a connection to `remote`, as [`TcpControl::Connect`] asks.
    fn connect(&mut self, env: &Env<'_, ()>, request: Request, remote: SocketAddr) {
        let failed = |layer: &mut TcpLayer, error| {
            layer.notice(TcpNotice::ConnectFailed { request, error });
        };
        let addr = self.addr;
        if remote.is_ipv4() != addr.is_ipv4() || remote.ip().is_unspecified() {
            return failed(self, ConnError::Refused);
        }
        if self.stopped {
            return failed(self, ConnError::Closed);
        }
        let mut port = None;
        for _ in 0..(65536 - EPHEMERAL as u32) {
            let p = self.next_port;
            self.next_port = if p == u16::MAX { EPHEMERAL } else { p + 1 };
            if !self.ports.contains_key(&p) {
                port = Some(p);
                break;
            }
        }
        // Every ephemeral port is taken: the kernel says EADDRNOTAVAIL.
        let Some(port) = port else {
            return failed(self, ConnError::Refused);
        };
        let Some(charge) = self.reserve(env.budget()) else {
            return failed(self, ConnError::Refused);
        };
        let local = SocketAddr::new(addr, port);
        let mut s = new_socket(self.buffer);
        if s.0.connect(self.iface.context(), remote, local).is_err() {
            return failed(self, ConnError::Refused);
        }
        let h = self.add_socket(env.entropy(), s);
        self.reserved.insert(h, charge);
        let mut conn = Conn::new(local, remote, Side::Client);
        conn.request = Some(request);
        self.sockets.insert_conn(h, conn);
        self.by_tuple.insert((local, remote), h);
        self.take_port(port);
        self.open_child(h, TcpOrigin::Connected(request));
        self.work = true;
    }

    /// Does what a control command asks.
    fn control(&mut self, env: &Env<'_, ()>, command: TcpControl) {
        match command {
            TcpControl::Listen {
                port,
                backlog,
                answer,
            } => {
                if self.listeners.contains_key(&port) || self.ports.contains_key(&port) {
                    return self.notice(TcpNotice::ListenFailed { port });
                }
                if !self.make_room() {
                    return self.notice(TcpNotice::ListenFailed { port });
                }
                let backlog = backlog.map_or(self.backlog, |n| n.clamp(1, MAX_BACKLOG));
                self.listeners.insert(
                    port,
                    Listen {
                        backlog,
                        answer,
                        ..Listen::default()
                    },
                );
                self.take_port(port);
                self.notice(TcpNotice::Listening { port });
            }
            TcpControl::Unlisten { port } => {
                let Some(l) = self.listeners.remove(&port) else {
                    return;
                };
                self.free_port(port);
                for h in l.idle {
                    self.remove_socket(h);
                }
                // Connections that never reached accept are reset.
                for h in l.embryonic.into_iter().map(|(_, h)| h).chain(l.ready) {
                    self.orphan(h, true);
                }
            }
            TcpControl::Connect { request, remote } => self.connect(env, request, remote),
            TcpControl::AbortPeers(which) => {
                let hs: Vec<Id> = self
                    .sockets
                    .conns()
                    .filter(|(_, c)| which(c.remote.ip()))
                    .map(|(h, _)| h)
                    .collect();
                for h in hs {
                    self.abort(h);
                }
            }
            TcpControl::Accept { port, count } => {
                if let Some(l) = self.listeners.get_mut(&port) {
                    l.accept = l.accept.saturating_add(count);
                    self.offer(port);
                }
            }
            TcpControl::Backlog { port, backlog } => {
                if let Some(l) = self.listeners.get_mut(&port) {
                    l.backlog = backlog.clamp(1, MAX_BACKLOG);
                }
            }
            TcpControl::Answer { port, answer } => {
                if let Some(l) = self.listeners.get_mut(&port) {
                    l.answer = Some(answer);
                }
            }
            TcpControl::Abort(id) => {
                if !self.gone(id)
                    && let Some(&h) = self.children.get(id)
                {
                    self.abort(h);
                }
            }
            TcpControl::KeepAlive { child, interval } => {
                if let Some(&h) = self.children.get(child)
                    && self.sockets.conn(h).is_some_and(|c| !c.orphaned)
                {
                    let socket = self.sock(h);
                    socket.set_keep_alive(interval.map(Into::into));
                    socket.restart_keep_alive(smol(env.now()));
                    self.work = true;
                }
            }
            TcpControl::Hold { child, item } => match self.children.get(child).copied() {
                Some(h) if !self.gone(child) => {
                    self.sockets.conn_mut(h).unwrap().held.push(item);
                }
                _ => drop(item),
            },
        }
    }

    /// Whether a command is refused: `Some(true)` for a child that is
    /// closed or cannot write any more, `Some(false)` for a write the send
    /// buffer has no room for yet, which credit never asks for.
    fn refuses(&self, op: &MuxOp<ByteStream, Messages<TcpNotice, TcpControl>>) -> Option<bool> {
        let MuxOp::Child(id, command) = op else {
            return None;
        };
        let Some(h) = self.open_socket(*id) else {
            return Some(true);
        };
        let StreamCommand::Write(chunk) = command else {
            return None;
        };
        let c = self.conn(h);
        let s = self.get(h);
        if c.shut
            || c.reset_sent
            || !matches!(s.state(), TcpState::Established | TcpState::CloseWait)
        {
            return Some(true);
        }
        (s.send_capacity() - s.send_queue() < chunk.len()).then_some(false)
    }

    /// Lets `units` more bytes come up for child `id`, in `window` from now
    /// on if the layer above lent one.
    fn credit(&mut self, env: &Env<'_, ()>, id: ChildId, units: u64, window: Option<Weak<Charge>>) {
        let Some(h) = self.open_socket(id) else {
            return;
        };
        let c = self.sockets.conn_mut(h).unwrap();
        c.recv_credit = c.recv_credit.saturating_add(units);
        if window.is_some() {
            c.window = window;
        }
        self.sockets.mark(h);
        self.refresh_all(env.budget());
    }

    /// The socket of child `id`, while the layer above holds the child.
    fn open_socket(&self, id: ChildId) -> Option<Id> {
        self.mapped(id).filter(|h| self.conn(*h).open)
    }

    /// Prepares for the packets of one step: the interface's clock, and
    /// the handshakes given up, before anything more is sent for them.
    fn prime(&mut self, now: smoltcp::time::Instant) {
        if !self.primed {
            self.iface.poll_maintenance(now);
            self.expire_handshakes(now);
            self.primed = true;
        }
    }

    /// One step: everything smoltcp has to send, the orphans and
    /// handshakes, the pages to give back, and every child's events.
    fn step(&mut self, env: &Env<'_, ()>) {
        let now = smol(env.now());
        // What this step changes, such as a socket it lets go, asks for
        // another.
        self.work = false;
        self.prime(now);
        while self
            .iface
            .poll_egress(now, &mut self.dev, &mut self.sockets.set)
            != smoltcp::iface::PollResult::None
        {}
        self.expire_orphans(now);
        self.housekeeping();
        self.saturated = self.dev.full();
        self.flush_transmit();
        if self.dirty.is_empty() {
            self.next_release = None;
        } else {
            match self.next_release {
                Some(at) if at <= now => {
                    self.release_quiet();
                    self.next_release =
                        (!self.dirty.is_empty()).then(|| now + RELEASE_EVERY.into());
                }
                Some(_) => {}
                None => self.next_release = Some(now + RELEASE_EVERY.into()),
            }
        }
        self.refresh_all(env.budget());
        self.schedule(now);
        self.primed = false;
        self.stepped = Some(env.now());
    }

    fn schedule(&mut self, now: smoltcp::time::Instant) {
        if self.dirty.is_empty() {
            self.next_release = None;
        }
        let at = self.iface.poll_at(now, &mut self.sockets.set);
        self.next = [at, self.next_release, self.next_expiry()]
            .into_iter()
            .flatten()
            .min()
            .map(unsmol);
    }

    fn flush_transmit(&mut self) {
        let mut sent = std::mem::take(&mut self.dev.tx);
        for p in &mut sent {
            self.sent(p);
        }
        self.dev.out.extend(sent.drain(..));
        self.dev.tx = sent;
    }

    // -----------------------------------------------------------------------
    // What the async handles ask

    /// The socket of child `id`, while it is mapped.
    fn mapped(&self, id: ChildId) -> Option<Id> {
        self.children.get(id).copied()
    }

    /// What a read on child `id` gets now that nothing is left to come up.
    pub(super) fn read_verdict(&mut self, id: ChildId) -> Verdict {
        let Some(h) = self.mapped(id) else {
            return Verdict::Failed(ConnError::Closed);
        };
        if self.stopped {
            return Verdict::Failed(ConnError::Closed);
        }
        let c = self.conn(h);
        if c.reset {
            return Verdict::Failed(self.closed_reason(h));
        }
        let (fin, rst) = (c.fin, c.rst);
        let s = self.sock(h);
        if s.can_recv() {
            return Verdict::Wait;
        }
        match s.recv_slice(&mut []) {
            Ok(_) => Verdict::Wait,
            Err(stcp::RecvError::Finished) => Verdict::Done,
            Err(stcp::RecvError::InvalidState) if fin && !rst => Verdict::Done,
            Err(stcp::RecvError::InvalidState) => Verdict::Failed(self.closed_reason(h)),
        }
    }

    /// What a write on child `id` gets with no credit left.
    pub(super) fn write_verdict(&self, id: ChildId) -> Verdict {
        let Some(h) = self.mapped(id) else {
            return Verdict::Failed(ConnError::Closed);
        };
        if self.stopped || self.conn(h).shut {
            return Verdict::Failed(ConnError::Closed);
        }
        match self.get(h).state() {
            TcpState::Established | TcpState::CloseWait => Verdict::Wait,
            TcpState::Closed => Verdict::Failed(self.closed_reason(h)),
            // The FIN went out already.
            _ => Verdict::Failed(ConnError::Closed),
        }
    }

    /// Whether the connect of child `id` finished, failed, or waits.
    pub(super) fn connect_verdict(&self, id: ChildId) -> Verdict {
        let Some(h) = self.mapped(id) else {
            return Verdict::Failed(ConnError::Closed);
        };
        if self.stopped {
            return Verdict::Failed(ConnError::Closed);
        }
        match self.get(h).state() {
            TcpState::SynSent | TcpState::SynReceived => Verdict::Wait,
            TcpState::Closed => Verdict::Failed(match self.closed_reason(h) {
                ConnError::Reset => ConnError::Refused,
                e => e,
            }),
            _ => Verdict::Done,
        }
    }

    /// Why ending child `id`'s stream fails, if its connection closed
    /// before this side ended it.
    pub(super) fn end_verdict(&self, id: ChildId) -> Option<ConnError> {
        let h = self.mapped(id)?;
        (self.get(h).state() == TcpState::Closed && !self.conn(h).shut)
            .then(|| self.closed_reason(h))
    }

    /// Whether the connection of child `id` is gone, whether or not the
    /// layer above still holds the child: reset by either side, retired
    /// into TIME-WAIT, in TIME-WAIT or closed on its own (see
    /// [`Conn::released`]), forgotten, or the endpoint stopped.
    pub(super) fn gone(&self, id: ChildId) -> bool {
        self.stopped
            || self
                .mapped(id)
                .and_then(|h| self.sockets.conn(h))
                .is_none_or(|c| c.rst || c.retired || c.released)
    }

    /// The peer addresses of every connection.
    pub(super) fn peers(&self) -> BTreeSet<IpAddr> {
        self.sockets.conns().map(|(_, c)| c.remote.ip()).collect()
    }

    /// The mapped children, in socket order.
    pub(super) fn child_ids(&self) -> Vec<ChildId> {
        self.sockets.conns().filter_map(|(_, c)| c.child).collect()
    }

    /// Whether the last step used up the output allowance, so more may be
    /// waiting to go once the layer below takes it.
    pub(super) fn saturated(&self) -> bool {
        self.saturated
    }

    /// Whether a step has something to do or packets wait to go.
    pub(super) fn busy(&self) -> bool {
        self.work || !self.dev.tx.is_empty() || !self.dev.out.is_empty()
    }

    /// The socket of child `id`.
    #[cfg(test)]
    pub(super) fn socket_of(&self, id: ChildId) -> Id {
        self.mapped(id).expect("a mapped child")
    }

    /// Opens a child for `h`, a connection a test took out of its accept
    /// queue by hand, as an accept would. A connection the test already
    /// orphaned gets a child the layer above has closed.
    #[cfg(test)]
    pub(super) fn adopt(&mut self, h: Id) -> ChildId {
        let handshake = self.conn(h).handshake.clone();
        self.open_child(h, TcpOrigin::Accepted(handshake));
        let c = self.sockets.conn_mut(h).unwrap();
        c.live = true;
        c.open = !c.orphaned;
        let id = c.child.unwrap();
        self.grant(h);
        id
    }
}

impl Layer for TcpLayer {
    type Lower = Packets<CheckedIpPacket, Chunk>;
    type Upper = Tcp;
    type Report = ();
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = Infallible;

    fn report_bytes(_: &()) -> Option<usize> {
        Some(0)
    }

    fn is_terminal(&self) -> bool {
        self.stopped && self.dev.out.is_empty()
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, ()>,
        event: EventOf<Self::Lower>,
    ) -> Result<Admit<EventOf<Self::Lower>>, Infallible> {
        let packet = match event {
            PacketEvent::Ended => {
                if !self.stopped {
                    self.stop();
                }
                return Ok(Admit::Taken);
            }
            PacketEvent::Packet(packet) => packet,
        };
        if self.stopped {
            return Ok(Admit::Closed(PacketEvent::Packet(packet)));
        }
        if !self.reserve_storage(env.budget()) {
            return Ok(Admit::Blocked(PacketEvent::Packet(packet)));
        }
        if self.dev.full() || self.up.len() >= UP_ROOM || self.urgent.len() >= UP_ROOM {
            return Ok(Admit::Blocked(PacketEvent::Packet(packet)));
        }
        if packet.sort() != Sort::Transport(Transport::Tcp) {
            return Ok(Admit::Taken);
        }
        let now = smol(env.now());
        self.prime(now);
        // After a packet with data, egress immediately, so smoltcp can ACK
        // every second segment as it means to. With one egress per batch,
        // a whole window of data got one ACK. The sender's slow start grows
        // by one segment per ACK, so its window then grew by one segment
        // per round trip. Pure ACKs are still handled as a batch.
        let bytes = packet.into_bytes().into_vec();
        if self.ingress(env.entropy(), env.budget(), now, bytes) {
            self.iface
                .poll_egress(now, &mut self.dev, &mut self.sockets.set);
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, ()>,
        command: CommandOf<Self::Upper>,
    ) -> Result<Admit<CommandOf<Self::Upper>>, Infallible> {
        if !self.reserve_storage(env.budget()) {
            return Ok(Admit::Blocked(command));
        }
        match self.refuses(command.op()) {
            Some(true) => return Ok(Admit::Closed(command)),
            Some(false) => return Ok(Admit::Blocked(command)),
            None => {}
        }
        // The commands that can repeat without end each add an event: a
        // control its answer to `up`, a write its completion to `urgent`.
        // Each waits for room in that queue alone, so a write never waits
        // behind events the layer above refused. The rest add a bounded
        // number per child.
        let full = match command.op() {
            MuxOp::Control(MessageCommand::Send(_)) => self.up.len() >= UP_ROOM,
            MuxOp::Child(_, StreamCommand::Write(_)) => self.urgent.len() >= UP_ROOM,
            _ => false,
        };
        if full {
            return Ok(Admit::Blocked(command));
        }
        match command.into_op() {
            MuxOp::Control(MessageCommand::Send(control)) => self.control(env, control),
            MuxOp::Control(MessageCommand::End) => {}
            MuxOp::Child(id, StreamCommand::Write(chunk)) => {
                let h = self.open_socket(id).expect("admitted");
                let n = self.sock(h).send_slice(&chunk).unwrap_or(0);
                let c = self.sockets.conn_mut(h).unwrap();
                c.send_granted = c.send_granted.saturating_sub(n as u64);
                self.urgent
                    .push_back(MuxEvent::Child(id, StreamEvent::Written(n as u64)));
                self.soiled(h);
                self.work = true;
            }
            MuxOp::Child(id, StreamCommand::End) => {
                let h = self.open_socket(id).expect("admitted");
                let c = self.sockets.conn_mut(h).unwrap();
                c.shut = true;
                c.send_granted = 0;
                self.close_if_drained(h);
                self.work = true;
            }
            MuxOp::Child(id, StreamCommand::Reset) => {
                let h = self.open_socket(id).expect("admitted");
                self.abort(h);
            }
            MuxOp::Credit(id, units) => self.credit(env, id, units, None),
            MuxOp::Window(id, units, window) => self.credit(env, id, units, Some(window)),
            MuxOp::Close(id, why) => {
                // TCP's only way to say why is how it closes. A connection
                // the receiver never took, past its limit, refused by the
                // application or for want of memory, is reset, as Linux
                // resets a connection still in the accept queue of a
                // listener that closes. One it took closes as a process's
                // socket does when the process is done or dies: a FIN, or
                // a reset if bytes it never read are left.
                if let Some(h) = self.open_socket(id) {
                    let refused = matches!(why, Closing::Prohibited | Closing::ResourceShortage);
                    self.orphan(h, refused);
                }
            }
        }
        Ok(Admit::Taken)
    }

    fn on_timer(&mut self, env: &mut Env<'_, ()>, (): ()) -> Result<bool, Infallible> {
        if !self.reserve_storage(env.budget()) {
            return Ok(false);
        }
        // A step at this time already ran and found nothing to send yet;
        // another would find the same, so the timer is declined.
        if self.work || self.stepped != Some(env.now()) {
            self.work = true;
            return Ok(true);
        }
        self.schedule(smol(env.now()));
        Ok(false)
    }

    fn advance(&mut self, env: &mut Env<'_, ()>) -> Result<bool, Infallible> {
        if !self.reserve_storage(env.budget()) {
            return Ok(false);
        }
        if !self.work {
            let before = (self.up.len(), self.urgent.len());
            self.refresh_all(env.budget());
            return Ok(before != (self.up.len(), self.urgent.len()));
        }
        self.step(env);
        Ok(true)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<CommandOf<Self::Lower>> {
        let full = self.dev.full();
        match self.dev.out.pop_front() {
            Some(packet) => {
                // Room again: smoltcp may have more to send.
                self.work |= full;
                Some(PacketCommand::Send(Chunk::unpaid(packet)))
            }
            None if self.stopped && self.dev.tx.is_empty() && !self.ended => {
                self.ended = true;
                Some(PacketCommand::End)
            }
            None => None,
        }
    }

    fn take_event(&mut self) -> Option<EventOf<Self::Upper>> {
        let full = self.up.len() >= UP_ROOM;
        let event = self.urgent.pop_front().or_else(|| self.up.pop_front());
        self.work |= full && self.up.len() < UP_ROOM && self.sockets.pending() != 0;
        event
    }

    fn take_urgent(&mut self) -> Option<EventOf<Self::Upper>> {
        self.urgent.pop_front()
    }

    fn deadline(&self) -> Option<(Instant, ())> {
        if self.dev.full() {
            return None;
        }
        self.next.map(|at| (at, ()))
    }
}
