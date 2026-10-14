//! One observer session on the world socket: requests in, replies out.
//!
//! Each session has a thread of its own. It waits for requests, answers
//! one-off requests at once, and sends what changed to each subscription
//! a few times a second. A session never touches the world's own thread:
//! it reads what the run records.

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, UNIX_EPOCH};

use fictionet::sync::Mutex;

use super::json::{self, Object, Scalar};
use super::packets::{LinkWatch, keylog};
use super::view::{self, View};
use super::watches::Subscription;
use crate::Attacher;
use crate::relay::{self, Message, unix};
use crate::watch::Graph;

/// How often a graph subscription sends what changed.
const GRAPH_TICK: Duration = Duration::from_millis(250);
/// How often a packet subscription looks for new packets.
const PACKET_TICK: Duration = Duration::from_millis(100);
/// A reply that cannot be sent for this long ends the session: the
/// observer has stopped reading.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Subscriptions one session may hold.
const MAX_SUBSCRIPTIONS: usize = 64;
/// Matches the dashboard's connection cap, including direct observers.
const DEFAULT_SESSIONS: usize = 64;

/// Sessions admitted by one listener, including clients with no streams.
pub(crate) struct Sessions(Mutex<Admission>);

struct Admission {
    limit: usize,
    active: usize,
}

impl Default for Sessions {
    fn default() -> Self {
        Self(Mutex::new(Admission {
            limit: DEFAULT_SESSIONS,
            active: 0,
        }))
    }
}

impl Sessions {
    pub(crate) fn set_limit(&self, limit: usize) {
        self.0.lock().limit = limit;
    }

    /// Reserves before sending `accept` or starting a thread.
    pub(crate) fn reserve(self: &Arc<Self>) -> Option<SessionSlot> {
        let mut admission = self.0.lock();
        if admission.active >= admission.limit {
            return None;
        }
        admission.active += 1;
        Some(SessionSlot(self.clone()))
    }
}

/// Releases admission on disconnect, failed acceptance, or failed spawn.
pub(crate) struct SessionSlot(Arc<Sessions>);

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.0.0.lock().active -= 1;
    }
}

pub(crate) fn start(attacher: Attacher, fd: OwnedFd, slot: SessionSlot) {
    let _ = start_thread(
        attacher,
        fd,
        slot,
        std::thread::Builder::new().name("fictionet-observe".into()),
    );
}

fn start_thread(
    attacher: Attacher,
    fd: OwnedFd,
    slot: SessionSlot,
    builder: std::thread::Builder,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    builder.spawn(move || {
        let _slot = slot;
        let mut session = Session {
            attacher,
            fd,
            subs: Vec::new(),
        };
        let _ = session.run();
    })
}

/// Counts a connected observer, so links copy packets and TLS keeps keys.
struct Viewer(Arc<Graph>);

impl Viewer {
    fn new(graph: Arc<Graph>) -> Viewer {
        graph.viewers.fetch_add(1, Ordering::Relaxed);
        Viewer(graph)
    }
}

impl Drop for Viewer {
    fn drop(&mut self) {
        self.0.viewers.fetch_sub(1, Ordering::Relaxed);
    }
}

enum Sub {
    /// `watch`: the graph, then what changed.
    /// `after` is where the events start, if the request said: the first
    /// run's events after that number, and every event of a later run.
    Graph {
        id: u32,
        shown: Option<(u64, View, Viewer)>,
        after: Option<u64>,
        said_waiting: bool,
        next: Instant,
        next_graph: Instant,
    },
    /// `packets`: one link's packets as they are copied.
    Packets {
        id: u32,
        watch: Arc<LinkWatch>,
        cursor: u64,
        _held: (Subscription, Viewer),
        next: Instant,
    },
}

impl Sub {
    fn id(&self) -> u32 {
        match self {
            Sub::Graph { id, .. } | Sub::Packets { id, .. } => *id,
        }
    }
}

struct Session {
    /// The world socket's channel, which knows the world's run.
    attacher: Attacher,
    fd: OwnedFd,
    subs: Vec<Sub>,
}

type Request = std::collections::HashMap<String, Scalar>;

fn error(message: &str) -> String {
    Object::new().str("error", message).done()
}

fn event(name: &str, data: &str) -> String {
    Object::new().str("event", name).raw("data", data).done()
}

fn link_id(req: &Request) -> Option<u64> {
    let link = req.get("link")?;
    match link {
        Scalar::Str(s) => s.strip_prefix('e').unwrap_or(s).parse().ok(),
        other => other.as_u64(),
    }
}

impl Session {
    /// The run of the world on this socket, and a number that is
    /// different for each run.
    fn current(&self) -> (Option<Arc<Graph>>, u64) {
        current(&self.attacher)
    }

    fn run(&mut self) -> std::io::Result<()> {
        let fd = self.fd.as_raw_fd();
        // Sends block, up to a limit; reads never do.
        unix::set_nonblocking(fd, false)?;
        let _ = unix::set_timeout(fd, libc::SO_SNDTIMEO, Some(SEND_TIMEOUT));
        let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
        loop {
            let wait = self.subs.iter().map(|s| match s {
                Sub::Graph { next, .. } | Sub::Packets { next, .. } => *next,
            });
            let timeout = wait.min().map_or(1000, |t| {
                t.saturating_duration_since(Instant::now()).as_millis() as i32
            });
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let ready = unsafe { libc::poll(&mut pfd, 1, timeout.max(0)) };
            if ready > 0 {
                let n = match unix::recv(fd, &mut buf, true) {
                    Ok(0) => return Ok(()),
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                    Err(e) => return Err(e),
                };
                if n > relay::MAX_MESSAGE {
                    return Ok(());
                }
                if n > 0 {
                    match relay::decode(&buf[..n]) {
                        Ok(Message::Request { id, body }) => {
                            let body = std::str::from_utf8(body).ok().and_then(json::parse_flat);
                            self.handle(id, body)?;
                        }
                        // Anything else closes the session.
                        _ => return Ok(()),
                    }
                }
            }
            self.pump()?;
        }
    }

    /// Sends one value as replies to `id`, cut into chunks that fit a
    /// message.
    fn send(&self, id: u32, value: &[u8], binary: bool, end: bool) -> std::io::Result<()> {
        let mut chunks = value.chunks(relay::MAX_REPLY_CHUNK).peekable();
        let mut first = true;
        while first || chunks.peek().is_some() {
            first = false;
            let chunk = chunks.next().unwrap_or(&[]);
            let mut flags = if binary { relay::BINARY } else { 0 };
            if chunks.peek().is_some() {
                flags |= relay::MORE;
            } else if end {
                flags |= relay::END;
            }
            let mut header = [relay::REPLY, 0, 0, 0, 0, flags];
            header[1..5].copy_from_slice(&id.to_be_bytes());
            unix::send_parts(self.fd.as_raw_fd(), &[&header, chunk], false)?;
        }
        Ok(())
    }

    fn reply(&self, id: u32, value: &str) -> std::io::Result<()> {
        self.send(id, value.as_bytes(), false, true)
    }

    fn handle(&mut self, id: u32, req: Option<Request>) -> std::io::Result<()> {
        let Some(req) = req else {
            return self.reply(id, &error("the request is not a flat JSON object"));
        };
        let Some(op) = req.get("op").and_then(Scalar::as_str) else {
            return self.reply(id, &error("the request has no op"));
        };
        let graph = self.current().0;
        match op {
            "world" => self.reply(id, &world(graph.as_deref())),
            "graph" => match graph {
                Some(g) => self.reply(id, &view::snapshot(&g, None).1.1),
                None => self.reply(id, &error("no world is running yet")),
            },
            "counters" => match graph {
                Some(g) => self.reply(id, &view::counters(&g)),
                None => self.reply(id, &error("no world is running yet")),
            },
            "events" => match graph {
                Some(g) => {
                    let after = req.get("after").and_then(Scalar::as_u64).unwrap_or(0);
                    let max = req
                        .get("max")
                        .and_then(Scalar::as_u64)
                        .map_or(view::EVENTS_PER_REPLY, |m| {
                            (m as usize).min(view::EVENTS_PER_REPLY)
                        });
                    self.reply(id, &view::events(&g, after, max))
                }
                None => self.reply(id, &error("no world is running yet")),
            },
            "keylog" => match graph {
                Some(g) => self.send(id, keylog(&g).as_bytes(), true, true),
                None => self.reply(id, &error("no world is running yet")),
            },
            "watch" | "packets" if self.subs.len() >= MAX_SUBSCRIPTIONS => {
                self.reply(id, &error("this session has too many subscriptions"))
            }
            "watch" => {
                let after = req.get("after").and_then(Scalar::as_u64);
                self.subs.push(Sub::Graph {
                    id,
                    shown: None,
                    after,
                    said_waiting: false,
                    next: Instant::now(),
                    next_graph: Instant::now(),
                });
                Ok(())
            }
            "link" | "packets" | "packet" | "pcap" => {
                let Some(link) = link_id(&req) else {
                    return self.reply(id, &error("the request needs a link, such as \"e5\""));
                };
                let watch = match (op, &graph) {
                    ("packets", Some(g)) => match g.watches.acquire(g, link) {
                        Ok((w, s)) => Some((w, Some(s))),
                        Err(reason) => return self.reply(id, &error(reason)),
                    },
                    ("packet" | "pcap", Some(g)) => g.watches.existing(link).map(|w| (w, None)),
                    _ => None,
                };
                match op {
                    "link" => match graph.as_ref().and_then(|g| view::link(g, link)) {
                        Some(info) => self.reply(id, &info),
                        None => self.reply(id, &error("no such link")),
                    },
                    "packets" => {
                        let Some((watch, Some(subscription))) = watch else {
                            return self.reply(id, &error("no such link"));
                        };
                        let after = req.get("after").and_then(Scalar::as_u64).unwrap_or(0);
                        self.send(
                            id,
                            event("link", &watch.describe()).as_bytes(),
                            false,
                            false,
                        )?;
                        let Some(g) = watch.graph() else {
                            return self.reply(id, &error("no such link"));
                        };
                        let held = (subscription, Viewer::new(g));
                        self.subs.push(Sub::Packets {
                            id,
                            watch,
                            cursor: after,
                            _held: held,
                            next: Instant::now(),
                        });
                        Ok(())
                    }
                    "packet" => {
                        let Some((watch, _)) = watch else {
                            return self.reply(id, &error("nothing is watching that link"));
                        };
                        watch.pump();
                        let detail = req
                            .get("seq")
                            .and_then(Scalar::as_u64)
                            .and_then(|seq| watch.detail(seq));
                        match detail {
                            Some(d) => self.reply(id, &d),
                            None => self.reply(id, &error("that packet is not kept")),
                        }
                    }
                    _ => {
                        let Some((watch, _)) = watch else {
                            return self.reply(id, &error("nothing is watching that link"));
                        };
                        watch.pump();
                        self.send(id, &watch.pcapng(), true, true)
                    }
                }
            }
            "cancel" => {
                // An id past what a request id can be names no subscription.
                let target = req
                    .get("id")
                    .and_then(Scalar::as_u64)
                    .and_then(|n| u32::try_from(n).ok());
                match self.subs.iter().position(|s| Some(s.id()) == target) {
                    Some(i) => {
                        let sub = self.subs.remove(i);
                        self.reply(sub.id(), &event("end", r#"{"reason":"cancelled"}"#))?;
                        drop(sub);
                        self.reply(id, r#"{"ok":true}"#)
                    }
                    None => self.reply(id, &error("no such subscription")),
                }
            }
            other => self.reply(id, &error(&format!("unknown op {other}"))),
        }
    }

    /// Sends what each subscription has that is new.
    fn pump(&mut self) -> std::io::Result<()> {
        let now = Instant::now();
        let mut ended = Vec::new();
        let mut out: Vec<(u32, String, bool)> = Vec::new();
        for sub in &mut self.subs {
            match sub {
                Sub::Graph {
                    id,
                    shown,
                    after,
                    said_waiting,
                    next,
                    next_graph,
                } => {
                    if *next > now {
                        continue;
                    }
                    *next = now + GRAPH_TICK;
                    let (graph, generation) = current(&self.attacher);
                    match (graph, shown) {
                        (None, _) => {
                            if !*said_waiting {
                                out.push((*id, event("waiting", "{}"), false));
                                *said_waiting = true;
                            }
                        }
                        (Some(graph), Some((g, view, _))) if *g == generation => {
                            if *next_graph <= now {
                                graph.watches.reap_idle();
                                for (name, data) in view::changes(&graph, view) {
                                    out.push((*id, event(name, &data), false));
                                }
                                *next_graph = now + GRAPH_TICK;
                            }
                            let (events, full) = view::event_changes(&graph, view);
                            for (name, data) in events {
                                out.push((*id, event(name, &data), false));
                            }
                            *next = if full { now } else { *next_graph };
                            if view.ended() && !view.events_pending(&graph) {
                                out.push((
                                    *id,
                                    event("end", r#"{"reason":"the world ended"}"#),
                                    true,
                                ));
                                ended.push(*id);
                            }
                        }
                        (Some(graph), shown) => {
                            let (view, (name, data)) = view::snapshot(&graph, *after);
                            // A later run's events start from its first.
                            *after = after.map(|_| 0);
                            out.push((*id, event(name, &data), false));
                            *next_graph = now + GRAPH_TICK;
                            *next = if view.events_pending(&graph) {
                                now
                            } else {
                                *next_graph
                            };
                            if view.ended() && !view.events_pending(&graph) {
                                out.push((
                                    *id,
                                    event("end", r#"{"reason":"the world ended"}"#),
                                    true,
                                ));
                                ended.push(*id);
                            }
                            *shown = Some((generation, view, Viewer::new(graph)));
                        }
                    }
                }
                Sub::Packets {
                    id,
                    watch,
                    cursor,
                    next,
                    ..
                } => {
                    if *next > now {
                        continue;
                    }
                    *next = now + PACKET_TICK;
                    watch.pump();
                    for (seq, row) in watch.rows_after(*cursor, 500) {
                        out.push((*id, event("packet", &row), false));
                        *cursor = seq;
                    }
                    if watch.closed() && watch.rows_after(*cursor, 1).is_empty() {
                        out.push((*id, event("end", r#"{"reason":"the link closed"}"#), true));
                        ended.push(*id);
                    }
                }
            }
        }
        // Ended subscriptions let go of the world only once their end is
        // sent: a world that is exiting waits for that (see `Listening`).
        let (finished, kept) = std::mem::take(&mut self.subs)
            .into_iter()
            .partition(|s| ended.contains(&s.id()));
        let finished: Vec<Sub> = finished;
        self.subs = kept;
        for (id, value, end) in out {
            self.send(id, value.as_bytes(), false, end)?;
        }
        drop(finished);
        Ok(())
    }
}

/// The run of the world on this socket, and a number that is different
/// for each run.
fn current(attacher: &Attacher) -> (Option<Arc<Graph>>, u64) {
    let graph = attacher.graph();
    let generation = graph.as_ref().map_or(0, |g| Arc::as_ptr(g) as usize as u64);
    (graph, generation)
}

/// The `world` reply: what this world is, and whether it runs.
fn world(graph: Option<&Graph>) -> String {
    let o = Object::new()
        .num("observe", relay::OBSERVE_VERSION)
        .str("fictionet", env!("CARGO_PKG_VERSION"));
    match graph {
        None => o
            .bool("running", false)
            .bool("ended", false)
            .raw("started", "null")
            .raw("t", "null")
            .done(),
        Some(g) => {
            let ended = g.state().ended;
            let started = g
                .start_wall
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis());
            o.bool("running", !ended)
                .bool("ended", ended)
                .num("started", started)
                .secs("t", g.since_start())
                .done()
        }
    }
}

#[cfg(all(test, feature = "observe"))]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;

    #[test]
    fn session_slots_are_bounded_and_reusable() {
        let sessions = Arc::new(Sessions::default());
        sessions.set_limit(2);
        let first = sessions.reserve().unwrap();
        let second = sessions.reserve().unwrap();
        assert!(sessions.reserve().is_none());
        drop(first);
        let reused = sessions.reserve().unwrap();
        assert!(sessions.reserve().is_none());
        sessions.set_limit(0);
        drop((second, reused));
        assert!(sessions.reserve().is_none());
        sessions.set_limit(1);
        assert!(sessions.reserve().is_some());
    }

    #[test]
    fn session_slots_release_on_disconnect_and_failed_thread_creation() {
        for fail in [false, true] {
            let sessions = Arc::new(Sessions::default());
            sessions.set_limit(1);
            let mut fds = [0; 2];
            // SAFETY: socketpair initializes two descriptors, owned from here.
            assert_eq!(
                unsafe {
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr())
                },
                0
            );
            let (ours, theirs) =
                unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            let (attacher, _attachments) = crate::attachments();
            let builder = std::thread::Builder::new();
            let builder = if fail {
                builder.stack_size(usize::MAX)
            } else {
                builder
            };
            let started = start_thread(attacher, ours, sessions.reserve().unwrap(), builder);
            if fail {
                assert!(started.is_err());
            } else {
                assert!(sessions.reserve().is_none());
                drop(theirs);
                started.unwrap().join().unwrap();
            }
            assert!(sessions.reserve().is_some());
        }
    }

    #[test]
    fn full_event_batch_schedules_immediate_catch_up() {
        let mut fds = [0; 2];
        // SAFETY: socketpair initializes the two owned descriptors.
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) },
            0
        );
        let (ours, theirs) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let reader = std::thread::spawn(move || {
            let mut buf = vec![0; relay::MAX_MESSAGE + 1];
            let mut count = 0;
            while let Ok(n) = unix::recv(theirs.as_raw_fd(), &mut buf, false) {
                if n == 0 {
                    break;
                }
                if let Ok(Message::Reply { body, .. }) = relay::decode(&buf[..n])
                    && std::str::from_utf8(body)
                        .unwrap()
                        .contains(r#""event":"event""#)
                {
                    count += 1;
                }
            }
            count
        });
        let (attacher, mut attachments) = crate::attachments();
        let mut session = Session {
            attacher,
            fd: ours,
            subs: Vec::new(),
        };
        crate::block_on(crate::run(crate::Seed::random(), |fcx| async move {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(
                std::future::Future::poll(std::pin::pin!(attachments.next(&fcx)).as_mut(), &mut cx)
                    .is_pending()
            );
            session
                .handle(1, json::parse_flat(r#"{"op":"watch","after":0}"#))
                .unwrap();
            session.pump().unwrap();
            let graph_tick = match &session.subs[0] {
                Sub::Graph { next_graph, .. } => *next_graph,
                _ => unreachable!(),
            };
            for i in 0..2001u32 {
                fcx.record(crate::events::Event::new("test", "tick").field("i", i));
            }
            if let Sub::Graph { next, .. } = &mut session.subs[0] {
                *next = Instant::now();
            }
            session.pump().unwrap();
            if let Sub::Graph {
                next, next_graph, ..
            } = &session.subs[0]
            {
                assert!(*next <= Instant::now());
                assert_eq!(*next_graph, graph_tick);
            }
            session.pump().unwrap();
            session.pump().unwrap();
            if let Sub::Graph {
                next, next_graph, ..
            } = &session.subs[0]
            {
                assert!(*next > Instant::now());
                assert_eq!(*next_graph, graph_tick);
            }
            drop(session);
            Ok(())
        }))
        .unwrap();
        assert_eq!(reader.join().unwrap(), 2001);
    }

    /// A cancel with an id past `u32` cancels nothing, rather than the
    /// subscription its low 32 bits name.
    #[test]
    fn an_out_of_range_cancel_cancels_nothing() {
        let mut fds = [0; 2];
        // SAFETY: socketpair fills two fds, owned from here.
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) },
            0
        );
        let (ours, theirs) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let (attacher, _attachments) = crate::attachments();
        let mut session = Session {
            attacher,
            fd: ours,
            subs: Vec::new(),
        };
        session
            .handle(1, json::parse_flat(r#"{"op":"watch"}"#))
            .unwrap();
        session
            .handle(2, json::parse_flat(r#"{"op":"cancel","id":4294967297}"#))
            .unwrap();
        assert_eq!(session.subs.len(), 1);
        let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
        let n = unix::recv(theirs.as_raw_fd(), &mut buf, false).unwrap();
        let Ok(Message::Reply { id, body, .. }) = relay::decode(&buf[..n]) else {
            panic!("not a reply")
        };
        assert_eq!((id, body), (2, &br#"{"error":"no such subscription"}"#[..]));
        session
            .handle(3, json::parse_flat(r#"{"op":"cancel","id":1}"#))
            .unwrap();
        assert!(session.subs.is_empty());
    }

    /// A value longer than one message goes out in chunks: `MORE` on all
    /// but the last, `END` only on the last.
    #[test]
    fn long_values_are_chunked() {
        let mut fds = [0; 2];
        // SAFETY: socketpair fills two fds, owned from here.
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) },
            0
        );
        let (ours, theirs) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        unix::raise_buffers(ours.as_raw_fd());
        unix::raise_buffers(theirs.as_raw_fd());
        let (attacher, _attachments) = crate::attachments();
        let session = Session {
            attacher,
            fd: ours,
            subs: Vec::new(),
        };
        let value: Vec<u8> = (0..150_000u32).map(|i| i as u8).collect();
        session.send(9, &value, true, true).unwrap();
        let mut buf = vec![0u8; relay::MAX_MESSAGE + 1];
        let mut got = Vec::new();
        let mut flags_seen = Vec::new();
        loop {
            let n = unix::recv(theirs.as_raw_fd(), &mut buf, false).unwrap();
            assert!(n <= relay::MAX_MESSAGE);
            let Ok(Message::Reply { id, flags, body }) = relay::decode(&buf[..n]) else {
                panic!("not a reply")
            };
            assert_eq!(id, 9);
            got.extend_from_slice(body);
            flags_seen.push(flags);
            if flags & relay::MORE == 0 {
                break;
            }
        }
        assert_eq!(got, value);
        let b = relay::BINARY;
        assert_eq!(
            flags_seen,
            [b | relay::MORE, b | relay::MORE, b | relay::END]
        );
    }
}
