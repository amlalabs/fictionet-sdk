use crate::iface::Context;
use crate::socket::PollAt;
use crate::socket::tcp::Socket;
use crate::time::Instant;
use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Unbounded};

/// A socket's slot in a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct SocketHandle(usize);

/// TCP sockets in slot order. Removed slots are reused before the set grows.
#[derive(Debug)]
pub struct SocketSet<'a> {
    sockets: Vec<Option<Socket<'a>>>,
    dirty: BTreeSet<SocketHandle>,
    changed: BTreeSet<SocketHandle>,
    deadlines: BTreeSet<(Instant, SocketHandle)>,
    scheduled: Vec<Option<Instant>>,
    ready: BTreeSet<SocketHandle>,
    served: Option<SocketHandle>,
}

impl<'a> SocketSet<'a> {
    pub fn new(sockets: Vec<Option<Socket<'a>>>) -> Self {
        let dirty: BTreeSet<_> = sockets
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|_| SocketHandle(i)))
            .collect();
        Self {
            scheduled: vec![None; sockets.len()],
            sockets,
            changed: dirty.clone(),
            dirty,
            deadlines: BTreeSet::new(),
            ready: BTreeSet::new(),
            served: None,
        }
    }

    pub fn add(&mut self, socket: Socket<'a>) -> SocketHandle {
        let handle = if let Some(index) = self.sockets.iter().position(Option::is_none) {
            self.sockets[index] = Some(socket);
            SocketHandle(index)
        } else {
            let handle = SocketHandle(self.sockets.len());
            self.sockets.push(Some(socket));
            self.scheduled.push(None);
            handle
        };
        self.dirty.insert(handle);
        self.changed.insert(handle);
        handle
    }

    /// Get a socket. Panics if its handle is invalid.
    pub fn get(&self, handle: SocketHandle) -> &Socket<'a> {
        self.sockets[handle.0]
            .as_ref()
            .expect("invalid socket handle")
    }

    pub(crate) fn try_get(&self, handle: SocketHandle) -> Option<&Socket<'a>> {
        self.sockets.get(handle.0)?.as_ref()
    }

    /// Get a mutable socket. Panics if its handle is invalid.
    pub fn get_mut(&mut self, handle: SocketHandle) -> &mut Socket<'a> {
        self.dirty.insert(handle);
        self.changed.insert(handle);
        self.sockets[handle.0]
            .as_mut()
            .expect("invalid socket handle")
    }

    /// Remove a socket without changing its state. Panics if its handle is invalid.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        self.dirty.remove(&handle);
        self.changed.remove(&handle);
        self.ready.remove(&handle);
        if let Some(at) = self.scheduled[handle.0].take() {
            self.deadlines.remove(&(at, handle));
        }
        self.sockets[handle.0]
            .take()
            .expect("invalid socket handle")
    }

    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.sockets
            .iter()
            .enumerate()
            .filter_map(|(i, socket)| socket.as_ref().map(|socket| (SocketHandle(i), socket)))
    }

    /// Take the next socket whose state may have changed.
    pub fn take_changed(&mut self) -> Option<SocketHandle> {
        self.changed.pop_first()
    }

    /// The caller has observed the socket after its own mutations.
    pub fn acknowledge_changed(&mut self, handle: SocketHandle) {
        self.changed.remove(&handle);
    }

    pub(crate) fn schedule(&mut self, cx: &mut Context) {
        while let Some(handle) = self.dirty.pop_first() {
            if let Some(at) = self.scheduled[handle.0].take() {
                self.deadlines.remove(&(at, handle));
            }
            self.ready.remove(&handle);
            let at = match self.get(handle).poll_at(cx) {
                PollAt::Ingress => None,
                PollAt::Time(at) => Some(at),
                PollAt::Now => Some(Instant::ZERO),
            };
            self.scheduled[handle.0] = at;
            if let Some(at) = at {
                self.deadlines.insert((at, handle));
            }
        }
    }

    pub(crate) fn prepare(&mut self, cx: &mut Context, now: Instant) -> usize {
        self.schedule(cx);
        while let Some(&(at, handle)) = self.deadlines.first() {
            if at > now {
                break;
            }
            self.deadlines.pop_first();
            self.scheduled[handle.0] = None;
            self.ready.insert(handle);
        }
        self.ready.len()
    }

    pub(crate) fn next_ready(&mut self) -> Option<SocketHandle> {
        let next = self
            .served
            .and_then(|after| self.ready.range((Excluded(after), Unbounded)).next())
            .or_else(|| self.ready.first())
            .copied()?;
        self.ready.remove(&next);
        Some(next)
    }

    pub(crate) fn dispatched(&mut self, handle: SocketHandle, blocked: bool) {
        if blocked {
            self.ready.insert(handle);
        } else {
            self.served = Some(handle);
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        if self.ready.is_empty() {
            self.deadlines.first().map(|&(at, _)| at)
        } else {
            Some(Instant::ZERO)
        }
    }
}
