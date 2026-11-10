use crate::iface::Context;
use crate::socket::PollAt;
use crate::socket::tcp::Socket;
use crate::time::Instant;
use std::collections::{BTreeSet, VecDeque};
use std::ops::Bound::{Excluded, Unbounded};

/// A socket's slot in a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct SocketHandle(usize);

impl SocketHandle {
    /// The storage slot, reused after removal from the set.
    pub fn index(self) -> usize {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Pending {
    dirty: bool,
    changed: bool,
}

/// TCP sockets in slot order. Removed slots are reused before the set grows.
#[derive(Debug, Default)]
pub struct SocketSet {
    sockets: Vec<Option<Socket>>,
    dirty: VecDeque<SocketHandle>,
    changed: VecDeque<SocketHandle>,
    pending: Vec<Pending>,
    deadlines: BTreeSet<(Instant, SocketHandle)>,
    scheduled: Vec<Option<Instant>>,
    ready: BTreeSet<SocketHandle>,
    served: Option<SocketHandle>,
}

impl SocketSet {
    pub fn add(&mut self, socket: Socket) -> SocketHandle {
        let handle = if let Some(index) = self.sockets.iter().position(Option::is_none) {
            self.sockets[index] = Some(socket);
            SocketHandle(index)
        } else {
            let handle = SocketHandle(self.sockets.len());
            self.sockets.push(Some(socket));
            self.scheduled.push(None);
            self.pending.push(Pending::default());
            handle
        };
        self.mark(handle);
        handle
    }

    /// Get a socket. Panics if its handle is invalid.
    pub fn get(&self, handle: SocketHandle) -> &Socket {
        self.sockets[handle.0]
            .as_ref()
            .expect("invalid socket handle")
    }

    pub fn try_get(&self, handle: SocketHandle) -> Option<&Socket> {
        self.sockets.get(handle.0)?.as_ref()
    }

    /// Get a mutable socket. Panics if its handle is invalid.
    pub fn get_mut(&mut self, handle: SocketHandle) -> &mut Socket {
        self.mark(handle);
        self.sockets[handle.0]
            .as_mut()
            .expect("invalid socket handle")
    }

    /// Remove a socket without changing its state. Panics if its handle is invalid.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket {
        if self.pending[handle.0].dirty {
            self.dirty.retain(|&h| h != handle);
        }
        self.acknowledge_changed(handle);
        self.pending[handle.0] = Pending::default();
        self.ready.remove(&handle);
        if let Some(at) = self.scheduled[handle.0].take() {
            self.deadlines.remove(&(at, handle));
        }
        self.sockets[handle.0]
            .take()
            .expect("invalid socket handle")
    }

    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket)> {
        self.sockets
            .iter()
            .enumerate()
            .filter_map(|(i, socket)| socket.as_ref().map(|socket| (SocketHandle(i), socket)))
    }

    /// Sockets whose state the caller has not yet observed.
    pub fn changed(&self) -> impl ExactSizeIterator<Item = SocketHandle> + '_ {
        self.changed.iter().copied()
    }

    /// Orders pending observations without allocating another queue.
    pub fn order_changed<K: Ord>(&mut self, mut key: impl FnMut(SocketHandle) -> K) {
        self.changed
            .make_contiguous()
            .sort_unstable_by_key(|&handle| key(handle));
    }

    /// The caller has work for this socket even if its transport state did not change.
    pub fn mark_changed(&mut self, handle: SocketHandle) {
        if !self.pending[handle.0].changed {
            self.changed.push_back(handle);
            self.pending[handle.0].changed = true;
        }
    }

    /// The caller has observed the socket after its own mutations.
    pub fn acknowledge_changed(&mut self, handle: SocketHandle) {
        if self.pending[handle.0].changed {
            let index = self
                .changed
                .iter()
                .position(|&h| h == handle)
                .expect("a pending observation is queued");
            self.changed.remove(index);
            self.pending[handle.0].changed = false;
        }
    }

    fn mark(&mut self, handle: SocketHandle) {
        let pending = &mut self.pending[handle.0];
        if !pending.dirty {
            self.dirty.push_back(handle);
            pending.dirty = true;
        }
        self.mark_changed(handle);
    }

    pub fn schedule(&mut self, cx: &mut Context) {
        while let Some(handle) = self.dirty.pop_front() {
            self.pending[handle.0].dirty = false;
            let at = match self
                .get(handle)
                .poll_at(cx, crate::socket::tcp::DispatchMode::All)
            {
                PollAt::Ingress => {
                    self.ready.remove(&handle);
                    None
                }
                PollAt::Time(at) => {
                    self.ready.remove(&handle);
                    Some(at)
                }
                PollAt::Now => {
                    self.ready.insert(handle);
                    None
                }
            };
            if self.scheduled[handle.0] != at {
                if let Some(old) = self.scheduled[handle.0] {
                    self.deadlines.remove(&(old, handle));
                }
                self.scheduled[handle.0] = at;
                if let Some(at) = at {
                    self.deadlines.insert((at, handle));
                }
            }
        }
    }

    pub fn prepare(&mut self, cx: &mut Context, now: Instant) -> usize {
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

    pub fn next_ready(&self) -> Option<SocketHandle> {
        self.served
            .and_then(|after| self.ready.range((Excluded(after), Unbounded)).next())
            .or_else(|| self.ready.first())
            .copied()
    }

    pub fn dispatched(&mut self, handle: SocketHandle, blocked: bool) {
        if !blocked {
            self.served = Some(handle);
        }
    }

    pub fn finish_egress(&mut self) {
        self.served = None;
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        if self.ready.is_empty() {
            self.deadlines.first().map(|&(at, _)| at)
        } else {
            Some(Instant::ZERO)
        }
    }
}

#[cfg(test)]
#[path = "socket_set_tests.rs"]
mod tests;
