use crate::socket::tcp::Socket;

/// A socket's slot in a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct SocketHandle(usize);

/// TCP sockets in slot order. Removed slots are reused before the set grows.
#[derive(Debug)]
pub struct SocketSet<'a> {
    sockets: Vec<Option<Socket<'a>>>,
}

impl<'a> SocketSet<'a> {
    pub fn new(sockets: Vec<Option<Socket<'a>>>) -> Self {
        Self { sockets }
    }

    pub fn add(&mut self, socket: Socket<'a>) -> SocketHandle {
        if let Some(index) = self.sockets.iter().position(Option::is_none) {
            self.sockets[index] = Some(socket);
            SocketHandle(index)
        } else {
            let handle = SocketHandle(self.sockets.len());
            self.sockets.push(Some(socket));
            handle
        }
    }

    /// Get a socket. Panics if its handle is invalid.
    pub fn get(&self, handle: SocketHandle) -> &Socket<'a> {
        self.sockets[handle.0]
            .as_ref()
            .expect("invalid socket handle")
    }

    /// Get a mutable socket. Panics if its handle is invalid.
    pub fn get_mut(&mut self, handle: SocketHandle) -> &mut Socket<'a> {
        self.sockets[handle.0]
            .as_mut()
            .expect("invalid socket handle")
    }

    /// Remove a socket without changing its state. Panics if its handle is invalid.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
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

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.sockets
            .iter_mut()
            .enumerate()
            .filter_map(|(i, socket)| socket.as_mut().map(|socket| (SocketHandle(i), socket)))
    }
}
