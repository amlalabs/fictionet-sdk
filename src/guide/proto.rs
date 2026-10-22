//! The relay protocol: what `fictionet attach` and a world say to each other.
//!
//! Most world authors never need this page. [`listen`](crate::listen)
//! speaks the protocol on the world's side, and `fictionet attach` speaks
//! it on the sandbox's side. Read this page to write an attach of your own,
//! or to debug a connection between the two.
//!
//! Attach and the world talk over a Unix socket on the same machine, such
//! as `/run/fictionet/world.sock`. The connection starts with a short
//! handshake, in which attach names the sandbox, and then carries IP
//! packets both ways until either side closes it. Observation uses a separate
//! socket and protocol, specified in
//! [Fictionet Observe](../../../fictionet_observe/index.html#observation-protocol-reference).
//!
//! # The socket
//!
//! The world socket is a Unix `SOCK_SEQPACKET` socket. Each message is one
//! datagram, so messages need no length prefix, and the socket takes a
//! whole message or none of it. The socket's file permissions decide who
//! may attach, so there is no password or token.
//!
//! ```text
//! one datagram per message:
//!
//! ┌──────┬───────────────────────┐
//! │ kind │ body                  │
//! └──────┴───────────────────────┘
//! ```
//!
//! # Messages
//!
//! Each message starts with one byte that says what kind of message it is,
//! followed by its body:
//!
//! | Kind | Name | Sent by | Body |
//! |---|---|---|---|
//! | 1 | `hello` | attach | version (u16), MTU (u16), type (u8 length, then ASCII), name (u8 length, then UTF-8) |
//! | 2 | `accept` | the world | empty |
//! | 3 | `refuse` | the world | the reason, in UTF-8, such as "agent is already attached" |
//! | 4 | `packet` | both | one IP packet |
//!
//! Kind 0 is reserved for a remote transport (see the
//! [roadmap](crate::guide::roadmap#remote-attach-a-tls-transport)).
//!
//! A message is at most 65,536 bytes, counting its kind byte. So a `packet`
//! carries at most 65,535 bytes of IP packet, the most an IPv4 packet can
//! hold. Both ends close the connection on a longer message. The world's
//! [`Attachment`](crate::Attachment) then reads
//! [`RecvError::Closed`](crate::RecvError::Closed), and `fictionet attach`
//! exits with status 1.
//!
//! Numbers are big-endian. The version is 1, and the world refuses a
//! `hello` with any other version. The MTU is the sandbox's, and the world
//! reads it with [`Attachment::mtu`](crate::Attachment::mtu). The type is
//! the attach type, such as `tun`, `tap`, `http_proxy`, or `socks5`.
//!
//! For example, attach started with `attach tun --name agent` on a sandbox with an MTU of 1500 sends
//! this 15-byte `hello`:
//!
//! ```text
//!   kind   version    MTU               type                   name
//! ┌──────┬─────────┬───────┬────────┬──────────┬────────┬────────────────┐
//! │  01  │  00 01  │ 05 DC │   03   │ 74 75 6E │   05   │ 61 67 65 6E 74 │
//! └──────┴─────────┴───────┴────────┴──────────┴────────┴────────────────┘
//!    u8      u16      u16    length    ASCII     length       UTF-8
//!                                      "tun"                 "agent"
//! ```
//!
//! A sandbox's name is 1 to 255 bytes of UTF-8, and the world refuses
//! any other. Once the world accepts a name, the
//! name is taken until the connection closes, from either side. The world
//! refuses a `hello` with a name that is taken.
//!
//! DHCP and router advertisements are ordinary packets, so they need no
//! messages of their own. How each attach type turns its sandbox's
//! traffic into the packets in `packet` messages, and what the world sees
//! from each, is on its own page: [`lowering`](crate::guide::lowering).
//!
//! # A connection, step by step
//!
//! 1. **Attach sends `hello`.** The world answers `accept` or `refuse`.
//!    After a `refuse`, the world closes the connection. The handshake
//!    must finish within 10 seconds, or the world closes the connection.
//! 2. **Both sides send `packet`s,** until either side closes the
//!    connection. Closing is the detach: the world's
//!    [`Attachment`](crate::Attachment) reads
//!    [`RecvError::Closed`](crate::RecvError::Closed), like any
//!    [`Interface`](crate::Interface) whose other end is gone. Attaching
//!    again with the same name makes a new attachment. A message other
//!    than `packet` at this point, or a message of an unknown kind, closes
//!    the connection.
//!
//! ```text
//! attach                                    world
//!    │                                        │
//! 1  │ ── hello ────────────────────────────▶ │  version, MTU, type, name
//!    │ ◀─────────────────────────── accept ── │  or refuse with a reason,
//!    │                                        │  then close
//!    │                                        │  (within 10 seconds)
//! 2  │ ◀══════════════ packet ══════════════▶ │  both ways, one IP packet each
//!    │ ┄┄┄┄┄┄┄┄┄ either side closes ┄┄┄┄┄┄┄┄┄ │  the detach: the Attachment
//!    │                                        │  reads RecvError::Closed
//! ```
//!
