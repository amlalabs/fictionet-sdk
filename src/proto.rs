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
//! packets both ways until either side closes it. Observers, such as
//! `fictionet dashboard`, use the same socket to watch the world: see
//! [Observer sessions](#observer-sessions).
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
//! | 5 | `request` | an observer | an id (u32), then a JSON object |
//! | 6 | `reply` | the world, to an observer | the request's id (u32), flags (u8), then part of a value |
//!
//! Kind 0 is reserved for a remote transport (see the
//! [roadmap](crate::roadmap#remote-attach-a-tls-transport)).
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
//! the attach type, such as `tun`, or `observe` for an
//! [observer](#observer-sessions).
//!
//! For example, attach started with `--name agent --type tun` (see
//! [`attaching`](crate::attaching)) on a sandbox with an MTU of 1500 sends
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
//! from each, is on its own page: [`lowering`](crate::lowering).
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
//! # Observer sessions
//!
//! An observer, such as `fictionet dashboard` or `fictionet observe`, uses
//! the same socket as attach. It sends a `hello` with the type `observe`
//! and version 1. The world ignores the MTU, and treats the name as a label
//! for the observer: unlike a sandbox's name, it is not reserved, so any
//! number of observers can use the same one. The world always answers
//! `accept`, unless the version is wrong, and never makes the connection
//! an [`Attachment`](crate::Attachment). It refuses any other type that
//! starts with `observe`, such as `observe2`: those are kept for later
//! versions of the observe API. Anyone who can open the world
//! socket can observe the world, so the socket's file permissions decide
//! who may watch, as they decide who may attach.
//!
//! Then the observer sends `request` messages, and the world answers each
//! with `reply` messages that carry the same id. The observer picks the
//! ids, and must not reuse one while it is still being answered. What the
//! requests ask for, and what the replies say, is the
//! [observe API](crate::observe#the-api).
//!
//! ```text
//!   kind     id        a JSON object
//! ┌──────┬─────────────┬────────────────────────┐
//! │  05  │ 00 00 00 01 │ {"op":"graph"}         │   request
//! └──────┴─────────────┴────────────────────────┘
//!
//!   kind     id       flags   part of a value
//! ┌──────┬─────────────┬────┬────────────────────┐
//! │  06  │ 00 00 00 01 │ 02 │ {"t":12.5,...}     │   reply
//! └──────┴─────────────┴────┴────────────────────┘
//! ```
//!
//! A reply's flags:
//!
//! | Mask | Name | Meaning |
//! |---|---|---|
//! | 1 | `MORE` | the value goes on in the next reply with this id |
//! | 2 | `END` | no more replies come for this id |
//! | 4 | `BINARY` | the value is raw bytes, such as a pcapng file, not JSON |
//!
//! A value longer than one message (65,530 bytes after the reply's header)
//! is cut into parts. Each part but the last has `MORE`, and the observer
//! joins them. A request for one value gets one value, with `END`. A
//! stream, such as `watch`, gets values until its last one, which has
//! `END`. Replies to different requests can arrive between each other, but
//! the parts of one value never do.
//!
//! ```text
//! observer                                  world
//!    │                                        │
//!    │ ── hello: version 1, type observe ───▶ │
//!    │ ◀─────────────────────────── accept ── │
//!    │ ── request 1: {"op":"watch"} ────────▶ │
//!    │ ◀── reply 1: {"event":"snapshot",.. ── │  MORE, MORE, then the last
//!    │ ◀── reply 1: {"event":"counters",.. ── │  part: one value each
//!    │ ── request 2: {"op":"graph"} ────────▶ │
//!    │ ◀── reply 2: {"t":..,"nodes":[..]} ─── │  END: request 2 is answered
//!    │ ◀── reply 1: {"event":"note",.. ────── │  the stream goes on
//!    │ ── request 3: {"op":"cancel","id":1} ▶ │
//!    │ ◀── reply 1: {"event":"end",..} ────── │  END: the stream is over
//!    │ ◀── reply 3: {"ok":true} ──────────── │  END
//!    │ ┄┄┄┄┄┄┄┄┄ either side closes ┄┄┄┄┄┄┄┄┄ │
//! ```
//!
//! Any other message from the observer closes the connection. So does an
//! observer that stops reading for 10 seconds, so that a reply cannot be
//! sent.
