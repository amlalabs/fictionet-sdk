//! RFB, the remote framebuffer protocol behind VNC: the handshake and the
//! messages, read and written with no I/O.
//!
//! RFB lets a client see and drive a remote screen. The server sends
//! pictures of its framebuffer, and the client sends key presses and
//! pointer moves. Servers usually listen on TCP port 5900. This module
//! follows RFC 6143.
//!
//! A connection starts with a handshake in which the two sides take turns.
//! The server sends its protocol version and the client answers with its
//! own. The server then offers security types and the client picks one.
//! For VNC Authentication the server sends a challenge and the client
//! answers it. The server reports the result. The client sends ClientInit,
//! and the server answers with ServerInit, which gives the screen size and
//! the pixel format. After that both sides send messages whenever they
//! like.
//!
//! Nothing here reads a socket. A world that plays a server keeps a
//! [`ServerSession`]. It feeds the session the bytes it reads from a
//! [`tcp`](crate::stdlib::tcp) connection, takes [`ClientMessage`]s out,
//! and writes the bytes [`ServerSession::send`] gives it for each
//! [`ServerMessage`]. A world that plays a client does the same with a
//! [`ClientSession`]. Each session knows the handshake phase from both
//! directions, because how the peer's bytes split into messages depends on
//! what the world sent.
//!
//! The module carries the VNC Authentication challenge and response but
//! does not compute them, since that needs DES. A world that wants to
//! check a password does that itself. Other security types are reported:
//! the session moves to [`Phase::Unsupported`] and reads no further.
//! Framebuffer updates are read for the Raw and CopyRect encodings and for
//! the Cursor and DesktopSize pseudo-encodings. Other encodings cannot be
//! split from the stream without decoding them, so they stop the session
//! with [`Error::Encoding`].
//!
//! Every reader checks lengths against the limits below, because the agent
//! can send any bytes it likes. Every writer refuses a message it cannot
//! put on the wire as it is, rather than cut it short.
//!
//! The sessions also keep the rules RFC 6143 sets for the normal phase.
//! A server sends a framebuffer update only after the client asked for
//! one, uses only the encodings the client listed, keeps rectangles inside
//! the framebuffer, and sends color map entries only for a color map
//! format. A client changes its pixel format only when no update request
//! is outstanding.
//!
//! ```
//! use fictionet::stdlib::rfb::{ClientMessage, PixelFormat, ServerInit, ServerMessage, ServerSession, Version};
//!
//! let mut server = ServerSession::new();
//! assert_eq!(server.send(&ServerMessage::Version(Version::V3_8)).unwrap(), b"RFB 003.008\n");
//! server.feed(b"RFB 003.008\n");
//! assert_eq!(server.next_message(), Some(Ok(ClientMessage::Version(Version::V3_8))));
//! // Offer one security type, None, and let the client in.
//! assert_eq!(server.send(&ServerMessage::SecurityTypes(vec![1])).unwrap(), [1, 1]);
//! server.feed(&[1]);
//! assert_eq!(server.next_message(), Some(Ok(ClientMessage::SecurityType(1))));
//! assert_eq!(server.send(&ServerMessage::SecurityOk).unwrap(), [0, 0, 0, 0]);
//! // ClientInit: the client is happy to share the desktop.
//! server.feed(&[1]);
//! assert_eq!(server.next_message(), Some(Ok(ClientMessage::ClientInit { shared: true })));
//! let init = ServerInit { width: 640, height: 480, format: PixelFormat::TRUE_COLOR_32, name: b"tank".to_vec() };
//! assert_eq!(server.send(&ServerMessage::ServerInit(init)).unwrap().len(), 2 + 2 + 16 + 4 + 4);
//! // The client asks for the whole screen.
//! server.feed(&[3, 0, 0, 0, 0, 0, 0x02, 0x80, 0x01, 0xe0]);
//! assert_eq!(
//!     server.next_message(),
//!     Some(Ok(ClientMessage::FramebufferUpdateRequest { incremental: false, x: 0, y: 0, width: 640, height: 480 }))
//! );
//! ```

/// The TCP port RFB servers listen on, for display 0.
pub const PORT: u16 = 5900;
/// The length of a protocol version line, such as `RFB 003.008\n`.
pub const VERSION_LEN: usize = 12;
/// The length of a VNC Authentication challenge, and of its response.
pub const CHALLENGE_LEN: usize = 16;
/// The length of a pixel format on the wire.
pub const PIXEL_FORMAT_LEN: usize = 16;
/// The longest text this module reads or writes: a failure reason, a
/// desktop name or cut text. Longer text is refused both ways.
pub const MAX_TEXT: usize = 1 << 20;
/// The longest message this module reads or writes, in bytes. It bounds
/// a framebuffer update, which can otherwise claim gigabytes.
pub const MAX_MESSAGE: usize = 1 << 26;
/// The most bytes a session holds that the peer sent before its turn.
pub const MAX_PENDING: usize = 1 << 16;
/// The most bytes a session holds that have not been taken out as
/// messages: room for two of the longest messages. Feeding more breaks the
/// stream with [`Error::TooLong`], so take messages out between feeds.
pub const MAX_BUFFERED: usize = 2 * MAX_MESSAGE;
/// The most security types a 3.7 or 3.8 server can offer.
pub const MAX_SECURITY_TYPES: usize = 255;
/// The most encodings, colors or rectangles one message can carry: the
/// count is 16 bits.
pub const MAX_ITEMS: usize = 65535;

/// Security type numbers. In versions 3.7 and 3.8 they are one byte; in
/// 3.3 the server sends one as four bytes.
pub mod security {
    /// Not a type. As the 3.3 type, or as a count of 0 types, it means the
    /// server refused the connection and a reason follows.
    pub const INVALID: u8 = 0;
    /// No authentication.
    pub const NONE: u8 = 1;
    /// VNC Authentication: a DES challenge and response.
    pub const VNC_AUTHENTICATION: u8 = 2;
}

/// Encoding numbers for framebuffer update rectangles, and the
/// pseudo-encodings, which are negative.
pub mod encoding {
    #![allow(missing_docs)]
    pub const RAW: i32 = 0;
    pub const COPY_RECT: i32 = 1;
    pub const RRE: i32 = 2;
    pub const HEXTILE: i32 = 5;
    pub const TRLE: i32 = 15;
    pub const ZRLE: i32 = 16;
    /// The client can draw the cursor itself.
    pub const CURSOR: i32 = -239;
    /// The client can follow changes to the screen size.
    pub const DESKTOP_SIZE: i32 = -223;
}

/// Message type numbers for what a client sends after the handshake.
pub mod client_type {
    #![allow(missing_docs)]
    pub const SET_PIXEL_FORMAT: u8 = 0;
    pub const SET_ENCODINGS: u8 = 2;
    pub const FRAMEBUFFER_UPDATE_REQUEST: u8 = 3;
    pub const KEY_EVENT: u8 = 4;
    pub const POINTER_EVENT: u8 = 5;
    pub const CLIENT_CUT_TEXT: u8 = 6;
}

/// Message type numbers for what a server sends after the handshake.
pub mod server_type {
    #![allow(missing_docs)]
    pub const FRAMEBUFFER_UPDATE: u8 = 0;
    pub const SET_COLOR_MAP_ENTRIES: u8 = 1;
    pub const BELL: u8 = 2;
    pub const SERVER_CUT_TEXT: u8 = 3;
}

/// Why bytes cannot be read, or a message cannot be sent. A read error
/// breaks the stream: the session keeps returning it, and a real peer
/// closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a version line, `RFB xxx.yyy\n` with digits.
    Version,
    /// A message type this module does not read.
    MessageType(u8),
    /// A rectangle encoding this module cannot read.
    Encoding(i32),
    /// Pixels in a format whose bits per pixel is not 8, 16 or 32.
    BitsPerPixel(u8),
    /// Text longer than [`MAX_TEXT`], or a message longer than
    /// [`MAX_MESSAGE`].
    TooLong,
    /// The client picked a security type the server did not offer.
    NotOffered(u8),
    /// The handshake picked a security type this module does not follow,
    /// and the peer sent more bytes.
    Unsupported(u32),
    /// The peer sent more than [`MAX_PENDING`] bytes before its turn.
    OutOfTurn,
    /// A pixel format RFC 6143 does not allow: bits per pixel other than
    /// 8, 16 or 32, a depth past bits per pixel, or, for true color, a
    /// maximum that is not one less than a power of two or a color that
    /// does not fit in the pixel.
    PixelFormat,
    /// A rectangle that reaches past the framebuffer, a CopyRect whose
    /// source does, or a DesktopSize rectangle that is not the last in its
    /// update.
    Rectangle,
    /// A server message the client did not ask for: a framebuffer update
    /// with no request outstanding, a rectangle in an encoding the client
    /// did not list (Raw is always allowed), CopyRect in answer to a
    /// request that was not incremental, or color map entries while pixels
    /// are true color.
    NotRequested,
    /// SetPixelFormat while a framebuffer update request is outstanding or
    /// an update is being read, when the client could not tell which
    /// format the update is in.
    Outstanding,
    /// A message sent in a phase where it does not belong.
    Phase(Phase),
    /// A message that cannot be written as it is: an empty list of
    /// security types, a security type of 0, a security offer in the wrong
    /// dialect, a failure reason in a dialect before 3.8, a version part
    /// past 999, more than [`MAX_ITEMS`] rectangles, encodings or colors,
    /// or pixel data whose length does not fit the rectangle.
    Unwritable,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Version => f.write_str("not an RFB protocol version line"),
            Error::MessageType(t) => write!(f, "unknown message type {t}"),
            Error::Encoding(e) => write!(f, "rectangle encoding {e} is not read"),
            Error::BitsPerPixel(b) => write!(f, "{b} bits per pixel, not 8, 16 or 32"),
            Error::TooLong => f.write_str("text or message too long"),
            Error::NotOffered(t) => write!(f, "security type {t} was not offered"),
            Error::Unsupported(t) => write!(f, "security type {t} is not followed"),
            Error::OutOfTurn => f.write_str("too many bytes sent before the peer's turn"),
            Error::PixelFormat => f.write_str("pixel format not allowed"),
            Error::Rectangle => f.write_str("rectangle outside the framebuffer or out of order"),
            Error::NotRequested => f.write_str("server message the client did not ask for"),
            Error::Outstanding => f.write_str("pixel format changed while an update is outstanding"),
            Error::Phase(p) => write!(f, "message does not belong in phase {p:?}"),
            Error::Unwritable => f.write_str("message cannot be written as it is"),
        }
    }
}

impl std::error::Error for Error {}

/// A protocol version, as in `RFB 003.008\n`. Each part has three digits
/// on the wire, so a message that carries a part past 999 cannot be
/// written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// The major version, 3 for every version in use.
    pub major: u16,
    /// The minor version.
    pub minor: u16,
}

/// Which handshake a version means. RFC 6143 says any version other than
/// 3.7 and 3.8 is handled as 3.3. A session uses the lower of the two
/// versions, since the client must not answer with one higher than the
/// server's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dialect {
    /// The server picks the security type, and sends it as four bytes.
    V3_3,
    /// The client picks from a list. No security result follows None.
    V3_7,
    /// As 3.7, but a security result follows every type, and a failed one
    /// carries a reason.
    V3_8,
}

impl Version {
    /// Version 3.3.
    pub const V3_3: Version = Version { major: 3, minor: 3 };
    /// Version 3.7.
    pub const V3_7: Version = Version { major: 3, minor: 7 };
    /// Version 3.8, the one RFC 6143 describes.
    pub const V3_8: Version = Version { major: 3, minor: 8 };

    /// Reads the version line at the start of `b`. It returns `Ok(None)`
    /// if `b` holds only part of one, and otherwise the version and how
    /// many bytes it took. A byte that cannot start a version line is an
    /// error as soon as it comes.
    pub fn parse(b: &[u8]) -> Result<Option<(Version, usize)>, Error> {
        run(b, version)
    }

    /// The version line's bytes. A part past 999 is written as 999; the
    /// message writers refuse such a version instead.
    pub fn to_bytes(self) -> [u8; VERSION_LEN] {
        let mut out = *b"RFB 000.000\n";
        for (at, n) in [(4, self.major.min(999)), (8, self.minor.min(999))] {
            out[at] = b'0' + (n / 100) as u8;
            out[at + 1] = b'0' + (n / 10 % 10) as u8;
            out[at + 2] = b'0' + (n % 10) as u8;
        }
        out
    }

    /// Whether both parts fit in three digits.
    fn writable(self) -> bool {
        self.major <= 999 && self.minor <= 999
    }

    /// The handshake this version means, when it is the one both sides
    /// speak.
    pub fn dialect(self) -> Dialect {
        match (self.major, self.minor) {
            (3, 7) => Dialect::V3_7,
            (3, 8) => Dialect::V3_8,
            _ => Dialect::V3_3,
        }
    }
}

/// How pixel values are laid out: in ServerInit, and in a client's
/// SetPixelFormat.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PixelFormat {
    /// Bits per pixel on the wire. Only 8, 16 and 32 are valid, and pixels
    /// in any other format cannot be read.
    pub bits_per_pixel: u8,
    /// How many of those bits are used.
    pub depth: u8,
    /// Whether multi-byte pixels are sent most significant byte first.
    pub big_endian: bool,
    /// Whether pixels hold colors directly (true) or index a color map.
    pub true_color: bool,
    /// The largest red value, such as 255.
    pub red_max: u16,
    /// The largest green value.
    pub green_max: u16,
    /// The largest blue value.
    pub blue_max: u16,
    /// How far red is shifted left in a pixel.
    pub red_shift: u8,
    /// How far green is shifted left.
    pub green_shift: u8,
    /// How far blue is shifted left.
    pub blue_shift: u8,
}

impl PixelFormat {
    /// 32 bits per pixel, 8 bits each of red, green and blue, little
    /// endian: the format most servers offer.
    pub const TRUE_COLOR_32: PixelFormat = PixelFormat {
        bits_per_pixel: 32,
        depth: 24,
        big_endian: false,
        true_color: true,
        red_max: 255,
        green_max: 255,
        blue_max: 255,
        red_shift: 16,
        green_shift: 8,
        blue_shift: 0,
    };

    /// Reads a pixel format. Any nonzero flag byte reads as true, and the
    /// three bytes of padding are ignored.
    pub fn parse(b: &[u8; PIXEL_FORMAT_LEN]) -> PixelFormat {
        PixelFormat {
            bits_per_pixel: b[0],
            depth: b[1],
            big_endian: b[2] != 0,
            true_color: b[3] != 0,
            red_max: u16::from_be_bytes([b[4], b[5]]),
            green_max: u16::from_be_bytes([b[6], b[7]]),
            blue_max: u16::from_be_bytes([b[8], b[9]]),
            red_shift: b[10],
            green_shift: b[11],
            blue_shift: b[12],
        }
    }

    /// The pixel format's bytes.
    pub fn to_bytes(&self) -> [u8; PIXEL_FORMAT_LEN] {
        let mut out = [0u8; PIXEL_FORMAT_LEN];
        out[0] = self.bits_per_pixel;
        out[1] = self.depth;
        out[2] = u8::from(self.big_endian);
        out[3] = u8::from(self.true_color);
        out[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        out[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        out[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        out[10] = self.red_shift;
        out[11] = self.green_shift;
        out[12] = self.blue_shift;
        out
    }

    /// Whether RFC 6143, section 7.4, allows this format: bits per pixel
    /// of 8, 16 or 32, no more than that many bits of depth, and for true
    /// color, each maximum one less than a power of two whose bits, moved
    /// up by the color's shift, fit in the pixel. A color map format's
    /// maximums and shifts are not used, so they are not checked.
    pub fn is_valid(&self) -> bool {
        if self.bytes_per_pixel().is_none() || self.depth > self.bits_per_pixel {
            return false;
        }
        if !self.true_color {
            return true;
        }
        [(self.red_max, self.red_shift), (self.green_max, self.green_shift), (self.blue_max, self.blue_shift)]
            .into_iter()
            .all(|(max, shift)| {
                let bits = 16 - max.leading_zeros();
                max & max.wrapping_add(1) == 0 && u32::from(shift) + bits <= u32::from(self.bits_per_pixel)
            })
    }

    /// Bytes per pixel, or `None` if bits per pixel is not 8, 16 or 32.
    pub fn bytes_per_pixel(&self) -> Option<usize> {
        match self.bits_per_pixel {
            8 => Some(1),
            16 => Some(2),
            32 => Some(4),
            _ => None,
        }
    }
}

/// What the server tells the client once the handshake is done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerInit {
    /// The framebuffer's width in pixels.
    pub width: u16,
    /// The framebuffer's height in pixels.
    pub height: u16,
    /// The server's natural pixel format, used until the client sets one.
    pub format: PixelFormat,
    /// The desktop's name. RFC 6143 recommends UTF-8.
    pub name: Vec<u8>,
}

/// One color map entry. Each value runs from 0 to 65535.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub struct Color {
    pub red: u16,
    pub green: u16,
    pub blue: u16,
}

/// One rectangle of a framebuffer update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rectangle {
    /// The left edge.
    pub x: u16,
    /// The top edge.
    pub y: u16,
    /// The width in pixels.
    pub width: u16,
    /// The height in pixels.
    pub height: u16,
    /// What the rectangle holds.
    pub contents: Contents,
}

/// What a rectangle holds, by encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Contents {
    /// Raw: every pixel, row by row, in the current pixel format. It holds
    /// width times height times bytes per pixel bytes.
    Raw(Vec<u8>),
    /// CopyRect: copy the rectangle from this spot of the framebuffer.
    CopyRect {
        /// The source's left edge.
        src_x: u16,
        /// The source's top edge.
        src_y: u16,
    },
    /// The Cursor pseudo-encoding: a new cursor shape the size of the
    /// rectangle, whose hot spot is the rectangle's x and y.
    Cursor {
        /// The cursor's pixels, as for [`Contents::Raw`].
        pixels: Vec<u8>,
        /// One bit per pixel, most significant first, each row padded to
        /// a whole byte. A set bit means the pixel is drawn.
        mask: Vec<u8>,
    },
    /// The DesktopSize pseudo-encoding: the framebuffer is now the
    /// rectangle's width and height.
    DesktopSize,
}

impl Contents {
    /// The encoding number this is sent with.
    pub fn encoding(&self) -> i32 {
        match self {
            Contents::Raw(_) => encoding::RAW,
            Contents::CopyRect { .. } => encoding::COPY_RECT,
            Contents::Cursor { .. } => encoding::CURSOR,
            Contents::DesktopSize => encoding::DESKTOP_SIZE,
        }
    }
}

/// Everything a client sends, the handshake included.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum ClientMessage {
    /// The version the client will speak. With the server's, it decides
    /// the handshake.
    Version(Version),
    /// Dialects 3.7 and 3.8: the security type the client picked.
    SecurityType(u8),
    /// The answer to a VNC Authentication challenge.
    VncResponse([u8; CHALLENGE_LEN]),
    /// ClientInit: whether other clients may stay connected.
    ClientInit { shared: bool },
    /// Send pixels in this format from now on.
    SetPixelFormat(PixelFormat),
    /// The encodings the client reads, most preferred first.
    SetEncodings(Vec<i32>),
    /// Send the pixels of this area, or only what changed if
    /// `incremental`.
    FramebufferUpdateRequest { incremental: bool, x: u16, y: u16, width: u16, height: u16 },
    /// A key went down or up. `key` is an X Window System keysym.
    KeyEvent { down: bool, key: u32 },
    /// The pointer is at `x`, `y`, with these buttons down, one bit each.
    PointerEvent { buttons: u8, x: u16, y: u16 },
    /// The client's clipboard changed. The text is ISO 8859-1.
    ClientCutText(Vec<u8>),
}

/// Everything a server sends, the handshake included.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(missing_docs)] // each variant's doc names its fields
pub enum ServerMessage {
    /// The highest version the server speaks.
    Version(Version),
    /// Dialects 3.7 and 3.8: the security types the server offers, 1 to
    /// [`MAX_SECURITY_TYPES`] of them.
    SecurityTypes(Vec<u8>),
    /// Version 3.3 (the dialect, not only the number): the security type
    /// the server picked, never 0.
    SecurityType(u32),
    /// The server refuses the connection, for this reason, and closes it.
    SecurityFailure(Vec<u8>),
    /// A VNC Authentication challenge.
    VncChallenge([u8; CHALLENGE_LEN]),
    /// Authentication passed.
    SecurityOk,
    /// Authentication failed, and the server closes the connection. Only
    /// version 3.8 sends the reason; before that it reads as empty.
    SecurityFailed(Vec<u8>),
    /// ServerInit.
    ServerInit(ServerInit),
    /// New contents for parts of the framebuffer.
    FramebufferUpdate(Vec<Rectangle>),
    /// Set color map entries from `first` on.
    SetColorMapEntries { first: u16, colors: Vec<Color> },
    /// Ring the bell.
    Bell,
    /// The server's clipboard changed. The text is ISO 8859-1.
    ServerCutText(Vec<u8>),
}

impl ClientMessage {
    /// Reads a message a client sends after the handshake from the start
    /// of `b`. It returns `Ok(None)` if `b` holds only part of one, and
    /// otherwise the message and how many bytes it took.
    pub fn parse(b: &[u8]) -> Result<Option<(ClientMessage, usize)>, Error> {
        run(b, client_normal)
    }

    /// Whether this message belongs to the handshake.
    pub fn is_handshake(&self) -> bool {
        matches!(
            self,
            ClientMessage::Version(_)
                | ClientMessage::SecurityType(_)
                | ClientMessage::VncResponse(_)
                | ClientMessage::ClientInit { .. }
        )
    }

    /// The message's bytes. A message that cannot be written so it reads
    /// back the same is [`Error::Unwritable`] (a version part past 999,
    /// more than [`MAX_ITEMS`] encodings), [`Error::TooLong`] (text past
    /// [`MAX_TEXT`]) or [`Error::PixelFormat`] (a format
    /// [`PixelFormat::is_valid`] refuses).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            ClientMessage::Version(v) => {
                if !v.writable() {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&v.to_bytes());
            }
            ClientMessage::SecurityType(t) => out.push(*t),
            ClientMessage::VncResponse(r) => out.extend_from_slice(r),
            ClientMessage::ClientInit { shared } => out.push(u8::from(*shared)),
            ClientMessage::SetPixelFormat(f) => {
                if !f.is_valid() {
                    return Err(Error::PixelFormat);
                }
                out.extend_from_slice(&[client_type::SET_PIXEL_FORMAT, 0, 0, 0]);
                out.extend_from_slice(&f.to_bytes());
            }
            ClientMessage::SetEncodings(list) => {
                if list.len() > MAX_ITEMS {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&[client_type::SET_ENCODINGS, 0]);
                out.extend_from_slice(&(list.len() as u16).to_be_bytes());
                for e in list {
                    out.extend_from_slice(&e.to_be_bytes());
                }
            }
            ClientMessage::FramebufferUpdateRequest { incremental, x, y, width, height } => {
                out.extend_from_slice(&[client_type::FRAMEBUFFER_UPDATE_REQUEST, u8::from(*incremental)]);
                for v in [x, y, width, height] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            ClientMessage::KeyEvent { down, key } => {
                out.extend_from_slice(&[client_type::KEY_EVENT, u8::from(*down), 0, 0]);
                out.extend_from_slice(&key.to_be_bytes());
            }
            ClientMessage::PointerEvent { buttons, x, y } => {
                out.extend_from_slice(&[client_type::POINTER_EVENT, *buttons]);
                out.extend_from_slice(&x.to_be_bytes());
                out.extend_from_slice(&y.to_be_bytes());
            }
            ClientMessage::ClientCutText(text) => {
                out.extend_from_slice(&[client_type::CLIENT_CUT_TEXT, 0, 0, 0]);
                put_text(&mut out, text)?;
            }
        }
        Ok(out)
    }
}

impl ServerMessage {
    /// Reads a message a server sends after the handshake from the start
    /// of `b`, with pixels in `format`. It returns `Ok(None)` if `b` holds
    /// only part of one, and otherwise the message and how many bytes it
    /// took.
    pub fn parse(b: &[u8], format: &PixelFormat) -> Result<Option<(ServerMessage, usize)>, Error> {
        run(b, |c| server_normal(c, format, &mut None))
    }

    /// Whether this message belongs to the handshake.
    pub fn is_handshake(&self) -> bool {
        !matches!(
            self,
            ServerMessage::FramebufferUpdate(_)
                | ServerMessage::SetColorMapEntries { .. }
                | ServerMessage::Bell
                | ServerMessage::ServerCutText(_)
        )
    }

    /// The message's bytes, for a handshake in `dialect` and pixels in
    /// `format`. A message that cannot be written so it reads back the same
    /// is [`Error::Unwritable`], [`Error::BitsPerPixel`], [`Error::TooLong`],
    /// [`Error::PixelFormat`] or [`Error::Rectangle`]. That includes a
    /// security type list in 3.3, a single security type in 3.7 or 3.8, an
    /// offer of type 0, a failure reason before 3.8, more than
    /// [`MAX_ITEMS`] colors, text past [`MAX_TEXT`], a ServerInit format
    /// [`PixelFormat::is_valid`] refuses, and a DesktopSize rectangle that
    /// is not the last.
    pub fn to_bytes(&self, dialect: Dialect, format: &PixelFormat) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            ServerMessage::Version(v) => {
                if !v.writable() {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&v.to_bytes());
            }
            ServerMessage::SecurityTypes(types) => {
                if dialect == Dialect::V3_3
                    || types.is_empty()
                    || types.len() > MAX_SECURITY_TYPES
                    || types.contains(&security::INVALID)
                {
                    return Err(Error::Unwritable);
                }
                out.push(types.len() as u8);
                out.extend_from_slice(types);
            }
            ServerMessage::SecurityType(t) => {
                if dialect != Dialect::V3_3 || *t == 0 {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&t.to_be_bytes());
            }
            ServerMessage::SecurityFailure(reason) => {
                match dialect {
                    Dialect::V3_3 => out.extend_from_slice(&[0, 0, 0, 0]),
                    Dialect::V3_7 | Dialect::V3_8 => out.push(0),
                }
                put_text(&mut out, reason)?;
            }
            ServerMessage::VncChallenge(c) => out.extend_from_slice(c),
            ServerMessage::SecurityOk => out.extend_from_slice(&[0, 0, 0, 0]),
            ServerMessage::SecurityFailed(reason) => {
                out.extend_from_slice(&[0, 0, 0, 1]);
                if dialect == Dialect::V3_8 {
                    put_text(&mut out, reason)?;
                } else if !reason.is_empty() {
                    return Err(Error::Unwritable);
                }
            }
            ServerMessage::ServerInit(init) => {
                if !init.format.is_valid() {
                    return Err(Error::PixelFormat);
                }
                out.extend_from_slice(&init.width.to_be_bytes());
                out.extend_from_slice(&init.height.to_be_bytes());
                out.extend_from_slice(&init.format.to_bytes());
                put_text(&mut out, &init.name)?;
            }
            ServerMessage::FramebufferUpdate(rects) => {
                if rects.len() > MAX_ITEMS {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&[server_type::FRAMEBUFFER_UPDATE, 0]);
                out.extend_from_slice(&(rects.len() as u16).to_be_bytes());
                if rects.iter().rev().skip(1).any(|r| r.contents == Contents::DesktopSize) {
                    return Err(Error::Rectangle);
                }
                for r in rects {
                    for v in [r.x, r.y, r.width, r.height] {
                        out.extend_from_slice(&v.to_be_bytes());
                    }
                    out.extend_from_slice(&r.contents.encoding().to_be_bytes());
                    match &r.contents {
                        Contents::Raw(pixels) => {
                            if pixels.len() != pixels_len(r.width, r.height, format)? {
                                return Err(Error::Unwritable);
                            }
                            out.extend_from_slice(pixels);
                        }
                        Contents::CopyRect { src_x, src_y } => {
                            out.extend_from_slice(&src_x.to_be_bytes());
                            out.extend_from_slice(&src_y.to_be_bytes());
                        }
                        Contents::Cursor { pixels, mask } => {
                            if pixels.len() != pixels_len(r.width, r.height, format)?
                                || mask.len() != mask_len(r.width, r.height)?
                            {
                                return Err(Error::Unwritable);
                            }
                            out.extend_from_slice(pixels);
                            out.extend_from_slice(mask);
                        }
                        Contents::DesktopSize => {}
                    }
                    if out.len() > MAX_MESSAGE {
                        return Err(Error::TooLong);
                    }
                }
            }
            ServerMessage::SetColorMapEntries { first, colors } => {
                if colors.len() > MAX_ITEMS {
                    return Err(Error::Unwritable);
                }
                out.extend_from_slice(&[server_type::SET_COLOR_MAP_ENTRIES, 0]);
                out.extend_from_slice(&first.to_be_bytes());
                out.extend_from_slice(&(colors.len() as u16).to_be_bytes());
                for c in colors {
                    for v in [c.red, c.green, c.blue] {
                        out.extend_from_slice(&v.to_be_bytes());
                    }
                }
            }
            ServerMessage::Bell => out.push(server_type::BELL),
            ServerMessage::ServerCutText(text) => {
                out.extend_from_slice(&[server_type::SERVER_CUT_TEXT, 0, 0, 0]);
                put_text(&mut out, text)?;
            }
        }
        Ok(out)
    }
}

/// Where a connection is in the protocol: whose turn it is and what comes
/// next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
    /// The server sends its version.
    ServerVersion,
    /// The client answers with its version.
    ClientVersion,
    /// The server offers security types (3.7, 3.8), names one (3.3), or
    /// refuses.
    SecurityOffer,
    /// The client picks a security type (3.7, 3.8).
    SecurityChoice,
    /// The server sends a VNC Authentication challenge.
    VncChallenge,
    /// The client answers the challenge.
    VncResponse,
    /// The server says whether authentication passed.
    SecurityResult,
    /// The client sends ClientInit.
    ClientInit,
    /// The server sends ServerInit.
    ServerInit,
    /// The handshake is done, and both sides send messages.
    Normal,
    /// The handshake picked this security type, which this module does
    /// not follow. Nothing more can be read or sent.
    Unsupported(u32),
    /// The server refused the connection. Bytes the peer sends are
    /// dropped, and nothing more can be sent.
    Closed,
}

impl Phase {
    /// Whether the server may send in this phase.
    pub fn server_turn(self) -> bool {
        matches!(
            self,
            Phase::ServerVersion
                | Phase::SecurityOffer
                | Phase::VncChallenge
                | Phase::SecurityResult
                | Phase::ServerInit
                | Phase::Normal
        )
    }

    /// Whether the client may send in this phase.
    pub fn client_turn(self) -> bool {
        matches!(
            self,
            Phase::ClientVersion | Phase::SecurityChoice | Phase::VncResponse | Phase::ClientInit | Phase::Normal
        )
    }
}

/// The connection state both sessions keep.
#[derive(Clone, Debug)]
struct State {
    phase: Phase,
    /// The version the server sent, or 3.8 before it has.
    server_version: Version,
    dialect: Dialect,
    offered: Vec<u8>,
    format: PixelFormat,
    /// The framebuffer's size: from ServerInit, then from the last
    /// DesktopSize rectangle.
    width: u16,
    height: u16,
    /// Whether the client asked for an update the server has not yet sent.
    requested: bool,
    /// Whether one of those requests was not incremental, which rules out
    /// CopyRect.
    full: bool,
    /// Which encodings past Raw the client listed in its last SetEncodings.
    copy_rect: bool,
    cursor: bool,
    desktop_size: bool,
}

impl State {
    fn new() -> State {
        State {
            phase: Phase::ServerVersion,
            server_version: Version::V3_8,
            dialect: Dialect::V3_8,
            offered: Vec::new(),
            format: PixelFormat::TRUE_COLOR_32,
            width: 0,
            height: 0,
            requested: false,
            full: false,
            copy_rect: false,
            cursor: false,
            desktop_size: false,
        }
    }

    /// The phase after security type `t` was settled on.
    fn after_type(&self, t: u32) -> Phase {
        match t {
            1 if self.dialect == Dialect::V3_8 => Phase::SecurityResult,
            1 => Phase::ClientInit,
            2 => Phase::VncChallenge,
            t => Phase::Unsupported(t),
        }
    }

    /// Moves on past a message the client sent, or fails if it does not
    /// belong here. Nothing changes on failure.
    fn client_step(&mut self, m: &ClientMessage) -> Result<(), Error> {
        match (self.phase, m) {
            (Phase::ClientVersion, ClientMessage::Version(v)) => {
                self.dialect = (*v).min(self.server_version).dialect();
                self.phase = Phase::SecurityOffer;
            }
            (Phase::SecurityChoice, ClientMessage::SecurityType(t)) => {
                if !self.offered.contains(t) {
                    return Err(Error::NotOffered(*t));
                }
                if *t == security::INVALID {
                    return Err(Error::Unwritable);
                }
                self.phase = self.after_type(u32::from(*t));
            }
            (Phase::VncResponse, ClientMessage::VncResponse(_)) => self.phase = Phase::SecurityResult,
            (Phase::ClientInit, ClientMessage::ClientInit { .. }) => self.phase = Phase::ServerInit,
            (Phase::Normal, ClientMessage::SetPixelFormat(f)) => self.format = *f,
            (Phase::Normal, ClientMessage::SetEncodings(list)) => {
                self.copy_rect = list.contains(&encoding::COPY_RECT);
                self.cursor = list.contains(&encoding::CURSOR);
                self.desktop_size = list.contains(&encoding::DESKTOP_SIZE);
            }
            (Phase::Normal, ClientMessage::FramebufferUpdateRequest { incremental, .. }) => {
                self.requested = true;
                self.full |= !incremental;
            }
            (Phase::Normal, m) if !m.is_handshake() => {}
            (p, _) => return Err(Error::Phase(p)),
        }
        Ok(())
    }

    /// Moves on past a message the server sent, or fails if it does not
    /// belong here. Nothing changes on failure.
    fn server_step(&mut self, m: &ServerMessage) -> Result<(), Error> {
        match (self.phase, m) {
            (Phase::ServerVersion, ServerMessage::Version(v)) => {
                self.server_version = *v;
                self.phase = Phase::ClientVersion;
            }
            (Phase::SecurityOffer, ServerMessage::SecurityTypes(types)) if self.dialect != Dialect::V3_3 => {
                if types.is_empty() || types.len() > MAX_SECURITY_TYPES {
                    return Err(Error::Unwritable);
                }
                self.offered = types.clone();
                self.phase = Phase::SecurityChoice;
            }
            (Phase::SecurityOffer, ServerMessage::SecurityType(t)) if self.dialect == Dialect::V3_3 => {
                if *t == 0 {
                    return Err(Error::Unwritable);
                }
                self.phase = self.after_type(*t);
            }
            (Phase::SecurityOffer, ServerMessage::SecurityFailure(_)) => self.phase = Phase::Closed,
            (Phase::VncChallenge, ServerMessage::VncChallenge(_)) => self.phase = Phase::VncResponse,
            (Phase::SecurityResult, ServerMessage::SecurityOk) => self.phase = Phase::ClientInit,
            (Phase::SecurityResult, ServerMessage::SecurityFailed(_)) => self.phase = Phase::Closed,
            (Phase::ServerInit, ServerMessage::ServerInit(init)) => {
                self.format = init.format;
                self.width = init.width;
                self.height = init.height;
                self.phase = Phase::Normal;
            }
            (Phase::Normal, ServerMessage::FramebufferUpdate(rects)) => {
                let (mut width, mut height) = (self.width, self.height);
                // RFC 6143, section 7.6.1, and The RFB Protocol, section
                // 2.1: updates stay inside the framebuffer.
                let inside = |x: u16, y: u16, r: &Rectangle| {
                    let fits = |at: u16, len: u16, max: u16| u32::from(at) + u32::from(len) <= u32::from(max);
                    if fits(x, r.width, self.width) && fits(y, r.height, self.height) { Ok(()) } else { Err(Error::Rectangle) }
                };
                for r in rects {
                    match r.contents {
                        Contents::Raw(_) => inside(r.x, r.y, r)?,
                        Contents::CopyRect { src_x, src_y } => {
                            inside(r.x, r.y, r)?;
                            inside(src_x, src_y, r)?;
                        }
                        // The x and y are the cursor's hot spot.
                        Contents::Cursor { .. } => {}
                        Contents::DesktopSize => (width, height) = (r.width, r.height),
                    }
                }
                self.width = width;
                self.height = height;
                self.requested = false;
                self.full = false;
            }
            (Phase::Normal, m) if !m.is_handshake() => {}
            (p, _) => return Err(Error::Phase(p)),
        }
        Ok(())
    }

    /// Whether the server may send `m` now, by what the client asked for.
    /// The client's reader does not hold the server to this, as clients in
    /// use do not, but a world playing a server keeps to it.
    fn requested(&self, m: &ServerMessage) -> Result<(), Error> {
        match m {
            ServerMessage::FramebufferUpdate(rects) => {
                if !self.requested {
                    return Err(Error::NotRequested);
                }
                for r in rects {
                    let listed = match r.contents {
                        Contents::Raw(_) => true,
                        Contents::CopyRect { .. } => self.copy_rect && !self.full,
                        Contents::Cursor { .. } => self.cursor,
                        Contents::DesktopSize => self.desktop_size,
                    };
                    if !listed {
                        return Err(Error::NotRequested);
                    }
                }
            }
            ServerMessage::SetColorMapEntries { .. } if self.format.true_color => return Err(Error::NotRequested),
            _ => {}
        }
        Ok(())
    }

    /// Reads the next client message, as this phase expects it.
    fn client_at(&self, c: &mut Cur<'_>) -> Result<ClientMessage, Stop> {
        Ok(match self.phase {
            Phase::ClientVersion => ClientMessage::Version(version(c)?),
            Phase::SecurityChoice => ClientMessage::SecurityType(c.u8()?),
            Phase::VncResponse => ClientMessage::VncResponse(c.array()?),
            Phase::ClientInit => ClientMessage::ClientInit { shared: c.u8()? != 0 },
            Phase::Normal => client_normal(c)?,
            p => return Err(Stop::Fail(Error::Phase(p))),
        })
    }

    /// Reads the next server message, as this phase expects it. A
    /// framebuffer update read in part goes on from `partial`.
    fn server_at(&self, c: &mut Cur<'_>, partial: &mut Option<Partial>) -> Result<ServerMessage, Stop> {
        Ok(match self.phase {
            Phase::ServerVersion => ServerMessage::Version(version(c)?),
            Phase::SecurityOffer => match self.dialect {
                Dialect::V3_3 => match c.u32()? {
                    0 => ServerMessage::SecurityFailure(text(c)?),
                    t => ServerMessage::SecurityType(t),
                },
                Dialect::V3_7 | Dialect::V3_8 => match c.u8()? {
                    0 => ServerMessage::SecurityFailure(text(c)?),
                    n => ServerMessage::SecurityTypes(c.take(usize::from(n))?.to_vec()),
                },
            },
            Phase::VncChallenge => ServerMessage::VncChallenge(c.array()?),
            Phase::SecurityResult => match c.u32()? {
                0 => ServerMessage::SecurityOk,
                _ if self.dialect == Dialect::V3_8 => ServerMessage::SecurityFailed(text(c)?),
                _ => ServerMessage::SecurityFailed(Vec::new()),
            },
            Phase::ServerInit => {
                let (width, height) = (c.u16()?, c.u16()?);
                let format = PixelFormat::parse(&c.array()?);
                if !format.is_valid() {
                    return Err(Stop::Fail(Error::PixelFormat));
                }
                ServerMessage::ServerInit(ServerInit { width, height, format, name: text(c)? })
            }
            Phase::Normal => server_normal(c, &self.format, partial)?,
            p => return Err(Stop::Fail(Error::Phase(p))),
        })
    }
}

/// The bytes the peer sent that are not yet taken out.
#[derive(Clone, Debug, Default)]
struct Reader {
    buf: Vec<u8>,
    /// Where the bytes not yet taken out start. Bytes before it are
    /// dropped in `feed` once they are half the buffer, so taking out many
    /// small messages costs time in proportion to their bytes.
    start: usize,
    /// How many bytes past `start` the next message needs at least, as
    /// far as the last try knew. Until that many have come, nothing is
    /// read again, so a message fed a byte at a time is not read over and
    /// over.
    need: usize,
    failed: Option<Error>,
}

impl Reader {
    fn feed(&mut self, bytes: &[u8]) {
        if self.failed.is_none() {
            if self.start > 0 && self.start >= self.buf.len() / 2 {
                self.buf.drain(..self.start);
                self.start = 0;
            }
            self.buf.extend_from_slice(bytes);
        }
    }

    fn held(&self) -> usize {
        self.buf.len() - self.start
    }

    fn clear(&mut self) {
        self.buf = Vec::new();
        self.start = 0;
        self.need = 0;
    }

    fn fail(&mut self, e: Error) -> Error {
        self.failed = Some(e);
        self.clear();
        e
    }

    /// Adds bytes, holding them to the limits for this phase, so the
    /// buffer stays bounded even if no message is asked for. Bytes past a
    /// limit are not copied.
    fn feed_in(&mut self, bytes: &[u8], turn: bool, phase: Phase) {
        if self.failed.is_some() {
            return;
        }
        let total = self.held().saturating_add(bytes.len());
        match phase {
            Phase::Unsupported(t) if total > 0 => {
                self.fail(Error::Unsupported(t));
            }
            _ if turn && total > MAX_BUFFERED => {
                self.fail(Error::TooLong);
            }
            _ if !turn && total > MAX_PENDING => {
                self.fail(Error::OutOfTurn);
            }
            _ => self.feed(bytes),
        }
    }

    /// What bytes held before the peer's turn mean: none in a closed
    /// connection, an error after an unsupported security type, and an
    /// error past [`MAX_PENDING`].
    fn out_of_turn(&mut self, phase: Phase) -> Option<Error> {
        if let Some(e) = self.failed {
            return Some(e);
        }
        match phase {
            Phase::Closed => {
                self.clear();
                None
            }
            Phase::Unsupported(t) if self.held() > 0 => Some(self.fail(Error::Unsupported(t))),
            _ if self.held() > MAX_PENDING => Some(self.fail(Error::OutOfTurn)),
            _ => None,
        }
    }

    /// The next message, read with `parse` if it is the peer's turn.
    fn next<T>(
        &mut self,
        turn: bool,
        phase: Phase,
        parse: impl FnOnce(&mut Cur<'_>) -> Result<T, Stop>,
    ) -> Option<Result<T, Error>> {
        if let Some(e) = self.failed {
            return Some(Err(e));
        }
        if !turn {
            return self.out_of_turn(phase).map(Err);
        }
        let held = self.held();
        if held == 0 || held < self.need {
            return None;
        }
        let mut c = Cur { b: &self.buf[self.start..], pos: 0 };
        match parse(&mut c) {
            Ok(m) => {
                self.start += c.pos;
                self.need = 0;
                Some(Ok(m))
            }
            Err(Stop::Need(n)) => {
                self.need = n;
                None
            }
            Err(Stop::Fail(e)) => Some(Err(self.fail(e))),
        }
    }
}

/// A connection as the server sees it: for a world that plays an RFB
/// server. It reads what the client sends and writes what the server
/// sends, and keeps the phase in step with both. A clone is a separate
/// copy of the connection's state.
#[derive(Clone, Debug)]
pub struct ServerSession {
    state: State,
    reader: Reader,
}

impl Default for ServerSession {
    fn default() -> ServerSession {
        ServerSession::new()
    }
}

impl ServerSession {
    /// A session at the start of a connection, where the server sends its
    /// version first.
    pub fn new() -> ServerSession {
        ServerSession { state: State::new(), reader: Reader::default() }
    }

    /// Adds bytes read from the client. After a read error, or once the
    /// server has refused the connection, they are dropped. More than
    /// [`MAX_PENDING`] bytes before the client's turn break the stream at
    /// once, so the session never holds more than that while it waits, and
    /// it never holds more than [`MAX_BUFFERED`] at all.
    pub fn feed(&mut self, bytes: &[u8]) {
        let phase = self.state.phase;
        if phase != Phase::Closed {
            self.reader.feed_in(bytes, phase.client_turn(), phase);
        }
    }

    /// The client's next whole message, if one has come and it is the
    /// client's turn. It returns `None` when it needs more bytes or the
    /// server must send first, and keeps returning the same error once the
    /// stream has broken.
    pub fn next_message(&mut self) -> Option<Result<ClientMessage, Error>> {
        let state = &self.state;
        let m = match self.reader.next(state.phase.client_turn(), state.phase, |c| state.client_at(c))? {
            Ok(m) => m,
            Err(e) => return Some(Err(e)),
        };
        match self.state.client_step(&m) {
            Ok(()) => Some(Ok(m)),
            Err(e) => Some(Err(self.reader.fail(e))),
        }
    }

    /// The bytes that send `msg` to the client. A message that does not
    /// belong in this phase is [`Error::Phase`]; one the client did not ask
    /// for is [`Error::NotRequested`]; a rectangle outside the framebuffer
    /// is [`Error::Rectangle`]; one that cannot be written is the error
    /// [`ServerMessage::to_bytes`] gives. On any error nothing changes.
    pub fn send(&mut self, msg: &ServerMessage) -> Result<Vec<u8>, Error> {
        let mut next = self.state.clone();
        next.server_step(msg)?;
        self.state.requested(msg)?;
        let bytes = msg.to_bytes(self.state.dialect, &self.state.format)?;
        if next.phase != self.state.phase {
            // The client's bytes now split another way.
            self.reader.need = 0;
        }
        self.state = next;
        Ok(bytes)
    }

    /// The phase the connection is in.
    pub fn phase(&self) -> Phase {
        self.state.phase
    }

    /// The handshake the two versions picked: the lower one's, as TigerVNC
    /// picks it. Before the client's version comes, it is
    /// [`Dialect::V3_8`].
    pub fn dialect(&self) -> Dialect {
        self.state.dialect
    }

    /// The security types the server offered, in 3.7 and 3.8.
    pub fn offered(&self) -> &[u8] {
        &self.state.offered
    }

    /// The pixel format updates are sent in: from ServerInit, then from the
    /// client's last SetPixelFormat.
    pub fn pixel_format(&self) -> PixelFormat {
        self.state.format
    }

    /// How many bytes are held, waiting to be read.
    pub fn buffered(&self) -> usize {
        self.reader.held()
    }
}

/// A connection as the client sees it: for a world that plays an RFB
/// client. It reads what the server sends and writes what the client
/// sends, and keeps the phase in step with both. A clone is a separate
/// copy of the connection's state.
#[derive(Clone, Debug)]
pub struct ClientSession {
    state: State,
    reader: Reader,
    partial: Option<Partial>,
}

impl Default for ClientSession {
    fn default() -> ClientSession {
        ClientSession::new()
    }
}

impl ClientSession {
    /// A session at the start of a connection, waiting for the server's
    /// version.
    pub fn new() -> ClientSession {
        ClientSession { state: State::new(), reader: Reader::default(), partial: None }
    }

    /// Adds bytes read from the server. After a read error, or once the
    /// server has refused the connection, they are dropped. More than
    /// [`MAX_PENDING`] bytes before the server's turn break the stream at
    /// once, so the session never holds more than that while it waits, and
    /// it never holds more than [`MAX_BUFFERED`] at all.
    pub fn feed(&mut self, bytes: &[u8]) {
        let phase = self.state.phase;
        if phase != Phase::Closed {
            self.reader.feed_in(bytes, phase.server_turn(), phase);
        }
    }

    /// The server's next whole message, if one has come and it is the
    /// server's turn. It returns `None` when it needs more bytes or the
    /// client must send first, and keeps returning the same error once the
    /// stream has broken.
    pub fn next_message(&mut self) -> Option<Result<ServerMessage, Error>> {
        let (state, partial) = (&self.state, &mut self.partial);
        let m = match self.reader.next(state.phase.server_turn(), state.phase, |c| state.server_at(c, partial))? {
            Ok(m) => m,
            Err(e) => return Some(Err(e)),
        };
        match self.state.server_step(&m) {
            Ok(()) => Some(Ok(m)),
            Err(e) => Some(Err(self.reader.fail(e))),
        }
    }

    /// The bytes that send `msg` to the server. A message that does not
    /// belong in this phase is [`Error::Phase`], a security type the
    /// server did not offer is [`Error::NotOffered`], SetPixelFormat while
    /// an update request is outstanding or an update is being read is
    /// [`Error::Outstanding`], and one that cannot be written is the error
    /// [`ClientMessage::to_bytes`] gives. On any error nothing changes.
    pub fn send(&mut self, msg: &ClientMessage) -> Result<Vec<u8>, Error> {
        let format_change = matches!(msg, ClientMessage::SetPixelFormat(_));
        // The RFB Protocol, section 7.4.1: with a request outstanding, the
        // client could not tell which format the next update is in.
        if format_change && self.state.phase == Phase::Normal && (self.state.requested || self.update_started()) {
            return Err(Error::Outstanding);
        }
        let mut next = self.state.clone();
        next.client_step(msg)?;
        let bytes = msg.to_bytes()?;
        if format_change || next.phase != self.state.phase {
            // The server's bytes now split another way. No update is in
            // progress, so `partial` holds nothing.
            self.reader.need = 0;
        }
        self.state = next;
        Ok(bytes)
    }

    /// Whether the bytes held start a framebuffer update.
    fn update_started(&self) -> bool {
        self.partial.is_some()
            || (self.state.phase == Phase::Normal
                && self.reader.buf.get(self.reader.start) == Some(&server_type::FRAMEBUFFER_UPDATE))
    }

    /// The phase the connection is in.
    pub fn phase(&self) -> Phase {
        self.state.phase
    }

    /// The handshake the two versions picked: the lower one's. Before the
    /// client sends its version, it is [`Dialect::V3_8`].
    pub fn dialect(&self) -> Dialect {
        self.state.dialect
    }

    /// The security types the server offered, in 3.7 and 3.8.
    pub fn offered(&self) -> &[u8] {
        &self.state.offered
    }

    /// The pixel format updates come in: from ServerInit, then from the
    /// client's last SetPixelFormat. The client sends that only when no
    /// update request is outstanding, so the next update is in the new
    /// format.
    pub fn pixel_format(&self) -> PixelFormat {
        self.state.format
    }

    /// How many bytes are held, waiting to be read.
    pub fn buffered(&self) -> usize {
        self.reader.held()
    }
}

/// Why a read stopped: it needs this many bytes in all, or it failed.
enum Stop {
    Need(usize),
    Fail(Error),
}

impl From<Error> for Stop {
    fn from(e: Error) -> Stop {
        Stop::Fail(e)
    }
}

/// A read position in a byte slice. Every read checks the length, and no
/// read reaches past [`MAX_MESSAGE`].
struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Stop> {
        let end = self.pos.checked_add(n).filter(|&e| e <= MAX_MESSAGE).ok_or(Stop::Fail(Error::TooLong))?;
        let s = self.b.get(self.pos..end).ok_or(Stop::Need(end))?;
        self.pos = end;
        Ok(s)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Stop> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Stop> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Stop> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Stop> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn i32(&mut self) -> Result<i32, Stop> {
        Ok(i32::from_be_bytes(self.array()?))
    }
}

/// Runs a read from the start of `b` and says how far it got.
fn run<T>(b: &[u8], read: impl FnOnce(&mut Cur<'_>) -> Result<T, Stop>) -> Result<Option<(T, usize)>, Error> {
    let mut c = Cur { b, pos: 0 };
    match read(&mut c) {
        Ok(v) => Ok(Some((v, c.pos))),
        Err(Stop::Need(_)) => Ok(None),
        Err(Stop::Fail(e)) => Err(e),
    }
}

fn version(c: &mut Cur<'_>) -> Result<Version, Stop> {
    const PATTERN: &[u8; VERSION_LEN] = b"RFB 000.000\n";
    // A wrong byte is known before the rest of the line comes.
    let have = c.b.get(c.pos..).unwrap_or_default();
    for (&x, &p) in have.iter().zip(PATTERN) {
        let fits = if p == b'0' { x.is_ascii_digit() } else { x == p };
        if !fits {
            return Err(Stop::Fail(Error::Version));
        }
    }
    if have.len() < VERSION_LEN {
        // Ask for one more byte, not the whole line, so each one is checked
        // as it comes.
        return Err(Stop::Need(c.pos + have.len() + 1));
    }
    let b = c.take(VERSION_LEN)?;
    let number = |d: &[u8]| d.iter().fold(0u16, |n, &x| n * 10 + u16::from(x - b'0'));
    Ok(Version { major: number(&b[4..7]), minor: number(&b[8..11]) })
}

/// A four-byte length and that many bytes of text.
fn text(c: &mut Cur<'_>) -> Result<Vec<u8>, Stop> {
    let n = usize::try_from(c.u32()?).map_err(|_| Error::TooLong)?;
    if n > MAX_TEXT {
        return Err(Stop::Fail(Error::TooLong));
    }
    Ok(c.take(n)?.to_vec())
}

fn put_text(out: &mut Vec<u8>, text: &[u8]) -> Result<(), Error> {
    if text.len() > MAX_TEXT {
        return Err(Error::TooLong);
    }
    out.extend_from_slice(&(text.len() as u32).to_be_bytes());
    out.extend_from_slice(text);
    Ok(())
}

/// The bytes of a width by height block of pixels in `format`.
fn pixels_len(width: u16, height: u16, format: &PixelFormat) -> Result<usize, Error> {
    let bytes = format.bytes_per_pixel().ok_or(Error::BitsPerPixel(format.bits_per_pixel))?;
    usize::from(width)
        .checked_mul(usize::from(height))
        .and_then(|n| n.checked_mul(bytes))
        .filter(|&n| n <= MAX_MESSAGE)
        .ok_or(Error::TooLong)
}

/// The bytes of a cursor's mask: one bit per pixel, rows padded to bytes.
fn mask_len(width: u16, height: u16) -> Result<usize, Error> {
    usize::from(width).div_ceil(8).checked_mul(usize::from(height)).ok_or(Error::TooLong)
}

fn client_normal(c: &mut Cur<'_>) -> Result<ClientMessage, Stop> {
    Ok(match c.u8()? {
        client_type::SET_PIXEL_FORMAT => {
            c.take(3)?;
            let format = PixelFormat::parse(&c.array()?);
            if !format.is_valid() {
                return Err(Stop::Fail(Error::PixelFormat));
            }
            ClientMessage::SetPixelFormat(format)
        }
        client_type::SET_ENCODINGS => {
            c.take(1)?;
            let n = usize::from(c.u16()?);
            let b = c.take(4 * n)?;
            ClientMessage::SetEncodings(b.chunks_exact(4).map(|e| i32::from_be_bytes([e[0], e[1], e[2], e[3]])).collect())
        }
        client_type::FRAMEBUFFER_UPDATE_REQUEST => {
            let incremental = c.u8()? != 0;
            let (x, y, width, height) = (c.u16()?, c.u16()?, c.u16()?, c.u16()?);
            ClientMessage::FramebufferUpdateRequest { incremental, x, y, width, height }
        }
        client_type::KEY_EVENT => {
            let down = c.u8()? != 0;
            c.take(2)?;
            ClientMessage::KeyEvent { down, key: c.u32()? }
        }
        client_type::POINTER_EVENT => {
            let buttons = c.u8()?;
            ClientMessage::PointerEvent { buttons, x: c.u16()?, y: c.u16()? }
        }
        client_type::CLIENT_CUT_TEXT => {
            c.take(3)?;
            ClientMessage::ClientCutText(text(c)?)
        }
        t => return Err(Stop::Fail(Error::MessageType(t))),
    })
}

/// A framebuffer update read in part: the rectangles read so far, where
/// the next one starts, and how many there are in all. Going on from here
/// keeps an update fed a byte at a time from being read over and over.
#[derive(Clone, Debug)]
struct Partial {
    pos: usize,
    count: usize,
    rects: Vec<Rectangle>,
}

fn server_normal(c: &mut Cur<'_>, format: &PixelFormat, partial: &mut Option<Partial>) -> Result<ServerMessage, Stop> {
    if let Some(p) = partial.take() {
        c.pos = p.pos;
        return rectangles(c, format, p, partial);
    }
    Ok(match c.u8()? {
        server_type::FRAMEBUFFER_UPDATE => {
            c.take(1)?;
            let count = usize::from(c.u16()?);
            return rectangles(c, format, Partial { pos: c.pos, count, rects: Vec::new() }, partial);
        }
        server_type::SET_COLOR_MAP_ENTRIES => {
            c.take(1)?;
            let first = c.u16()?;
            let n = usize::from(c.u16()?);
            let b = c.take(6 * n)?;
            let colors = b
                .chunks_exact(6)
                .map(|v| Color {
                    red: u16::from_be_bytes([v[0], v[1]]),
                    green: u16::from_be_bytes([v[2], v[3]]),
                    blue: u16::from_be_bytes([v[4], v[5]]),
                })
                .collect();
            ServerMessage::SetColorMapEntries { first, colors }
        }
        server_type::BELL => ServerMessage::Bell,
        server_type::SERVER_CUT_TEXT => {
            c.take(3)?;
            ServerMessage::ServerCutText(text(c)?)
        }
        t => return Err(Stop::Fail(Error::MessageType(t))),
    })
}

/// Reads the rest of a framebuffer update's rectangles. If they have not
/// all come, it leaves its progress in `keep`.
fn rectangles(
    c: &mut Cur<'_>,
    format: &PixelFormat,
    mut p: Partial,
    keep: &mut Option<Partial>,
) -> Result<ServerMessage, Stop> {
    while p.rects.len() < p.count {
        let at = c.pos;
        match rectangle(c, format) {
            // RFC 6143, section 7.8.2: DesktopSize comes last.
            Ok(r) if r.contents == Contents::DesktopSize && p.rects.len() + 1 < p.count => {
                return Err(Stop::Fail(Error::Rectangle));
            }
            Ok(r) => p.rects.push(r),
            Err(Stop::Need(n)) => {
                p.pos = at;
                *keep = Some(p);
                return Err(Stop::Need(n));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(ServerMessage::FramebufferUpdate(p.rects))
}

fn rectangle(c: &mut Cur<'_>, format: &PixelFormat) -> Result<Rectangle, Stop> {
    let (x, y, width, height) = (c.u16()?, c.u16()?, c.u16()?, c.u16()?);
    let contents = match c.i32()? {
        encoding::RAW => Contents::Raw(c.take(pixels_len(width, height, format)?)?.to_vec()),
        encoding::COPY_RECT => Contents::CopyRect { src_x: c.u16()?, src_y: c.u16()? },
        encoding::CURSOR => {
            let (p, m) = (pixels_len(width, height, format)?, mask_len(width, height)?);
            let b = c.take(p.checked_add(m).ok_or(Error::TooLong)?)?;
            Contents::Cursor { pixels: b[..p].to_vec(), mask: b[p..].to_vec() }
        }
        encoding::DESKTOP_SIZE => Contents::DesktopSize,
        e => return Err(Stop::Fail(Error::Encoding(e))),
    };
    Ok(Rectangle { x, y, width, height, contents })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic pseudo-random sequence (Knuth's MMIX LCG).
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn byte(&mut self) -> u8 {
            // Mostly small values, so message types and counts hit.
            if self.below(2) == 0 { self.below(8) as u8 } else { self.next() as u8 }
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.byte()).collect()
        }
    }

    /// What a scripted server sends whenever it is its turn.
    fn server_script(s: &ServerSession, vnc: bool) -> Option<ServerMessage> {
        Some(match s.phase() {
            Phase::ServerVersion => ServerMessage::Version(Version::V3_8),
            Phase::SecurityOffer if s.dialect() == Dialect::V3_3 => ServerMessage::SecurityType(if vnc { 2 } else { 1 }),
            Phase::SecurityOffer => ServerMessage::SecurityTypes(vec![1, 2]),
            Phase::VncChallenge => ServerMessage::VncChallenge([7; CHALLENGE_LEN]),
            Phase::SecurityResult => ServerMessage::SecurityOk,
            Phase::ServerInit => ServerMessage::ServerInit(ServerInit {
                width: 4,
                height: 3,
                format: PixelFormat::TRUE_COLOR_32,
                name: b"x".to_vec(),
            }),
            _ => return None,
        })
    }

    /// What a scripted client sends whenever it is its turn.
    fn client_script(s: &ClientSession, version: Version, vnc: bool) -> Option<ClientMessage> {
        Some(match s.phase() {
            Phase::ClientVersion => ClientMessage::Version(version),
            Phase::SecurityChoice => {
                let o = s.offered();
                // Type 0 is not a type, and cannot be picked.
                let t = if vnc && o.contains(&2) {
                    2
                } else if o.contains(&1) {
                    1
                } else {
                    *o.iter().find(|&&t| t != security::INVALID)?
                };
                ClientMessage::SecurityType(t)
            }
            Phase::VncResponse => ClientMessage::VncResponse([9; CHALLENGE_LEN]),
            Phase::ClientInit => ClientMessage::ClientInit { shared: true },
            _ => return None,
        })
    }

    /// Feeds `chunks` to a scripted server, and returns what it read up to
    /// and with the first error.
    fn drive_server<'a>(vnc: bool, chunks: impl IntoIterator<Item = &'a [u8]>) -> Vec<Result<ClientMessage, Error>> {
        let mut s = ServerSession::new();
        let mut got = Vec::new();
        for chunk in chunks {
            s.feed(chunk);
            loop {
                if let Some(m) = server_script(&s, vnc) {
                    s.send(&m).unwrap();
                    continue;
                }
                match s.next_message() {
                    Some(Ok(m)) => got.push(Ok(m)),
                    Some(Err(e)) => {
                        got.push(Err(e));
                        return got;
                    }
                    None => break,
                }
            }
        }
        got
    }

    /// Feeds `chunks` to a scripted client, and returns what it read up to
    /// and with the first error.
    fn drive_client<'a>(
        version: Version,
        vnc: bool,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<Result<ServerMessage, Error>> {
        let mut s = ClientSession::new();
        let mut got = Vec::new();
        for chunk in chunks {
            s.feed(chunk);
            loop {
                if let Some(m) = client_script(&s, version, vnc) {
                    s.send(&m).unwrap();
                    continue;
                }
                match s.next_message() {
                    Some(Ok(m)) => {
                        if !m.is_handshake() {
                            let bytes = m.to_bytes(s.dialect(), &s.pixel_format()).unwrap();
                            assert_eq!(ServerMessage::parse(&bytes, &s.pixel_format()), Ok(Some((m.clone(), bytes.len()))));
                        }
                        got.push(Ok(m));
                    }
                    Some(Err(e)) => {
                        got.push(Err(e));
                        return got;
                    }
                    None => break,
                }
            }
        }
        got
    }

    /// Runs a server and a client session against each other, passing
    /// every message through bytes, and checks each side reads what the
    /// other sent.
    fn converse(version: Version, offer: ServerMessage, choice: Option<u8>, result: Option<ServerMessage>) -> (ServerSession, ClientSession) {
        let mut s = ServerSession::new();
        let mut c = ClientSession::new();
        let to_client = |s: &mut ServerSession, c: &mut ClientSession, m: ServerMessage| {
            c.feed(&s.send(&m).unwrap());
            assert_eq!(c.next_message(), Some(Ok(m)));
            assert_eq!(c.buffered(), 0);
        };
        let to_server = |s: &mut ServerSession, c: &mut ClientSession, m: ClientMessage| {
            s.feed(&c.send(&m).unwrap());
            assert_eq!(s.next_message(), Some(Ok(m)));
            assert_eq!(s.buffered(), 0);
        };
        to_client(&mut s, &mut c, ServerMessage::Version(Version::V3_8));
        to_server(&mut s, &mut c, ClientMessage::Version(version));
        to_client(&mut s, &mut c, offer);
        if let Some(t) = choice {
            to_server(&mut s, &mut c, ClientMessage::SecurityType(t));
        }
        if s.phase() == Phase::VncChallenge {
            to_client(&mut s, &mut c, ServerMessage::VncChallenge([1; 16]));
            to_server(&mut s, &mut c, ClientMessage::VncResponse([2; 16]));
        }
        if let Some(r) = result {
            to_client(&mut s, &mut c, r);
        }
        assert_eq!(s.phase(), c.phase());
        if s.phase() == Phase::ClientInit {
            to_server(&mut s, &mut c, ClientMessage::ClientInit { shared: false });
            let init = ServerInit { width: 1024, height: 768, format: PixelFormat::TRUE_COLOR_32, name: b"desk".to_vec() };
            to_client(&mut s, &mut c, ServerMessage::ServerInit(init));
            assert_eq!(s.phase(), Phase::Normal);
            assert_eq!(c.phase(), Phase::Normal);
        }
        (s, c)
    }

    fn sample_client_messages() -> Vec<ClientMessage> {
        let f = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            big_endian: true,
            true_color: true,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        };
        vec![
            ClientMessage::SetPixelFormat(f),
            ClientMessage::SetEncodings(vec![encoding::COPY_RECT, encoding::RAW, encoding::CURSOR, encoding::DESKTOP_SIZE]),
            ClientMessage::SetEncodings(vec![]),
            ClientMessage::FramebufferUpdateRequest { incremental: true, x: 1, y: 2, width: 300, height: 400 },
            ClientMessage::KeyEvent { down: true, key: 0xff0d },
            ClientMessage::KeyEvent { down: false, key: 0x61 },
            ClientMessage::PointerEvent { buttons: 0b101, x: 0x1234, y: 7 },
            ClientMessage::ClientCutText(b"hello".to_vec()),
            ClientMessage::ClientCutText(vec![]),
        ]
    }

    fn sample_server_messages() -> Vec<ServerMessage> {
        vec![
            ServerMessage::FramebufferUpdate(vec![
                Rectangle { x: 0, y: 0, width: 2, height: 1, contents: Contents::Raw(vec![1, 2, 3, 4, 5, 6, 7, 8]) },
                Rectangle { x: 5, y: 6, width: 10, height: 10, contents: Contents::CopyRect { src_x: 1, src_y: 2 } },
                Rectangle {
                    x: 1,
                    y: 1,
                    width: 9,
                    height: 1,
                    contents: Contents::Cursor { pixels: vec![0xaa; 36], mask: vec![0xff, 0x80] },
                },
                Rectangle { x: 0, y: 0, width: 0, height: 0, contents: Contents::Raw(vec![]) },
                Rectangle { x: 0, y: 0, width: 800, height: 600, contents: Contents::DesktopSize },
            ]),
            ServerMessage::FramebufferUpdate(vec![]),
            ServerMessage::SetColorMapEntries {
                first: 3,
                colors: vec![Color { red: 1, green: 2, blue: 3 }, Color { red: 65535, green: 0, blue: 9 }],
            },
            ServerMessage::Bell,
            ServerMessage::ServerCutText(b"copied".to_vec()),
        ]
    }

    #[test]
    fn version_lines() {
        // RFC 6143, section 7.1.1.
        assert_eq!(Version::parse(b"RFB 003.008\n"), Ok(Some((Version::V3_8, 12))));
        assert_eq!(Version::V3_3.to_bytes(), *b"RFB 003.003\n");
        assert_eq!(Version::V3_7.to_bytes(), *b"RFB 003.007\n");
        assert_eq!(Version { major: 3, minor: 889 }.to_bytes(), *b"RFB 003.889\n");
        for n in 0..12 {
            assert_eq!(Version::parse(&b"RFB 003.008\n"[..n]), Ok(None), "{n} bytes");
        }
        // A wrong byte is an error at once.
        assert_eq!(Version::parse(b"G"), Err(Error::Version));
        assert_eq!(Version::parse(b"RFB 0x"), Err(Error::Version));
        assert_eq!(Version::parse(b"RFB 003.008\r"), Err(Error::Version));
        // The line clamps what three digits cannot hold, and the message
        // writers refuse it.
        let big = Version { major: 1000, minor: 65535 };
        assert_eq!(Version::parse(&big.to_bytes()), Ok(Some((Version { major: 999, minor: 999 }, 12))));
        assert_eq!(ClientMessage::Version(big).to_bytes(), Err(Error::Unwritable));
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(ServerMessage::Version(big).to_bytes(Dialect::V3_8, &f), Err(Error::Unwritable));
        let mut s = ServerSession::new();
        assert_eq!(s.send(&ServerMessage::Version(big)), Err(Error::Unwritable));
        assert_eq!(s.phase(), Phase::ServerVersion);
        // Dialects, as RFC 6143 says: anything else is 3.3.
        assert_eq!(Version::V3_8.dialect(), Dialect::V3_8);
        assert_eq!(Version::V3_7.dialect(), Dialect::V3_7);
        assert_eq!(Version { major: 3, minor: 5 }.dialect(), Dialect::V3_3);
        assert_eq!(Version { major: 3, minor: 889 }.dialect(), Dialect::V3_3);
        assert_eq!(Version { major: 4, minor: 8 }.dialect(), Dialect::V3_3);
    }

    #[test]
    fn handshake_3_8_none() {
        let (s, c) = converse(Version::V3_8, ServerMessage::SecurityTypes(vec![1]), Some(1), Some(ServerMessage::SecurityOk));
        assert_eq!(s.phase(), Phase::Normal);
        assert_eq!(c.pixel_format(), PixelFormat::TRUE_COLOR_32);
        assert_eq!(c.offered(), [1]);
    }

    #[test]
    fn handshake_3_8_vnc_auth_and_failure() {
        let (s, c) = converse(
            Version::V3_8,
            ServerMessage::SecurityTypes(vec![2, 1]),
            Some(2),
            Some(ServerMessage::SecurityFailed(b"bad password".to_vec())),
        );
        assert_eq!(s.phase(), Phase::Closed);
        assert_eq!(c.phase(), Phase::Closed);
        // The 3.8 failure carries its reason.
        assert_eq!(
            ServerMessage::SecurityFailed(b"no".to_vec()).to_bytes(Dialect::V3_8, &PixelFormat::TRUE_COLOR_32),
            Ok(vec![0, 0, 0, 1, 0, 0, 0, 2, b'n', b'o'])
        );
    }

    #[test]
    fn handshake_3_7_none_has_no_result() {
        let (s, _) = converse(Version::V3_7, ServerMessage::SecurityTypes(vec![1, 2]), Some(1), None);
        assert_eq!(s.phase(), Phase::Normal);
        // A 3.7 failure has no reason on the wire.
        let (s, c) = converse(Version::V3_7, ServerMessage::SecurityTypes(vec![2]), Some(2), Some(ServerMessage::SecurityFailed(vec![])));
        assert_eq!((s.phase(), c.phase()), (Phase::Closed, Phase::Closed));
        assert_eq!(ServerMessage::SecurityFailed(vec![]).to_bytes(Dialect::V3_7, &PixelFormat::TRUE_COLOR_32), Ok(vec![0, 0, 0, 1]));
        // A reason the wire cannot carry is refused, not dropped.
        assert_eq!(
            ServerMessage::SecurityFailed(b"x".to_vec()).to_bytes(Dialect::V3_7, &PixelFormat::TRUE_COLOR_32),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn handshake_3_3() {
        // The server picks VNC Authentication, sent as four bytes.
        let (s, _) = converse(Version::V3_3, ServerMessage::SecurityType(2), None, Some(ServerMessage::SecurityOk));
        assert_eq!(s.phase(), Phase::Normal);
        // None goes straight to ClientInit.
        let (s, _) = converse(Version::V3_3, ServerMessage::SecurityType(1), None, None);
        assert_eq!(s.phase(), Phase::Normal);
        assert_eq!(
            ServerMessage::SecurityType(1).to_bytes(Dialect::V3_3, &PixelFormat::TRUE_COLOR_32),
            Ok(vec![0, 0, 0, 1])
        );
    }

    #[test]
    fn handshake_refused() {
        let reason = ServerMessage::SecurityFailure(b"too many".to_vec());
        let (s, c) = converse(Version::V3_8, reason.clone(), None, None);
        assert_eq!((s.phase(), c.phase()), (Phase::Closed, Phase::Closed));
        let (s, _) = converse(Version::V3_3, reason.clone(), None, None);
        assert_eq!(s.phase(), Phase::Closed);
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(reason.to_bytes(Dialect::V3_8, &f).unwrap()[..5], [0, 0, 0, 0, 8]);
        assert_eq!(reason.to_bytes(Dialect::V3_3, &f).unwrap()[..8], [0, 0, 0, 0, 0, 0, 0, 8]);
        // A closed connection drops what the peer sends.
        let mut s = s;
        s.feed(&[1, 2, 3]);
        assert_eq!(s.next_message(), None);
        assert_eq!(s.buffered(), 0);
        assert_eq!(s.send(&ServerMessage::Bell), Err(Error::Phase(Phase::Closed)));
    }

    #[test]
    fn unsupported_security_type_is_reported() {
        let mut s = ServerSession::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        s.feed(b"RFB 003.008\n");
        s.next_message().unwrap().unwrap();
        s.send(&ServerMessage::SecurityTypes(vec![18, 19])).unwrap();
        s.feed(&[19]);
        assert_eq!(s.next_message(), Some(Ok(ClientMessage::SecurityType(19))));
        assert_eq!(s.phase(), Phase::Unsupported(19));
        assert_eq!(s.send(&ServerMessage::SecurityOk), Err(Error::Phase(Phase::Unsupported(19))));
        assert_eq!(s.next_message(), None);
        s.feed(&[0]);
        assert_eq!(s.next_message(), Some(Err(Error::Unsupported(19))));
        // A 3.3 server can name one too.
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.003\n");
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_3)).unwrap();
        c.feed(&[0, 0, 0, 16]);
        assert_eq!(c.next_message(), Some(Ok(ServerMessage::SecurityType(16))));
        assert_eq!(c.phase(), Phase::Unsupported(16));
    }

    #[test]
    fn choice_must_be_offered() {
        let mut s = ServerSession::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        s.feed(b"RFB 003.008\n");
        s.next_message().unwrap().unwrap();
        s.send(&ServerMessage::SecurityTypes(vec![2])).unwrap();
        s.feed(&[1]);
        assert_eq!(s.next_message(), Some(Err(Error::NotOffered(1))));
        assert_eq!(s.next_message(), Some(Err(Error::NotOffered(1))));
        // A client world cannot pick one either.
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.008\n");
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        c.feed(&[1, 2]);
        assert_eq!(c.next_message(), Some(Ok(ServerMessage::SecurityTypes(vec![2]))));
        assert_eq!(c.send(&ClientMessage::SecurityType(1)), Err(Error::NotOffered(1)));
        assert_eq!(c.phase(), Phase::SecurityChoice);
        assert_eq!(c.send(&ClientMessage::SecurityType(2)), Ok(vec![2]));
    }

    #[test]
    fn sends_out_of_phase_are_refused() {
        let mut s = ServerSession::new();
        assert_eq!(s.send(&ServerMessage::Bell), Err(Error::Phase(Phase::ServerVersion)));
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(s.send(&ServerMessage::Version(Version::V3_8)), Err(Error::Phase(Phase::ClientVersion)));
        s.feed(b"RFB 003.008\n");
        s.next_message().unwrap().unwrap();
        // A 3.8 server offers a list; a single type is 3.3's.
        assert_eq!(s.send(&ServerMessage::SecurityType(1)), Err(Error::Phase(Phase::SecurityOffer)));
        assert_eq!(s.send(&ServerMessage::SecurityTypes(vec![])), Err(Error::Unwritable));
        assert_eq!(s.send(&ServerMessage::SecurityTypes(vec![1; 256])), Err(Error::Unwritable));
        assert_eq!(s.phase(), Phase::SecurityOffer);
        let mut c = ClientSession::new();
        assert_eq!(c.send(&ClientMessage::Version(Version::V3_8)), Err(Error::Phase(Phase::ServerVersion)));
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(ServerMessage::SecurityType(0).to_bytes(Dialect::V3_3, &f), Err(Error::Unwritable));
        // A 3.3 world on the server side cannot send a list.
        let mut s = ServerSession::new();
        s.send(&ServerMessage::Version(Version::V3_3)).unwrap();
        s.feed(b"RFB 003.003\n");
        s.next_message().unwrap().unwrap();
        assert_eq!(s.send(&ServerMessage::SecurityTypes(vec![1])), Err(Error::Phase(Phase::SecurityOffer)));
        assert_eq!(s.send(&ServerMessage::SecurityType(0)), Err(Error::Unwritable));
    }

    #[test]
    fn dialect_is_the_lower_version() {
        // RFC 6143, section 7.1.1: the client must not reply with a version
        // higher than the server's. A 3.3 server keeps its 3.3 handshake if
        // a client answers 3.8 anyway.
        let mut s = ServerSession::new();
        s.send(&ServerMessage::Version(Version::V3_3)).unwrap();
        s.feed(b"RFB 003.008\n");
        s.next_message().unwrap().unwrap();
        assert_eq!(s.dialect(), Dialect::V3_3);
        assert_eq!(s.send(&ServerMessage::SecurityType(1)), Ok(vec![0, 0, 0, 1]));
        // A client world that answers a 3.7 server with 3.8 reads a 3.7 list.
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.007\n");
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(c.dialect(), Dialect::V3_7);
        // A server version past 3.8, such as 3.889, leaves the client's.
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.889\n");
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(c.dialect(), Dialect::V3_8);
    }

    #[test]
    fn handshake_writers_follow_the_dialect() {
        // A 3.3 type sent to a 3.8 client would read as a refusal, and a
        // list sent to a 3.3 client as a type number.
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(ServerMessage::SecurityType(1).to_bytes(Dialect::V3_8, &f), Err(Error::Unwritable));
        assert_eq!(ServerMessage::SecurityType(1).to_bytes(Dialect::V3_7, &f), Err(Error::Unwritable));
        assert_eq!(ServerMessage::SecurityTypes(vec![1]).to_bytes(Dialect::V3_3, &f), Err(Error::Unwritable));
        assert_eq!(ServerMessage::SecurityTypes(vec![1]).to_bytes(Dialect::V3_7, &f), Ok(vec![1, 1]));
    }

    #[test]
    fn early_bytes_wait_their_turn() {
        let mut s = ServerSession::new();
        // The client's version, sent before the server's.
        s.feed(b"RFB 003.008\n");
        assert_eq!(s.next_message(), None);
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(s.next_message(), Some(Ok(ClientMessage::Version(Version::V3_8))));
        // Too much early is an error.
        s.feed(&vec![0; MAX_PENDING + 1]);
        assert_eq!(s.next_message(), Some(Err(Error::OutOfTurn)));
        s.feed(&[1]);
        assert_eq!(s.next_message(), Some(Err(Error::OutOfTurn)));
        assert_eq!(s.buffered(), 0);
    }

    #[test]
    fn feed_bounds_early_bytes_without_reads() {
        // A world that feeds and never asks for a message still holds no
        // more than MAX_PENDING bytes before the peer's turn.
        let mut s = ServerSession::new();
        for _ in 0..(MAX_PENDING / 1024 + 4) {
            s.feed(&[0; 1024]);
            assert!(s.buffered() <= MAX_PENDING, "{}", s.buffered());
        }
        assert_eq!(s.next_message(), Some(Err(Error::OutOfTurn)));
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.008\n");
        c.next_message().unwrap().unwrap();
        for _ in 0..(MAX_PENDING / 1024 + 4) {
            c.feed(&[0; 1024]);
            assert!(c.buffered() <= MAX_PENDING);
        }
        assert_eq!(c.next_message(), Some(Err(Error::OutOfTurn)));
        // After an unsupported security type, the first byte breaks it.
        let mut s = ServerSession::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        s.feed(b"RFB 003.008\n");
        s.next_message().unwrap().unwrap();
        s.send(&ServerMessage::SecurityTypes(vec![30])).unwrap();
        s.feed(&[30]);
        s.next_message().unwrap().unwrap();
        for _ in 0..100 {
            s.feed(&[0; 1024]);
        }
        assert_eq!(s.buffered(), 0);
        assert_eq!(s.next_message(), Some(Err(Error::Unsupported(30))));
        // Sessions can be copied, so a world can try a branch.
        let copy = s.clone();
        assert_eq!(copy.phase(), s.phase());
    }

    #[test]
    fn server_init_example() {
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.003\n");
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_3)).unwrap();
        c.feed(&[0, 0, 0, 1]);
        assert_eq!(c.next_message(), Some(Ok(ServerMessage::SecurityType(1))));
        assert_eq!(c.send(&ClientMessage::ClientInit { shared: true }), Ok(vec![1]));
        let mut bytes = vec![0x04, 0x00, 0x03, 0x00];
        bytes.extend_from_slice(&[16, 16, 1, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 3, b'a', b'b', b'c']);
        for n in 0..bytes.len() {
            let mut c2 = ClientSession::new();
            c2.feed(b"RFB 003.003\n");
            c2.next_message().unwrap().unwrap();
            c2.send(&ClientMessage::Version(Version::V3_3)).unwrap();
            c2.feed(&[0, 0, 0, 1]);
            c2.next_message().unwrap().unwrap();
            c2.send(&ClientMessage::ClientInit { shared: true }).unwrap();
            c2.feed(&bytes[..n]);
            assert_eq!(c2.next_message(), None, "{n} bytes");
        }
        c.feed(&bytes);
        let format = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            big_endian: true,
            true_color: true,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
        };
        let init = ServerInit { width: 1024, height: 768, format, name: b"abc".to_vec() };
        assert_eq!(c.next_message(), Some(Ok(ServerMessage::ServerInit(init.clone()))));
        assert_eq!(c.pixel_format(), format);
        assert_eq!(ServerMessage::ServerInit(init).to_bytes(Dialect::V3_3, &format), Ok(bytes));
        // Raw pixels are now two bytes each.
        c.feed(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xab, 0xcd]);
        let Some(Ok(ServerMessage::FramebufferUpdate(r))) = c.next_message() else { panic!() };
        assert_eq!(r[0].contents, Contents::Raw(vec![0xab, 0xcd]));
        // After SetPixelFormat, four.
        c.send(&ClientMessage::SetPixelFormat(PixelFormat::TRUE_COLOR_32)).unwrap();
        c.feed(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4]);
        let Some(Ok(ServerMessage::FramebufferUpdate(r))) = c.next_message() else { panic!() };
        assert_eq!(r[0].contents, Contents::Raw(vec![1, 2, 3, 4]));
    }

    #[test]
    fn pixel_formats() {
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(f.to_bytes(), [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        assert_eq!(PixelFormat::parse(&f.to_bytes()), f);
        assert_eq!(f.bytes_per_pixel(), Some(4));
        let mut odd = [24u8, 24, 7, 9, 0, 1, 0, 2, 0, 3, 4, 5, 6, 0xee, 0xee, 0xee];
        let p = PixelFormat::parse(&odd);
        assert!(p.big_endian && p.true_color);
        assert_eq!(p.bytes_per_pixel(), None);
        odd[2] = 1;
        odd[3] = 1;
        odd[13..].copy_from_slice(&[0, 0, 0]);
        assert_eq!(p.to_bytes(), odd);
        // RFC 6143, section 7.4.
        assert!(f.is_valid());
        assert!(!p.is_valid());
        let rgb565 = PixelFormat { bits_per_pixel: 16, depth: 16, red_max: 31, green_max: 63, blue_max: 31, red_shift: 11, green_shift: 5, blue_shift: 0, ..f };
        assert!(rgb565.is_valid());
        assert!(!PixelFormat { red_shift: 12, ..rgb565 }.is_valid());
        assert!(!PixelFormat { red_max: 30, ..rgb565 }.is_valid());
        assert!(!PixelFormat { depth: 17, ..rgb565 }.is_valid());
        assert!(!PixelFormat { bits_per_pixel: 24, ..f }.is_valid());
        assert!(PixelFormat { red_max: 65535, red_shift: 16, green_max: 0, blue_max: 0, ..f }.is_valid());
        // A color map format's maximums and shifts are not used.
        assert!(PixelFormat { bits_per_pixel: 8, depth: 8, true_color: false, red_shift: 255, red_max: 250, ..f }.is_valid());
    }

    #[test]
    fn client_message_examples() {
        // RFC 6143, sections 7.5.3 to 7.5.6.
        assert_eq!(
            ClientMessage::parse(&[3, 1, 0, 0, 0, 0, 0x04, 0x00, 0x03, 0x00]),
            Ok(Some((ClientMessage::FramebufferUpdateRequest { incremental: true, x: 0, y: 0, width: 1024, height: 768 }, 10)))
        );
        // Return, pressed: keysym 0xff0d.
        assert_eq!(
            ClientMessage::parse(&[4, 1, 0, 0, 0, 0, 0xff, 0x0d]),
            Ok(Some((ClientMessage::KeyEvent { down: true, key: 0xff0d }, 8)))
        );
        assert_eq!(
            ClientMessage::parse(&[5, 1, 0, 10, 0, 20]),
            Ok(Some((ClientMessage::PointerEvent { buttons: 1, x: 10, y: 20 }, 6)))
        );
        assert_eq!(
            ClientMessage::parse(&[2, 0, 0, 2, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0x21]),
            Ok(Some((ClientMessage::SetEncodings(vec![1, -223]), 12)))
        );
        assert_eq!(
            ClientMessage::parse(&[6, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']),
            Ok(Some((ClientMessage::ClientCutText(b"hi".to_vec()), 10)))
        );
    }

    #[test]
    fn client_messages_round_trip_and_truncate() {
        for m in sample_client_messages() {
            let bytes = m.to_bytes().unwrap();
            assert_eq!(ClientMessage::parse(&bytes), Ok(Some((m.clone(), bytes.len()))));
            for n in 0..bytes.len() {
                assert_eq!(ClientMessage::parse(&bytes[..n]), Ok(None), "{m:?} cut to {n}");
            }
            // And through a session, a byte at a time.
            let (mut s, _) = converse(Version::V3_8, ServerMessage::SecurityTypes(vec![1]), Some(1), Some(ServerMessage::SecurityOk));
            for b in &bytes {
                assert_eq!(s.next_message(), None);
                s.feed(std::slice::from_ref(b));
            }
            assert_eq!(s.next_message(), Some(Ok(m)));
        }
        // Handshake messages are fixed bytes.
        assert_eq!(ClientMessage::SecurityType(2).to_bytes(), Ok(vec![2]));
        assert_eq!(ClientMessage::VncResponse([5; 16]).to_bytes(), Ok(vec![5; 16]));
        assert_eq!(ClientMessage::ClientInit { shared: false }.to_bytes(), Ok(vec![0]));
        assert!(ClientMessage::ClientInit { shared: false }.is_handshake());
        assert!(!ClientMessage::ClientCutText(vec![]).is_handshake());
    }

    #[test]
    fn server_messages_round_trip_and_truncate() {
        let f = PixelFormat::TRUE_COLOR_32;
        for m in sample_server_messages() {
            let bytes = m.to_bytes(Dialect::V3_8, &f).unwrap();
            assert_eq!(ServerMessage::parse(&bytes, &f), Ok(Some((m.clone(), bytes.len()))));
            for n in 0..bytes.len() {
                assert_eq!(ServerMessage::parse(&bytes[..n], &f), Ok(None), "{m:?} cut to {n}");
            }
            let (_, mut c) = converse(Version::V3_8, ServerMessage::SecurityTypes(vec![1]), Some(1), Some(ServerMessage::SecurityOk));
            for b in &bytes {
                assert_eq!(c.next_message(), None);
                c.feed(std::slice::from_ref(b));
            }
            assert_eq!(c.next_message(), Some(Ok(m)));
        }
        assert_eq!(ServerMessage::Bell.to_bytes(Dialect::V3_3, &f), Ok(vec![2]));
        assert!(ServerMessage::SecurityOk.is_handshake());
        assert!(!ServerMessage::Bell.is_handshake());
    }

    #[test]
    fn framebuffer_update_example() {
        // One 1x1 Raw rectangle at (2, 3) and one CopyRect from (0, 0).
        let bytes = [
            0, 0, 0, 2, //
            0, 2, 0, 3, 0, 1, 0, 1, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x00, //
            0, 4, 0, 4, 0, 2, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0,
        ];
        let want = ServerMessage::FramebufferUpdate(vec![
            Rectangle { x: 2, y: 3, width: 1, height: 1, contents: Contents::Raw(vec![0x11, 0x22, 0x33, 0]) },
            Rectangle { x: 4, y: 4, width: 2, height: 2, contents: Contents::CopyRect { src_x: 0, src_y: 0 } },
        ]);
        assert_eq!(ServerMessage::parse(&bytes, &PixelFormat::TRUE_COLOR_32), Ok(Some((want, bytes.len()))));
    }

    #[test]
    fn read_errors() {
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(ClientMessage::parse(&[1]), Err(Error::MessageType(1)));
        assert_eq!(ClientMessage::parse(&[7, 0, 0]), Err(Error::MessageType(7)));
        assert_eq!(ServerMessage::parse(&[4], &f), Err(Error::MessageType(4)));
        // Encodings this module cannot size, known from the header.
        let rect = |enc: i32| {
            let mut b = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1];
            b.extend_from_slice(&enc.to_be_bytes());
            b
        };
        assert_eq!(ServerMessage::parse(&rect(encoding::HEXTILE), &f), Err(Error::Encoding(5)));
        assert_eq!(ServerMessage::parse(&rect(-224), &f), Err(Error::Encoding(-224)));
        // Raw pixels need a valid format.
        let mut bad = f;
        bad.bits_per_pixel = 24;
        assert_eq!(ServerMessage::parse(&rect(encoding::RAW), &bad), Err(Error::BitsPerPixel(24)));
        assert_eq!(ServerMessage::parse(&rect(encoding::CURSOR), &bad), Err(Error::BitsPerPixel(24)));
        assert_eq!(ServerMessage::parse(&rect(encoding::COPY_RECT), &bad), Ok(None));
        // Text and messages past the limits.
        assert_eq!(ClientMessage::parse(&[6, 0, 0, 0, 0, 0x10, 0, 1]), Err(Error::TooLong));
        assert_eq!(ServerMessage::parse(&[3, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], &f), Err(Error::TooLong));
        assert!(ClientMessage::parse(&[6, 0, 0, 0, 0, 0x10, 0, 0]).unwrap().is_none());
        let mut huge = vec![0, 0, 0, 1, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        huge.extend_from_slice(&encoding::RAW.to_be_bytes());
        assert_eq!(ServerMessage::parse(&huge, &f), Err(Error::TooLong));
        // Through a session, the error sticks.
        let (mut s, _) = converse(Version::V3_8, ServerMessage::SecurityTypes(vec![1]), Some(1), Some(ServerMessage::SecurityOk));
        s.feed(&[9]);
        assert_eq!(s.next_message(), Some(Err(Error::MessageType(9))));
        s.feed(&[2]);
        assert_eq!(s.next_message(), Some(Err(Error::MessageType(9))));
        assert_eq!(s.buffered(), 0);
        let mut s = ServerSession::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        s.feed(b"RFB 3.8\n");
        assert_eq!(s.next_message(), Some(Err(Error::Version)));
        // Every error has words.
        for e in [Error::Version, Error::Encoding(5), Error::Phase(Phase::Normal), Error::Unwritable, Error::OutOfTurn] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_refuse_or_cap() {
        let f = PixelFormat::TRUE_COLOR_32;
        let rect = |contents| ServerMessage::FramebufferUpdate(vec![Rectangle { x: 0, y: 0, width: 2, height: 2, contents }]);
        assert_eq!(rect(Contents::Raw(vec![0; 15])).to_bytes(Dialect::V3_8, &f), Err(Error::Unwritable));
        assert_eq!(
            rect(Contents::Cursor { pixels: vec![0; 16], mask: vec![0; 3] }).to_bytes(Dialect::V3_8, &f),
            Err(Error::Unwritable)
        );
        let mut bad = f;
        bad.bits_per_pixel = 12;
        assert_eq!(rect(Contents::Raw(vec![])).to_bytes(Dialect::V3_8, &bad), Err(Error::BitsPerPixel(12)));
        let many = ServerMessage::FramebufferUpdate(vec![
            Rectangle { x: 0, y: 0, width: 0, height: 0, contents: Contents::DesktopSize };
            MAX_ITEMS + 1
        ]);
        assert_eq!(many.to_bytes(Dialect::V3_8, &f), Err(Error::Unwritable));
        // Two rectangles that are each under the limit but not together.
        let half = Rectangle { x: 0, y: 0, width: 4096, height: 4096, contents: Contents::Raw(vec![0; 4096 * 4096 * 4 / 2]) };
        let mut bad = f;
        bad.bits_per_pixel = 16;
        let both = ServerMessage::FramebufferUpdate(vec![half.clone(), half]);
        assert_eq!(both.to_bytes(Dialect::V3_8, &bad), Err(Error::TooLong));
        // Long text and lists are refused, not cut, so what is written
        // reads back the same.
        assert_eq!(ClientMessage::ClientCutText(vec![b'a'; MAX_TEXT + 1]).to_bytes(), Err(Error::TooLong));
        let longest = ClientMessage::ClientCutText(vec![b'a'; MAX_TEXT]);
        let b = longest.to_bytes().unwrap();
        assert_eq!(ClientMessage::parse(&b), Ok(Some((longest, b.len()))));
        assert_eq!(ClientMessage::SetEncodings(vec![0; MAX_ITEMS + 1]).to_bytes(), Err(Error::Unwritable));
        let most = ClientMessage::SetEncodings(vec![0; MAX_ITEMS]);
        let b = most.to_bytes().unwrap();
        assert_eq!(ClientMessage::parse(&b), Ok(Some((most, b.len()))));
        let colors = |n| ServerMessage::SetColorMapEntries { first: 0, colors: vec![Color { red: 1, green: 1, blue: 1 }; n] };
        assert_eq!(colors(MAX_ITEMS + 1).to_bytes(Dialect::V3_8, &f), Err(Error::Unwritable));
        let b = colors(MAX_ITEMS).to_bytes(Dialect::V3_8, &f).unwrap();
        assert_eq!(ServerMessage::parse(&b, &f), Ok(Some((colors(MAX_ITEMS), b.len()))));
        let name = ServerMessage::ServerInit(ServerInit { width: 1, height: 1, format: f, name: vec![0; MAX_TEXT + 1] });
        assert_eq!(name.to_bytes(Dialect::V3_8, &f), Err(Error::TooLong));
        for long in [
            ServerMessage::ServerCutText(vec![0; MAX_TEXT + 1]),
            ServerMessage::SecurityFailure(vec![0; MAX_TEXT + 1]),
            ServerMessage::SecurityFailed(vec![0; MAX_TEXT + 1]),
        ] {
            assert_eq!(long.to_bytes(Dialect::V3_8, &f), Err(Error::TooLong));
        }
    }

    #[test]
    fn handshake_truncated_prefixes() {
        // Every prefix of a whole 3.8 VNC Authentication conversation, as
        // the server reads it, gives the same messages as far as it goes.
        let mut stream = b"RFB 003.008\n".to_vec();
        stream.push(2);
        stream.extend_from_slice(&[9; 16]);
        stream.push(1);
        stream.extend_from_slice(&ClientMessage::KeyEvent { down: true, key: 65 }.to_bytes().unwrap());
        let whole = drive_server(true, [&stream[..]]);
        assert_eq!(whole.len(), 5);
        assert!(whole.iter().all(|m| m.is_ok()));
        for n in 0..stream.len() {
            let part = drive_server(true, [&stream[..n]]);
            assert_eq!(part[..], whole[..part.len()], "{n} bytes");
            assert!(part.len() < whole.len());
        }
        // And as the client reads the server.
        let mut stream = b"RFB 003.008\n".to_vec();
        stream.extend_from_slice(&[2, 1, 2]);
        stream.extend_from_slice(&[3; 16]);
        stream.extend_from_slice(&[0, 0, 0, 0]);
        stream.extend_from_slice(&[0, 1, 0, 1]);
        stream.extend_from_slice(&PixelFormat::TRUE_COLOR_32.to_bytes());
        stream.extend_from_slice(&[0, 0, 0, 1, b'n', 2]);
        let whole = drive_client(Version::V3_8, true, [&stream[..]]);
        assert_eq!(whole.len(), 6, "{whole:?}");
        for n in 0..stream.len() {
            let part = drive_client(Version::V3_8, true, [&stream[..n]]);
            assert_eq!(part[..], whole[..part.len()], "{n} bytes");
            assert!(part.len() < whole.len());
        }
    }

    #[test]
    fn many_rectangles_byte_at_a_time_is_fast() {
        let rects = vec![Rectangle { x: 0, y: 0, width: 1, height: 1, contents: Contents::Raw(vec![1, 2, 3, 4]) }; MAX_ITEMS];
        let bytes = ServerMessage::FramebufferUpdate(rects).to_bytes(Dialect::V3_8, &PixelFormat::TRUE_COLOR_32).unwrap();
        let started = std::time::Instant::now();
        let (_, mut c) = converse(Version::V3_8, ServerMessage::SecurityTypes(vec![1]), Some(1), Some(ServerMessage::SecurityOk));
        let mut got = 0;
        for b in &bytes {
            c.feed(std::slice::from_ref(b));
            while let Some(m) = c.next_message() {
                m.unwrap();
                got += 1;
            }
        }
        assert_eq!(got, 1);
        assert_eq!(c.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn many_small_messages_in_linear_time() {
        let one = ClientMessage::PointerEvent { buttons: 0, x: 1, y: 1 }.to_bytes().unwrap();
        let stream: Vec<u8> = one.iter().copied().cycle().take(one.len() * 200_000).collect();
        let started = std::time::Instant::now();
        let (mut s, _) = converse(Version::V3_8, ServerMessage::SecurityTypes(vec![1]), Some(1), Some(ServerMessage::SecurityOk));
        s.feed(&stream);
        let mut n = 0;
        while let Some(m) = s.next_message() {
            m.unwrap();
            n += 1;
        }
        assert_eq!(n, 200_000);
        assert_eq!(s.buffered(), 0);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    /// A server and a client past the handshake, with a 1024 by 768
    /// framebuffer.
    fn normal_pair() -> (ServerSession, ClientSession) {
        converse(Version::V3_8, ServerMessage::SecurityTypes(vec![1]), Some(1), Some(ServerMessage::SecurityOk))
    }

    /// Passes a client message to the server through bytes.
    fn client_says(s: &mut ServerSession, c: &mut ClientSession, m: ClientMessage) {
        s.feed(&c.send(&m).unwrap());
        assert_eq!(s.next_message(), Some(Ok(m)));
    }

    /// Passes a server message to the client through bytes.
    fn server_says(s: &mut ServerSession, c: &mut ClientSession, m: ServerMessage) {
        c.feed(&s.send(&m).unwrap());
        assert_eq!(c.next_message(), Some(Ok(m)));
    }

    #[test]
    fn feed_bounds_bytes_in_turn() {
        // A world that feeds in its peer's turn and never takes a message
        // out still holds no more than MAX_BUFFERED bytes.
        let (_, mut c) = normal_pair();
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..MAX_BUFFERED / chunk.len() {
            c.feed(&chunk);
        }
        assert_eq!(c.buffered(), MAX_BUFFERED);
        c.feed(&[0]);
        assert_eq!(c.buffered(), 0);
        assert_eq!(c.next_message(), Some(Err(Error::TooLong)));
        // One feed past the limit is refused before it is copied.
        let (mut s, _) = normal_pair();
        s.feed(&vec![0; MAX_BUFFERED + 1]);
        assert_eq!(s.buffered(), 0);
        assert_eq!(s.next_message(), Some(Err(Error::TooLong)));
        // And so is one feed past MAX_PENDING before the peer's turn.
        let mut s = ServerSession::new();
        s.feed(&vec![0; MAX_PENDING + 1]);
        assert_eq!(s.buffered(), 0);
        assert_eq!(s.next_message(), Some(Err(Error::OutOfTurn)));
    }

    #[test]
    fn sends_between_feeds_keep_update_progress() {
        // A client that sends pointer events while an update comes in does
        // not read the update's rectangles over again.
        let rects = vec![Rectangle { x: 0, y: 0, width: 1, height: 1, contents: Contents::Raw(vec![1, 2, 3, 4]) }; MAX_ITEMS];
        let bytes = ServerMessage::FramebufferUpdate(rects).to_bytes(Dialect::V3_8, &PixelFormat::TRUE_COLOR_32).unwrap();
        let (_, mut c) = normal_pair();
        let started = std::time::Instant::now();
        c.feed(&bytes[..4]);
        let mut got = 0;
        for r in bytes[4..].chunks(16) {
            c.feed(r);
            match c.next_message() {
                Some(m) => {
                    m.unwrap();
                    got += 1;
                }
                None => {
                    c.send(&ClientMessage::PointerEvent { buttons: 0, x: 1, y: 1 }).unwrap();
                }
            }
        }
        assert_eq!(got, 1);
        assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
    }

    #[test]
    fn pixel_format_waits_for_outstanding_updates() {
        // The RFB Protocol, section 7.4.1.
        let f8 = PixelFormat {
            bits_per_pixel: 8,
            depth: 8,
            big_endian: false,
            true_color: true,
            red_max: 7,
            green_max: 7,
            blue_max: 3,
            red_shift: 0,
            green_shift: 3,
            blue_shift: 6,
        };
        let update = [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        // An update half read keeps its format.
        let (_, mut c) = normal_pair();
        c.feed(&update[..18]);
        assert_eq!(c.next_message(), None);
        assert_eq!(c.send(&ClientMessage::SetPixelFormat(f8)), Err(Error::Outstanding));
        assert_eq!(c.pixel_format(), PixelFormat::TRUE_COLOR_32);
        c.feed(&update[18..]);
        let Some(Ok(ServerMessage::FramebufferUpdate(r))) = c.next_message() else { panic!() };
        assert_eq!(r[0].contents, Contents::Raw(vec![0xaa, 0xbb, 0xcc, 0xdd]));
        assert_eq!(c.send(&ClientMessage::SetPixelFormat(f8)).map(|b| b.len()), Ok(20));
        // So does an update whose first byte alone has come.
        let (_, mut c) = normal_pair();
        c.feed(&update[..1]);
        assert_eq!(c.next_message(), None);
        assert_eq!(c.send(&ClientMessage::SetPixelFormat(f8)), Err(Error::Outstanding));
        // An outstanding request waits for its update.
        let (_, mut c) = normal_pair();
        c.send(&ClientMessage::FramebufferUpdateRequest { incremental: true, x: 0, y: 0, width: 1, height: 1 }).unwrap();
        assert_eq!(c.send(&ClientMessage::SetPixelFormat(f8)), Err(Error::Outstanding));
        c.feed(&update);
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::SetPixelFormat(f8)).unwrap();
        assert_eq!(c.pixel_format(), f8);
        c.feed(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0x5a]);
        let Some(Ok(ServerMessage::FramebufferUpdate(r))) = c.next_message() else { panic!() };
        assert_eq!(r[0].contents, Contents::Raw(vec![0x5a]));
    }

    #[test]
    fn invalid_pixel_formats_are_refused() {
        // RFC 6143, section 7.4.
        let bad = PixelFormat { bits_per_pixel: 8, depth: 24, red_max: 250, red_shift: 255, ..PixelFormat::TRUE_COLOR_32 };
        let mut b = vec![client_type::SET_PIXEL_FORMAT, 0, 0, 0];
        b.extend_from_slice(&bad.to_bytes());
        assert_eq!(ClientMessage::parse(&b), Err(Error::PixelFormat));
        assert_eq!(ClientMessage::SetPixelFormat(bad).to_bytes(), Err(Error::PixelFormat));
        let (mut s, mut c) = normal_pair();
        assert_eq!(c.send(&ClientMessage::SetPixelFormat(bad)), Err(Error::PixelFormat));
        assert_eq!(c.pixel_format(), PixelFormat::TRUE_COLOR_32);
        s.feed(&b);
        assert_eq!(s.next_message(), Some(Err(Error::PixelFormat)));
        // A ServerInit in 24 bits per pixel is refused before the first
        // update, on both sides.
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.003\n");
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_3)).unwrap();
        c.feed(&[0, 0, 0, 1]);
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::ClientInit { shared: true }).unwrap();
        let f24 = PixelFormat { bits_per_pixel: 24, ..PixelFormat::TRUE_COLOR_32 };
        let init = ServerMessage::ServerInit(ServerInit { width: 1, height: 1, format: f24, name: vec![] });
        assert_eq!(init.to_bytes(Dialect::V3_3, &f24), Err(Error::PixelFormat));
        let mut bytes = vec![0, 1, 0, 1];
        bytes.extend_from_slice(&f24.to_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        c.feed(&bytes);
        assert_eq!(c.next_message(), Some(Err(Error::PixelFormat)));
    }

    #[test]
    fn rectangles_stay_inside_the_framebuffer() {
        let f = PixelFormat::TRUE_COLOR_32;
        let (mut s, mut c) = converse(Version::V3_3, ServerMessage::SecurityType(1), None, None);
        client_says(&mut s, &mut c, ClientMessage::SetEncodings(vec![encoding::COPY_RECT, encoding::DESKTOP_SIZE]));
        let update = |rects| ServerMessage::FramebufferUpdate(rects);
        let rect = |x, y, width, height, contents| Rectangle { x, y, width, height, contents };
        let request = ClientMessage::FramebufferUpdateRequest { incremental: true, x: 0, y: 0, width: 1024, height: 768 };
        client_says(&mut s, &mut c, request.clone());
        for bad in [
            update(vec![rect(1024, 0, 1, 1, Contents::Raw(vec![0; 4]))]),
            update(vec![rect(0, 700, 1, 69, Contents::Raw(vec![0; 69 * 4]))]),
            update(vec![rect(u16::MAX, 0, 2, 0, Contents::Raw(vec![]))]),
            update(vec![rect(0, 0, 10, 10, Contents::CopyRect { src_x: 1020, src_y: 0 })]),
        ] {
            assert_eq!(s.send(&bad), Err(Error::Rectangle), "{bad:?}");
            let mut c2 = c.clone();
            c2.feed(&bad.to_bytes(Dialect::V3_8, &f).unwrap());
            assert_eq!(c2.next_message(), Some(Err(Error::Rectangle)), "{bad:?}");
        }
        // The edges are inside, and the cursor's hot spot is not checked.
        let good = update(vec![
            rect(1023, 767, 1, 1, Contents::Raw(vec![0; 4])),
            rect(1024, 768, 0, 0, Contents::Raw(vec![])),
            rect(0, 0, 24, 8, Contents::CopyRect { src_x: 1000, src_y: 760 }),
        ]);
        c.feed(&s.send(&good).unwrap());
        assert_eq!(c.next_message(), Some(Ok(good)));
        // DesktopSize shrinks the framebuffer for the updates after it.
        client_says(&mut s, &mut c, request);
        let shrink = update(vec![rect(1000, 0, 8, 8, Contents::Raw(vec![0; 256])), rect(0, 0, 640, 480, Contents::DesktopSize)]);
        c.feed(&s.send(&shrink).unwrap());
        assert_eq!(c.next_message(), Some(Ok(shrink)));
        client_says(&mut s, &mut c, ClientMessage::FramebufferUpdateRequest { incremental: true, x: 0, y: 0, width: 1, height: 1 });
        let past = update(vec![rect(640, 0, 1, 1, Contents::Raw(vec![0; 4]))]);
        assert_eq!(s.send(&past), Err(Error::Rectangle));
        c.feed(&past.to_bytes(Dialect::V3_8, &f).unwrap());
        assert_eq!(c.next_message(), Some(Err(Error::Rectangle)));
    }

    #[test]
    fn desktop_size_comes_last() {
        // RFC 6143, section 7.8.2.
        let f = PixelFormat::TRUE_COLOR_32;
        let early = vec![
            Rectangle { x: 0, y: 0, width: 800, height: 600, contents: Contents::DesktopSize },
            Rectangle { x: 0, y: 0, width: 1, height: 1, contents: Contents::Raw(vec![0; 4]) },
        ];
        assert_eq!(ServerMessage::FramebufferUpdate(early.clone()).to_bytes(Dialect::V3_8, &f), Err(Error::Rectangle));
        let late: Vec<Rectangle> = early.into_iter().rev().collect();
        let b = ServerMessage::FramebufferUpdate(late.clone()).to_bytes(Dialect::V3_8, &f).unwrap();
        assert_eq!(ServerMessage::parse(&b, &f), Ok(Some((ServerMessage::FramebufferUpdate(late), b.len()))));
        // The same bytes with the rectangles swapped do not read.
        let mut swapped = b[..4].to_vec();
        swapped.extend_from_slice(&b[4 + 16..]);
        swapped.extend_from_slice(&b[4..4 + 16]);
        assert_eq!(ServerMessage::parse(&swapped, &f), Err(Error::Rectangle));
    }

    #[test]
    fn server_sends_only_what_the_client_asked_for() {
        // RFC 6143, sections 7.5.2, 7.6.1 and 7.6.2, and The RFB Protocol,
        // section 7.5.3, on CopyRect.
        let (mut s, mut c) = normal_pair();
        let raw = ServerMessage::FramebufferUpdate(vec![Rectangle { x: 0, y: 0, width: 1, height: 1, contents: Contents::Raw(vec![0; 4]) }]);
        let copy = ServerMessage::FramebufferUpdate(vec![Rectangle { x: 0, y: 0, width: 1, height: 1, contents: Contents::CopyRect { src_x: 1, src_y: 1 } }]);
        let cursor = ServerMessage::FramebufferUpdate(vec![Rectangle {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            contents: Contents::Cursor { pixels: vec![0; 4], mask: vec![0x80] },
        }]);
        let resize = ServerMessage::FramebufferUpdate(vec![Rectangle { x: 0, y: 0, width: 640, height: 480, contents: Contents::DesktopSize }]);
        // No request yet.
        assert_eq!(s.send(&raw), Err(Error::NotRequested));
        assert_eq!(s.send(&ServerMessage::FramebufferUpdate(vec![])), Err(Error::NotRequested));
        let full = ClientMessage::FramebufferUpdateRequest { incremental: false, x: 0, y: 0, width: 1024, height: 768 };
        let incremental = ClientMessage::FramebufferUpdateRequest { incremental: true, x: 0, y: 0, width: 1024, height: 768 };
        client_says(&mut s, &mut c, full.clone());
        // Encodings the client did not list.
        for m in [&copy, &cursor, &resize] {
            assert_eq!(s.send(m), Err(Error::NotRequested), "{m:?}");
        }
        client_says(&mut s, &mut c, ClientMessage::SetEncodings(vec![encoding::COPY_RECT, encoding::CURSOR, encoding::DESKTOP_SIZE]));
        // Listed, but a request that was not incremental rules out CopyRect.
        assert_eq!(s.send(&copy), Err(Error::NotRequested));
        server_says(&mut s, &mut c, cursor);
        // That update answered the request.
        assert_eq!(s.send(&raw), Err(Error::NotRequested));
        client_says(&mut s, &mut c, incremental.clone());
        client_says(&mut s, &mut c, incremental);
        server_says(&mut s, &mut c, copy);
        assert_eq!(s.send(&raw), Err(Error::NotRequested));
        client_says(&mut s, &mut c, full);
        server_says(&mut s, &mut c, resize);
        // Color map entries only for a color map format.
        let colors = ServerMessage::SetColorMapEntries { first: 0, colors: vec![Color { red: 1, green: 2, blue: 3 }] };
        assert_eq!(s.send(&colors), Err(Error::NotRequested));
        let map = PixelFormat { bits_per_pixel: 8, depth: 8, true_color: false, ..PixelFormat::TRUE_COLOR_32 };
        client_says(&mut s, &mut c, ClientMessage::SetPixelFormat(map));
        server_says(&mut s, &mut c, colors);
        // Bell and cut text need no request.
        server_says(&mut s, &mut c, ServerMessage::Bell);
        server_says(&mut s, &mut c, ServerMessage::ServerCutText(b"x".to_vec()));
    }

    #[test]
    fn security_type_zero_is_refused() {
        // RFC 6143, section 7.1.2: 0 is Invalid.
        let mut s = ServerSession::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        s.feed(b"RFB 003.008\n");
        s.next_message().unwrap().unwrap();
        assert_eq!(s.send(&ServerMessage::SecurityTypes(vec![0])), Err(Error::Unwritable));
        assert_eq!(s.send(&ServerMessage::SecurityTypes(vec![1, 0])), Err(Error::Unwritable));
        assert_eq!(s.phase(), Phase::SecurityOffer);
        // A client world cannot pick 0, even from a peer that offered it.
        let mut c = ClientSession::new();
        c.feed(b"RFB 003.008\n");
        c.next_message().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        c.feed(&[2, 0, 1]);
        assert_eq!(c.next_message(), Some(Ok(ServerMessage::SecurityTypes(vec![0, 1]))));
        assert_eq!(c.send(&ClientMessage::SecurityType(0)), Err(Error::Unwritable));
        assert_eq!(c.phase(), Phase::SecurityChoice);
        assert_eq!(c.send(&ClientMessage::SecurityType(1)), Ok(vec![1]));
    }

    /// A stream that starts with some of a valid handshake and goes on at
    /// random.
    fn random_stream(rng: &mut Lcg, prefixes: &[Vec<u8>]) -> Vec<u8> {
        let mut b = prefixes[rng.below(prefixes.len() as u64) as usize].clone();
        let n = rng.below(80) as usize;
        b.extend(rng.bytes(n));
        b
    }

    #[test]
    fn lcg_fuzz_sessions() {
        let mut rng = Lcg(0x5900);
        // What a client might send a server, to get it past the handshake.
        let mut to_server: Vec<Vec<u8>> = vec![vec![], b"RFB 003.008\n".to_vec(), b"RFB 003.003\n".to_vec()];
        to_server.push([&b"RFB 003.008\n"[..], &[1, 1]].concat());
        to_server.push([&b"RFB 003.007\n"[..], &[2], &[0; 16], &[0]].concat());
        to_server.push([&b"RFB 003.003\n"[..], &[0; 16], &[1]].concat());
        // What a server might send a client.
        let init = [&[0u8, 2, 0, 2][..], &PixelFormat::TRUE_COLOR_32.to_bytes(), &[0, 0, 0, 0]].concat();
        let mut to_client: Vec<Vec<u8>> = vec![vec![], b"RFB 003.008\n".to_vec()];
        to_client.push([&b"RFB 003.008\n"[..], &[1, 1], &[0; 4], &init].concat());
        to_client.push([&b"RFB 003.008\n"[..], &[0, 0, 0, 1], &init].concat());
        to_client.push([&b"RFB 003.008\n"[..], &[1, 2], &[0; 16], &[0; 4], &init].concat());
        let versions = [Version::V3_3, Version::V3_7, Version::V3_8];
        let mut normal = 0;
        for i in 0..4000 {
            let vnc = i % 2 == 0;
            let data = random_stream(&mut rng, &to_server);
            let whole = drive_server(vnc, [&data[..]]);
            let bytewise = drive_server(vnc, data.chunks(1));
            assert_eq!(whole, bytewise, "{data:?}");
            for m in whole.iter().flatten() {
                if !m.is_handshake() {
                    normal += 1;
                    let b = m.to_bytes().unwrap();
                    assert_eq!(ClientMessage::parse(&b), Ok(Some((m.clone(), b.len()))));
                }
            }
            let version = versions[i % 3];
            let data = random_stream(&mut rng, &to_client);
            let whole = drive_client(version, vnc, [&data[..]]);
            let bytewise = drive_client(version, vnc, data.chunks(1));
            assert_eq!(whole, bytewise, "{data:?}");
            normal += whole.iter().flatten().filter(|m| !m.is_handshake()).count();
            // Any bytes, read on their own.
            let len = rng.below(64) as usize;
            let raw = rng.bytes(len);
            let _ = Version::parse(&raw);
            if let Ok(Some((m, _))) = ClientMessage::parse(&raw) {
                assert_eq!(ClientMessage::parse(&m.to_bytes().unwrap()).unwrap().unwrap().0, m);
            }
            let mut f = PixelFormat::TRUE_COLOR_32;
            f.bits_per_pixel = [8, 16, 32, 24][i % 4];
            if let Ok(Some((m, _))) = ServerMessage::parse(&raw, &f) {
                let b = m.to_bytes(Dialect::V3_8, &f).unwrap();
                assert_eq!(ServerMessage::parse(&b, &f).unwrap().unwrap().0, m);
            }
        }
        // The loop reached past the handshake often.
        assert!(normal > 500, "{normal}");
    }

    #[test]
    fn lcg_fuzz_written_messages_read_back() {
        let mut rng = Lcg(6143);
        for _ in 0..3000 {
            let m = match rng.below(6) {
                0 => ClientMessage::SetEncodings((0..rng.below(20)).map(|_| rng.next() as i32).collect()),
                1 => ClientMessage::KeyEvent { down: rng.below(2) == 0, key: rng.next() as u32 },
                2 => ClientMessage::PointerEvent { buttons: rng.byte(), x: rng.next() as u16, y: rng.next() as u16 },
                3 => {
                    let len = rng.below(50) as usize;
                    ClientMessage::ClientCutText(rng.bytes(len))
                }
                4 => ClientMessage::SetPixelFormat(PixelFormat::parse(&rng.bytes(16).try_into().unwrap())),
                _ => ClientMessage::FramebufferUpdateRequest {
                    incremental: rng.below(2) == 0,
                    x: rng.next() as u16,
                    y: rng.next() as u16,
                    width: rng.next() as u16,
                    height: rng.next() as u16,
                },
            };
            match m {
                ClientMessage::SetPixelFormat(f) if !f.is_valid() => {
                    assert_eq!(m.to_bytes(), Err(Error::PixelFormat));
                    let mut b = vec![client_type::SET_PIXEL_FORMAT, 0, 0, 0];
                    b.extend_from_slice(&f.to_bytes());
                    assert_eq!(ClientMessage::parse(&b), Err(Error::PixelFormat));
                }
                _ => {
                    let b = m.to_bytes().unwrap();
                    assert_eq!(ClientMessage::parse(&b), Ok(Some((m, b.len()))));
                }
            }
            let f = [PixelFormat { bits_per_pixel: 8, ..PixelFormat::TRUE_COLOR_32 }, PixelFormat::TRUE_COLOR_32][rng.below(2) as usize];
            let bpp = f.bytes_per_pixel().unwrap();
            let count = rng.below(4);
            let rects = (0..count)
                .map(|i| {
                    let (width, height) = (rng.below(9) as u16, rng.below(9) as u16);
                    let n = usize::from(width) * usize::from(height);
                    // DesktopSize only as the last rectangle.
                    let kinds = if i + 1 == count { 4 } else { 3 };
                    let contents = match rng.below(kinds) {
                        0 => Contents::Raw(rng.bytes(n * bpp)),
                        1 => Contents::CopyRect { src_x: rng.next() as u16, src_y: rng.next() as u16 },
                        2 => Contents::Cursor {
                            pixels: rng.bytes(n * bpp),
                            mask: rng.bytes(usize::from(width).div_ceil(8) * usize::from(height)),
                        },
                        _ => Contents::DesktopSize,
                    };
                    Rectangle { x: rng.next() as u16, y: rng.next() as u16, width, height, contents }
                })
                .collect();
            let m = ServerMessage::FramebufferUpdate(rects);
            let b = m.to_bytes(Dialect::V3_8, &f).unwrap();
            assert_eq!(ServerMessage::parse(&b, &f), Ok(Some((m, b.len()))));
        }
    }
}
