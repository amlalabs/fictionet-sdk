//! RFB, the remote framebuffer protocol behind VNC: the handshake and the
//! messages, read and written with no I/O.
//!
//! Complete wire values, directional decoders, and caller-driven `Client` and
//! `Server` sessions cover the handshake and supported framebuffer messages.
//! Updates support Raw, CopyRect, Cursor, and DesktopSize only. There is no DES
//! authentication computation, encrypted transport, or VNC `Service`.
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
//! A world that plays a server keeps a [`Server`] session. It pushes bytes
//! from a [`tcp`](fictionet::stdlib::tcp) connection, takes [`ClientMessage`]s out, and
//! answers with [`ServerMessage`]s. A client uses [`Client`]. Each session
//! tracks both directions, since the next peer unit depends on what was
//! sent. The byte layers are [`Stream<ClientMessages>`](fictionet::stdlib::codec::Stream)
//! and [`Stream<ServerMessages>`](fictionet::stdlib::codec::Stream). A [`Service`](fictionet::stdlib::serve::Service) served by
//! [`serve::connection`](fictionet::stdlib::serve::connection) can instead use [`ClientMessages`] directly,
//! calling `driver.decoder().set_phase()` in `on_item` as the handshake advances. Unsupported security and closed sessions preserve the unread
//! suffix for `into_parts` or `swap`.
//!
//! The module carries the VNC Authentication challenge and response but
//! does not compute them, since that needs DES. A world that wants to
//! check a password does that itself. Other security types are reported:
//! the session moves to [`Phase::Unsupported`] and reads no further.
//! Framebuffer updates are read for the Raw and CopyRect encodings and for
//! the Cursor and DesktopSize pseudo-encodings. Other encodings cannot be
//! split from the stream without decoding them, so they stop the session
//! with [`FrameError::Encoding`].
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
//! use fictionet::stdlib::rfb::{ClientMessage, PixelFormat, ServerInit, ServerMessage, Server, Version};
//!
//! let mut server = Server::new();
//! assert_eq!(server.send(&ServerMessage::Version(Version::V3_8)).unwrap(), b"RFB 003.008\n");
//! let _ = server.push(b"RFB 003.008\n");
//! assert_eq!(server.next(), Some(Ok(Ok(ClientMessage::Version(Version::V3_8)))));
//! // Offer one security type, None, and let the client in.
//! assert_eq!(server.send(&ServerMessage::SecurityTypes(vec![1])).unwrap(), [1, 1]);
//! let _ = server.push(&[1]);
//! assert_eq!(server.next(), Some(Ok(Ok(ClientMessage::SecurityType(1)))));
//! assert_eq!(server.send(&ServerMessage::SecurityOk).unwrap(), [0, 0, 0, 0]);
//! // ClientInit: the client is happy to share the desktop.
//! let _ = server.push(&[1]);
//! assert_eq!(server.next(), Some(Ok(Ok(ClientMessage::ClientInit { shared: true }))));
//! let init = ServerInit { width: 640, height: 480, format: PixelFormat::TRUE_COLOR_32, name: b"tank".to_vec() };
//! assert_eq!(server.send(&ServerMessage::ServerInit(init)).unwrap().len(), 2 + 2 + 16 + 4 + 4);
//! // The client asks for the whole screen.
//! let _ = server.push(&[3, 0, 0, 0, 0, 0, 0x02, 0x80, 0x01, 0xe0]);
//! assert_eq!(
//!     server.next(),
//!     Some(Ok(Ok(ClientMessage::FramebufferUpdateRequest { incremental: false, x: 0, y: 0, width: 640, height: 480 })))
//! );
//! ```

use fictionet::stdlib::codec::{self, Decode, Reader, Step, Stream, Wire, be16, be32};

fn exact<T>(parsed: Result<Option<(T, usize)>, Error>, len: usize) -> Result<T, Error> {
    let (value, used) = parsed?.ok_or(Error::Truncated)?;
    if used != len {
        return Err(Error::Trailing);
    }
    Ok(value)
}

impl Wire for Version {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one version line. Refuses non-digits, an invalid prefix or ending,
    /// incomplete input and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(Version::parse_prefix(bytes), bytes.len())
    }
    /// Refuses version parts above 999. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.writable() {
            return Err(Error::Unwritable);
        }
        let mut bytes = *b"RFB 000.000\n";
        for (at, n) in [(4, self.major), (8, self.minor)] {
            bytes[at] = b'0' + (n / 100) as u8;
            bytes[at + 1] = b'0' + (n / 10 % 10) as u8;
            bytes[at + 2] = b'0' + (n % 10) as u8;
        }
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for PixelFormat {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads a pixel format. Nonzero flags mean true; padding is ignored.
    /// Refuses incomplete or trailing bytes and invalid pixel formats.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let raw: &[u8; PIXEL_FORMAT_LEN] = bytes.try_into().map_err(|_| {
            if bytes.len() < PIXEL_FORMAT_LEN {
                Error::Truncated
            } else {
                Error::Trailing
            }
        })?;
        let format = PixelFormat::read(raw);
        if !format.is_valid() {
            return Err(Error::PixelFormat);
        }
        Ok(format)
    }
    /// Refuses formats that RFC 6143 section 7.4 does not allow.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.is_valid() {
            return Err(Error::PixelFormat);
        }
        let mut bytes = [0u8; PIXEL_FORMAT_LEN];
        bytes[0] = self.bits_per_pixel;
        bytes[1] = self.depth;
        bytes[2] = u8::from(self.big_endian);
        bytes[3] = u8::from(self.true_color);
        bytes[4..6].copy_from_slice(&self.red_max.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.green_max.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.blue_max.to_be_bytes());
        bytes[10] = self.red_shift;
        bytes[11] = self.green_shift;
        bytes[12] = self.blue_shift;
        out.extend_from_slice(&bytes);
        Ok(())
    }
}

impl Wire for ServerInit {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one ServerInit. Refuses invalid pixel formats, names longer
    /// than `MAX_TEXT`, incomplete input and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let state = State {
            phase: Phase::ServerInit,
            ..State::new()
        };
        let message = exact(run(bytes, |c| state.server_at(c)), bytes.len())?;
        match message {
            ServerMessage::ServerInit(init) => Ok(init),
            _ => Err(Error::Unwritable),
        }
    }
    /// Refuses invalid pixel formats and names longer than `MAX_TEXT`.
    /// Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.format.is_valid() {
            return Err(Error::PixelFormat);
        }
        if self.name.len() > MAX_TEXT {
            return Err(Error::TooLong);
        }
        out.extend_from_slice(&self.width.to_be_bytes());
        out.extend_from_slice(&self.height.to_be_bytes());
        self.format.write(out)?;
        Text::new(&self.name).write(out)
    }
}

impl Wire for ClientMessage {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads exactly one normal client message. Handshake units require
    /// a phase and use [`ClientMessages`]; they have no shared wire tag.
    /// Refuses unknown tags, invalid pixel formats, oversized text,
    /// incomplete input and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(ClientMessage::parse_prefix(bytes), bytes.len())
    }

    /// Appends one normal client message. Refuses handshake variants,
    /// invalid pixel formats, more than [`MAX_ITEMS`] encodings and text
    /// longer than [`MAX_TEXT`]. Leaves the destination unchanged on error.
    fn write(&self, dest: &mut Vec<u8>) -> Result<(), Error> {
        let mut out = Vec::new();
        match self {
            ClientMessage::Version(_)
            | ClientMessage::SecurityType(_)
            | ClientMessage::VncResponse(_)
            | ClientMessage::ClientInit { .. } => return Err(Error::Unwritable),
            ClientMessage::SetPixelFormat(f) => {
                if !f.is_valid() {
                    return Err(Error::PixelFormat);
                }
                out.extend_from_slice(&[client_type::SET_PIXEL_FORMAT, 0, 0, 0]);
                f.write(&mut out)?;
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
            ClientMessage::FramebufferUpdateRequest {
                incremental,
                x,
                y,
                width,
                height,
            } => {
                out.extend_from_slice(&[
                    client_type::FRAMEBUFFER_UPDATE_REQUEST,
                    u8::from(*incremental),
                ]);
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
                Text::new(text).write(&mut out)?;
            }
        }
        dest.extend_from_slice(&out);
        Ok(())
    }
}

impl ServerMessage {
    /// Appends a message in `dialect` with pixels in `format`. Refuses
    /// security offers in the wrong dialect, empty lists, type zero,
    /// failure reasons before 3.8, invalid versions or pixel formats,
    /// oversized text or lists, mismatched pixel data and DesktopSize
    /// rectangles before the last rectangle. Leaves `dest` unchanged on error.
    pub fn write(
        &self,
        dialect: Dialect,
        format: &PixelFormat,
        dest: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let mut out = Vec::new();
        match self {
            ServerMessage::Version(v) => v.write(&mut out)?,
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
                Text::new(reason).write(&mut out)?;
            }
            ServerMessage::VncChallenge(c) => out.extend_from_slice(c),
            ServerMessage::SecurityOk => out.extend_from_slice(&[0, 0, 0, 0]),
            ServerMessage::SecurityFailed(reason) => {
                out.extend_from_slice(&[0, 0, 0, 1]);
                if dialect == Dialect::V3_8 {
                    Text::new(reason).write(&mut out)?;
                } else if !reason.is_empty() {
                    return Err(Error::Unwritable);
                }
            }
            ServerMessage::ServerInit(init) => init.write(&mut out)?,
            ServerMessage::FramebufferUpdate(rects) => {
                if rects.len() > MAX_ITEMS {
                    return Err(Error::Unwritable);
                }
                if rects
                    .iter()
                    .rev()
                    .skip(1)
                    .any(|r| r.contents == Contents::DesktopSize)
                {
                    return Err(Error::Rectangle);
                }
                let mut total = 4usize;
                for r in rects {
                    let body = match &r.contents {
                        Contents::Raw(pixels) => {
                            if pixels.len() != pixels_len(r.width, r.height, format)? {
                                return Err(Error::Unwritable);
                            }
                            pixels.len()
                        }
                        Contents::CopyRect { .. } => 4,
                        Contents::Cursor { pixels, mask } => {
                            if pixels.len() != pixels_len(r.width, r.height, format)?
                                || mask.len() != mask_len(r.width, r.height)?
                            {
                                return Err(Error::Unwritable);
                            }
                            pixels.len().checked_add(mask.len()).ok_or(Error::TooLong)?
                        }
                        Contents::DesktopSize => 0,
                    };
                    total = total
                        .checked_add(12)
                        .and_then(|n| n.checked_add(body))
                        .filter(|&n| n <= MAX_MESSAGE)
                        .ok_or(Error::TooLong)?;
                }
                out.try_reserve_exact(total).map_err(|_| Error::TooLong)?;
                out.extend_from_slice(&[server_type::FRAMEBUFFER_UPDATE, 0]);
                out.extend_from_slice(&(rects.len() as u16).to_be_bytes());
                for r in rects {
                    for v in [r.x, r.y, r.width, r.height] {
                        out.extend_from_slice(&v.to_be_bytes());
                    }
                    out.extend_from_slice(&r.contents.encoding().to_be_bytes());
                    match &r.contents {
                        Contents::Raw(pixels) => {
                            out.extend_from_slice(pixels);
                        }
                        Contents::CopyRect { src_x, src_y } => {
                            out.extend_from_slice(&src_x.to_be_bytes());
                            out.extend_from_slice(&src_y.to_be_bytes());
                        }
                        Contents::Cursor { pixels, mask } => {
                            out.extend_from_slice(pixels);
                            out.extend_from_slice(mask);
                        }
                        Contents::DesktopSize => {}
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
                Text::new(text).write(&mut out)?;
            }
        }
        dest.extend_from_slice(&out);
        Ok(())
    }
}

/// A four-byte length followed by RFB text bytes, bounded by [`MAX_TEXT`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Text<'a> {
    /// Text bytes. RFB does not require valid UTF-8.
    pub bytes: std::borrow::Cow<'a, [u8]>,
}
impl<'a> Text<'a> {
    /// Borrows text for a wire value. The writer checks its length.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes: std::borrow::Cow::Borrowed(bytes),
        }
    }
}
impl Wire for Text<'_> {
    type ParseError = Error;
    type WriteError = Error;

    /// Reads one length-prefixed text value. Refuses lengths above
    /// [`MAX_TEXT`], incomplete input and trailing bytes.
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        exact(run(bytes, text), bytes.len()).map(|bytes| Self {
            bytes: std::borrow::Cow::Owned(bytes),
        })
    }

    /// Refuses text longer than [`MAX_TEXT`]. Leaves `out` unchanged on error.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.bytes.len() > MAX_TEXT {
            return Err(Error::TooLong);
        }
        let len = u32::try_from(self.bytes.len()).map_err(|_| Error::TooLong)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(())
    }
}

/// The one-byte client security selection. Zero is carried but cannot be selected by a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityChoice(
    /// The selected security type code.
    pub u8,
);
/// The sixteen-byte VNC Authentication response. DES is supplied by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VncResponse(
    /// The response bytes supplied by the caller's DES implementation.
    pub [u8; CHALLENGE_LEN],
);
/// The client's desktop-sharing preference after authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientInit {
    /// Whether other clients may share the desktop.
    pub shared: bool,
}
macro_rules! fixed_wire {
    ($ty:ty, $len:expr, |$b:ident| $read:expr, |$v:ident, $out:ident| $write:block) => {
        impl Wire for $ty {
            type ParseError = Error;
            type WriteError = Error;
            /// Reads the complete fixed unit. Refuses incomplete and trailing bytes.
            fn parse(bytes: &[u8]) -> Result<Self, Error> {
                let $b: &[u8; $len] = bytes.try_into().map_err(|_| {
                    if bytes.len() < $len { Error::Truncated } else { Error::Trailing }
                })?;
                Ok($read)
            }
            /// Appends the complete fixed unit. Every value fits; no values are refused.
            fn write(&self, $out: &mut Vec<u8>) -> Result<(), Error> {
                let $v = self;
                $write
                Ok(())
            }
        }
    };
}
fixed_wire!(SecurityChoice, 1, |b| Self(b[0]), |v, out| {
    out.push(v.0);
});
fixed_wire!(VncResponse, CHALLENGE_LEN, |b| Self(*b), |v, out| {
    out.extend_from_slice(&v.0);
});
fixed_wire!(ClientInit, 1, |b| Self { shared: b[0] != 0 }, |v, out| {
    out.push(u8::from(v.shared));
});

// Only offsets and counts survive Need. Each rectangle header is scanned
// once; pixel bodies stay in the driver's buffer until the whole item.
#[derive(Clone, Debug, Default)]
struct FrameScan {
    next: usize,
    remaining: Option<usize>,
}

// The version line and pixel lengths are read by the body parsers too,
// which report them as `Error`. Found while framing, they end the stream.
// These readers fail only with Version, BitsPerPixel or TooLong.
fn framing(e: Error) -> FrameError {
    match e {
        Error::Version => FrameError::Version,
        Error::BitsPerPixel(b) => FrameError::BitsPerPixel(b),
        _ => FrameError::TooLong,
    }
}
fn sized_end(at: usize, count: usize, width: usize, limit: usize) -> Result<usize, FrameError> {
    count
        .checked_mul(width)
        .and_then(|n| at.checked_add(n))
        .filter(|&n| n <= limit)
        .ok_or(FrameError::TooLong)
}
fn text_end(b: &[u8], at: usize, limit: usize) -> Result<Option<usize>, FrameError> {
    let header = sized_end(at, 4, 1, limit)?;
    let Some(n) = be32(b, at) else {
        return Ok(None);
    };
    let n = usize::try_from(n).map_err(|_| FrameError::TooLong)?;
    if n > MAX_TEXT {
        return Err(FrameError::TooLong);
    }
    Ok(Some(sized_end(header, n, 1, limit)?))
}
fn counted_end(
    b: &[u8],
    at: usize,
    header: usize,
    width: usize,
    limit: usize,
) -> Result<Option<usize>, FrameError> {
    let Some(n) = be16(b, at) else {
        return Ok(None);
    };
    Ok(Some(sized_end(header, usize::from(n), width, limit)?))
}

fn client_end(b: &[u8], phase: Phase, limit: usize) -> Result<Option<usize>, FrameError> {
    let end = match phase {
        Phase::ClientVersion => {
            Version::parse_prefix(b).map_err(framing)?;
            VERSION_LEN
        }
        Phase::SecurityChoice | Phase::ClientInit => 1,
        Phase::VncResponse => CHALLENGE_LEN,
        Phase::Normal => match b.first() {
            None => return Ok(None),
            Some(&client_type::SET_PIXEL_FORMAT) => 4 + PIXEL_FORMAT_LEN,
            Some(&client_type::SET_ENCODINGS) => return counted_end(b, 2, 4, 4, limit),
            Some(&client_type::FRAMEBUFFER_UPDATE_REQUEST) => 10,
            Some(&client_type::KEY_EVENT) => 8,
            Some(&client_type::POINTER_EVENT) => 6,
            Some(&client_type::CLIENT_CUT_TEXT) => return text_end(b, 4, limit),
            Some(&t) => return Err(FrameError::MessageType(t)),
        },
        p => return Err(FrameError::Phase(p)),
    };
    Ok(Some(sized_end(0, end, 1, limit)?))
}

impl FrameScan {
    fn server_end(
        &mut self,
        b: &[u8],
        phase: Phase,
        dialect: Dialect,
        format: &PixelFormat,
        limit: usize,
    ) -> Result<Option<usize>, FrameError> {
        let end = match phase {
            Phase::ServerVersion => {
                Version::parse_prefix(b).map_err(framing)?;
                VERSION_LEN
            }
            Phase::SecurityOffer => match dialect {
                Dialect::V3_3 => match be32(b, 0) {
                    None => return Ok(None),
                    Some(0) => return text_end(b, 4, limit),
                    Some(_) => 4,
                },
                _ => match b.first() {
                    None => return Ok(None),
                    Some(0) => return text_end(b, 1, limit),
                    Some(&n) => sized_end(1, usize::from(n), 1, limit)?,
                },
            },
            Phase::VncChallenge => CHALLENGE_LEN,
            Phase::SecurityResult => match be32(b, 0) {
                None => return Ok(None),
                Some(0) => 4,
                Some(_) if dialect == Dialect::V3_8 => return text_end(b, 4, limit),
                Some(_) => 4,
            },
            Phase::ServerInit => return text_end(b, 20, limit),
            Phase::Normal => match b.first() {
                None => return Ok(None),
                Some(&server_type::FRAMEBUFFER_UPDATE) => return self.update_end(b, format, limit),
                Some(&server_type::SET_COLOR_MAP_ENTRIES) => return counted_end(b, 4, 6, 6, limit),
                Some(&server_type::BELL) => 1,
                Some(&server_type::SERVER_CUT_TEXT) => return text_end(b, 4, limit),
                Some(&t) => return Err(FrameError::MessageType(t)),
            },
            p => return Err(FrameError::Phase(p)),
        };
        Ok(Some(sized_end(0, end, 1, limit)?))
    }

    fn update_end(
        &mut self,
        b: &[u8],
        format: &PixelFormat,
        limit: usize,
    ) -> Result<Option<usize>, FrameError> {
        if self.remaining.is_none() {
            let Some(n) = be16(b, 2) else { return Ok(None) };
            // Every rectangle needs at least its twelve-byte header.
            sized_end(4, usize::from(n), 12, limit)?;
            self.remaining = Some(usize::from(n));
            self.next = 4;
        }
        while let Some(left) = self.remaining.filter(|&n| n > 0) {
            let at = self.next;
            let header = sized_end(at, 12, 1, limit)?;
            if b.get(..header).is_none() {
                return Ok(None);
            }
            let width = be16(b, sized_end(at, 4, 1, limit)?).ok_or(FrameError::TooLong)?;
            let height = be16(b, sized_end(at, 6, 1, limit)?).ok_or(FrameError::TooLong)?;
            let encoding = be32(b, sized_end(at, 8, 1, limit)?).ok_or(FrameError::TooLong)? as i32;
            let size = match encoding {
                encoding::RAW => pixels_len(width, height, format).map_err(framing)?,
                encoding::COPY_RECT => 4,
                encoding::CURSOR => {
                    let pixels = pixels_len(width, height, format).map_err(framing)?;
                    pixels
                        .checked_add(mask_len(width, height).map_err(framing)?)
                        .ok_or(FrameError::TooLong)?
                }
                encoding::DESKTOP_SIZE => 0,
                other => return Err(FrameError::Encoding(other)),
            };
            self.next = sized_end(header, size, 1, limit)?;
            self.remaining = Some(left - 1);
            // Also reserve the minimum space for all remaining headers.
            sized_end(self.next, left - 1, 12, limit)?;
        }
        Ok(Some(self.next))
    }
}

/// Reads client handshake and normal messages in a chosen phase.
///
/// Use with [`Stream`]. Call [`set_phase`](Self::set_phase) between items;
/// a phase stays selected until changed. `Closed` and `Unsupported` return
/// `End`, leaving the unread suffix for `swap` or `into_parts`. All other
/// phases yield one `Result<ClientMessage, Error>` per complete unit.
/// Malformed bodies are items; unknown framing and limits end the stream
/// with a [`FrameError`].
/// Partial input returns `Need`, including at EOF. No input is retained.
#[derive(Clone, Debug)]
pub struct ClientMessages {
    phase: Phase,
    limit: usize,
    partial: bool,
    out_of_turn: bool,
}
impl ClientMessages {
    /// Starts at the client's version, with [`MAX_CLIENT_MESSAGE`] as the limit.
    pub fn new() -> Self {
        Self::with_limit(MAX_CLIENT_MESSAGE)
    }
    /// Sets the whole-message limit, clamped to 24 through [`MAX_CLIENT_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            phase: Phase::ClientVersion,
            limit: limit.clamp(24, MAX_CLIENT_MESSAGE),
            partial: false,
            out_of_turn: false,
        }
    }
    /// The currently selected phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Selects a phase before decoding or just after an item. Once decoding
    /// returns `Need` with unread bytes, changes (including `Closed`) return
    /// [`Error::PartialUnit`] until that unit completes. A phase in which
    /// only the server can speak returns [`Error::Phase`].
    pub fn set_phase(&mut self, phase: Phase) -> Result<(), Error> {
        if self.partial {
            return Err(Error::PartialUnit);
        }
        if !(phase.client_turn() || matches!(phase, Phase::Closed | Phase::Unsupported(_))) {
            return Err(Error::Phase(phase));
        }
        self.phase = phase;
        Ok(())
    }
}
impl Default for ClientMessages {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for ClientMessages {
    type Item = Result<ClientMessage, Error>;
    type Error = FrameError;
    const NAME: &'static str = "RFB client units";
    fn capacity(&self) -> usize {
        self.limit
    }
    fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Self::Item>, FrameError> {
        if self.out_of_turn {
            return Err(FrameError::OutOfTurn);
        }
        if matches!(self.phase, Phase::Closed | Phase::Unsupported(_)) {
            return Ok(Step::End);
        }
        if b.is_empty() {
            return Ok(Step::Need);
        }
        self.partial = true;
        let Some(used) = client_end(b, self.phase, self.limit)? else {
            return Ok(Step::Need);
        };
        let Some(bytes) = b.get(..used) else {
            return Ok(Step::Need);
        };
        let state = State {
            phase: self.phase,
            ..State::new()
        };
        let item = exact(run(bytes, |c| state.client_at(c)), used);
        self.partial = false;
        Ok(Step::Item(item, used))
    }
}

/// Reads server handshake and normal messages in a chosen mode.
///
/// [`set_phase`](Self::set_phase) supplies the phase, negotiated dialect and
/// pixel format between items. Mode stays selected until changed. `Closed`
/// and `Unsupported` return `End` without consuming the unread suffix.
/// Complete body failures are [`Error`] items; unknown message types, encodings and
/// excessive declared lengths are a terminal [`FrameError`]. EOF inside a unit
/// returns `Need`. A scan cursor makes bytewise framebuffer input linear;
/// all pixel bytes remain in [`Stream`]'s buffer until an item is complete.
#[derive(Clone, Debug)]
pub struct ServerMessages {
    phase: Phase,
    dialect: Dialect,
    format: PixelFormat,
    limit: usize,
    partial: bool,
    out_of_turn: bool,
    scan: FrameScan,
}
impl ServerMessages {
    /// Starts at the server's version, using 3.8 and 32-bit true color.
    pub fn new() -> Self {
        Self::with_limit(MAX_MESSAGE)
    }
    /// Sets the whole-message limit, clamped to 24 through [`MAX_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            phase: Phase::ServerVersion,
            dialect: Dialect::V3_8,
            format: PixelFormat::TRUE_COLOR_32,
            limit: limit.clamp(24, MAX_MESSAGE),
            partial: false,
            out_of_turn: false,
            scan: FrameScan::default(),
        }
    }
    /// The currently selected phase.
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Sets the phase, with the dialect and pixel format, before decoding or just after an item. Once decoding
    /// returns `Need` with unread bytes, changes (including `Closed`) return
    /// [`Error::PartialUnit`] until that unit completes. Invalid pixel formats
    /// and client-only phases return [`Error::PixelFormat`] or [`Error::Phase`].
    pub fn set_phase(
        &mut self,
        phase: Phase,
        dialect: Dialect,
        format: PixelFormat,
    ) -> Result<(), Error> {
        if self.partial {
            return Err(Error::PartialUnit);
        }
        if !(phase.server_turn() || matches!(phase, Phase::Closed | Phase::Unsupported(_))) {
            return Err(Error::Phase(phase));
        }
        if !format.is_valid() {
            return Err(Error::PixelFormat);
        }
        self.phase = phase;
        self.dialect = dialect;
        self.format = format;
        self.scan = FrameScan::default();
        Ok(())
    }
}
impl Default for ServerMessages {
    fn default() -> Self {
        Self::new()
    }
}
impl Decode for ServerMessages {
    type Item = Result<ServerMessage, Error>;
    type Error = FrameError;
    const NAME: &'static str = "RFB server units";
    fn capacity(&self) -> usize {
        self.limit
    }
    fn decode(&mut self, b: &[u8], _: bool) -> Result<Step<Self::Item>, FrameError> {
        if self.out_of_turn {
            return Err(FrameError::OutOfTurn);
        }
        if matches!(self.phase, Phase::Closed | Phase::Unsupported(_)) {
            return Ok(Step::End);
        }
        if b.is_empty() {
            return Ok(Step::Need);
        }
        self.partial = true;
        let Some(used) =
            self.scan
                .server_end(b, self.phase, self.dialect, &self.format, self.limit)?
        else {
            return Ok(Step::Need);
        };
        let Some(bytes) = b.get(..used) else {
            return Ok(Step::Need);
        };
        let state = State {
            phase: self.phase,
            dialect: self.dialect,
            format: self.format,
            ..State::new()
        };
        let item = exact(run(bytes, |c| state.server_at(c)), used);
        self.partial = false;
        self.scan = FrameScan::default();
        Ok(Step::Item(item, used))
    }
}

trait SessionInput: Decode<Error = FrameError, Item = Result<Self::Message, Error>> {
    type Message;
    fn receiving(phase: Phase) -> bool;
    fn sending(phase: Phase) -> bool;
    fn sync(&mut self, state: &State);
    fn out_of_turn(&mut self) -> &mut bool;
    fn step(state: &mut State, message: &Self::Message) -> Result<(), Error>;
}

impl SessionInput for ClientMessages {
    type Message = ClientMessage;
    fn receiving(phase: Phase) -> bool {
        phase.client_turn()
    }
    fn sending(phase: Phase) -> bool {
        phase.server_turn()
    }
    fn sync(&mut self, state: &State) {
        self.phase = state.phase;
    }
    fn out_of_turn(&mut self) -> &mut bool {
        &mut self.out_of_turn
    }
    fn step(state: &mut State, message: &ClientMessage) -> Result<(), Error> {
        state.client_step(message)
    }
}

impl SessionInput for ServerMessages {
    type Message = ServerMessage;
    fn receiving(phase: Phase) -> bool {
        phase.server_turn()
    }
    fn sending(phase: Phase) -> bool {
        phase.client_turn()
    }
    fn sync(&mut self, state: &State) {
        self.phase = state.phase;
        self.dialect = state.dialect;
        self.format = state.format;
    }
    fn out_of_turn(&mut self) -> &mut bool {
        &mut self.out_of_turn
    }
    fn step(state: &mut State, message: &ServerMessage) -> Result<(), Error> {
        state.server_step(message)
    }
}

fn session_push<D: SessionInput>(state: &mut State, input: &mut Stream<D>, bytes: &[u8]) -> usize {
    if input.is_done() {
        return bytes.len();
    }
    if *input.decoder().out_of_turn() {
        return 0;
    }
    if D::sending(state.phase) && state.phase != Phase::Normal {
        let room = MAX_PENDING
            .min(input.decoder().capacity())
            .saturating_sub(input.buffered());
        let accepted = input.push(&bytes[..bytes.len().min(room)]);
        if bytes.len() > room {
            *input.decoder().out_of_turn() = true;
            state.phase = Phase::Closed;
        }
        return accepted;
    }
    input.push(bytes)
}

type SessionItem<T> = Result<Result<T, Error>, codec::Fail<FrameError>>;

fn session_next<D: SessionInput>(
    state: &mut State,
    input: &mut Stream<D>,
) -> Option<SessionItem<D::Message>> {
    if !D::receiving(state.phase) && !matches!(state.phase, Phase::Closed | Phase::Unsupported(_)) {
        return None;
    }
    input.decoder().sync(state);
    let result = input.next()?;
    Some(result.map(|item| {
        let item = item.and_then(|m| {
            D::step(state, &m)?;
            Ok(m)
        });
        if item.is_err() && state.phase != Phase::Normal {
            state.phase = Phase::Closed;
        }
        if D::sending(state.phase) && state.phase != Phase::Normal && input.buffered() > MAX_PENDING
        {
            *input.decoder().out_of_turn() = true;
            state.phase = Phase::Closed;
        }
        item
    }))
}

/// A server session whose client byte layer is a [`Stream<ClientMessages>`].
///
/// This keeps the same two-direction protocol rules as [`Server`].
/// `push` reports accepted bytes; framing errors are returned once. Body
/// and session refusals are items; a handshake refusal also moves to `Closed`.
/// Before the client's turn, input is capped at [`MAX_PENDING`] buffered
/// bytes or the stream's smaller capacity. Pending bytes are also checked
/// when a received unit passes the turn to the server. Any excess closes
/// the session and the next read reports [`FrameError::OutOfTurn`] once, leaving
/// accepted bytes available for inspection.
/// Once `is_done` is true, `push` takes and drops every byte, as [`Stream`]
/// does. `into_stream` exposes unread bytes for handoff after a refusal or
/// unsupported security selection.
pub struct Server {
    state: State,
    input: Stream<ClientMessages>,
}
impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Server")
            .field("state", &self.state)
            .field("buffered", &self.input.buffered())
            .field("failed", &self.input.failed())
            .field("done", &self.input.is_done())
            .finish_non_exhaustive()
    }
}
impl Server {
    /// Starts before the server version, with a [`MAX_CLIENT_MESSAGE`] input limit.
    pub fn new() -> Self {
        Self::with_limit(MAX_CLIENT_MESSAGE)
    }
    /// Starts with a whole-message limit clamped to 24 through [`MAX_CLIENT_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            state: State::new(),
            input: Stream::new(ClientMessages::with_limit(limit)),
        }
    }
    /// Adds what fits. Keep the unaccepted suffix and drain before retrying.
    /// Before the client's turn, exceeding [`MAX_PENDING`] buffered bytes
    /// or the stream's smaller capacity closes the session; `next`
    /// reports [`FrameError::OutOfTurn`]. After completion, takes and drops all bytes.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        session_push(&mut self.state, &mut self.input, bytes)
    }
    /// Marks the peer's input as ended. Drain to report truncation.
    pub fn end(&mut self) {
        self.input.end();
    }
    /// Takes one client item when it is the client's turn. The caller sends
    /// the next server handshake unit before calling again.
    // Not an Iterator: None means "not this side's turn", not the end.
    #[allow(clippy::should_implement_trait)]
    pub fn next(
        &mut self,
    ) -> Option<Result<Result<ClientMessage, Error>, codec::Fail<FrameError>>> {
        session_next(&mut self.state, &mut self.input)
    }
    /// Writes a server message and advances the session only on success.
    /// Normal framebuffer replies must satisfy the client's requests.
    pub fn send(&mut self, msg: &ServerMessage) -> Result<Vec<u8>, Error> {
        let mut next = self.state.clone();
        next.server_step(msg)?;
        self.state.requested(msg)?;
        let mut bytes = Vec::new();
        msg.write(self.state.dialect, &self.state.format, &mut bytes)?;
        self.state = next;
        self.input.decoder().phase = self.state.phase;
        Ok(bytes)
    }
    /// The current two-direction handshake phase.
    pub fn phase(&self) -> Phase {
        self.state.phase
    }
    /// The negotiated dialect.
    pub fn dialect(&self) -> Dialect {
        self.state.dialect
    }
    /// The offered security types, bounded by [`MAX_SECURITY_TYPES`].
    pub fn offered(&self) -> &[u8] {
        &self.state.offered
    }
    /// The negotiated pixel format.
    pub fn pixel_format(&self) -> PixelFormat {
        self.state.format
    }
    /// Bytes awaiting decoding in the shared buffer.
    pub fn buffered(&self) -> usize {
        self.input.buffered()
    }
    /// Whether the input decoder has ended or failed.
    pub fn is_done(&self) -> bool {
        self.input.is_done()
    }
    /// Extracts the byte layer with its offset, unread suffix and EOF state.
    pub fn into_stream(mut self) -> Stream<ClientMessages> {
        self.input.decoder().phase = self.state.phase;
        self.input
    }
}
impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// A client session whose server byte layer is a [`Stream<ServerMessages>`].
///
/// Handshake
/// phases use both received items and sent messages. Body and session
/// refusals are items; any refused handshake item also moves to `Closed`.
/// Framing errors are returned once by the stream. Before the server's turn,
/// input is capped at [`MAX_PENDING`] buffered bytes or the stream's smaller
/// capacity. Pending bytes are also checked when a received unit passes
/// the turn to the client. Excess input closes the session and reports
/// [`FrameError::OutOfTurn`] once. Once `is_done` is true, `push` takes and drops
/// every byte, as [`Stream`] does.
/// Pixel format changes are refused while an update is pending or partial.
/// Use `into_stream` for an unread suffix after `End` or a terminal error.
pub struct Client {
    state: State,
    input: Stream<ServerMessages>,
}
impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("state", &self.state)
            .field("buffered", &self.input.buffered())
            .field("failed", &self.input.failed())
            .field("done", &self.input.is_done())
            .finish_non_exhaustive()
    }
}
impl Client {
    /// Starts waiting for the server version, with [`MAX_MESSAGE`] as the limit.
    pub fn new() -> Self {
        Self::with_limit(MAX_MESSAGE)
    }
    /// Sets the whole-message limit, clamped to 24 through [`MAX_MESSAGE`].
    pub fn with_limit(limit: usize) -> Self {
        Self {
            state: State::new(),
            input: Stream::new(ServerMessages::with_limit(limit)),
        }
    }
    /// Adds what fits. Keep the unaccepted suffix and drain before retrying.
    /// Before the server's turn, exceeding [`MAX_PENDING`] buffered bytes
    /// or the stream's smaller capacity closes the session; `next`
    /// reports [`FrameError::OutOfTurn`]. After completion, takes and drops all bytes.
    #[must_use = "bytes past the returned count were not taken"]
    pub fn push(&mut self, bytes: &[u8]) -> usize {
        session_push(&mut self.state, &mut self.input, bytes)
    }
    /// Marks the peer's input as ended. Drain to report truncation.
    pub fn end(&mut self) {
        self.input.end();
    }
    /// Takes one server item when it is the server's turn. Send the next
    /// client handshake unit before calling again when the turn changes.
    // Not an Iterator: None means "not this side's turn", not the end.
    #[allow(clippy::should_implement_trait)]
    pub fn next(
        &mut self,
    ) -> Option<Result<Result<ServerMessage, Error>, codec::Fail<FrameError>>> {
        session_next(&mut self.state, &mut self.input)
    }
    fn sync(&mut self) {
        let dec = self.input.decoder();
        dec.phase = self.state.phase;
        dec.dialect = self.state.dialect;
        dec.format = self.state.format;
    }
    /// Writes a client message and advances the session only on success.
    pub fn send(&mut self, msg: &ClientMessage) -> Result<Vec<u8>, Error> {
        if matches!(msg, ClientMessage::SetPixelFormat(_))
            && self.state.phase == Phase::Normal
            && (self.state.requested || !self.input.unread().is_empty())
        {
            return Err(Error::Outstanding);
        }
        let mut next = self.state.clone();
        next.client_step(msg)?;
        let mut bytes = Vec::new();
        match msg {
            ClientMessage::Version(v) => v.write(&mut bytes)?,
            ClientMessage::SecurityType(t) => SecurityChoice(*t).write(&mut bytes)?,
            ClientMessage::VncResponse(r) => VncResponse(*r).write(&mut bytes)?,
            ClientMessage::ClientInit { shared } => {
                ClientInit { shared: *shared }.write(&mut bytes)?
            }
            _ => msg.write(&mut bytes)?,
        }
        self.state = next;
        self.sync();
        Ok(bytes)
    }
    /// The current two-direction handshake phase.
    pub fn phase(&self) -> Phase {
        self.state.phase
    }
    /// The negotiated dialect.
    pub fn dialect(&self) -> Dialect {
        self.state.dialect
    }
    /// The offered security types, bounded by [`MAX_SECURITY_TYPES`].
    pub fn offered(&self) -> &[u8] {
        &self.state.offered
    }
    /// The negotiated pixel format.
    pub fn pixel_format(&self) -> PixelFormat {
        self.state.format
    }
    /// Bytes awaiting decoding in the shared buffer.
    pub fn buffered(&self) -> usize {
        self.input.buffered()
    }
    /// Whether the input decoder has ended or failed.
    pub fn is_done(&self) -> bool {
        self.input.is_done()
    }
    /// Extracts the byte layer with its offset, unread suffix and EOF state.
    pub fn into_stream(mut self) -> Stream<ServerMessages> {
        self.sync();
        self.input
    }
}
impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

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
/// The longest client message: a ClientCutText header and [`MAX_TEXT`] bytes.
/// This is the default and maximum whole-unit limit for [`ClientMessages`].
pub const MAX_CLIENT_MESSAGE: usize = 8 + MAX_TEXT;
/// The longest message this module reads or writes, in bytes. It bounds
/// a framebuffer update, which can otherwise claim gigabytes.
pub const MAX_MESSAGE: usize = 1 << 26;
/// The most bytes a session holds that the peer sent before its turn.
pub const MAX_PENDING: usize = 1 << 16;
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

/// Why an RFB unit cannot be read, a message cannot be sent, or a
/// decoder mode cannot change. Stream decoders yield body failures as
/// items; a [`FrameError`] ends the stream.
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
    /// The bytes end inside the value.
    Truncated,
    /// Bytes follow the value.
    Trailing,
    /// A phase or mode change was attempted inside an incomplete unit.
    PartialUnit,
    /// The client picked a security type the server did not offer.
    NotOffered(u8),
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
    /// server bytes remain unread. Pending updates must keep their format.
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
            Error::Truncated => f.write_str("incomplete RFB value"),
            Error::Trailing => f.write_str("bytes after the RFB value"),
            Error::PartialUnit => f.write_str("mode change inside a partial RFB unit"),
            Error::NotOffered(t) => write!(f, "security type {t} was not offered"),
            Error::PixelFormat => f.write_str("pixel format not allowed"),
            Error::Rectangle => f.write_str("rectangle outside the framebuffer or out of order"),
            Error::NotRequested => f.write_str("server message the client did not ask for"),
            Error::Outstanding => {
                f.write_str("pixel format changed while an update is outstanding")
            }
            Error::Phase(p) => write!(f, "message does not belong in phase {p:?}"),
            Error::Unwritable => f.write_str("RFB value cannot be written unchanged"),
        }
    }
}

impl std::error::Error for Error {}

/// Why [`ClientMessages`] or [`ServerMessages`] cannot find the next
/// unit. It ends the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The bytes are not a version line, `RFB xxx.yyy\n` with digits.
    Version,
    /// A message type this module does not read.
    MessageType(u8),
    /// A rectangle encoding this module cannot read.
    Encoding(i32),
    /// Pixels in a format whose bits per pixel is not 8, 16 or 32.
    BitsPerPixel(u8),
    /// Text longer than [`MAX_TEXT`], or a unit longer than the decoder's
    /// limit.
    TooLong,
    /// The peer exceeded [`MAX_PENDING`] or the smaller stream capacity
    /// before its turn.
    OutOfTurn,
    /// The decoder is in a phase where the peer does not speak.
    Phase(Phase),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Version => f.write_str("not an RFB protocol version line"),
            FrameError::MessageType(t) => write!(f, "unknown message type {t}"),
            FrameError::Encoding(e) => write!(f, "rectangle encoding {e} is not read"),
            FrameError::BitsPerPixel(b) => write!(f, "{b} bits per pixel, not 8, 16 or 32"),
            FrameError::TooLong => f.write_str("text or message too long"),
            FrameError::OutOfTurn => f.write_str("too many bytes sent before the peer's turn"),
            FrameError::Phase(p) => write!(f, "message does not belong in phase {p:?}"),
        }
    }
}

impl std::error::Error for FrameError {}

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
    fn parse_prefix(b: &[u8]) -> Result<Option<(Version, usize)>, Error> {
        run(b, version)
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
    fn read(b: &[u8; PIXEL_FORMAT_LEN]) -> PixelFormat {
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
        [
            (self.red_max, self.red_shift),
            (self.green_max, self.green_shift),
            (self.blue_max, self.blue_shift),
        ]
        .into_iter()
        .all(|(max, shift)| {
            let bits = 16 - max.leading_zeros();
            max & max.wrapping_add(1) == 0
                && u32::from(shift) + bits <= u32::from(self.bits_per_pixel)
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
    FramebufferUpdateRequest {
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    },
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
    fn parse_prefix(b: &[u8]) -> Result<Option<(ClientMessage, usize)>, Error> {
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
}

impl ServerMessage {
    /// Reads a message a server sends after the handshake from the start
    /// of `b`, with pixels in `format`. Refuses incomplete input, trailing
    /// bytes, unknown tags or encodings and lengths past the named limits.
    pub fn parse(b: &[u8], format: &PixelFormat) -> Result<ServerMessage, Error> {
        exact(run(b, |c| server_normal(c, format)), b.len())
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
    /// The session refused the connection; nothing more can be sent.
    /// Sessions preserve unread bytes for handoff.
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
            Phase::ClientVersion
                | Phase::SecurityChoice
                | Phase::VncResponse
                | Phase::ClientInit
                | Phase::Normal
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
            (Phase::VncResponse, ClientMessage::VncResponse(_)) => {
                self.phase = Phase::SecurityResult
            }
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
            (Phase::SecurityOffer, ServerMessage::SecurityTypes(types))
                if self.dialect != Dialect::V3_3 =>
            {
                if types.is_empty() || types.len() > MAX_SECURITY_TYPES {
                    return Err(Error::Unwritable);
                }
                self.offered = types.clone();
                self.phase = Phase::SecurityChoice;
            }
            (Phase::SecurityOffer, ServerMessage::SecurityType(t))
                if self.dialect == Dialect::V3_3 =>
            {
                if *t == 0 {
                    return Err(Error::Unwritable);
                }
                self.phase = self.after_type(*t);
            }
            (Phase::SecurityOffer, ServerMessage::SecurityFailure(_)) => self.phase = Phase::Closed,
            (Phase::VncChallenge, ServerMessage::VncChallenge(_)) => {
                self.phase = Phase::VncResponse
            }
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
                    let fits = |at: u16, len: u16, max: u16| {
                        u32::from(at) + u32::from(len) <= u32::from(max)
                    };
                    if fits(x, r.width, self.width) && fits(y, r.height, self.height) {
                        Ok(())
                    } else {
                        Err(Error::Rectangle)
                    }
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
            ServerMessage::SetColorMapEntries { .. } if self.format.true_color => {
                return Err(Error::NotRequested);
            }
            _ => {}
        }
        Ok(())
    }

    /// Reads the next client message, as this phase expects it.
    fn client_at(&self, c: &mut Reader<'_>) -> Result<ClientMessage, Stop> {
        Ok(match self.phase {
            Phase::ClientVersion => ClientMessage::Version(version(c)?),
            Phase::SecurityChoice => ClientMessage::SecurityType(take(c, 1)?[0]),
            Phase::VncResponse => ClientMessage::VncResponse(array(c)?),
            Phase::ClientInit => ClientMessage::ClientInit {
                shared: take(c, 1)?[0] != 0,
            },
            Phase::Normal => client_normal(c)?,
            p => return Err(Stop::Fail(Error::Phase(p))),
        })
    }

    /// Reads one complete server message in the current phase.
    fn server_at(&self, c: &mut Reader<'_>) -> Result<ServerMessage, Stop> {
        Ok(match self.phase {
            Phase::ServerVersion => ServerMessage::Version(version(c)?),
            Phase::SecurityOffer => match self.dialect {
                Dialect::V3_3 => match u32::from_be_bytes(array(c)?) {
                    0 => ServerMessage::SecurityFailure(text(c)?),
                    t => ServerMessage::SecurityType(t),
                },
                Dialect::V3_7 | Dialect::V3_8 => match take(c, 1)?[0] {
                    0 => ServerMessage::SecurityFailure(text(c)?),
                    n => ServerMessage::SecurityTypes(take(c, usize::from(n))?.to_vec()),
                },
            },
            Phase::VncChallenge => ServerMessage::VncChallenge(array(c)?),
            Phase::SecurityResult => match u32::from_be_bytes(array(c)?) {
                0 => ServerMessage::SecurityOk,
                _ if self.dialect == Dialect::V3_8 => ServerMessage::SecurityFailed(text(c)?),
                _ => ServerMessage::SecurityFailed(Vec::new()),
            },
            Phase::ServerInit => {
                let (width, height) =
                    (u16::from_be_bytes(array(c)?), u16::from_be_bytes(array(c)?));
                let format = PixelFormat::read(&array(c)?);
                if !format.is_valid() {
                    return Err(Stop::Fail(Error::PixelFormat));
                }
                ServerMessage::ServerInit(ServerInit {
                    width,
                    height,
                    format,
                    name: text(c)?,
                })
            }
            Phase::Normal => server_normal(c, &self.format)?,
            p => return Err(Stop::Fail(Error::Phase(p))),
        })
    }
}

enum Stop {
    Need,
    Fail(Error),
}

impl From<Error> for Stop {
    fn from(e: Error) -> Stop {
        Stop::Fail(e)
    }
}

/// Runs a read from the start of `b` and says how far it got.
fn run<T>(
    b: &[u8],
    read: impl FnOnce(&mut Reader<'_>) -> Result<T, Stop>,
) -> Result<Option<(T, usize)>, Error> {
    let mut c = Reader::new(b);
    match read(&mut c) {
        Ok(v) => Ok(Some((v, c.position()))),
        Err(Stop::Need) => Ok(None),
        Err(Stop::Fail(e)) => Err(e),
    }
}

fn version(c: &mut Reader<'_>) -> Result<Version, Stop> {
    const PATTERN: &[u8; VERSION_LEN] = b"RFB 000.000\n";
    // A wrong byte is known before the rest of the line comes.
    let have = c.clone().rest();
    for (&x, &p) in have.iter().zip(PATTERN) {
        let fits = if p == b'0' {
            x.is_ascii_digit()
        } else {
            x == p
        };
        if !fits {
            return Err(Stop::Fail(Error::Version));
        }
    }
    if have.len() < VERSION_LEN {
        // Ask for one more byte, not the whole line, so each one is checked
        // as it comes.
        return Err(Stop::Need);
    }
    let b = take(c, VERSION_LEN)?;
    let number = |d: &[u8]| d.iter().fold(0u16, |n, &x| n * 10 + u16::from(x - b'0'));
    Ok(Version {
        major: number(&b[4..7]),
        minor: number(&b[8..11]),
    })
}

/// A four-byte length and that many bytes of text.
fn text(c: &mut Reader<'_>) -> Result<Vec<u8>, Stop> {
    let n = usize::try_from(u32::from_be_bytes(array(c)?)).map_err(|_| Error::TooLong)?;
    if n > MAX_TEXT {
        return Err(Stop::Fail(Error::TooLong));
    }
    Ok(take(c, n)?.to_vec())
}

fn pixels_len(width: u16, height: u16, format: &PixelFormat) -> Result<usize, Error> {
    let bytes = format
        .bytes_per_pixel()
        .ok_or(Error::BitsPerPixel(format.bits_per_pixel))?;
    usize::from(width)
        .checked_mul(usize::from(height))
        .and_then(|n| n.checked_mul(bytes))
        .filter(|&n| n <= MAX_MESSAGE)
        .ok_or(Error::TooLong)
}

/// The bytes of a cursor's mask: one bit per pixel, rows padded to bytes.
fn mask_len(width: u16, height: u16) -> Result<usize, Error> {
    usize::from(width)
        .div_ceil(8)
        .checked_mul(usize::from(height))
        .ok_or(Error::TooLong)
}

fn client_normal(c: &mut Reader<'_>) -> Result<ClientMessage, Stop> {
    Ok(match take(c, 1)?[0] {
        client_type::SET_PIXEL_FORMAT => {
            take(c, 3)?;
            let format = PixelFormat::read(&array(c)?);
            if !format.is_valid() {
                return Err(Stop::Fail(Error::PixelFormat));
            }
            ClientMessage::SetPixelFormat(format)
        }
        client_type::SET_ENCODINGS => {
            take(c, 1)?;
            let n = usize::from(u16::from_be_bytes(array(c)?));
            let b = take(c, 4 * n)?;
            ClientMessage::SetEncodings(
                b.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|e| i32::from_be_bytes([e[0], e[1], e[2], e[3]]))
                    .collect(),
            )
        }
        client_type::FRAMEBUFFER_UPDATE_REQUEST => {
            let incremental = take(c, 1)?[0] != 0;
            let (x, y, width, height) = (
                u16::from_be_bytes(array(c)?),
                u16::from_be_bytes(array(c)?),
                u16::from_be_bytes(array(c)?),
                u16::from_be_bytes(array(c)?),
            );
            ClientMessage::FramebufferUpdateRequest {
                incremental,
                x,
                y,
                width,
                height,
            }
        }
        client_type::KEY_EVENT => {
            let down = take(c, 1)?[0] != 0;
            take(c, 2)?;
            ClientMessage::KeyEvent {
                down,
                key: u32::from_be_bytes(array(c)?),
            }
        }
        client_type::POINTER_EVENT => {
            let buttons = take(c, 1)?[0];
            ClientMessage::PointerEvent {
                buttons,
                x: u16::from_be_bytes(array(c)?),
                y: u16::from_be_bytes(array(c)?),
            }
        }
        client_type::CLIENT_CUT_TEXT => {
            take(c, 3)?;
            ClientMessage::ClientCutText(text(c)?)
        }
        t => return Err(Stop::Fail(Error::MessageType(t))),
    })
}

fn server_normal(c: &mut Reader<'_>, format: &PixelFormat) -> Result<ServerMessage, Stop> {
    Ok(match take(c, 1)?[0] {
        server_type::FRAMEBUFFER_UPDATE => {
            take(c, 1)?;
            let count = usize::from(u16::from_be_bytes(array(c)?));
            let mut rects = Vec::new();
            for i in 0..count {
                let r = rectangle(c, format)?;
                if r.contents == Contents::DesktopSize && i + 1 < count {
                    return Err(Stop::Fail(Error::Rectangle));
                }
                rects.push(r);
            }
            ServerMessage::FramebufferUpdate(rects)
        }
        server_type::SET_COLOR_MAP_ENTRIES => {
            take(c, 1)?;
            let first = u16::from_be_bytes(array(c)?);
            let n = usize::from(u16::from_be_bytes(array(c)?));
            let b = take(c, 6 * n)?;
            let colors = b
                .as_chunks::<6>()
                .0
                .iter()
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
            take(c, 3)?;
            ServerMessage::ServerCutText(text(c)?)
        }
        t => return Err(Stop::Fail(Error::MessageType(t))),
    })
}

fn rectangle(c: &mut Reader<'_>, format: &PixelFormat) -> Result<Rectangle, Stop> {
    let (x, y, width, height) = (
        u16::from_be_bytes(array(c)?),
        u16::from_be_bytes(array(c)?),
        u16::from_be_bytes(array(c)?),
        u16::from_be_bytes(array(c)?),
    );
    let contents = match i32::from_be_bytes(array(c)?) {
        encoding::RAW => Contents::Raw(take(c, pixels_len(width, height, format)?)?.to_vec()),
        encoding::COPY_RECT => Contents::CopyRect {
            src_x: u16::from_be_bytes(array(c)?),
            src_y: u16::from_be_bytes(array(c)?),
        },
        encoding::CURSOR => {
            let (p, m) = (pixels_len(width, height, format)?, mask_len(width, height)?);
            let b = take(c, p.checked_add(m).ok_or(Error::TooLong)?)?;
            Contents::Cursor {
                pixels: b[..p].to_vec(),
                mask: b[p..].to_vec(),
            }
        }
        encoding::DESKTOP_SIZE => Contents::DesktopSize,
        e => return Err(Stop::Fail(Error::Encoding(e))),
    };
    Ok(Rectangle {
        x,
        y,
        width,
        height,
        contents,
    })
}

#[inline]
fn take<'a>(r: &mut Reader<'a>, n: usize) -> Result<&'a [u8], Stop> {
    r.position()
        .checked_add(n)
        .filter(|&end| end <= MAX_MESSAGE)
        .ok_or(Stop::Fail(Error::TooLong))?;
    r.take(n).map_err(|_| Stop::Need)
}

#[inline]
fn array<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N], Stop> {
    let mut out = [0; N];
    out.copy_from_slice(take(r, N)?);
    Ok(out)
}

/// Checks shared by this module's tests and its fuzz target.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod harness {
    use super::{
        Client, ClientMessage, Dialect, Error, FrameError, Phase, PixelFormat, Server, ServerInit,
        ServerMessage, Version,
    };
    use fictionet::stdlib::codec;

    /// One session result, preserving both unit and terminal failures.
    pub type Item<T> = Result<Result<T, Error>, codec::Fail<FrameError>>;

    fn server_turn(server: &Server, vnc: bool) -> Option<ServerMessage> {
        Some(match server.phase() {
            Phase::ServerVersion => ServerMessage::Version(Version::V3_8),
            Phase::SecurityOffer if server.dialect() == Dialect::V3_3 => {
                ServerMessage::SecurityType(if vnc { 2 } else { 1 })
            }
            Phase::SecurityOffer => ServerMessage::SecurityTypes(vec![1, 2]),
            Phase::VncChallenge => ServerMessage::VncChallenge([7; 16]),
            Phase::SecurityResult => ServerMessage::SecurityOk,
            Phase::ServerInit => ServerMessage::ServerInit(ServerInit {
                width: 4,
                height: 3,
                format: PixelFormat::TRUE_COLOR_32,
                name: vec![],
            }),
            _ => return None,
        })
    }

    fn client_turn(client: &Client, version: Version, vnc: bool) -> Option<ClientMessage> {
        Some(match client.phase() {
            Phase::ClientVersion => ClientMessage::Version(version),
            Phase::SecurityChoice => {
                let offered = client.offered();
                let pick = [if vnc { 2 } else { 1 }, 1, 2]
                    .into_iter()
                    .find(|t| offered.contains(t));
                ClientMessage::SecurityType(
                    pick.or_else(|| offered.iter().copied().find(|&t| t != 0))?,
                )
            }
            Phase::VncResponse => ClientMessage::VncResponse([9; 16]),
            Phase::ClientInit => ClientMessage::ClientInit { shared: true },
            _ => return None,
        })
    }

    fn server_pump(server: &mut Server, vnc: bool, got: &mut Vec<Item<ClientMessage>>) -> bool {
        loop {
            if let Some(message) = server_turn(server, vnc) {
                server.send(&message).unwrap();
                continue;
            }
            match server.next() {
                Some(item) => {
                    let failed = !matches!(item, Ok(Ok(_)));
                    got.push(item);
                    if failed {
                        return false;
                    }
                }
                None => {
                    // Sends between pushes must preserve an incomplete peer unit.
                    if server.phase() == Phase::Normal {
                        server.send(&ServerMessage::Bell).unwrap();
                    }
                    return true;
                }
            }
        }
    }

    /// Reads bounded client input with scripted server replies and intervening Bells.
    pub fn as_server<'a>(
        vnc: bool,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<Item<ClientMessage>> {
        let mut server = Server::new();
        let mut got = Vec::new();
        server_pump(&mut server, vnc, &mut got);
        for chunk in chunks {
            assert_eq!(server.push(chunk), chunk.len());
            if !server_pump(&mut server, vnc, &mut got) {
                break;
            }
        }
        got
    }

    /// Reads bounded server input with scripted client replies and intervening pointer events.
    pub fn as_client<'a>(
        version: Version,
        vnc: bool,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<Item<(ServerMessage, PixelFormat)>> {
        let mut client = Client::new();
        let mut got = Vec::new();
        'input: for chunk in chunks {
            assert_eq!(client.push(chunk), chunk.len());
            loop {
                if let Some(message) = client_turn(&client, version, vnc) {
                    client.send(&message).unwrap();
                    continue;
                }
                match client.next() {
                    Some(item) => {
                        let failed = !matches!(item, Ok(Ok(_)));
                        got.push(
                            item.map(|result| {
                                result.map(|message| (message, client.pixel_format()))
                            }),
                        );
                        if failed {
                            break 'input;
                        }
                    }
                    None => {
                        // Even a send inside an update must preserve decoder progress.
                        if client.phase() == Phase::Normal {
                            client
                                .send(&ClientMessage::PointerEvent {
                                    buttons: 0,
                                    x: 1,
                                    y: 1,
                                })
                                .unwrap();
                        }
                        break;
                    }
                }
            }
        }
        got
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Lcg;
    use fictionet::stdlib::test_support::contract;
    use fictionet::stdlib::test_support::{assert_linear, rounds};
    use fictionet::stdlib::test_support::{chunks, decode_all, mutate};

    /// Runs a server and a client session against each other, passing
    /// every message through bytes, and checks each side reads what the
    /// other sent.
    fn converse(
        version: Version,
        offer: ServerMessage,
        choice: Option<u8>,
        result: Option<ServerMessage>,
    ) -> (Server, Client) {
        let mut s = Server::new();
        let mut c = Client::new();
        let to_client = |s: &mut Server, c: &mut Client, m: ServerMessage| {
            let _ = c.push(&s.send(&m).unwrap());
            assert_eq!(c.next(), Some(Ok(Ok(m))));
            assert_eq!(c.buffered(), 0);
        };
        let to_server = |s: &mut Server, c: &mut Client, m: ClientMessage| {
            let _ = s.push(&c.send(&m).unwrap());
            assert_eq!(s.next(), Some(Ok(Ok(m))));
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
            let init = ServerInit {
                width: 1024,
                height: 768,
                format: PixelFormat::TRUE_COLOR_32,
                name: b"desk".to_vec(),
            };
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
            ClientMessage::SetEncodings(vec![
                encoding::COPY_RECT,
                encoding::RAW,
                encoding::CURSOR,
                encoding::DESKTOP_SIZE,
            ]),
            ClientMessage::SetEncodings(vec![]),
            ClientMessage::FramebufferUpdateRequest {
                incremental: true,
                x: 1,
                y: 2,
                width: 300,
                height: 400,
            },
            ClientMessage::KeyEvent {
                down: true,
                key: 0xff0d,
            },
            ClientMessage::KeyEvent {
                down: false,
                key: 0x61,
            },
            ClientMessage::PointerEvent {
                buttons: 0b101,
                x: 0x1234,
                y: 7,
            },
            ClientMessage::ClientCutText(b"hello".to_vec()),
            ClientMessage::ClientCutText(vec![]),
        ]
    }

    fn sample_server_messages() -> Vec<ServerMessage> {
        vec![
            ServerMessage::FramebufferUpdate(vec![
                Rectangle {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 1,
                    contents: Contents::Raw(vec![1, 2, 3, 4, 5, 6, 7, 8]),
                },
                Rectangle {
                    x: 5,
                    y: 6,
                    width: 10,
                    height: 10,
                    contents: Contents::CopyRect { src_x: 1, src_y: 2 },
                },
                Rectangle {
                    x: 1,
                    y: 1,
                    width: 9,
                    height: 1,
                    contents: Contents::Cursor {
                        pixels: vec![0xaa; 36],
                        mask: vec![0xff, 0x80],
                    },
                },
                Rectangle {
                    x: 0,
                    y: 0,
                    width: 0,
                    height: 0,
                    contents: Contents::Raw(vec![]),
                },
                Rectangle {
                    x: 0,
                    y: 0,
                    width: 800,
                    height: 600,
                    contents: Contents::DesktopSize,
                },
            ]),
            ServerMessage::FramebufferUpdate(vec![]),
            ServerMessage::SetColorMapEntries {
                first: 3,
                colors: vec![
                    Color {
                        red: 1,
                        green: 2,
                        blue: 3,
                    },
                    Color {
                        red: 65535,
                        green: 0,
                        blue: 9,
                    },
                ],
            },
            ServerMessage::Bell,
            ServerMessage::ServerCutText(b"copied".to_vec()),
        ]
    }

    #[test]
    fn review_pixel_format_waits_after_bell() {
        let (_, mut c) = normal_pair();
        assert_eq!(
            c.push(&[server_type::BELL, server_type::FRAMEBUFFER_UPDATE, 0]),
            3
        );
        assert_eq!(
            c.send(&ClientMessage::SetPixelFormat(PixelFormat::TRUE_COLOR_32)),
            Err(Error::Outstanding)
        );
        assert_eq!(c.next(), Some(Ok(Ok(ServerMessage::Bell))));
        assert_eq!(c.next(), None);
        assert_eq!(
            c.send(&ClientMessage::SetPixelFormat(PixelFormat::TRUE_COLOR_32)),
            Err(Error::Outstanding)
        );
    }

    #[test]
    fn version_lines() {
        // RFC 6143, section 7.1.1.
        assert_eq!(Version::parse(b"RFB 003.008\n"), Ok(Version::V3_8));
        assert_eq!(Version::V3_3.to_bytes().unwrap(), *b"RFB 003.003\n");
        assert_eq!(Version::V3_7.to_bytes().unwrap(), *b"RFB 003.007\n");
        assert_eq!(
            Version {
                major: 3,
                minor: 889
            }
            .to_bytes()
            .unwrap(),
            *b"RFB 003.889\n"
        );
        for n in 0..12 {
            assert_eq!(
                Version::parse(&b"RFB 003.008\n"[..n]),
                Err(Error::Truncated),
                "{n} bytes"
            );
        }
        // A wrong byte is an error at once.
        assert_eq!(Version::parse(b"G"), Err(Error::Version));
        assert_eq!(Version::parse(b"RFB 0x"), Err(Error::Version));
        assert_eq!(Version::parse(b"RFB 003.008\r"), Err(Error::Version));
        // The line clamps what three digits cannot hold, and the message
        // writers refuse it.
        let big = Version {
            major: 1000,
            minor: 65535,
        };
        assert_eq!(big.to_bytes(), Err(Error::Unwritable));
        assert_eq!(
            ClientMessage::Version(big).to_bytes(),
            Err(Error::Unwritable)
        );
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(
            server_bytes(&ServerMessage::Version(big), Dialect::V3_8, &f),
            Err(Error::Unwritable)
        );
        let mut s = Server::new();
        assert_eq!(s.send(&ServerMessage::Version(big)), Err(Error::Unwritable));
        assert_eq!(s.phase(), Phase::ServerVersion);
        // Dialects, as RFC 6143 says: anything else is 3.3.
        assert_eq!(Version::V3_8.dialect(), Dialect::V3_8);
        assert_eq!(Version::V3_7.dialect(), Dialect::V3_7);
        assert_eq!(Version { major: 3, minor: 5 }.dialect(), Dialect::V3_3);
        assert_eq!(
            Version {
                major: 3,
                minor: 889
            }
            .dialect(),
            Dialect::V3_3
        );
        assert_eq!(Version { major: 4, minor: 8 }.dialect(), Dialect::V3_3);
    }

    #[test]
    fn handshake_3_8_none() {
        let (s, c) = converse(
            Version::V3_8,
            ServerMessage::SecurityTypes(vec![1]),
            Some(1),
            Some(ServerMessage::SecurityOk),
        );
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
            server_bytes(
                &ServerMessage::SecurityFailed(b"no".to_vec()),
                Dialect::V3_8,
                &PixelFormat::TRUE_COLOR_32
            ),
            Ok(vec![0, 0, 0, 1, 0, 0, 0, 2, b'n', b'o'])
        );
    }

    #[test]
    fn handshake_3_7_none_has_no_result() {
        let (s, _) = converse(
            Version::V3_7,
            ServerMessage::SecurityTypes(vec![1, 2]),
            Some(1),
            None,
        );
        assert_eq!(s.phase(), Phase::Normal);
        // A 3.7 failure has no reason on the wire.
        let (s, c) = converse(
            Version::V3_7,
            ServerMessage::SecurityTypes(vec![2]),
            Some(2),
            Some(ServerMessage::SecurityFailed(vec![])),
        );
        assert_eq!((s.phase(), c.phase()), (Phase::Closed, Phase::Closed));
        assert_eq!(
            server_bytes(
                &ServerMessage::SecurityFailed(vec![]),
                Dialect::V3_7,
                &PixelFormat::TRUE_COLOR_32
            ),
            Ok(vec![0, 0, 0, 1])
        );
        // A reason the wire cannot carry is refused, not dropped.
        assert_eq!(
            server_bytes(
                &ServerMessage::SecurityFailed(b"x".to_vec()),
                Dialect::V3_7,
                &PixelFormat::TRUE_COLOR_32
            ),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn handshake_3_3() {
        // The server picks VNC Authentication, sent as four bytes.
        let (s, _) = converse(
            Version::V3_3,
            ServerMessage::SecurityType(2),
            None,
            Some(ServerMessage::SecurityOk),
        );
        assert_eq!(s.phase(), Phase::Normal);
        // None goes straight to ClientInit.
        let (s, _) = converse(Version::V3_3, ServerMessage::SecurityType(1), None, None);
        assert_eq!(s.phase(), Phase::Normal);
        assert_eq!(
            server_bytes(
                &ServerMessage::SecurityType(1),
                Dialect::V3_3,
                &PixelFormat::TRUE_COLOR_32
            ),
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
        assert_eq!(
            server_bytes(&reason, Dialect::V3_8, &f).unwrap()[..5],
            [0, 0, 0, 0, 8]
        );
        assert_eq!(
            server_bytes(&reason, Dialect::V3_3, &f).unwrap()[..8],
            [0, 0, 0, 0, 0, 0, 0, 8]
        );
        // An ended stream drops later input.
        let mut s = s;
        assert_eq!(s.next(), None);
        assert_eq!(s.push(&[1, 2, 3]), 3);
        assert_eq!(s.next(), None);
        assert_eq!(s.buffered(), 0);
        assert_eq!(
            s.send(&ServerMessage::Bell),
            Err(Error::Phase(Phase::Closed))
        );
    }

    #[test]
    fn unsupported_security_type_is_reported() {
        let mut s = Server::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        let _ = s.push(b"RFB 003.008\n");
        s.next().unwrap().unwrap().unwrap();
        s.send(&ServerMessage::SecurityTypes(vec![18, 19])).unwrap();
        let _ = s.push(&[19]);
        assert_eq!(s.next(), Some(Ok(Ok(ClientMessage::SecurityType(19)))));
        assert_eq!(s.phase(), Phase::Unsupported(19));
        assert_eq!(
            s.send(&ServerMessage::SecurityOk),
            Err(Error::Phase(Phase::Unsupported(19)))
        );
        assert_eq!(s.next(), None);
        let _ = s.push(&[0]);
        assert_eq!(s.next(), None);
        // A 3.3 server can name one too.
        let mut c = Client::new();
        let _ = c.push(b"RFB 003.003\n");
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_3)).unwrap();
        let _ = c.push(&[0, 0, 0, 16]);
        assert_eq!(c.next(), Some(Ok(Ok(ServerMessage::SecurityType(16)))));
        assert_eq!(c.phase(), Phase::Unsupported(16));
    }

    #[test]
    fn choice_must_be_offered() {
        let mut s = Server::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        let _ = s.push(b"RFB 003.008\n");
        s.next().unwrap().unwrap().unwrap();
        s.send(&ServerMessage::SecurityTypes(vec![2])).unwrap();
        let _ = s.push(&[1]);
        assert_eq!(s.next(), Some(Ok(Err(Error::NotOffered(1)))));
        assert_eq!(s.next(), None);
        // A client world cannot pick one either.
        let mut c = Client::new();
        let _ = c.push(b"RFB 003.008\n");
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        let _ = c.push(&[1, 2]);
        assert_eq!(
            c.next(),
            Some(Ok(Ok(ServerMessage::SecurityTypes(vec![2]))))
        );
        assert_eq!(
            c.send(&ClientMessage::SecurityType(1)),
            Err(Error::NotOffered(1))
        );
        assert_eq!(c.phase(), Phase::SecurityChoice);
        assert_eq!(c.send(&ClientMessage::SecurityType(2)), Ok(vec![2]));
    }

    #[test]
    fn sends_out_of_phase_are_refused() {
        let mut s = Server::new();
        assert_eq!(
            s.send(&ServerMessage::Bell),
            Err(Error::Phase(Phase::ServerVersion))
        );
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(
            s.send(&ServerMessage::Version(Version::V3_8)),
            Err(Error::Phase(Phase::ClientVersion))
        );
        let _ = s.push(b"RFB 003.008\n");
        s.next().unwrap().unwrap().unwrap();
        // A 3.8 server offers a list; a single type is 3.3's.
        assert_eq!(
            s.send(&ServerMessage::SecurityType(1)),
            Err(Error::Phase(Phase::SecurityOffer))
        );
        assert_eq!(
            s.send(&ServerMessage::SecurityTypes(vec![])),
            Err(Error::Unwritable)
        );
        assert_eq!(
            s.send(&ServerMessage::SecurityTypes(vec![1; 256])),
            Err(Error::Unwritable)
        );
        assert_eq!(s.phase(), Phase::SecurityOffer);
        let mut c = Client::new();
        assert_eq!(
            c.send(&ClientMessage::Version(Version::V3_8)),
            Err(Error::Phase(Phase::ServerVersion))
        );
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(
            server_bytes(&ServerMessage::SecurityType(0), Dialect::V3_3, &f),
            Err(Error::Unwritable)
        );
        // A 3.3 world on the server side cannot send a list.
        let mut s = Server::new();
        s.send(&ServerMessage::Version(Version::V3_3)).unwrap();
        let _ = s.push(b"RFB 003.003\n");
        s.next().unwrap().unwrap().unwrap();
        assert_eq!(
            s.send(&ServerMessage::SecurityTypes(vec![1])),
            Err(Error::Phase(Phase::SecurityOffer))
        );
        assert_eq!(
            s.send(&ServerMessage::SecurityType(0)),
            Err(Error::Unwritable)
        );
    }

    #[test]
    fn dialect_is_the_lower_version() {
        // RFC 6143, section 7.1.1: the client must not reply with a version
        // higher than the server's. A 3.3 server keeps its 3.3 handshake if
        // a client answers 3.8 anyway.
        let mut s = Server::new();
        s.send(&ServerMessage::Version(Version::V3_3)).unwrap();
        let _ = s.push(b"RFB 003.008\n");
        s.next().unwrap().unwrap().unwrap();
        assert_eq!(s.dialect(), Dialect::V3_3);
        assert_eq!(
            s.send(&ServerMessage::SecurityType(1)),
            Ok(vec![0, 0, 0, 1])
        );
        // A client world that answers a 3.7 server with 3.8 reads a 3.7 list.
        let mut c = Client::new();
        let _ = c.push(b"RFB 003.007\n");
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(c.dialect(), Dialect::V3_7);
        // A server version past 3.8, such as 3.889, leaves the client's.
        let mut c = Client::new();
        let _ = c.push(b"RFB 003.889\n");
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(c.dialect(), Dialect::V3_8);
    }

    #[test]
    fn handshake_writers_follow_the_dialect() {
        // A 3.3 type sent to a 3.8 client would read as a refusal, and a
        // list sent to a 3.3 client as a type number.
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(
            server_bytes(&ServerMessage::SecurityType(1), Dialect::V3_8, &f),
            Err(Error::Unwritable)
        );
        assert_eq!(
            server_bytes(&ServerMessage::SecurityType(1), Dialect::V3_7, &f),
            Err(Error::Unwritable)
        );
        assert_eq!(
            server_bytes(&ServerMessage::SecurityTypes(vec![1]), Dialect::V3_3, &f),
            Err(Error::Unwritable)
        );
        assert_eq!(
            server_bytes(&ServerMessage::SecurityTypes(vec![1]), Dialect::V3_7, &f),
            Ok(vec![1, 1])
        );
    }

    #[test]
    fn early_bytes_wait_their_turn() {
        let mut s = Server::new();
        // The client's version, sent before the server's.
        let _ = s.push(b"RFB 003.008\n");
        assert_eq!(s.next(), None);
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        assert_eq!(
            s.next(),
            Some(Ok(Ok(ClientMessage::Version(Version::V3_8))))
        );
        // Too much early is an error.
        let _ = s.push(&vec![0; MAX_PENDING + 1]);
        assert_eq!(
            s.next(),
            Some(Err(codec::Fail::Protocol(FrameError::OutOfTurn)))
        );
        assert_eq!(s.push(&[1]), 1);
        assert_eq!(s.next(), None);
        assert_eq!(s.buffered(), MAX_PENDING);
    }

    #[test]
    fn server_init_example() {
        let mut c = Client::new();
        let _ = c.push(b"RFB 003.003\n");
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_3)).unwrap();
        let _ = c.push(&[0, 0, 0, 1]);
        assert_eq!(c.next(), Some(Ok(Ok(ServerMessage::SecurityType(1)))));
        assert_eq!(
            c.send(&ClientMessage::ClientInit { shared: true }),
            Ok(vec![1])
        );
        let mut bytes = vec![0x04, 0x00, 0x03, 0x00];
        bytes.extend_from_slice(&[16, 16, 1, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 3, b'a', b'b', b'c']);
        for n in 0..bytes.len() {
            let mut c2 = Client::new();
            let _ = c2.push(b"RFB 003.003\n");
            c2.next().unwrap().unwrap().unwrap();
            c2.send(&ClientMessage::Version(Version::V3_3)).unwrap();
            let _ = c2.push(&[0, 0, 0, 1]);
            c2.next().unwrap().unwrap().unwrap();
            c2.send(&ClientMessage::ClientInit { shared: true })
                .unwrap();
            let _ = c2.push(&bytes[..n]);
            assert_eq!(c2.next(), None, "{n} bytes");
        }
        let _ = c.push(&bytes);
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
        let init = ServerInit {
            width: 1024,
            height: 768,
            format,
            name: b"abc".to_vec(),
        };
        assert_eq!(
            c.next(),
            Some(Ok(Ok(ServerMessage::ServerInit(init.clone()))))
        );
        assert_eq!(c.pixel_format(), format);
        assert_eq!(
            server_bytes(&ServerMessage::ServerInit(init), Dialect::V3_3, &format),
            Ok(bytes)
        );
        // Raw pixels are now two bytes each.
        let _ = c.push(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xab, 0xcd]);
        let Some(Ok(Ok(ServerMessage::FramebufferUpdate(r)))) = c.next() else {
            panic!()
        };
        assert_eq!(r[0].contents, Contents::Raw(vec![0xab, 0xcd]));
        // After SetPixelFormat, four.
        c.send(&ClientMessage::SetPixelFormat(PixelFormat::TRUE_COLOR_32))
            .unwrap();
        let _ = c.push(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4]);
        let Some(Ok(Ok(ServerMessage::FramebufferUpdate(r)))) = c.next() else {
            panic!()
        };
        assert_eq!(r[0].contents, Contents::Raw(vec![1, 2, 3, 4]));
    }

    #[test]
    fn handshake_truncated_prefixes() {
        let mut to_server = b"RFB 003.008\n".to_vec();
        SecurityChoice(2).write(&mut to_server).unwrap();
        VncResponse([9; 16]).write(&mut to_server).unwrap();
        ClientInit { shared: true }.write(&mut to_server).unwrap();
        ClientMessage::KeyEvent {
            down: true,
            key: 65,
        }
        .write(&mut to_server)
        .unwrap();
        let whole = harness::as_server(true, [&to_server[..]]);
        assert_eq!(whole.len(), 5);
        assert!(whole.iter().all(|item| matches!(item, Ok(Ok(_)))));
        for n in 0..=to_server.len() {
            let part = harness::as_server(true, [&to_server[..n]]);
            assert_eq!(
                part,
                harness::as_server(true, chunks(&to_server[..n], &[1]))
            );
            assert_eq!(part, whole[..part.len()]);
            if n < to_server.len() {
                assert!(part.len() < whole.len());
            }
        }
        let mut to_client = b"RFB 003.008\n".to_vec();
        let format = PixelFormat::TRUE_COLOR_32;
        for message in [
            ServerMessage::SecurityTypes(vec![1, 2]),
            ServerMessage::VncChallenge([3; 16]),
            ServerMessage::SecurityOk,
            ServerMessage::ServerInit(ServerInit {
                width: 1,
                height: 1,
                format,
                name: b"n".to_vec(),
            }),
            ServerMessage::Bell,
        ] {
            message
                .write(Dialect::V3_8, &format, &mut to_client)
                .unwrap();
        }
        let whole = harness::as_client(Version::V3_8, true, [&to_client[..]]);
        assert_eq!(whole.len(), 6);
        assert!(whole.iter().all(|item| matches!(item, Ok(Ok(_)))));
        for n in 0..=to_client.len() {
            let part = harness::as_client(Version::V3_8, true, [&to_client[..n]]);
            assert_eq!(
                part,
                harness::as_client(Version::V3_8, true, chunks(&to_client[..n], &[1]))
            );
            assert_eq!(part, whole[..part.len()]);
            if n < to_client.len() {
                assert!(part.len() < whole.len());
            }
        }
    }

    #[test]
    fn generated_sessions_agree_across_pushes() {
        let mut rng = Lcg::new(0x5900);
        let to_server = [
            vec![],
            b"RFB 003.008\n".to_vec(),
            b"RFB 003.003\n".to_vec(),
            [&b"RFB 003.008\n"[..], &[1, 1]].concat(),
            [&b"RFB 003.007\n"[..], &[2], &[0; 16], &[0]].concat(),
            [&b"RFB 003.003\n"[..], &[0; 16], &[1]].concat(),
        ];
        let init = ServerInit {
            width: 2,
            height: 2,
            format: PixelFormat::TRUE_COLOR_32,
            name: vec![],
        }
        .to_bytes()
        .unwrap();
        let to_client = [
            vec![],
            b"RFB 003.008\n".to_vec(),
            [&b"RFB 003.008\n"[..], &[1, 1], &[0; 4], &init].concat(),
            [&b"RFB 003.008\n"[..], &[0, 0, 0, 1], &init].concat(),
            [&b"RFB 003.008\n"[..], &[1, 2], &[0; 16], &[0; 4], &init].concat(),
        ];
        let versions = [Version::V3_3, Version::V3_7, Version::V3_8];
        let mut normal = 0;
        for _ in 0..4000 {
            let vnc = rng.coin();
            let mut data = to_server[rng.index(to_server.len())].clone();
            ClientMessage::PointerEvent {
                buttons: rng.next() as u8,
                x: 1,
                y: 1,
            }
            .write(&mut data)
            .unwrap();
            data.extend(rng.bytes(80));
            let whole = harness::as_server(vnc, [&data[..]]);
            assert_eq!(whole, harness::as_server(vnc, chunks(&data, &[1])));
            for message in whole
                .iter()
                .flatten()
                .flatten()
                .filter(|m| !m.is_handshake())
            {
                normal += 1;
                assert!(message.to_bytes().is_ok());
                contract::check_wire_value(message);
            }
            let version = versions[rng.index(versions.len())];
            let mut data = to_client[rng.index(to_client.len())].clone();
            ServerMessage::ServerCutText(rng.bytes(30))
                .write(Dialect::V3_8, &PixelFormat::TRUE_COLOR_32, &mut data)
                .unwrap();
            data.extend(rng.bytes(80));
            let whole = harness::as_client(version, vnc, [&data[..]]);
            assert_eq!(whole, harness::as_client(version, vnc, chunks(&data, &[1])));
            for (message, format) in whole
                .iter()
                .flatten()
                .flatten()
                .filter(|(m, _)| !m.is_handshake())
            {
                normal += 1;
                let bytes = server_bytes(message, Dialect::V3_8, format).unwrap();
                assert_eq!(ServerMessage::parse(&bytes, format), Ok(message.clone()));
            }
        }
        assert!(normal > 500, "only {normal} normal messages");
    }

    #[test]
    fn session_messages_byte_at_a_time_are_bounded() {
        let check = |size| {
            let rectangles = vec![
                Rectangle {
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                    contents: Contents::Raw(vec![1, 2, 3, 4])
                };
                size
            ];
            let update = ServerMessage::FramebufferUpdate(rectangles);
            let bytes = server_bytes(&update, Dialect::V3_8, &PixelFormat::TRUE_COLOR_32).unwrap();
            let (mut server, mut client) = normal_pair();
            for (i, chunk) in chunks(&bytes, &[1]).enumerate() {
                assert_eq!(client.push(chunk), 1);
                if i + 1 < bytes.len() {
                    assert_eq!(client.next(), None);
                }
                assert!(client.buffered() <= MAX_MESSAGE);
            }
            assert_eq!(client.next(), Some(Ok(Ok(update))));
            assert_eq!(client.buffered(), 0);
            let message = ClientMessage::PointerEvent {
                buttons: 0,
                x: 1,
                y: 1,
            };
            let bytes = message.to_bytes().unwrap();
            for _ in 0..size * 2 {
                for (i, chunk) in chunks(&bytes, &[1]).enumerate() {
                    assert_eq!(server.push(chunk), 1);
                    if i + 1 < bytes.len() {
                        assert_eq!(server.next(), None);
                    }
                    assert!(server.buffered() <= MAX_CLIENT_MESSAGE);
                }
                assert_eq!(server.next(), Some(Ok(Ok(message.clone()))));
            }
            assert_eq!(server.buffered(), 0);
        };
        check(MAX_ITEMS);
        assert_linear(
            "session_messages_byte_at_a_time_are_bounded",
            MAX_ITEMS / 4,
            check,
        );
    }

    #[test]
    fn pixel_formats() {
        let f = PixelFormat::TRUE_COLOR_32;
        assert_eq!(
            f.to_bytes().unwrap(),
            [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]
        );
        assert_eq!(PixelFormat::parse(&f.to_bytes().unwrap()), Ok(f));
        assert_eq!(f.bytes_per_pixel(), Some(4));
        let mut odd = f.to_bytes().unwrap();
        odd[2] = 7;
        odd[3] = 9;
        odd[13..].fill(0xee);
        let p = PixelFormat::parse(&odd).unwrap();
        assert!(p.big_endian && p.true_color);
        odd[2] = 1;
        odd[3] = 1;
        odd[13..].fill(0);
        assert_eq!(p.to_bytes().unwrap(), odd);
        assert_eq!(
            PixelFormat {
                bits_per_pixel: 24,
                ..f
            }
            .bytes_per_pixel(),
            None
        );
        odd[0] = 24;
        assert_eq!(PixelFormat::parse(&odd), Err(Error::PixelFormat));
        // RFC 6143, section 7.4.
        assert!(f.is_valid());
        assert!(p.is_valid());
        let rgb565 = PixelFormat {
            bits_per_pixel: 16,
            depth: 16,
            red_max: 31,
            green_max: 63,
            blue_max: 31,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
            ..f
        };
        assert!(rgb565.is_valid());
        assert!(
            !PixelFormat {
                red_shift: 12,
                ..rgb565
            }
            .is_valid()
        );
        assert!(
            !PixelFormat {
                red_max: 30,
                ..rgb565
            }
            .is_valid()
        );
        assert!(
            !PixelFormat {
                depth: 17,
                ..rgb565
            }
            .is_valid()
        );
        assert!(
            !PixelFormat {
                bits_per_pixel: 24,
                ..f
            }
            .is_valid()
        );
        assert!(
            PixelFormat {
                red_max: 65535,
                red_shift: 16,
                green_max: 0,
                blue_max: 0,
                ..f
            }
            .is_valid()
        );
        // A color map format's maximums and shifts are not used.
        assert!(
            PixelFormat {
                bits_per_pixel: 8,
                depth: 8,
                true_color: false,
                red_shift: 255,
                red_max: 250,
                ..f
            }
            .is_valid()
        );
    }

    #[test]
    fn client_message_examples() {
        // RFC 6143, sections 7.5.3 to 7.5.6.
        assert_eq!(
            ClientMessage::parse(&[3, 1, 0, 0, 0, 0, 0x04, 0x00, 0x03, 0x00]),
            Ok(ClientMessage::FramebufferUpdateRequest {
                incremental: true,
                x: 0,
                y: 0,
                width: 1024,
                height: 768
            })
        );
        // Return, pressed: keysym 0xff0d.
        assert_eq!(
            ClientMessage::parse(&[4, 1, 0, 0, 0, 0, 0xff, 0x0d]),
            Ok(ClientMessage::KeyEvent {
                down: true,
                key: 0xff0d
            })
        );
        assert_eq!(
            ClientMessage::parse(&[5, 1, 0, 10, 0, 20]),
            Ok(ClientMessage::PointerEvent {
                buttons: 1,
                x: 10,
                y: 20
            })
        );
        assert_eq!(
            ClientMessage::parse(&[2, 0, 0, 2, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0x21]),
            Ok(ClientMessage::SetEncodings(vec![1, -223]))
        );
        assert_eq!(
            ClientMessage::parse(&[6, 0, 0, 0, 0, 0, 0, 2, b'h', b'i']),
            Ok(ClientMessage::ClientCutText(b"hi".to_vec()))
        );
    }

    #[test]
    fn client_messages_round_trip_and_truncate() {
        for m in sample_client_messages() {
            let bytes = m.to_bytes().unwrap();
            assert_eq!(ClientMessage::parse(&bytes), Ok(m.clone()));
            for n in 0..bytes.len() {
                assert_eq!(
                    ClientMessage::parse(&bytes[..n]),
                    Err(Error::Truncated),
                    "{m:?} cut to {n}"
                );
            }
            // And through a session, a byte at a time.
            let (mut s, _) = converse(
                Version::V3_8,
                ServerMessage::SecurityTypes(vec![1]),
                Some(1),
                Some(ServerMessage::SecurityOk),
            );
            for (i, chunk) in chunks(&bytes, &[1]).enumerate() {
                assert_eq!(s.push(chunk), chunk.len());
                if i + 1 < bytes.len() {
                    assert_eq!(s.next(), None);
                }
            }
            assert_eq!(s.next(), Some(Ok(Ok(m))));
        }
        // Handshake messages are fixed bytes.
        assert_eq!(SecurityChoice(2).to_bytes(), Ok(vec![2]));
        assert_eq!(VncResponse([5; 16]).to_bytes(), Ok(vec![5; 16]));
        assert_eq!(ClientInit { shared: false }.to_bytes(), Ok(vec![0]));
        assert!(ClientMessage::ClientInit { shared: false }.is_handshake());
        assert!(!ClientMessage::ClientCutText(vec![]).is_handshake());
    }

    #[test]
    fn server_messages_round_trip_and_truncate() {
        let f = PixelFormat::TRUE_COLOR_32;
        for m in sample_server_messages() {
            let bytes = server_bytes(&m, Dialect::V3_8, &f).unwrap();
            assert_eq!(ServerMessage::parse(&bytes, &f), Ok(m.clone()));
            for n in 0..bytes.len() {
                assert_eq!(
                    ServerMessage::parse(&bytes[..n], &f),
                    Err(Error::Truncated),
                    "{m:?} cut to {n}"
                );
            }
            let (_, mut c) = converse(
                Version::V3_8,
                ServerMessage::SecurityTypes(vec![1]),
                Some(1),
                Some(ServerMessage::SecurityOk),
            );
            for (i, chunk) in chunks(&bytes, &[1]).enumerate() {
                assert_eq!(c.push(chunk), chunk.len());
                if i + 1 < bytes.len() {
                    assert_eq!(c.next(), None);
                }
            }
            assert_eq!(c.next(), Some(Ok(Ok(m))));
        }
        assert_eq!(
            server_bytes(&ServerMessage::Bell, Dialect::V3_3, &f),
            Ok(vec![2])
        );
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
            Rectangle {
                x: 2,
                y: 3,
                width: 1,
                height: 1,
                contents: Contents::Raw(vec![0x11, 0x22, 0x33, 0]),
            },
            Rectangle {
                x: 4,
                y: 4,
                width: 2,
                height: 2,
                contents: Contents::CopyRect { src_x: 0, src_y: 0 },
            },
        ]);
        assert_eq!(
            ServerMessage::parse(&bytes, &PixelFormat::TRUE_COLOR_32),
            Ok(want)
        );
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
        assert_eq!(
            ServerMessage::parse(&rect(encoding::HEXTILE), &f),
            Err(Error::Encoding(5))
        );
        assert_eq!(
            ServerMessage::parse(&rect(-224), &f),
            Err(Error::Encoding(-224))
        );
        // Raw pixels need a valid format.
        let mut bad = f;
        bad.bits_per_pixel = 24;
        assert_eq!(
            ServerMessage::parse(&rect(encoding::RAW), &bad),
            Err(Error::BitsPerPixel(24))
        );
        assert_eq!(
            ServerMessage::parse(&rect(encoding::CURSOR), &bad),
            Err(Error::BitsPerPixel(24))
        );
        assert_eq!(
            ServerMessage::parse(&rect(encoding::COPY_RECT), &bad),
            Err(Error::Truncated)
        );
        // Text and messages past the limits.
        assert_eq!(
            ClientMessage::parse(&[6, 0, 0, 0, 0, 0x10, 0, 1]),
            Err(Error::TooLong)
        );
        assert_eq!(
            ServerMessage::parse(&[3, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], &f),
            Err(Error::TooLong)
        );
        assert_eq!(
            ClientMessage::parse(&[6, 0, 0, 0, 0, 0x10, 0, 0]),
            Err(Error::Truncated)
        );
        let mut huge = vec![0, 0, 0, 1, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        huge.extend_from_slice(&encoding::RAW.to_be_bytes());
        assert_eq!(ServerMessage::parse(&huge, &f), Err(Error::TooLong));
        // Through a session, the error sticks.
        let (mut s, _) = converse(
            Version::V3_8,
            ServerMessage::SecurityTypes(vec![1]),
            Some(1),
            Some(ServerMessage::SecurityOk),
        );
        let _ = s.push(&[9]);
        assert_eq!(
            s.next(),
            Some(Err(codec::Fail::Protocol(FrameError::MessageType(9))))
        );
        assert_eq!(s.push(&[2]), 1);
        assert_eq!(s.next(), None);
        assert_eq!(s.buffered(), 1);
        let mut s = Server::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        let _ = s.push(b"RFB 3.8\n");
        assert_eq!(
            s.next(),
            Some(Err(codec::Fail::Protocol(FrameError::Version)))
        );
        // Every error has words.
        for e in [
            Error::Version,
            Error::Encoding(5),
            Error::Phase(Phase::Normal),
            Error::Unwritable,
            Error::Truncated,
        ] {
            assert!(!e.to_string().is_empty());
        }
        for e in [
            FrameError::Version,
            FrameError::Encoding(5),
            FrameError::Phase(Phase::Normal),
            FrameError::OutOfTurn,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn writers_refuse_changes() {
        let f = PixelFormat::TRUE_COLOR_32;
        let rect = |contents| {
            ServerMessage::FramebufferUpdate(vec![Rectangle {
                x: 0,
                y: 0,
                width: 2,
                height: 2,
                contents,
            }])
        };
        assert_eq!(
            server_bytes(&rect(Contents::Raw(vec![0; 15])), Dialect::V3_8, &f),
            Err(Error::Unwritable)
        );
        assert_eq!(
            server_bytes(
                &rect(Contents::Cursor {
                    pixels: vec![0; 16],
                    mask: vec![0; 3]
                }),
                Dialect::V3_8,
                &f
            ),
            Err(Error::Unwritable)
        );
        let mut bad = f;
        bad.bits_per_pixel = 12;
        assert_eq!(
            server_bytes(&rect(Contents::Raw(vec![])), Dialect::V3_8, &bad),
            Err(Error::BitsPerPixel(12))
        );
        let many = ServerMessage::FramebufferUpdate(vec![
            Rectangle {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
                contents: Contents::DesktopSize
            };
            MAX_ITEMS + 1
        ]);
        assert_eq!(
            server_bytes(&many, Dialect::V3_8, &f),
            Err(Error::Unwritable)
        );
        // Two rectangles that are each under the limit but not together.
        let half = Rectangle {
            x: 0,
            y: 0,
            width: 4096,
            height: 4096,
            contents: Contents::Raw(vec![0; 4096 * 4096 * 4 / 2]),
        };
        let mut bad = f;
        bad.bits_per_pixel = 16;
        let both = ServerMessage::FramebufferUpdate(vec![half.clone(), half]);
        assert_eq!(
            server_bytes(&both, Dialect::V3_8, &bad),
            Err(Error::TooLong)
        );
        // Long text and lists are refused, not cut, so what is written
        // reads back the same.
        assert_eq!(
            ClientMessage::ClientCutText(vec![b'a'; MAX_TEXT + 1]).to_bytes(),
            Err(Error::TooLong)
        );
        let longest = ClientMessage::ClientCutText(vec![b'a'; MAX_TEXT]);
        let b = longest.to_bytes().unwrap();
        assert_eq!(ClientMessage::parse(&b), Ok(longest));
        assert_eq!(
            ClientMessage::SetEncodings(vec![0; MAX_ITEMS + 1]).to_bytes(),
            Err(Error::Unwritable)
        );
        let most = ClientMessage::SetEncodings(vec![0; MAX_ITEMS]);
        let b = most.to_bytes().unwrap();
        assert_eq!(ClientMessage::parse(&b), Ok(most));
        let colors = |n| ServerMessage::SetColorMapEntries {
            first: 0,
            colors: vec![
                Color {
                    red: 1,
                    green: 1,
                    blue: 1
                };
                n
            ],
        };
        assert_eq!(
            server_bytes(&colors(MAX_ITEMS + 1), Dialect::V3_8, &f),
            Err(Error::Unwritable)
        );
        let b = server_bytes(&colors(MAX_ITEMS), Dialect::V3_8, &f).unwrap();
        assert_eq!(ServerMessage::parse(&b, &f), Ok(colors(MAX_ITEMS)));
        let name = ServerMessage::ServerInit(ServerInit {
            width: 1,
            height: 1,
            format: f,
            name: vec![0; MAX_TEXT + 1],
        });
        assert_eq!(server_bytes(&name, Dialect::V3_8, &f), Err(Error::TooLong));
        for long in [
            ServerMessage::ServerCutText(vec![0; MAX_TEXT + 1]),
            ServerMessage::SecurityFailure(vec![0; MAX_TEXT + 1]),
            ServerMessage::SecurityFailed(vec![0; MAX_TEXT + 1]),
        ] {
            assert_eq!(server_bytes(&long, Dialect::V3_8, &f), Err(Error::TooLong));
        }
    }

    /// A server and a client past the handshake, with a 1024 by 768
    /// framebuffer.
    fn normal_pair() -> (Server, Client) {
        converse(
            Version::V3_8,
            ServerMessage::SecurityTypes(vec![1]),
            Some(1),
            Some(ServerMessage::SecurityOk),
        )
    }

    /// Passes a client message to the server through bytes.
    fn client_says(s: &mut Server, c: &mut Client, m: ClientMessage) {
        let _ = s.push(&c.send(&m).unwrap());
        assert_eq!(s.next(), Some(Ok(Ok(m))));
    }

    /// Passes a server message to the client through bytes.
    fn server_says(s: &mut Server, c: &mut Client, m: ServerMessage) {
        let _ = c.push(&s.send(&m).unwrap());
        assert_eq!(c.next(), Some(Ok(Ok(m))));
    }

    #[test]
    fn sends_between_pushes_keep_update_progress() {
        let check = |size| {
            // A client that sends pointer events while an update comes in does
            // not read the update's rectangles over again.
            let rects = vec![
                Rectangle {
                    x: 0,
                    y: 0,
                    width: 1,
                    height: 1,
                    contents: Contents::Raw(vec![1, 2, 3, 4])
                };
                size
            ];
            let bytes = server_bytes(
                &ServerMessage::FramebufferUpdate(rects),
                Dialect::V3_8,
                &PixelFormat::TRUE_COLOR_32,
            )
            .unwrap();
            let (_, mut c) = normal_pair();
            let _ = c.push(&bytes[..4]);
            let mut got = 0;
            for r in chunks(&bytes[4..], &[16]) {
                let _ = c.push(r);
                match c.next() {
                    Some(m) => {
                        m.unwrap().unwrap();
                        got += 1;
                    }
                    None => {
                        c.send(&ClientMessage::PointerEvent {
                            buttons: 0,
                            x: 1,
                            y: 1,
                        })
                        .unwrap();
                    }
                }
            }
            assert_eq!(got, 1);
        };
        check(MAX_ITEMS);
        assert_linear(
            "sends_between_pushes_keep_update_progress",
            MAX_ITEMS / 4,
            check,
        );
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
        let update = [
            0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        // An update half read keeps its format.
        let (_, mut c) = normal_pair();
        let _ = c.push(&update[..18]);
        assert_eq!(c.next(), None);
        assert_eq!(
            c.send(&ClientMessage::SetPixelFormat(f8)),
            Err(Error::Outstanding)
        );
        assert_eq!(c.pixel_format(), PixelFormat::TRUE_COLOR_32);
        let _ = c.push(&update[18..]);
        let Some(Ok(Ok(ServerMessage::FramebufferUpdate(r)))) = c.next() else {
            panic!()
        };
        assert_eq!(r[0].contents, Contents::Raw(vec![0xaa, 0xbb, 0xcc, 0xdd]));
        assert_eq!(
            c.send(&ClientMessage::SetPixelFormat(f8)).map(|b| b.len()),
            Ok(20)
        );
        // So does an update whose first byte alone has come.
        let (_, mut c) = normal_pair();
        let _ = c.push(&update[..1]);
        assert_eq!(c.next(), None);
        assert_eq!(
            c.send(&ClientMessage::SetPixelFormat(f8)),
            Err(Error::Outstanding)
        );
        // An outstanding request waits for its update.
        let (_, mut c) = normal_pair();
        c.send(&ClientMessage::FramebufferUpdateRequest {
            incremental: true,
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        })
        .unwrap();
        assert_eq!(
            c.send(&ClientMessage::SetPixelFormat(f8)),
            Err(Error::Outstanding)
        );
        let _ = c.push(&update);
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::SetPixelFormat(f8)).unwrap();
        assert_eq!(c.pixel_format(), f8);
        let _ = c.push(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0x5a]);
        let Some(Ok(Ok(ServerMessage::FramebufferUpdate(r)))) = c.next() else {
            panic!()
        };
        assert_eq!(r[0].contents, Contents::Raw(vec![0x5a]));
    }

    #[test]
    fn invalid_pixel_formats_are_refused() {
        // RFC 6143, section 7.4.
        let bad = PixelFormat {
            bits_per_pixel: 8,
            depth: 24,
            red_max: 250,
            red_shift: 255,
            ..PixelFormat::TRUE_COLOR_32
        };
        let mut b = vec![client_type::SET_PIXEL_FORMAT, 0, 0, 0];
        b.extend_from_slice(&[8, 24, 0, 1, 0, 250, 0, 255, 0, 255, 255, 8, 0, 0, 0, 0]);
        assert_eq!(ClientMessage::parse(&b), Err(Error::PixelFormat));
        assert_eq!(
            ClientMessage::SetPixelFormat(bad).to_bytes(),
            Err(Error::PixelFormat)
        );
        let (mut s, mut c) = normal_pair();
        assert_eq!(
            c.send(&ClientMessage::SetPixelFormat(bad)),
            Err(Error::PixelFormat)
        );
        assert_eq!(c.pixel_format(), PixelFormat::TRUE_COLOR_32);
        let _ = s.push(&b);
        assert_eq!(s.next(), Some(Ok(Err(Error::PixelFormat))));
        // A ServerInit in 24 bits per pixel is refused before the first
        // update, on both sides.
        let mut c = Client::new();
        let _ = c.push(b"RFB 003.003\n");
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_3)).unwrap();
        let _ = c.push(&[0, 0, 0, 1]);
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::ClientInit { shared: true }).unwrap();
        let f24 = PixelFormat {
            bits_per_pixel: 24,
            ..PixelFormat::TRUE_COLOR_32
        };
        let init = ServerMessage::ServerInit(ServerInit {
            width: 1,
            height: 1,
            format: f24,
            name: vec![],
        });
        assert_eq!(
            server_bytes(&init, Dialect::V3_3, &f24),
            Err(Error::PixelFormat)
        );
        let mut bytes = vec![0, 1, 0, 1];
        let mut raw = PixelFormat::TRUE_COLOR_32.to_bytes().unwrap();
        raw[0] = 24;
        bytes.extend_from_slice(&raw);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        let _ = c.push(&bytes);
        assert_eq!(c.next(), Some(Ok(Err(Error::PixelFormat))));
    }

    #[test]
    fn rectangles_stay_inside_the_framebuffer() {
        let f = PixelFormat::TRUE_COLOR_32;
        let (mut s, mut c) = converse(Version::V3_3, ServerMessage::SecurityType(1), None, None);
        client_says(
            &mut s,
            &mut c,
            ClientMessage::SetEncodings(vec![encoding::COPY_RECT, encoding::DESKTOP_SIZE]),
        );
        let update = |rects| ServerMessage::FramebufferUpdate(rects);
        let rect = |x, y, width, height, contents| Rectangle {
            x,
            y,
            width,
            height,
            contents,
        };
        let request = ClientMessage::FramebufferUpdateRequest {
            incremental: true,
            x: 0,
            y: 0,
            width: 1024,
            height: 768,
        };
        client_says(&mut s, &mut c, request.clone());
        for bad in [
            update(vec![rect(1024, 0, 1, 1, Contents::Raw(vec![0; 4]))]),
            update(vec![rect(0, 700, 1, 69, Contents::Raw(vec![0; 69 * 4]))]),
            update(vec![rect(u16::MAX, 0, 2, 0, Contents::Raw(vec![]))]),
            update(vec![rect(
                0,
                0,
                10,
                10,
                Contents::CopyRect {
                    src_x: 1020,
                    src_y: 0,
                },
            )]),
        ] {
            assert_eq!(s.send(&bad), Err(Error::Rectangle), "{bad:?}");
            let _ = c.push(&server_bytes(&bad, Dialect::V3_8, &f).unwrap());
            assert_eq!(c.next(), Some(Ok(Err(Error::Rectangle))), "{bad:?}");
        }
        // The edges are inside, and the cursor's hot spot is not checked.
        let good = update(vec![
            rect(1023, 767, 1, 1, Contents::Raw(vec![0; 4])),
            rect(1024, 768, 0, 0, Contents::Raw(vec![])),
            rect(
                0,
                0,
                24,
                8,
                Contents::CopyRect {
                    src_x: 1000,
                    src_y: 760,
                },
            ),
        ]);
        let _ = c.push(&s.send(&good).unwrap());
        assert_eq!(c.next(), Some(Ok(Ok(good))));
        // DesktopSize shrinks the framebuffer for the updates after it.
        client_says(&mut s, &mut c, request);
        let shrink = update(vec![
            rect(1000, 0, 8, 8, Contents::Raw(vec![0; 256])),
            rect(0, 0, 640, 480, Contents::DesktopSize),
        ]);
        let _ = c.push(&s.send(&shrink).unwrap());
        assert_eq!(c.next(), Some(Ok(Ok(shrink))));
        client_says(
            &mut s,
            &mut c,
            ClientMessage::FramebufferUpdateRequest {
                incremental: true,
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
        );
        let past = update(vec![rect(640, 0, 1, 1, Contents::Raw(vec![0; 4]))]);
        assert_eq!(s.send(&past), Err(Error::Rectangle));
        let _ = c.push(&server_bytes(&past, Dialect::V3_8, &f).unwrap());
        assert_eq!(c.next(), Some(Ok(Err(Error::Rectangle))));
    }

    #[test]
    fn desktop_size_comes_last() {
        // RFC 6143, section 7.8.2.
        let f = PixelFormat::TRUE_COLOR_32;
        let early = vec![
            Rectangle {
                x: 0,
                y: 0,
                width: 800,
                height: 600,
                contents: Contents::DesktopSize,
            },
            Rectangle {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
                contents: Contents::Raw(vec![0; 4]),
            },
        ];
        assert_eq!(
            server_bytes(
                &ServerMessage::FramebufferUpdate(early.clone()),
                Dialect::V3_8,
                &f
            ),
            Err(Error::Rectangle)
        );
        let late: Vec<Rectangle> = early.into_iter().rev().collect();
        let b = server_bytes(
            &ServerMessage::FramebufferUpdate(late.clone()),
            Dialect::V3_8,
            &f,
        )
        .unwrap();
        assert_eq!(
            ServerMessage::parse(&b, &f),
            Ok(ServerMessage::FramebufferUpdate(late))
        );
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
        let raw = ServerMessage::FramebufferUpdate(vec![Rectangle {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            contents: Contents::Raw(vec![0; 4]),
        }]);
        let copy = ServerMessage::FramebufferUpdate(vec![Rectangle {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            contents: Contents::CopyRect { src_x: 1, src_y: 1 },
        }]);
        let cursor = ServerMessage::FramebufferUpdate(vec![Rectangle {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            contents: Contents::Cursor {
                pixels: vec![0; 4],
                mask: vec![0x80],
            },
        }]);
        let resize = ServerMessage::FramebufferUpdate(vec![Rectangle {
            x: 0,
            y: 0,
            width: 640,
            height: 480,
            contents: Contents::DesktopSize,
        }]);
        // No request yet.
        assert_eq!(s.send(&raw), Err(Error::NotRequested));
        assert_eq!(
            s.send(&ServerMessage::FramebufferUpdate(vec![])),
            Err(Error::NotRequested)
        );
        let full = ClientMessage::FramebufferUpdateRequest {
            incremental: false,
            x: 0,
            y: 0,
            width: 1024,
            height: 768,
        };
        let incremental = ClientMessage::FramebufferUpdateRequest {
            incremental: true,
            x: 0,
            y: 0,
            width: 1024,
            height: 768,
        };
        client_says(&mut s, &mut c, full.clone());
        // Encodings the client did not list.
        for m in [&copy, &cursor, &resize] {
            assert_eq!(s.send(m), Err(Error::NotRequested), "{m:?}");
        }
        client_says(
            &mut s,
            &mut c,
            ClientMessage::SetEncodings(vec![
                encoding::COPY_RECT,
                encoding::CURSOR,
                encoding::DESKTOP_SIZE,
            ]),
        );
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
        let colors = ServerMessage::SetColorMapEntries {
            first: 0,
            colors: vec![Color {
                red: 1,
                green: 2,
                blue: 3,
            }],
        };
        assert_eq!(s.send(&colors), Err(Error::NotRequested));
        let map = PixelFormat {
            bits_per_pixel: 8,
            depth: 8,
            true_color: false,
            ..PixelFormat::TRUE_COLOR_32
        };
        client_says(&mut s, &mut c, ClientMessage::SetPixelFormat(map));
        server_says(&mut s, &mut c, colors);
        // Bell and cut text need no request.
        server_says(&mut s, &mut c, ServerMessage::Bell);
        server_says(&mut s, &mut c, ServerMessage::ServerCutText(b"x".to_vec()));
    }

    #[test]
    fn security_type_zero_is_refused() {
        // RFC 6143, section 7.1.2: 0 is Invalid.
        let mut s = Server::new();
        s.send(&ServerMessage::Version(Version::V3_8)).unwrap();
        let _ = s.push(b"RFB 003.008\n");
        s.next().unwrap().unwrap().unwrap();
        assert_eq!(
            s.send(&ServerMessage::SecurityTypes(vec![0])),
            Err(Error::Unwritable)
        );
        assert_eq!(
            s.send(&ServerMessage::SecurityTypes(vec![1, 0])),
            Err(Error::Unwritable)
        );
        assert_eq!(s.phase(), Phase::SecurityOffer);
        // A client world cannot pick 0, even from a peer that offered it.
        let mut c = Client::new();
        let _ = c.push(b"RFB 003.008\n");
        c.next().unwrap().unwrap().unwrap();
        c.send(&ClientMessage::Version(Version::V3_8)).unwrap();
        let _ = c.push(&[2, 0, 1]);
        assert_eq!(
            c.next(),
            Some(Ok(Ok(ServerMessage::SecurityTypes(vec![0, 1]))))
        );
        assert_eq!(
            c.send(&ClientMessage::SecurityType(0)),
            Err(Error::Unwritable)
        );
        assert_eq!(c.phase(), Phase::SecurityChoice);
        assert_eq!(c.send(&ClientMessage::SecurityType(1)), Ok(vec![1]));
    }

    fn server_bytes(
        message: &ServerMessage,
        dialect: Dialect,
        format: &PixelFormat,
    ) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        message.write(dialect, format, &mut out)?;
        Ok(out)
    }

    fn normal_client() -> ClientMessages {
        let mut d = ClientMessages::new();
        d.set_phase(Phase::Normal).unwrap();
        d
    }
    fn normal_server(format: PixelFormat) -> ServerMessages {
        let mut d = ServerMessages::new();
        d.set_phase(Phase::Normal, Dialect::V3_8, format).unwrap();
        d
    }

    #[test]
    fn normal_units_follow_the_contract() {
        for message in sample_client_messages() {
            let bytes = message.to_bytes().unwrap();
            contract::check_wire::<ClientMessage>(&bytes);
            contract::check_decode_with_alloc_limit(normal_client, &bytes, 2 * MAX_CLIENT_MESSAGE);
            assert_eq!(decode_all(normal_client, &bytes), (vec![Ok(message)], None));
        }
        for message in sample_server_messages() {
            let f = PixelFormat::TRUE_COLOR_32;
            let bytes = server_bytes(&message, Dialect::V3_8, &f).unwrap();
            contract::check_decode_with_alloc_limit(|| normal_server(f), &bytes, 2 * MAX_MESSAGE);
            assert_eq!(
                decode_all(|| normal_server(f), &bytes),
                (vec![Ok(message)], None)
            );
        }
        let rect = Rectangle {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
            contents: Contents::Raw(vec![1, 2, 3, 4]),
        };
        let f = PixelFormat::TRUE_COLOR_32;
        let bytes = server_bytes(
            &ServerMessage::FramebufferUpdate(vec![rect; MAX_ITEMS]),
            Dialect::V3_8,
            &f,
        )
        .unwrap();
        contract::check_decode_with_alloc_limit(|| normal_server(f), &bytes, 2 * MAX_MESSAGE);
        let bytes = ClientMessage::PointerEvent {
            buttons: 0,
            x: 1,
            y: 1,
        }
        .to_bytes()
        .unwrap()
        .repeat(rounds(20_000));
        contract::check_decode_with_alloc_limit(normal_client, &bytes, 2 * MAX_CLIENT_MESSAGE);
    }

    #[test]
    fn generated_contracts() {
        let mut rng = Lcg::new(6143);
        for _ in 0..512 {
            let mut bytes = rng.bytes(80);
            if rng.coin() {
                bytes = ClientMessage::ClientCutText(rng.text(40).into_bytes())
                    .to_bytes()
                    .unwrap();
            }
            mutate(&mut rng, &mut bytes);
            contract::check_decode_with_alloc_limit(normal_client, &bytes, 2 * MAX_CLIENT_MESSAGE);
            contract::check_decode_with_alloc_limit(
                || normal_server(PixelFormat::TRUE_COLOR_32),
                &bytes,
                2 * MAX_MESSAGE,
            );
            contract::check_decode_with_alloc_limit(
                ClientMessages::new,
                &bytes,
                2 * MAX_CLIENT_MESSAGE,
            );
            contract::check_decode_with_alloc_limit(ServerMessages::new, &bytes, 2 * MAX_MESSAGE);
            contract::check_wire::<Version>(&bytes);
            contract::check_wire::<PixelFormat>(&bytes);
            contract::check_wire::<ServerInit>(&bytes);
            contract::check_wire::<ClientMessage>(&bytes);
            contract::check_wire::<SecurityChoice>(&bytes);
            contract::check_wire::<VncResponse>(&bytes);
            contract::check_wire::<ClientInit>(&bytes);
            contract::check_wire::<Text>(&bytes);
        }
    }
    #[test]
    fn generated_messages_read_back() {
        let mut rng = Lcg::new(6143);
        for _ in 0..512 {
            let message = match rng.index(5) {
                0 => ClientMessage::SetEncodings(
                    (0..rng.index(20)).map(|_| rng.next() as i32).collect(),
                ),
                1 => ClientMessage::KeyEvent {
                    down: rng.coin(),
                    key: rng.next() as u32,
                },
                2 => ClientMessage::PointerEvent {
                    buttons: rng.next() as u8,
                    x: rng.next() as u16,
                    y: rng.next() as u16,
                },
                3 => ClientMessage::ClientCutText(rng.bytes(50)),
                _ => ClientMessage::FramebufferUpdateRequest {
                    incremental: rng.coin(),
                    x: rng.next() as u16,
                    y: rng.next() as u16,
                    width: rng.next() as u16,
                    height: rng.next() as u16,
                },
            };
            contract::check_wire_value(&message);
            let format = PixelFormat {
                bits_per_pixel: rng.next() as u8,
                depth: rng.next() as u8,
                big_endian: rng.coin(),
                true_color: rng.coin(),
                red_max: rng.next() as u16,
                green_max: rng.next() as u16,
                blue_max: rng.next() as u16,
                red_shift: rng.next() as u8,
                green_shift: rng.next() as u8,
                blue_shift: rng.next() as u8,
            };
            contract::check_wire_value(&format);
            contract::check_wire_value(&ClientMessage::SetPixelFormat(format));
            let bpp = [8, 16, 32][rng.index(3)];
            let format = PixelFormat {
                bits_per_pixel: bpp,
                depth: bpp,
                true_color: false,
                ..PixelFormat::TRUE_COLOR_32
            };
            let count = rng.index(4);
            let mut rects = Vec::new();
            for i in 0..count {
                let (width, height) = (rng.index(9) as u16, rng.index(9) as u16);
                let mut pixels =
                    vec![0; usize::from(width) * usize::from(height) * usize::from(bpp / 8)];
                rng.fill(&mut pixels);
                let contents = match rng.index(if i + 1 == count { 4 } else { 3 }) {
                    0 => Contents::Raw(pixels),
                    1 => Contents::CopyRect {
                        src_x: rng.next() as u16,
                        src_y: rng.next() as u16,
                    },
                    2 => {
                        let mut mask =
                            vec![0; usize::from(width).div_ceil(8) * usize::from(height)];
                        rng.fill(&mut mask);
                        Contents::Cursor { pixels, mask }
                    }
                    _ => Contents::DesktopSize,
                };
                rects.push(Rectangle {
                    x: rng.next() as u16,
                    y: rng.next() as u16,
                    width,
                    height,
                    contents,
                });
            }
            let message = ServerMessage::FramebufferUpdate(rects);
            let mut bytes = vec![7, 8];
            message.write(Dialect::V3_8, &format, &mut bytes).unwrap();
            assert_eq!(ServerMessage::parse(&bytes[2..], &format), Ok(message));
        }
    }
}
