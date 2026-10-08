//! Cboe US Equities Multicast PITCH: the Sequenced Unit Header framing,
//! every PITCH 2.X message and every Gap Request Proxy and Spin Server
//! message as a [`Wire`] value, a framer for the TCP side, a gap detector
//! per unit, and a bounded order book, with no I/O.
//!
//! PITCH is Cboe's depth-of-book market data feed for its BYX, BZX, EDGA
//! and EDGX equities exchanges (and, with a few extra types and trailing
//! bytes, its options exchanges). This module follows the
//! [Cboe Titanium U.S. Equities/Options Multicast PITCH Specification](https://cdn.cboe.com/resources/techspec/technical-specifications-cboe-titanium-u-s-equitiesoptions-multicast-pitch-specification.pdf),
//! version 2.41.82 of October 2, 2026. Section names below are that
//! document's.
//!
//! Every datagram, and every block on a Gap Request Proxy (GRP) or Spin
//! Server TCP connection, is one [`Unit`]: an eight-byte Sequenced Unit
//! Header (length, count, unit, sequence) and `count` messages. Each
//! message starts with its own one-byte length and a type byte. Binary
//! fields are unsigned and little-endian; alphanumeric fields are ASCII
//! padded on the right with spaces ([`Alpha`]); long prices have four
//! implied decimal places ([`Price`]) and short prices two
//! ([`ShortPrice`]) ("Data Types"). One-byte code fields are kept as the
//! byte (`u8`); [`codes`] names the listed values.
//!
//! Cboe "reserves the right to add message types and grow the length of
//! any message" ("Message Format"). So [`Message::parse`] reads a type it
//! does not know as [`Message::Unknown`], and every message keeps the
//! bytes past the fields it knows in `extra`, so it writes back as read.
//! The options variants of Order Executed, Order Executed at Price/Size
//! and Trade carry a Trade Condition byte in `extra`; the options layout
//! of Trading Status shares its offsets with the equities one
//! ([`TradingStatus`]).
//!
//! [`GapDetector`] follows each unit's sequence numbers across the
//! rollover from 4,294,967,295 to 1 ("Symbol Ranges, Units, and Sequence
//! Numbers") and names the [`Gap`] to request from the GRP. [`Book`]
//! applies the order messages to per-symbol bid and ask levels.
//!
//! ```
//! use fictionet::stdlib::cboe_pitch::{
//!     AddOrderShort, Alpha, Book, BookConfig, GapDetector, Message, ReduceSizeShort, ShortPrice,
//!     Side, Unit,
//! };
//! use fictionet::stdlib::codec::Wire;
//!
//! // "Sequenced Unit Header with 2 Messages": an Add Order and a Reduce
//! // Size on unit 1, sequence 1.
//! let add = AddOrderShort {
//!     time_offset: 447_000,
//!     order_id: 0x0b1d_568f_775b_4005,
//!     side: Side::Buy,
//!     quantity: 737,
//!     symbol: Alpha::right_padded("ZVZZT")?,
//!     price: ShortPrice(1),
//!     flags: 1,
//!     extra: Vec::new(),
//! };
//! let reduce = ReduceSizeShort {
//!     time_offset: 449_000,
//!     order_id: add.order_id,
//!     canceled_quantity: 737,
//!     extra: Vec::new(),
//! };
//! let unit = Unit::of(1, 1, &[add.into(), reduce.into()])?;
//! let datagram = unit.to_bytes()?;
//! assert_eq!(datagram.len(), 50);
//!
//! // A feed handler checks the sequence, then applies each message.
//! let mut gaps = GapDetector::new();
//! let mut book = Book::new(BookConfig::default())?;
//! let unit = Unit::parse(&datagram)?;
//! let seen = gaps.receive(&unit);
//! assert_eq!((seen.skip, seen.count, seen.gap), (0, 2, None));
//! let mut messages = unit.messages.iter().map(|m| Message::parse(m));
//! book.apply(unit.unit, &messages.next().unwrap()?)?;
//! let symbol = Alpha::right_padded("ZVZZT")?;
//! assert_eq!(book.best_bid(symbol).unwrap().quantity, 737);
//! book.apply(unit.unit, &messages.next().unwrap()?)?;
//! assert_eq!(book.best_bid(symbol), None);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use fictionet::stdlib::codec::field;
use fictionet::stdlib::codec::Prefixed;
#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::{Wire};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

/// Bytes in the Sequenced Unit Header.
pub const HEADER_LENGTH: usize = 8;
/// The largest unit the two-byte Hdr Length can describe.
pub const MAX_UNIT_LENGTH: usize = u16::MAX as usize;
/// The most messages one header can count.
pub const MAX_MESSAGES: usize = u8::MAX as usize;
/// The longest message its one-byte Length can describe.
pub const MAX_MESSAGE_LENGTH: usize = u8::MAX as usize;
/// The highest sequence number; the next is 1, never 0 ("Symbol Ranges,
/// Units, and Sequence Numbers").
pub const MAX_SEQUENCE: u32 = u32::MAX;
/// The most messages one Gap Request asks for: its Count is two bytes.
pub const MAX_GAP_COUNT: u32 = u16::MAX as u32;

/// The default most live orders a [`Book`] holds.
pub const DEFAULT_MAX_ORDERS: usize = 1 << 20;
/// The most live orders a [`Book`] may be configured to hold.
pub const MAX_ORDERS: usize = 1 << 26;
/// The default most price levels, over every symbol and side, of a [`Book`].
pub const DEFAULT_MAX_LEVELS: usize = 1 << 18;
/// The most price levels a [`Book`] may be configured to hold.
pub const MAX_LEVELS: usize = 1 << 24;
/// The default most symbols with orders a [`Book`] tracks.
pub const DEFAULT_MAX_SYMBOLS: usize = 16_384;
/// The most symbols a [`Book`] may be configured to track.
pub const MAX_SYMBOLS: usize = 1 << 20;

/// Why bytes or a value were refused, or why a [`Book`] refused a
/// message. A refused message leaves the book unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A message's Length byte disagrees with its bytes, or is shorter
    /// than the type's fields; or a unit's Hdr Length disagrees with its
    /// bytes or messages.
    Length,
    /// Bytes of another message type than the one asked for, or an
    /// [`Unknown`] message written with a type this module defines.
    Type(u8),
    /// Text for an alphanumeric field is longer than the field or not
    /// printable ASCII.
    Field,
    /// A side indicator other than "B" or "S".
    Side(u8),
    /// A unit's Hdr Count disagrees with the messages that follow, or a
    /// unit to write has more than [`MAX_MESSAGES`].
    Count,
    /// A decimal price with more places than the field, or too large.
    Price,
    /// A unit longer than the framer's limit, or than [`MAX_UNIT_LENGTH`].
    TooLong,
    /// A configuration value outside its named limits.
    Config,
    /// An execute, reduce, modify or delete names an order not on the book.
    UnknownOrder(u64),
    /// An add reuses an Order Id on the book.
    DuplicateOrder(u64),
    /// An add with zero shares, or an execute or reduce of more shares
    /// than the order has.
    Shares(u64),
    /// The message's unit differs from the order's.
    Unit(u64),
    /// The book holds [`BookConfig::max_orders`] orders.
    TooManyOrders,
    /// The book holds [`BookConfig::max_levels`] price levels.
    TooManyLevels,
    /// The book holds orders for [`BookConfig::max_symbols`] symbols.
    TooManySymbols,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Length => f.write_str("PITCH length is wrong"),
            Error::Type(t) => write!(f, "unexpected PITCH message type {t:#04x}"),
            Error::Field => f.write_str("PITCH alphanumeric field is invalid"),
            Error::Side(s) => write!(f, "invalid PITCH side indicator {s:#04x}"),
            Error::Count => f.write_str("PITCH message count is wrong"),
            Error::Price => f.write_str("PITCH price is invalid"),
            Error::TooLong => f.write_str("PITCH unit is too long"),
            Error::Config => f.write_str("PITCH book configuration is out of range"),
            Error::UnknownOrder(id) => write!(f, "PITCH order {id} is not on the book"),
            Error::DuplicateOrder(id) => write!(f, "PITCH order {id} is already on the book"),
            Error::Shares(id) => write!(f, "PITCH order {id} share count is invalid"),
            Error::Unit(id) => write!(f, "PITCH order {id} belongs to another unit"),
            Error::TooManyOrders => f.write_str("PITCH book order limit reached"),
            Error::TooManyLevels => f.write_str("PITCH book price level limit reached"),
            Error::TooManySymbols => f.write_str("PITCH book symbol limit reached"),
        }
    }
}
impl std::error::Error for Error {}

/// One fixed-width field: its size, and how it reads and writes.
trait Field: Sized {
    const LEN: usize;
    /// Reads exactly `LEN` bytes.
    fn get(b: &[u8]) -> Result<Self, Error>;
    fn put(&self, out: &mut Vec<u8>);
}
/// Reads the next field from `b` and moves past it.
fn take<T: Field>(b: &mut &[u8]) -> Result<T, Error> {
    let (head, rest) = b.split_at_checked(T::LEN).ok_or(Error::Length)?;
    *b = rest;
    T::get(head)
}
fn array<const N: usize>(b: &[u8]) -> Result<[u8; N], Error> {
    b.try_into().map_err(|_| Error::Length)
}
macro_rules! int_field {
    ($($t:ty),*) => {$(
        impl Field for $t {
            const LEN: usize = size_of::<$t>();
            fn get(b: &[u8]) -> Result<Self, Error> {
                Ok(<$t>::from_le_bytes(array(b)?))
            }
            fn put(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }
        }
    )*};
}
int_field!(u8, u16, u32, u64);

/// A Binary Long Price: eight bytes with four implied decimal places. The
/// raw value 9050 is $0.9050 ("Data Types").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Price(pub u64);
impl fmt::Display for Price {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        field::write_decimal(f, self.0, 4)
    }
}
impl FromStr for Price {
    type Err = Error;
    /// Reads "102.5" or "102" as dollars; refuses more than four places.
    fn from_str(s: &str) -> Result<Self, Error> {
        field::parse_decimal(s, 4).map_err(|_| Error::Price).map(Self)
    }
}
impl Field for Price {
    const LEN: usize = 8;
    fn get(b: &[u8]) -> Result<Self, Error> {
        u64::get(b).map(Self)
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
    }
}

/// A Binary Short Price: two bytes with two implied decimal places. The
/// raw value 10250 is $102.50 ("Data Types").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortPrice(pub u16);
impl ShortPrice {
    /// The same price with four places, as a long price.
    pub fn to_price(self) -> Price {
        Price(u64::from(self.0) * 100)
    }
}
impl fmt::Display for ShortPrice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        field::write_decimal(f, u64::from(self.0), 2)
    }
}
impl FromStr for ShortPrice {
    type Err = Error;
    /// Reads "102.5" as dollars; refuses more than two places.
    fn from_str(s: &str) -> Result<Self, Error> {
        u16::try_from(field::parse_decimal(s, 2).map_err(|_| Error::Price)?)
            .map(Self)
            .map_err(|_| Error::Price)
    }
}
impl Field for ShortPrice {
    const LEN: usize = 2;
    fn get(b: &[u8]) -> Result<Self, Error> {
        u16::get(b).map(Self)
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
    }
}

/// A fixed-width alphanumeric field, left justified and padded on the
/// right with spaces ("Data Types"). Bytes are kept exactly as read, so
/// fields round-trip byte for byte. Parsing accepts any byte: Cboe's
/// Reserved bytes can sit inside a field of this type (the options layout
/// of [`TradingStatus`] keeps two in `symbol`), and a feed may fill them
/// with NUL. [`right_padded`](Self::right_padded) builds only printable
/// ASCII.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Alpha<const N: usize>([u8; N]);
impl<const N: usize> Alpha<N> {
    /// All spaces.
    pub fn blank() -> Self {
        Self([b' '; N])
    }
    /// The field's exact bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
    /// `text` padded on the right with spaces. Refuses text longer than
    /// the field or with a byte outside printable ASCII (0x20..=0x7e).
    pub fn right_padded(text: &str) -> Result<Self, Error> {
        if text.len() > N || !text.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(Error::Field);
        }
        let mut bytes = [b' '; N];
        bytes
            .get_mut(..text.len())
            .ok_or(Error::Field)?
            .copy_from_slice(text.as_bytes());
        Ok(Self(bytes))
    }
    /// The field's bytes, padding included.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
    /// The text: the bytes up to the first one outside printable ASCII
    /// (NUL fill, reserved bytes), without trailing spaces.
    pub fn trimmed(&self) -> &str {
        let end = self
            .0
            .iter()
            .position(|b| !(0x20..=0x7e).contains(b))
            .unwrap_or(N);
        // Every byte before `end` is printable ASCII, so this is UTF-8.
        std::str::from_utf8(self.0.get(..end).unwrap_or_default())
            .unwrap_or_default()
            .trim_end_matches(' ')
    }
    /// The same text in a field of `M` bytes, padded with spaces. Refuses
    /// text that does not fit.
    pub fn resized<const M: usize>(&self) -> Result<Alpha<M>, Error> {
        Alpha::right_padded(self.trimmed())
    }
}
impl<const N: usize> fmt::Debug for Alpha<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.escape_ascii())
    }
}
impl<const N: usize> Field for Alpha<N> {
    const LEN: usize = N;
    fn get(b: &[u8]) -> Result<Self, Error> {
        array(b).map(Self)
    }
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

/// A side indicator ("Add Order Message Fields").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// "B": a buy order, on the bid side of the book.
    Buy,
    /// "S": a sell order, on the ask side of the book.
    Sell,
}
impl Side {
    /// The byte on the wire.
    pub fn code(self) -> u8 {
        match self {
            Side::Buy => b'B',
            Side::Sell => b'S',
        }
    }
}
impl Field for Side {
    const LEN: usize = 1;
    fn get(b: &[u8]) -> Result<Self, Error> {
        match u8::get(b)? {
            b'B' => Ok(Side::Buy),
            b'S' => Ok(Side::Sell),
            other => Err(Error::Side(other)),
        }
    }
    fn put(&self, out: &mut Vec<u8>) {
        out.push(self.code());
    }
}

/// A six-byte symbol, as the long and short messages carry it.
pub type Symbol6 = Alpha<6>;
/// An eight-byte symbol, as the expanded messages carry it. [`Book`] keys
/// every order by this width.
pub type Symbol = Alpha<8>;

/// A message whose type this module does not define. Cboe may add types
/// without notice ("Message Format").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unknown {
    /// The type byte.
    pub kind: u8,
    /// The bytes after the type byte.
    pub body: Vec<u8>,
}

/// Defines one family's messages: a struct per message with its fixed
/// fields (their total checked at compile time against the
/// specification's Total Length) and the bytes past them; then the enum
/// over them, with [`Unknown`] for any other type.
macro_rules! messages {
    (
        $(#[doc = $edoc:literal])*
        $enum:ident;
        $(
            $(#[doc = $doc:literal])*
            $name:ident = $kind:literal, $len:literal {
                $( $(#[doc = $fdoc:literal])* $field:ident: $ty:ty, )*
            }
        )*
    ) => {
        $(
            $(#[doc = $doc])*
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct $name {
                $( $(#[doc = $fdoc])* pub $field: $ty, )*
                /// Bytes after the fields this revision defines, kept so
                /// the message writes back as read. Empty for a message of
                /// exactly the specified length.
                pub extra: Vec<u8>,
            }
            impl $name {
                /// The message type byte.
                pub const KIND: u8 = $kind;
                /// The specified Total Length, Length and type bytes
                /// included.
                pub const LEN: usize = $len;
                #[allow(unused_mut)]
                fn read_body(mut b: &[u8]) -> Result<Self, Error> {
                    $( let $field = take(&mut b)?; )*
                    Ok(Self { $($field,)* extra: b.to_vec() })
                }
                /// Bytes on the wire.
                pub fn wire_len(&self) -> usize {
                    $len + self.extra.len()
                }
                fn write_body(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                    let len = u8::try_from(self.wire_len()).map_err(|_| Error::Length)?;
                    out.reserve(self.wire_len());
                    out.push(len);
                    out.push(Self::KIND);
                    $( Field::put(&self.$field, out); )*
                    out.extend_from_slice(&self.extra);
                    Ok(())
                }
            }
            const _: () = assert!(2 $(+ <$ty as Field>::LEN)* == $len);
            impl Wire for $name {
                type ParseError = Error;
                type WriteError = Error;
                /// Reads one whole message of this type, Length byte first.
                fn parse(b: &[u8]) -> Result<Self, Error> {
                    let kind = framed(b)?;
                    if kind != $kind {
                        return Err(Error::Type(kind));
                    }
                    if b.len() < $len {
                        return Err(Error::Length);
                    }
                    Self::read_body(b.get(2..).unwrap_or_default())
                }
                /// Writes the message. Refuses one longer than
                /// [`MAX_MESSAGE_LENGTH`].
                fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                    self.write_body(out)
                }
            }
            impl From<$name> for $enum {
                fn from(m: $name) -> Self {
                    $enum::$name(m)
                }
            }
        )*

        $(#[doc = $edoc])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum $enum {
            $(
                #[doc = concat!("A [`", stringify!($name), "`].")]
                $name($name),
            )*
            /// A type this module does not define.
            Unknown(Unknown),
        }
        impl $enum {
            /// The message type byte.
            pub fn kind(&self) -> u8 {
                match self {
                    $( $enum::$name(_) => $kind, )*
                    $enum::Unknown(u) => u.kind,
                }
            }
            /// Bytes on the wire.
            pub fn wire_len(&self) -> usize {
                match self {
                    $( $enum::$name(m) => m.wire_len(), )*
                    $enum::Unknown(u) => 2 + u.body.len(),
                }
            }
            /// The specified length of messages of type `kind`, or `None`
            /// for a type this module does not define.
            pub fn length_of(kind: u8) -> Option<usize> {
                match kind {
                    $( $kind => Some($len), )*
                    _ => None,
                }
            }
            /// Every type byte this module defines, in specification order.
            pub const KINDS: &'static [u8] = &[$($kind),*];
        }
        impl Wire for $enum {
            type ParseError = Error;
            type WriteError = Error;
            /// Reads one whole message, Length byte first. A type this
            /// module does not define reads as `Unknown`.
            fn parse(b: &[u8]) -> Result<Self, Error> {
                let kind = framed(b)?;
                let body = b.get(2..).unwrap_or_default();
                match kind {
                    $(
                        $kind => {
                            if b.len() < $len {
                                return Err(Error::Length);
                            }
                            $name::read_body(body).map($enum::$name)
                        }
                    )*
                    other => Ok($enum::Unknown(Unknown { kind: other, body: body.to_vec() })),
                }
            }
            /// Writes the message. Refuses one longer than
            /// [`MAX_MESSAGE_LENGTH`], and an `Unknown` with a defined type.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                match self {
                    $( $enum::$name(m) => m.write_body(out), )*
                    $enum::Unknown(u) => {
                        if Self::length_of(u.kind).is_some() {
                            return Err(Error::Type(u.kind));
                        }
                        let len = u8::try_from(2 + u.body.len()).map_err(|_| Error::Length)?;
                        out.reserve(usize::from(len));
                        out.push(len);
                        out.push(u.kind);
                        out.extend_from_slice(&u.body);
                        Ok(())
                    }
                }
            }
        }
    };
}

/// Checks a message's Length byte against its bytes and returns its type.
fn framed(b: &[u8]) -> Result<u8, Error> {
    match b {
        [len, kind, ..] if usize::from(*len) == b.len() => Ok(*kind),
        _ => Err(Error::Length),
    }
}

messages! {
    /// Any PITCH 2.X message ("PITCH 2.X Messages").
    Message;

    /// 0xB1, Time Reference: the midnight reference for later Time
    /// messages, and the trade date. Effective 11/02/26 on BZX and EDGX
    /// Equities.
    TimeReference = 0xB1, 18 {
        /// Midnight Eastern Time, in seconds since the Unix epoch.
        midnight_reference: u32,
        /// Whole seconds since the start of the Eastern Time day.
        time: u32,
        /// Nanoseconds since `time`.
        time_offset: u32,
        /// The trade date as YYYYMMDD.
        trade_date: u32,
    }

    /// 0x20, Time: the unit's clock second; later Time Offsets count from
    /// it. The 10-byte form adds Epoch Time, kept in `extra` (see
    /// [`Time::epoch_time`]).
    Time = 0x20, 6 {
        /// Whole seconds since midnight Eastern Time.
        time: u32,
    }

    /// 0x97, Unit Clear: clear every order of the unit.
    UnitClear = 0x97, 6 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
    }

    /// 0xBC, Transaction Begin (options only).
    TransactionBegin = 0xBC, 6 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
    }

    /// 0xBD, Transaction End (options only).
    TransactionEnd = 0xBD, 6 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
    }

    /// 0x21, Add Order (long): a new visible order.
    AddOrderLong = 0x21, 34 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The day-specific order identifier.
        order_id: u64,
        /// The side.
        side: Side,
        /// Shares added to the book.
        quantity: u32,
        /// The symbol.
        symbol: Symbol6,
        /// The limit price.
        price: Price,
        /// Add Flags: bit 0 reserved and set, bit 3 AON (options).
        flags: u8,
    }

    /// 0x22, Add Order (short).
    AddOrderShort = 0x22, 26 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The day-specific order identifier.
        order_id: u64,
        /// The side.
        side: Side,
        /// Shares added to the book.
        quantity: u16,
        /// The symbol.
        symbol: Symbol6,
        /// The limit price.
        price: ShortPrice,
        /// Add Flags.
        flags: u8,
    }

    /// 0x2F, Add Order (expanded), equities layout. Options add Client ID
    /// and five reserved bytes, kept in `extra`.
    AddOrderExpanded = 0x2F, 41 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The day-specific order identifier.
        order_id: u64,
        /// The side.
        side: Side,
        /// Shares added to the book.
        quantity: u32,
        /// The symbol.
        symbol: Symbol,
        /// The limit price.
        price: Price,
        /// Add Flags.
        flags: u8,
        /// The attributed MPID, "RTAL", or spaces.
        participant_id: Alpha<4>,
        /// "N", "C", "R" (EDGX retail priority), or a space.
        customer_indicator: u8,
    }

    /// 0x23, Order Executed, equities layout: shares of a book order
    /// executed at its price. Options add a Trade Condition byte.
    OrderExecuted = 0x23, 26 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order executed.
        order_id: u64,
        /// Shares executed.
        executed_quantity: u32,
        /// The day-unique execution identifier.
        execution_id: u64,
    }

    /// 0x24, Order Executed at Price/Size, equities layout.
    OrderExecutedAtPrice = 0x24, 38 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order executed.
        order_id: u64,
        /// Shares executed.
        executed_quantity: u32,
        /// Shares left on the book; 0 removes the order.
        remaining_quantity: u32,
        /// The day-unique execution identifier.
        execution_id: u64,
        /// The execution price.
        price: Price,
    }

    /// 0x25, Reduce Size (long): shares canceled from a book order.
    ReduceSizeLong = 0x25, 18 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order reduced.
        order_id: u64,
        /// Shares canceled.
        canceled_quantity: u32,
    }

    /// 0x26, Reduce Size (short).
    ReduceSizeShort = 0x26, 16 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order reduced.
        order_id: u64,
        /// Shares canceled.
        canceled_quantity: u16,
    }

    /// 0x27, Modify Order (long): a book order's size and price after a
    /// modify.
    ModifyOrderLong = 0x27, 27 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order modified.
        order_id: u64,
        /// Shares after the modify.
        quantity: u32,
        /// The price after the modify.
        price: Price,
        /// Modify Flags: bit 0 display, bit 1 maintain priority.
        flags: u8,
    }

    /// 0x28, Modify Order (short).
    ModifyOrderShort = 0x28, 19 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order modified.
        order_id: u64,
        /// Shares after the modify.
        quantity: u16,
        /// The price after the modify.
        price: ShortPrice,
        /// Modify Flags.
        flags: u8,
    }

    /// 0x29, Delete Order: the order leaves the book. The same Order Id may
    /// be added again later.
    DeleteOrder = 0x29, 14 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order removed.
        order_id: u64,
    }

    /// 0x2A, Trade (long), equities layout: an execution of a hidden or
    /// routed order. It does not change the book.
    TradeLong = 0x2A, 41 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order executed, usually obfuscated.
        order_id: u64,
        /// Always "B".
        side: Side,
        /// Shares executed.
        quantity: u32,
        /// The symbol.
        symbol: Symbol6,
        /// The execution price.
        price: Price,
        /// The day-unique execution identifier.
        execution_id: u64,
    }

    /// 0x2B, Trade (short), equities layout.
    TradeShort = 0x2B, 33 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order executed, usually obfuscated.
        order_id: u64,
        /// Always "B".
        side: Side,
        /// Shares executed.
        quantity: u16,
        /// The symbol.
        symbol: Symbol6,
        /// The execution price.
        price: ShortPrice,
        /// The day-unique execution identifier.
        execution_id: u64,
    }

    /// 0x30, Trade (expanded), equities layout.
    TradeExpanded = 0x30, 43 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The order executed, usually obfuscated.
        order_id: u64,
        /// Always "B".
        side: Side,
        /// Shares executed.
        quantity: u32,
        /// The symbol.
        symbol: Symbol,
        /// The execution price.
        price: Price,
        /// The day-unique execution identifier.
        execution_id: u64,
    }

    /// 0x2C, Trade Break: an execution was broken.
    TradeBreak = 0x2C, 14 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The execution broken.
        execution_id: u64,
    }

    /// 0x2D, End of Session: the unit sends no more sequenced messages.
    EndOfSession = 0x2D, 6 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
    }

    /// 0x2E, Symbol Mapping (options only, unsequenced).
    SymbolMapping = 0x2E, 38 {
        /// The six-character feed symbol.
        feed_symbol: Symbol6,
        /// The OSI symbol.
        osi_symbol: Alpha<21>,
        /// "N" normal, "C" closing only.
        symbol_condition: u8,
        /// The underlying.
        underlying: Symbol,
    }

    /// 0x31, Trading Status, equities layout. The options layout has the
    /// same length: a six-byte symbol and two reserved bytes in `symbol`,
    /// and the GTH Trading Status in `reserved1`.
    TradingStatus = 0x31, 18 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The symbol.
        symbol: Symbol,
        /// See [`codes::trading_status`].
        trading_status: u8,
        /// "0" no Reg SHO price test, "1" restriction in effect.
        reg_sho_action: u8,
        /// Reserved.
        reserved1: u8,
        /// Reserved.
        reserved2: u8,
    }

    /// 0xD2, Width Update (options only).
    WidthUpdate = 0xD2, 19 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The underlying.
        underlying: Symbol,
        /// "Q", "R" or "V".
        width_type: u8,
        /// The multiplier with one implied decimal place.
        multiplier: u32,
    }

    /// 0x95, Auction Update (BYX and BZX Equities).
    AuctionUpdate = 0x95, 47 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The symbol.
        symbol: Symbol,
        /// See [`codes::auction_type`].
        auction_type: u8,
        /// The collared auction price.
        reference_price: Price,
        /// Buy shares at the reference price.
        buy_shares: u32,
        /// Sell shares at the reference price.
        sell_shares: u32,
        /// Where the auction and continuous books would match.
        indicative_price: Price,
        /// Where eligible auction orders alone would match.
        auction_only_price: Price,
    }

    /// 0xD1, Options Auction Update (options only).
    OptionsAuctionUpdate = 0xD1, 64 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The symbol.
        symbol: Symbol,
        /// "G", "O", "H" or "V".
        auction_type: u8,
        /// The collared price on the queuing book.
        reference_price: Price,
        /// Buy contracts at the reference price and above.
        buy_contracts: u32,
        /// Sell contracts at the reference price and below.
        sell_contracts: u32,
        /// The collared price on both books.
        indicative_price: Price,
        /// The uncollared price on the queuing book.
        auction_only_price: Price,
        /// "O", "Q", "B", "S" or "C".
        opening_condition: u8,
        /// The composite market bid.
        composite_bid_price: Price,
        /// The composite market offer.
        composite_offer_price: Price,
    }

    /// 0x96, Auction Summary: an auction's result.
    AuctionSummary = 0x96, 27 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The symbol.
        symbol: Symbol,
        /// See [`codes::auction_type`].
        auction_type: u8,
        /// The auction price.
        price: Price,
        /// Shares executed.
        shares: u32,
    }

    /// 0xAD, Auction Notification (options only).
    AuctionNotification = 0xAD, 47 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The symbol.
        symbol: Symbol6,
        /// The day-specific auction identifier.
        auction_id: u64,
        /// "B", "S", "T" or "A".
        auction_type: u8,
        /// The side.
        side: Side,
        /// The price.
        price: Price,
        /// Contracts in the auction.
        contracts: u32,
        /// "N" or "C".
        customer_indicator: u8,
        /// The executing broker, or spaces.
        participant_id: Alpha<4>,
        /// The auction's end, in nanoseconds since the unit's last Time.
        auction_end_offset: u32,
        /// The client identifier, or spaces.
        client_id: Alpha<4>,
    }

    /// 0xAE, Auction Cancel (options only).
    AuctionCancel = 0xAE, 14 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The auction canceled.
        auction_id: u64,
    }

    /// 0xAF, Auction Trade (options only).
    AuctionTrade = 0xAF, 34 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The auction.
        auction_id: u64,
        /// The execution.
        execution_id: u64,
        /// The trade price.
        price: Price,
        /// Contracts traded.
        contracts: u32,
    }

    /// 0x98, Retail Price Improvement (BYX and EDGX).
    RetailPriceImprovement = 0x98, 15 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The symbol.
        symbol: Symbol,
        /// "B", "S", "A" (both) or "N" (none).
        retail_price_improvement: u8,
    }

    /// 0x9D, SOQ Strike Range Update (C1 only).
    SoqStrikeRangeUpdate = 0x9D, 42 {
        /// Nanoseconds since the unit's last Time.
        time_offset: u32,
        /// The SOQ's dissemination symbol.
        soq_identifier: Alpha<20>,
        /// The lower strike price.
        lower_strike_price: Price,
        /// The upper strike price.
        upper_strike_price: Price,
    }

    /// 0x9E, Constituent Symbol Mapping (C1 only, unsequenced).
    ConstituentSymbolMapping = 0x9E, 58 {
        /// The six-character feed symbol.
        feed_symbol: Symbol6,
        /// The OSI symbol.
        osi_symbol: Alpha<21>,
        /// "N" normal, "C" closing only.
        symbol_condition: u8,
        /// The underlying.
        underlying: Symbol,
        /// The SOQ's dissemination symbol.
        soq_identifier: Alpha<20>,
    }
}

messages! {
    /// Any Gap Request Proxy or Spin Server message ("Gap Request Proxy
    /// Messages", "Spin Messages"). Both servers share Login and Login
    /// Response.
    Control;

    /// 0x01, Login: the first message to a GRP or Spin Server.
    Login = 0x01, 22 {
        /// The SessionSubId supplied by Cboe.
        session_sub_id: Alpha<4>,
        /// The username supplied by Cboe.
        username: Alpha<4>,
        /// Space filled.
        filler: Alpha<2>,
        /// The password supplied by Cboe.
        password: Alpha<10>,
    }

    /// 0x02, Login Response.
    LoginResponse = 0x02, 3 {
        /// See [`codes::login_status`].
        status: u8,
    }

    /// 0x03, Gap Request: retransmit `count` messages from `sequence`.
    GapRequest = 0x03, 9 {
        /// The unit.
        unit: u8,
        /// The first sequence requested.
        sequence: u32,
        /// Messages requested.
        count: u16,
    }

    /// 0x04, Gap Response.
    GapResponse = 0x04, 10 {
        /// The unit requested.
        unit: u8,
        /// The first sequence requested.
        sequence: u32,
        /// Messages requested.
        count: u16,
        /// See [`codes::gap_status`].
        status: u8,
    }

    /// 0x80, Spin Image Available: a spin is current through `sequence`.
    SpinImageAvailable = 0x80, 6 {
        /// The last sequence the spin includes.
        sequence: u32,
    }

    /// 0x81, Spin Request.
    SpinRequest = 0x81, 6 {
        /// A sequence from a Spin Image Available message.
        sequence: u32,
    }

    /// 0x82, Spin Response.
    SpinResponse = 0x82, 11 {
        /// The sequence requested.
        sequence: u32,
        /// Add Order messages the spin will hold.
        order_count: u32,
        /// See [`codes::spin_status`].
        status: u8,
    }

    /// 0x83, Spin Finished.
    SpinFinished = 0x83, 6 {
        /// The sequence requested.
        sequence: u32,
    }

    /// 0x84, Instrument Definition Request.
    InstrumentDefinitionRequest = 0x84, 6 {
        /// Must be 0.
        sequence: u32,
    }

    /// 0x85, Instrument Definition Response.
    InstrumentDefinitionResponse = 0x85, 11 {
        /// Always 0.
        sequence: u32,
        /// Instruments the spin will hold.
        instrument_count: u32,
        /// See [`codes::spin_status`].
        status: u8,
    }

    /// 0x86, Instrument Definition Finished.
    InstrumentDefinitionFinished = 0x86, 2 {
    }
}

impl Time {
    /// The Epoch Time field of the 10-byte form: seconds since the Unix
    /// epoch, sent on C1 Options and, from 11/02/26, BZX and EDGX Equities.
    pub fn epoch_time(&self) -> Option<u32> {
        self.extra
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    }
}

/// The values the specification lists for one-byte code fields.
pub mod codes {
    /// Trading Status values (equities and options).
    pub mod trading_status {
        /// Accepting orders for queuing (equities).
        pub const ACCEPTING: u8 = b'A';
        /// Halted.
        pub const HALTED: u8 = b'H';
        /// Curb trading (C1 only).
        pub const CURB: u8 = b'L';
        /// Quote-only.
        pub const QUOTE_ONLY: u8 = b'Q';
        /// Opening rotation (options).
        pub const OPENING_ROTATION: u8 = b'R';
        /// Exchange-specific suspension (equities).
        pub const SUSPENDED: u8 = b'S';
        /// Trading.
        pub const TRADING: u8 = b'T';
    }
    /// Auction types (Auction Update, Auction Summary).
    pub mod auction_type {
        /// Opening auction.
        pub const OPENING: u8 = b'O';
        /// Closing auction.
        pub const CLOSING: u8 = b'C';
        /// Halt auction.
        pub const HALT: u8 = b'H';
        /// IPO auction.
        pub const IPO: u8 = b'I';
        /// Cboe Market Close.
        pub const MARKET_CLOSE: u8 = b'M';
        /// Periodic auction (BYX).
        pub const PERIODIC: u8 = b'P';
    }
    /// Login Response status values.
    pub mod login_status {
        /// Login accepted.
        pub const ACCEPTED: u8 = b'A';
        /// Not authorized.
        pub const NOT_AUTHORIZED: u8 = b'N';
        /// Session in use.
        pub const SESSION_IN_USE: u8 = b'B';
        /// Invalid session.
        pub const INVALID_SESSION: u8 = b'S';
    }
    /// Gap Response status values; anything but `ACCEPTED` is a reject.
    pub mod gap_status {
        /// Accepted.
        pub const ACCEPTED: u8 = b'A';
        /// Out of range.
        pub const OUT_OF_RANGE: u8 = b'O';
        /// Daily allocation exhausted.
        pub const DAILY_LIMIT: u8 = b'D';
        /// Minute allocation exhausted.
        pub const MINUTE_LIMIT: u8 = b'M';
        /// Second allocation exhausted.
        pub const SECOND_LIMIT: u8 = b'S';
        /// Count limit exceeded.
        pub const COUNT_LIMIT: u8 = b'C';
        /// Invalid unit.
        pub const INVALID_UNIT: u8 = b'I';
        /// Unit unavailable.
        pub const UNIT_UNAVAILABLE: u8 = b'U';
    }
    /// Spin Response and Instrument Definition Response status values.
    pub mod spin_status {
        /// Accepted.
        pub const ACCEPTED: u8 = b'A';
        /// Out of range.
        pub const OUT_OF_RANGE: u8 = b'O';
        /// A spin is already running.
        pub const IN_PROGRESS: u8 = b'S';
    }
}

/// One Sequenced Unit Header and the messages after it: a multicast
/// datagram, or one block on a GRP or Spin Server connection
/// ("Sequenced Unit Header Message Fields").
///
/// Each message is kept as its bytes, Length byte included, because the
/// same header carries PITCH, GRP and Spin messages; read each with
/// [`Message::parse`] or [`Control::parse`]. A unit with no messages is a
/// heartbeat ("Heartbeat Messages"). Sequence 0 marks unsequenced data.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unit {
    /// Hdr Unit: the unit the messages belong to.
    pub unit: u8,
    /// Hdr Sequence: the first message's sequence number, 0 if unsequenced.
    pub sequence: u32,
    /// The messages, each with its Length byte.
    pub messages: Vec<Vec<u8>>,
}
impl Unit {
    /// A unit holding `messages`, written.
    pub fn of(unit: u8, sequence: u32, messages: &[Message]) -> Result<Self, Error> {
        let messages = messages
            .iter()
            .map(Wire::to_bytes)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            unit,
            sequence,
            messages,
        })
    }
    /// A unit holding one GRP or Spin message, unsequenced.
    pub fn control(message: &Control) -> Result<Self, Error> {
        Ok(Self {
            unit: 0,
            sequence: 0,
            messages: vec![message.to_bytes()?],
        })
    }
    /// A heartbeat: no messages.
    pub fn heartbeat(unit: u8, sequence: u32) -> Self {
        Self {
            unit,
            sequence,
            messages: Vec::new(),
        }
    }
    /// Whether this unit is a heartbeat.
    pub fn is_heartbeat(&self) -> bool {
        self.messages.is_empty()
    }
    /// The sequence number of the first message of the next unit: Hdr
    /// Sequence plus Hdr Count, across the rollover. `None` if unsequenced.
    pub fn next_sequence(&self) -> Option<u32> {
        if self.sequence == 0 {
            return None;
        }
        Some(sequence_after(self.sequence, self.messages.len() as u32))
    }
    /// Bytes on the wire.
    pub fn wire_len(&self) -> usize {
        HEADER_LENGTH + self.messages.iter().map(Vec::len).sum::<usize>()
    }
}
impl Wire for Unit {
    type ParseError = Error;
    type WriteError = Error;
    /// Reads one whole unit: Hdr Length must equal the bytes, and Hdr
    /// Count messages, each framed by its Length byte, must fill the rest.
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let mut rest = b;
        let length: u16 = take(&mut rest)?;
        let count: u8 = take(&mut rest)?;
        let unit = take(&mut rest)?;
        let sequence = take(&mut rest)?;
        if usize::from(length) != b.len() {
            return Err(Error::Length);
        }
        let mut messages = Vec::with_capacity(usize::from(count));
        while let Some(&len) = rest.first() {
            if messages.len() == usize::from(count) {
                return Err(Error::Count);
            }
            let len = usize::from(len);
            if len < 2 {
                return Err(Error::Length);
            }
            let (message, after) = rest.split_at_checked(len).ok_or(Error::Length)?;
            messages.push(message.to_vec());
            rest = after;
        }
        if messages.len() != usize::from(count) {
            return Err(Error::Count);
        }
        Ok(Self {
            unit,
            sequence,
            messages,
        })
    }
    /// Writes the unit. Refuses more than [`MAX_MESSAGES`] messages, one
    /// whose Length byte disagrees with its bytes, and a unit over
    /// [`MAX_UNIT_LENGTH`].
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let count = u8::try_from(self.messages.len()).map_err(|_| Error::Count)?;
        for m in &self.messages {
            framed(m)?;
        }
        let length = u16::try_from(self.wire_len()).map_err(|_| Error::TooLong)?;
        out.reserve(self.wire_len());
        length.put(out);
        count.put(out);
        self.unit.put(out);
        self.sequence.put(out);
        for m in &self.messages {
            out.extend_from_slice(m);
        }
        Ok(())
    }
}

/// The sequence number `n` messages after `sequence`, rolling over from
/// [`MAX_SEQUENCE`] to 1. Sequence 0 means unsequenced and stays 0.
pub fn sequence_after(sequence: u32, n: u32) -> u32 {
    if sequence == 0 {
        return 0;
    }
    let span = u64::from(MAX_SEQUENCE);
    let next = (u64::from(sequence) - 1 + u64::from(n)) % span + 1;
    // `next` is in 1..=MAX_SEQUENCE.
    u32::try_from(next).unwrap_or(MAX_SEQUENCE)
}
/// How many steps forward `to` is from `from` across the rollover, both
/// nonzero: 0 when equal, `MAX_SEQUENCE - 1` when `to` is one behind.
pub fn sequence_distance(from: u32, to: u32) -> u32 {
    let span = u64::from(MAX_SEQUENCE);
    let d = (u64::from(to) + span - u64::from(from)) % span;
    u32::try_from(d).unwrap_or(0)
}

/// Reads units from a GRP or Spin Server TCP connection, where blocks may
/// cross segments ("Message Format"). Each item is one unit, parsed: `Err`
/// for a block that frames by its Hdr Length but does not parse. A Hdr
/// Length below the header or over the limit ends the stream, read from
/// the header alone.
///
/// ```
/// use fictionet::stdlib::codec::Frames;
/// use fictionet::stdlib::cboe_pitch::{Control, LoginResponse, Unit};
/// use fictionet::stdlib::codec::{finish, pump, Stream, Wire};
///
/// let response = Control::from(LoginResponse { status: b'A', extra: Vec::new() });
/// let bytes = Unit::control(&response)?.to_bytes()?;
/// let mut stream = Stream::new(Frames::<Unit>::default());
/// let mut units = Vec::new();
/// pump(&mut stream, &bytes[..5], |u| units.push(u))?;
/// pump(&mut stream, &bytes[5..], |u| units.push(u))?;
/// finish(&mut stream, |u| units.push(u))?;
/// let unit = units.remove(0)?;
/// assert_eq!(Control::parse(&unit.messages[0])?, response);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
impl Prefixed for Unit {
    type Item = Result<Unit, Error>;
    type Error = Error;
    type Limit = usize;
    const NAME: &'static str = "PITCH";

    #[inline]
    fn default_limit() -> Self::Limit { MAX_UNIT_LENGTH }

    #[inline]
    fn normalize_limit(limit: Self::Limit) -> Self::Limit { limit.clamp(HEADER_LENGTH, MAX_UNIT_LENGTH) }

    #[inline]
    fn capacity(limit: &Self::Limit) -> usize { *limit }

    #[inline]
    fn parse_prefix(input: &[u8], limit: &Self::Limit) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        let Some(prefix) = input.get(..2) else {
            return Ok(None);
        };
        let length = usize::from(u16::from_le_bytes([prefix[0], prefix[1]]));
        if length < HEADER_LENGTH {
            return Err(Error::Length);
        }
        if length > limit {
            return Err(Error::TooLong);
        }
        let Some(unit) = input.get(..length) else {
            return Ok(None);
        };
        Ok(Some((Unit::parse(unit), length)))
    }
}


/// Missing messages on one unit, ready to request from the GRP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gap {
    /// The unit.
    pub unit: u8,
    /// The first missing sequence number.
    pub sequence: u32,
    /// How many are missing.
    pub count: u32,
}
impl Gap {
    /// Gap Request messages covering the gap, each for at most
    /// [`MAX_GAP_COUNT`] messages, across the rollover.
    pub fn requests(&self) -> Vec<GapRequest> {
        let mut out = Vec::new();
        let mut sequence = self.sequence;
        let mut left = self.count;
        while left > 0 {
            let n = left.min(MAX_GAP_COUNT);
            out.push(GapRequest {
                unit: self.unit,
                sequence,
                // `n` is at most u16::MAX.
                count: u16::try_from(n).unwrap_or(u16::MAX),
                extra: Vec::new(),
            });
            sequence = sequence_after(sequence, n);
            left -= n;
        }
        out
    }
}

/// What [`GapDetector::receive`] found in one unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// Whether the unit is sequenced.
    pub sequenced: bool,
    /// Messages at the front already seen, to skip.
    pub skip: usize,
    /// Messages after those to process.
    pub count: usize,
    /// Messages missing before this unit, if any.
    pub gap: Option<Gap>,
}

/// Follows each unit's sequence numbers, without I/O.
///
/// Pass every unit received, from any of a unit's feeds, to
/// [`receive`](Self::receive) and process the messages it says are new.
/// The first sequenced unit seen for a unit number sets where that unit
/// starts. A unit ahead of the next expected number reports the [`Gap`]
/// before it (heartbeats included, since their Hdr Sequence is the next
/// sequence to be sent, "Heartbeat Messages"); its messages are still new,
/// so a caller that fills gaps from the GRP or a spin buffers them. A unit
/// behind it is a duplicate, in whole or in part, as when arbitrating the
/// A and B feeds. Ahead and behind are judged across the rollover: up to
/// 2^31 sequence numbers forward is ahead.
///
/// After an End of Session, or the daily restart that resets sequences,
/// call [`reset`](Self::reset). State is a fixed size.
#[derive(Clone, Debug)]
pub struct GapDetector {
    expected: [u32; 256],
}
impl Default for GapDetector {
    fn default() -> Self {
        Self::new()
    }
}
impl GapDetector {
    /// A detector that knows no unit.
    pub fn new() -> Self {
        Self { expected: [0; 256] }
    }
    /// The next sequence number expected on `unit`, once known.
    pub fn expected(&self, unit: u8) -> Option<u32> {
        Some(self.expected[usize::from(unit)]).filter(|s| *s != 0)
    }
    /// Forgets `unit`, so its next sequenced unit sets where it starts.
    pub fn reset(&mut self, unit: u8) {
        self.expected[usize::from(unit)] = 0;
    }
    /// Sets the next sequence number expected on `unit`, as after a spin
    /// current through `sequence - 1`. 0 forgets the unit.
    pub fn set_expected(&mut self, unit: u8, sequence: u32) {
        self.expected[usize::from(unit)] = sequence;
    }
    /// Classifies one unit and moves the unit's expected number past it.
    pub fn receive(&mut self, unit: &Unit) -> Seen {
        let count = unit.messages.len();
        if unit.sequence == 0 {
            return Seen {
                sequenced: false,
                skip: 0,
                count,
                gap: None,
            };
        }
        let slot = &mut self.expected[usize::from(unit.unit)];
        // Up to 255 messages: fits u32.
        let n = count as u32;
        let next = sequence_after(unit.sequence, n);
        if *slot == 0 {
            *slot = next;
            return Seen {
                sequenced: true,
                skip: 0,
                count,
                gap: None,
            };
        }
        let ahead = sequence_distance(*slot, unit.sequence);
        if ahead < 1 << 31 {
            let gap = (ahead > 0).then_some(Gap {
                unit: unit.unit,
                sequence: *slot,
                count: ahead,
            });
            *slot = next;
            return Seen {
                sequenced: true,
                skip: 0,
                count,
                gap,
            };
        }
        // Behind: `seen` of this unit's messages came before the expected.
        let seen = sequence_distance(unit.sequence, *slot);
        if seen >= n {
            return Seen {
                sequenced: true,
                skip: count,
                count: 0,
                gap: None,
            };
        }
        *slot = next;
        let skip = seen as usize;
        Seen {
            sequenced: true,
            skip,
            count: count - skip,
            gap: None,
        }
    }
}

/// The limits of a [`Book`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookConfig {
    /// The most live orders, 1 to [`MAX_ORDERS`].
    pub max_orders: usize,
    /// The most price levels over every symbol and side, 1 to
    /// [`MAX_LEVELS`].
    pub max_levels: usize,
    /// The most symbols with orders, 1 to [`MAX_SYMBOLS`].
    pub max_symbols: usize,
}
impl Default for BookConfig {
    fn default() -> Self {
        Self {
            max_orders: DEFAULT_MAX_ORDERS,
            max_levels: DEFAULT_MAX_LEVELS,
            max_symbols: DEFAULT_MAX_SYMBOLS,
        }
    }
}

/// A live order on a [`Book`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    /// The unit that added it.
    pub unit: u8,
    /// The symbol, widened to eight bytes.
    pub symbol: Symbol,
    /// The side.
    pub side: Side,
    /// The limit price, with four places.
    pub price: Price,
    /// Shares left.
    pub quantity: u32,
}

/// One price level of one side of a symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Level {
    /// The price.
    pub price: Price,
    /// Shares at this price.
    pub quantity: u64,
    /// Orders at this price.
    pub orders: usize,
}

/// What [`Book::apply`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The message does not change the book: trades, statuses, auctions.
    Ignored,
    /// The message changed this side of this symbol.
    Changed {
        /// The symbol.
        symbol: Symbol,
        /// The side changed.
        side: Side,
    },
    /// A Unit Clear removed every order of the unit.
    Cleared {
        /// The unit cleared.
        unit: u8,
        /// Orders removed.
        orders: usize,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Aggregate {
    quantity: u64,
    orders: usize,
}

#[derive(Clone, Debug, Default)]
struct SymbolBook {
    bids: BTreeMap<Price, Aggregate>,
    asks: BTreeMap<Price, Aggregate>,
}
impl SymbolBook {
    fn side(&self, side: Side) -> &BTreeMap<Price, Aggregate> {
        match side {
            Side::Buy => &self.bids,
            Side::Sell => &self.asks,
        }
    }
    fn side_mut(&mut self, side: Side) -> &mut BTreeMap<Price, Aggregate> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }
}

/// A full-depth order book built from PITCH order messages, without I/O.
///
/// [`apply`](Self::apply) each new message with the unit it arrived on,
/// in sequence order. Add Order (long, short, expanded) puts an order on
/// the book; Order Executed and Reduce Size take shares off it, removing
/// it at zero; Order Executed at Price/Size leaves its Remaining Quantity;
/// Modify Order sets its shares and price, removing it at zero; Delete
/// Order removes it; Unit Clear removes every order of the unit ("Order
/// Modification Messages", "Unit Clear Message Fields"). Other messages
/// leave the book as it is. Short prices are widened to four places and
/// six-byte symbols to eight.
///
/// Orders, price levels and symbols are each bounded by [`BookConfig`]. A
/// message that would pass a limit, or that does not fit the book, is
/// refused and the book is unchanged.
#[derive(Clone, Debug)]
pub struct Book {
    config: BookConfig,
    orders: HashMap<u64, Order>,
    /// Order Ids per unit, so Unit Clear costs the orders it removes.
    by_unit: HashMap<u8, HashSet<u64>>,
    symbols: HashMap<Symbol, SymbolBook>,
    levels: usize,
}
impl Book {
    /// An empty book. Refuses limits outside their named ranges.
    pub fn new(config: BookConfig) -> Result<Self, Error> {
        if !(1..=MAX_ORDERS).contains(&config.max_orders)
            || !(1..=MAX_LEVELS).contains(&config.max_levels)
            || !(1..=MAX_SYMBOLS).contains(&config.max_symbols)
        {
            return Err(Error::Config);
        }
        Ok(Self {
            config,
            orders: HashMap::new(),
            by_unit: HashMap::new(),
            symbols: HashMap::new(),
            levels: 0,
        })
    }
    /// Live orders.
    pub fn order_count(&self) -> usize {
        self.orders.len()
    }
    /// Price levels over every symbol and side.
    pub fn level_count(&self) -> usize {
        self.levels
    }
    /// Symbols with orders.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
    /// A live order by Order Id.
    pub fn order(&self, order_id: u64) -> Option<&Order> {
        self.orders.get(&order_id)
    }
    /// The highest bid of `symbol`.
    pub fn best_bid(&self, symbol: Symbol) -> Option<Level> {
        let (price, a) = self.symbols.get(&symbol)?.bids.last_key_value()?;
        Some(level(*price, a))
    }
    /// The lowest ask of `symbol`.
    pub fn best_ask(&self, symbol: Symbol) -> Option<Level> {
        let (price, a) = self.symbols.get(&symbol)?.asks.first_key_value()?;
        Some(level(*price, a))
    }
    /// Up to `n` levels of one side of `symbol`, best first.
    pub fn depth(&self, symbol: Symbol, side: Side, n: usize) -> Vec<Level> {
        let Some(book) = self.symbols.get(&symbol) else {
            return Vec::new();
        };
        let levels = book.side(side).iter().map(|(p, a)| level(*p, a));
        match side {
            Side::Buy => levels.rev().take(n).collect(),
            Side::Sell => levels.take(n).collect(),
        }
    }

    /// Applies one message that arrived on `unit`. See [`Book`] for which
    /// messages change it.
    pub fn apply(&mut self, unit: u8, message: &Message) -> Result<Applied, Error> {
        let widen = |s: &Symbol6| -> Symbol {
            let mut b = [b' '; 8];
            b[..6].copy_from_slice(s.as_bytes());
            Alpha(b)
        };
        match message {
            Message::AddOrderLong(m) => self.add(
                m.order_id,
                Order {
                    unit,
                    symbol: widen(&m.symbol),
                    side: m.side,
                    price: m.price,
                    quantity: m.quantity,
                },
            ),
            Message::AddOrderShort(m) => self.add(
                m.order_id,
                Order {
                    unit,
                    symbol: widen(&m.symbol),
                    side: m.side,
                    price: m.price.to_price(),
                    quantity: u32::from(m.quantity),
                },
            ),
            Message::AddOrderExpanded(m) => self.add(
                m.order_id,
                Order {
                    unit,
                    symbol: m.symbol,
                    side: m.side,
                    price: m.price,
                    quantity: m.quantity,
                },
            ),
            Message::OrderExecuted(m) => self.reduce(unit, m.order_id, m.executed_quantity),
            Message::OrderExecutedAtPrice(m) => {
                let old = self.live(unit, m.order_id)?;
                self.modify(m.order_id, old, old.price, m.remaining_quantity)
            }
            Message::ReduceSizeLong(m) => self.reduce(unit, m.order_id, m.canceled_quantity),
            Message::ReduceSizeShort(m) => {
                self.reduce(unit, m.order_id, u32::from(m.canceled_quantity))
            }
            Message::ModifyOrderLong(m) => {
                let old = self.live(unit, m.order_id)?;
                self.modify(m.order_id, old, m.price, m.quantity)
            }
            Message::ModifyOrderShort(m) => {
                let old = self.live(unit, m.order_id)?;
                self.modify(m.order_id, old, m.price.to_price(), u32::from(m.quantity))
            }
            Message::DeleteOrder(m) => {
                let old = self.live(unit, m.order_id)?;
                self.modify(m.order_id, old, old.price, 0)
            }
            Message::UnitClear(_) => {
                let ids = self.by_unit.remove(&unit).unwrap_or_default();
                for id in &ids {
                    if let Some(order) = self.orders.get(id).copied() {
                        self.remove(*id, order);
                    }
                }
                Ok(Applied::Cleared {
                    unit,
                    orders: ids.len(),
                })
            }
            _ => Ok(Applied::Ignored),
        }
    }

    fn live(&self, unit: u8, order_id: u64) -> Result<Order, Error> {
        let order = *self
            .orders
            .get(&order_id)
            .ok_or(Error::UnknownOrder(order_id))?;
        if order.unit != unit {
            return Err(Error::Unit(order_id));
        }
        Ok(order)
    }
    fn aggregate(&self, symbol: Symbol, side: Side, price: Price) -> Option<&Aggregate> {
        self.symbols.get(&symbol)?.side(side).get(&price)
    }
    /// Checks that `new` can be placed once `old`, an order the change
    /// takes off the book first, is gone.
    fn check_place(&self, new: Order, old: Option<Order>) -> Result<(), Error> {
        let mut orders = self.orders.len();
        let mut levels = self.levels;
        let mut symbol_empties = false;
        let mut joins = self.aggregate(new.symbol, new.side, new.price).is_some();
        if let Some(old) = old {
            orders -= 1;
            if self
                .aggregate(old.symbol, old.side, old.price)
                .is_some_and(|a| a.orders == 1)
            {
                levels -= 1;
                if (old.side, old.price) == (new.side, new.price) {
                    joins = false;
                }
                symbol_empties = self
                    .symbols
                    .get(&old.symbol)
                    .is_some_and(|b| b.bids.len() + b.asks.len() == 1);
            }
        }
        if orders >= self.config.max_orders {
            return Err(Error::TooManyOrders);
        }
        if !joins && levels >= self.config.max_levels {
            return Err(Error::TooManyLevels);
        }
        let known = self.symbols.contains_key(&new.symbol)
            && !(symbol_empties && old.is_some_and(|o| o.symbol == new.symbol));
        let symbols = self.symbols.len() - usize::from(symbol_empties);
        if !known && symbols >= self.config.max_symbols {
            return Err(Error::TooManySymbols);
        }
        Ok(())
    }
    fn insert(&mut self, order_id: u64, order: Order) {
        let book = self.symbols.entry(order.symbol).or_default();
        let level = book
            .side_mut(order.side)
            .entry(order.price)
            .or_insert_with(|| {
                self.levels += 1;
                Aggregate::default()
            });
        level.quantity = level.quantity.saturating_add(u64::from(order.quantity));
        level.orders = level.orders.saturating_add(1);
        self.by_unit.entry(order.unit).or_default().insert(order_id);
        self.orders.insert(order_id, order);
    }
    fn remove(&mut self, order_id: u64, order: Order) {
        if let Some(book) = self.symbols.get_mut(&order.symbol) {
            let map = book.side_mut(order.side);
            if let Some(level) = map.get_mut(&order.price) {
                level.quantity = level.quantity.saturating_sub(u64::from(order.quantity));
                level.orders = level.orders.saturating_sub(1);
                if level.orders == 0 {
                    map.remove(&order.price);
                    self.levels = self.levels.saturating_sub(1);
                }
            }
            if book.bids.is_empty() && book.asks.is_empty() {
                self.symbols.remove(&order.symbol);
            }
        }
        if let Some(ids) = self.by_unit.get_mut(&order.unit) {
            ids.remove(&order_id);
            if ids.is_empty() {
                self.by_unit.remove(&order.unit);
            }
        }
        self.orders.remove(&order_id);
    }
    fn add(&mut self, order_id: u64, order: Order) -> Result<Applied, Error> {
        if order.quantity == 0 {
            return Err(Error::Shares(order_id));
        }
        if self.orders.contains_key(&order_id) {
            return Err(Error::DuplicateOrder(order_id));
        }
        self.check_place(order, None)?;
        self.insert(order_id, order);
        Ok(Applied::Changed {
            symbol: order.symbol,
            side: order.side,
        })
    }
    fn reduce(&mut self, unit: u8, order_id: u64, shares: u32) -> Result<Applied, Error> {
        let old = self.live(unit, order_id)?;
        let left = old
            .quantity
            .checked_sub(shares)
            .ok_or(Error::Shares(order_id))?;
        self.modify(order_id, old, old.price, left)
    }
    /// Sets a live order's price and shares; zero shares removes it.
    fn modify(
        &mut self,
        order_id: u64,
        old: Order,
        price: Price,
        quantity: u32,
    ) -> Result<Applied, Error> {
        let changed = Applied::Changed {
            symbol: old.symbol,
            side: old.side,
        };
        if quantity == 0 {
            self.remove(order_id, old);
            return Ok(changed);
        }
        let new = Order {
            price,
            quantity,
            ..old
        };
        if price == old.price {
            // Same level: only its share total changes.
            if let Some(level) = self
                .symbols
                .get_mut(&old.symbol)
                .and_then(|b| b.side_mut(old.side).get_mut(&price))
            {
                level.quantity = level
                    .quantity
                    .saturating_sub(u64::from(old.quantity))
                    .saturating_add(u64::from(quantity));
            }
            self.orders.insert(order_id, new);
            return Ok(changed);
        }
        self.check_place(new, Some(old))?;
        self.remove(order_id, old);
        self.insert(order_id, new);
        Ok(changed)
    }
}
fn level(price: Price, a: &Aggregate) -> Level {
    Level {
        price,
        quantity: a.quantity,
        orders: a.orders,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        Fail, Lcg,
        contract::{check_decode, check_decode_with_alloc_limit, check_wire, check_wire_value},
        test_support::{decode_all, mutate},
    };

    /// Bytes from the specification's hexadecimal examples.
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }
    fn sym6(s: &str) -> Symbol6 {
        Alpha::right_padded(s).unwrap()
    }
    fn sym(s: &str) -> Symbol {
        Alpha::right_padded(s).unwrap()
    }
    const OFFSET: &str = "18 D2 06 00";
    const ORDER_ID: &str = "05 40 5B 77 8F 56 1D 0B";
    const EXEC_ID: &str = "34 2B 46 E0 BB 00 00 00";
    const ORDER: u64 = 0x0b1d_568f_775b_4005;
    const EXEC: u64 = 0xbb_e046_2b34;

    /// Checks `bytes` read as `want` through the message's own parser and
    /// the enum's, and that `want` writes back as `bytes`.
    fn exact<M: Wire<ParseError = Error> + Into<Message> + Clone + PartialEq + fmt::Debug>(
        bytes: &[u8],
        want: M,
    ) where
        M::WriteError: fmt::Debug,
    {
        assert_eq!(M::parse(bytes).unwrap(), want);
        assert_eq!(want.to_bytes().unwrap(), bytes);
        assert_eq!(Message::parse(bytes).unwrap(), want.into());
        check_wire::<Message>(bytes);
    }
    fn exact_control<M: Wire<ParseError = Error> + Into<Control> + Clone + PartialEq + fmt::Debug>(
        bytes: &[u8],
        want: M,
    ) where
        M::WriteError: fmt::Debug,
    {
        assert_eq!(M::parse(bytes).unwrap(), want);
        assert_eq!(want.to_bytes().unwrap(), bytes);
        assert_eq!(Control::parse(bytes).unwrap(), want.into());
        check_wire::<Control>(bytes);
    }

    // "Sequenced Unit Header with 2 Messages". The example's Hdr Length
    // reads 31 00 (49) but the note and the bytes make 50 (8 + 26 + 16);
    // 0x32 is used here.
    #[test]
    fn sequenced_unit_header_example() {
        let bytes = hex(&format!(
            "32 00 02 01 01 00 00 00 \
             1A 22 {OFFSET} {ORDER_ID} 42 E1 02 5A 56 5A 5A 54 20 01 00 01 \
             10 26 E8 D9 06 00 {ORDER_ID} E1 02"
        ));
        let unit = Unit::parse(&bytes).unwrap();
        assert_eq!((unit.unit, unit.sequence), (1, 1));
        assert_eq!(unit.next_sequence(), Some(3));
        let add = AddOrderShort {
            time_offset: 447_000,
            order_id: ORDER,
            side: Side::Buy,
            quantity: 737,
            symbol: sym6("ZVZZT"),
            price: ShortPrice(1),
            flags: 1,
            extra: Vec::new(),
        };
        let reduce = ReduceSizeShort {
            time_offset: 449_000,
            order_id: ORDER,
            canceled_quantity: 737,
            extra: Vec::new(),
        };
        assert_eq!(
            Message::parse(&unit.messages[0]).unwrap(),
            add.clone().into()
        );
        assert_eq!(
            Message::parse(&unit.messages[1]).unwrap(),
            reduce.clone().into()
        );
        assert_eq!(
            Unit::of(1, 1, &[add.into(), reduce.into()])
                .unwrap()
                .to_bytes()
                .unwrap(),
            bytes
        );
        check_wire::<Unit>(&bytes);
        // The 49 of the printed example is refused.
        let mut printed = bytes.clone();
        printed[0] = 0x31;
        assert_eq!(Unit::parse(&printed), Err(Error::Length));
    }

    #[test]
    fn units_refuse_bad_headers() {
        let good = Unit::heartbeat(3, 7).to_bytes().unwrap();
        assert_eq!(good, [8, 0, 0, 3, 7, 0, 0, 0]);
        assert!(Unit::parse(&good).unwrap().is_heartbeat());
        // Count says one message, none follows.
        assert_eq!(Unit::parse(&[8, 0, 1, 3, 7, 0, 0, 0]), Err(Error::Count));
        // A message of length 0 or 1 cannot hold its type.
        assert_eq!(
            Unit::parse(&[9, 0, 1, 3, 7, 0, 0, 0, 1]),
            Err(Error::Length)
        );
        // A message running past the unit.
        assert_eq!(
            Unit::parse(&[10, 0, 1, 3, 7, 0, 0, 0, 3, 0x20]),
            Err(Error::Length)
        );
        // Two messages where the count says one.
        assert_eq!(
            Unit::parse(&[12, 0, 1, 3, 7, 0, 0, 0, 2, 0x86, 2, 0x86]),
            Err(Error::Count)
        );
        assert_eq!(Unit::parse(&[7, 0, 0, 0, 0, 0, 0]), Err(Error::Length));
        let bad = Unit {
            unit: 1,
            sequence: 1,
            messages: vec![vec![3, 0x20]],
        };
        assert_eq!(bad.to_bytes(), Err(Error::Length));
        let many = Unit {
            unit: 1,
            sequence: 1,
            messages: vec![vec![2, 0x86]; 256],
        };
        assert_eq!(many.to_bytes(), Err(Error::Count));
    }

    #[test]
    fn grp_and_spin_examples() {
        exact_control(
            &hex("16 01 30 30 30 31 46 49 52 4D 20 20 41 42 43 44 30 30 20 20 20 20"),
            Login {
                session_sub_id: Alpha(*b"0001"),
                username: Alpha(*b"FIRM"),
                filler: Alpha::blank(),
                password: Alpha::right_padded("ABCD00").unwrap(),
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("03 02 41"),
            LoginResponse {
                status: codes::login_status::ACCEPTED,
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("09 03 01 3B 10 00 00 32 00"),
            GapRequest {
                unit: 1,
                sequence: 4155,
                count: 50,
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("0A 04 01 3B 10 00 00 32 00 41"),
            GapResponse {
                unit: 1,
                sequence: 4155,
                count: 50,
                status: b'A',
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("06 80 3B 10 00 00"),
            SpinImageAvailable {
                sequence: 4155,
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("06 81 3B 10 00 00"),
            SpinRequest {
                sequence: 4155,
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("0B 82 3B 10 00 00 42 00 00 00 41"),
            SpinResponse {
                sequence: 4155,
                order_count: 66,
                status: b'A',
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("06 83 3B 10 00 00"),
            SpinFinished {
                sequence: 4155,
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("06 84 00 00 00 00"),
            InstrumentDefinitionRequest {
                sequence: 0,
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("0B 85 00 00 00 00 B8 0B 00 00 41"),
            InstrumentDefinitionResponse {
                sequence: 0,
                instrument_count: 3000,
                status: b'A',
                extra: Vec::new(),
            },
        );
        exact_control(
            &hex("02 86"),
            InstrumentDefinitionFinished { extra: Vec::new() },
        );
        assert_eq!(Control::KINDS.len(), 11);
    }

    #[test]
    fn time_and_unit_messages_examples() {
        // Midnight Reference 1614056400, Time 57600 (16:00), Trade Date
        // 20210223.
        exact(
            &hex("12 B1 D0 8B 34 60 00 E1 00 00 00 00 00 00 2F 62 34 01"),
            TimeReference {
                midnight_reference: 1_614_056_400,
                time: 57_600,
                time_offset: 0,
                trade_date: 20_210_223,
                extra: Vec::new(),
            },
        );
        exact(
            &hex("06 20 98 85 00 00"),
            Time {
                time: 34_200,
                extra: Vec::new(),
            },
        );
        // The 10-byte Time with Epoch Time keeps it in `extra`.
        let long = hex("0A 20 98 85 00 00 68 11 35 60");
        let Message::Time(t) = Message::parse(&long).unwrap() else {
            panic!()
        };
        assert_eq!(t.epoch_time(), Some(1_614_090_600));
        assert_eq!(t.to_bytes().unwrap(), long);
        exact(
            &hex(&format!("06 97 {OFFSET}")),
            UnitClear {
                time_offset: 447_000,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("06 2D {OFFSET}")),
            EndOfSession {
                time_offset: 447_000,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("0E 2C {OFFSET} {EXEC_ID}")),
            TradeBreak {
                time_offset: 447_000,
                execution_id: EXEC,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("06 BC {OFFSET}")),
            TransactionBegin {
                time_offset: 447_000,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("06 BD {OFFSET}")),
            TransactionEnd {
                time_offset: 447_000,
                extra: Vec::new(),
            },
        );
    }

    #[test]
    fn order_message_examples() {
        exact(
            &hex(&format!(
                "22 21 {OFFSET} {ORDER_ID} 42 20 4E 00 00 5A 56 5A 5A 54 20 5A 23 00 00 00 00 00 00 01"
            )),
            AddOrderLong {
                time_offset: 447_000,
                order_id: ORDER,
                side: Side::Buy,
                quantity: 20_000,
                symbol: sym6("ZVZZT"),
                price: "0.905".parse().unwrap(),
                flags: 1,
                extra: Vec::new(),
            },
        );
        // The Add Order (short) example prints an eight-byte price; the
        // table and the 26-byte length make it two bytes. Two are used.
        exact(
            &hex(&format!(
                "1A 22 {OFFSET} {ORDER_ID} 42 20 4E 5A 56 5A 5A 54 20 0A 28 01"
            )),
            AddOrderShort {
                time_offset: 447_000,
                order_id: ORDER,
                side: Side::Buy,
                quantity: 20_000,
                symbol: sym6("ZVZZT"),
                price: "102.50".parse().unwrap(),
                flags: 1,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "29 2F {OFFSET} {ORDER_ID} 42 20 4E 00 00 5A 56 5A 5A 54 20 20 20 \
                 5A 23 00 00 00 00 00 00 01 4D 50 49 44 4E"
            )),
            AddOrderExpanded {
                time_offset: 447_000,
                order_id: ORDER,
                side: Side::Buy,
                quantity: 20_000,
                symbol: sym("ZVZZT"),
                price: Price(9050),
                flags: 1,
                participant_id: Alpha(*b"MPID"),
                customer_indicator: b'N',
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("1A 23 {OFFSET} {ORDER_ID} 64 00 00 00 {EXEC_ID}")),
            OrderExecuted {
                time_offset: 447_000,
                order_id: ORDER,
                executed_quantity: 100,
                execution_id: EXEC,
                extra: Vec::new(),
            },
        );
        // The options form carries the Trade Condition in `extra`.
        exact(
            &hex(&format!(
                "1B 23 {OFFSET} {ORDER_ID} 64 00 00 00 {EXEC_ID} 53"
            )),
            OrderExecuted {
                time_offset: 447_000,
                order_id: ORDER,
                executed_quantity: 100,
                execution_id: EXEC,
                extra: vec![b'S'],
            },
        );
        exact(
            &hex(&format!(
                "26 24 {OFFSET} {ORDER_ID} 64 00 00 00 BC 4D 00 00 {EXEC_ID} E8 A3 0F 00 00 00 00 00"
            )),
            OrderExecutedAtPrice {
                time_offset: 447_000,
                order_id: ORDER,
                executed_quantity: 100,
                remaining_quantity: 19_900,
                execution_id: EXEC,
                price: "102.5".parse().unwrap(),
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("12 25 {OFFSET} {ORDER_ID} F8 24 01 00")),
            ReduceSizeLong {
                time_offset: 447_000,
                order_id: ORDER,
                canceled_quantity: 75_000,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("10 26 {OFFSET} {ORDER_ID} 64 00")),
            ReduceSizeShort {
                time_offset: 447_000,
                order_id: ORDER,
                canceled_quantity: 100,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "1B 27 {OFFSET} {ORDER_ID} F8 24 01 00 E8 A3 0F 00 00 00 00 00 03"
            )),
            ModifyOrderLong {
                time_offset: 447_000,
                order_id: ORDER,
                quantity: 75_000,
                price: Price(1_025_000),
                flags: 3,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("13 28 {OFFSET} {ORDER_ID} 64 00 0A 28 03")),
            ModifyOrderShort {
                time_offset: 447_000,
                order_id: ORDER,
                quantity: 100,
                price: ShortPrice(10_250),
                flags: 3,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("0E 29 {OFFSET} {ORDER_ID}")),
            DeleteOrder {
                time_offset: 447_000,
                order_id: ORDER,
                extra: Vec::new(),
            },
        );
        assert_eq!(ShortPrice(10_250).to_string(), "102.50");
        assert_eq!(ShortPrice(10_250).to_price(), Price(1_025_000));
    }

    #[test]
    fn trade_message_examples() {
        exact(
            &hex(&format!(
                "29 2A {OFFSET} {ORDER_ID} 42 F8 24 01 00 5A 56 5A 5A 54 20 E8 A3 0F 00 00 00 00 00 {EXEC_ID}"
            )),
            TradeLong {
                time_offset: 447_000,
                order_id: ORDER,
                side: Side::Buy,
                quantity: 75_000,
                symbol: sym6("ZVZZT"),
                price: Price(1_025_000),
                execution_id: EXEC,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "21 2B {OFFSET} {ORDER_ID} 42 64 00 5A 56 5A 5A 54 20 0A 28 {EXEC_ID}"
            )),
            TradeShort {
                time_offset: 447_000,
                order_id: ORDER,
                side: Side::Buy,
                quantity: 100,
                symbol: sym6("ZVZZT"),
                price: ShortPrice(10_250),
                execution_id: EXEC,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "2B 30 {OFFSET} {ORDER_ID} 42 F8 24 01 00 5A 56 5A 5A 54 20 20 20 E8 A3 0F 00 00 00 00 00 {EXEC_ID}"
            )),
            TradeExpanded {
                time_offset: 447_000,
                order_id: ORDER,
                side: Side::Buy,
                quantity: 75_000,
                symbol: sym("ZVZZT"),
                price: Price(1_025_000),
                execution_id: EXEC,
                extra: Vec::new(),
            },
        );
    }

    #[test]
    fn status_and_auction_examples() {
        exact(
            &hex(&format!(
                "12 31 {OFFSET} 5A 56 5A 5A 54 20 20 20 54 30 20 20"
            )),
            TradingStatus {
                time_offset: 447_000,
                symbol: sym("ZVZZT"),
                trading_status: codes::trading_status::TRADING,
                reg_sho_action: b'0',
                reserved1: b' ',
                reserved2: b' ',
                extra: Vec::new(),
            },
        );
        // The options example reads through the same offsets.
        let options = hex(&format!(
            "12 31 {OFFSET} 39 39 38 38 37 37 20 20 54 20 48 20"
        ));
        let Message::TradingStatus(s) = Message::parse(&options).unwrap() else {
            panic!()
        };
        assert_eq!(
            (s.symbol.trimmed(), s.trading_status, s.reserved1),
            ("998877", b'T', b'H')
        );
        exact(
            &hex(&format!(
                "2F 95 {OFFSET} 5A 56 5A 5A 54 20 20 20 49 E8 A3 0F 00 00 00 00 00 F8 24 01 00 \
                 20 4E 00 00 E8 A3 0F 00 00 00 00 00 E8 A3 0F 00 00 00 00 00"
            )),
            AuctionUpdate {
                time_offset: 447_000,
                symbol: sym("ZVZZT"),
                auction_type: codes::auction_type::IPO,
                reference_price: Price(1_025_000),
                buy_shares: 75_000,
                sell_shares: 20_000,
                indicative_price: Price(1_025_000),
                auction_only_price: Price(1_025_000),
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "1B 96 {OFFSET} 30 30 6D 45 56 5F 20 20 4F E8 A3 0F 00 00 00 00 00 4B 00 00 00"
            )),
            AuctionSummary {
                time_offset: 447_000,
                symbol: sym("00mEV_"),
                auction_type: b'O',
                price: Price(1_025_000),
                shares: 75,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("0F 98 {OFFSET} 5A 56 5A 5A 54 20 20 20 41")),
            RetailPriceImprovement {
                time_offset: 447_000,
                symbol: sym("ZVZZT"),
                retail_price_improvement: b'A',
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "40 D1 {OFFSET} 30 30 6D 45 56 4F 20 20 56 E8 A3 0F 00 00 00 00 00 64 00 00 00 \
                 C8 00 00 00 E8 A3 0F 00 00 00 00 00 E8 A3 0F 00 00 00 00 00 4F \
                 50 69 0F 00 00 00 00 00 70 B7 0F 00 00 00 00 00"
            )),
            OptionsAuctionUpdate {
                time_offset: 447_000,
                symbol: sym("00mEVO"),
                auction_type: b'V',
                reference_price: Price(1_025_000),
                buy_contracts: 100,
                sell_contracts: 200,
                indicative_price: Price(1_025_000),
                auction_only_price: Price(1_025_000),
                opening_condition: b'O',
                composite_bid_price: "101".parse().unwrap(),
                composite_offer_price: "103".parse().unwrap(),
                extra: Vec::new(),
            },
        );
    }

    #[test]
    fn options_only_examples() {
        exact(
            &hex(
                "26 2E 30 30 6D 45 56 4F 4D 53 46 54 20 20 31 39 30 39 32 30 43 30 30 31 35 30 30 30 30 \
                 4E 4D 53 46 54 20 20 20 20",
            ),
            SymbolMapping {
                feed_symbol: sym6("00mEVO"),
                osi_symbol: Alpha::right_padded("MSFT  190920C00150000").unwrap(),
                symbol_condition: b'N',
                underlying: sym("MSFT"),
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "13 D2 {OFFSET} 5A 56 5A 5A 54 20 20 20 52 0F 00 00 00"
            )),
            WidthUpdate {
                time_offset: 447_000,
                underlying: sym("ZVZZT"),
                width_type: b'R',
                multiplier: 15,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "2F AD {OFFSET} 30 30 6D 45 56 4F {ORDER_ID} 54 42 E8 A3 0F 00 00 00 00 00 \
                 64 00 00 00 43 45 46 49 44 38 73 0E 00 43 4C 49 44"
            )),
            AuctionNotification {
                time_offset: 447_000,
                symbol: sym6("00mEVO"),
                auction_id: ORDER,
                auction_type: b'T',
                side: Side::Buy,
                price: Price(1_025_000),
                contracts: 100,
                customer_indicator: b'C',
                participant_id: Alpha(*b"EFID"),
                auction_end_offset: 947_000,
                client_id: Alpha(*b"CLID"),
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!("0E AE {OFFSET} {ORDER_ID}")),
            AuctionCancel {
                time_offset: 447_000,
                auction_id: ORDER,
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "22 AF {OFFSET} {ORDER_ID} {EXEC_ID} E8 A3 0F 00 00 00 00 00 64 00 00 00"
            )),
            AuctionTrade {
                time_offset: 447_000,
                auction_id: ORDER,
                execution_id: EXEC,
                price: Price(1_025_000),
                contracts: 100,
                extra: Vec::new(),
            },
        );
        let vxs = "56 58 53 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20";
        exact(
            &hex(&format!(
                "2A 9D {OFFSET} {vxs} 40 66 03 01 00 00 00 00 00 48 E8 01 00 00 00 00"
            )),
            SoqStrikeRangeUpdate {
                time_offset: 447_000,
                soq_identifier: Alpha::right_padded("VXS").unwrap(),
                lower_strike_price: "1700".parse().unwrap(),
                upper_strike_price: "3200".parse().unwrap(),
                extra: Vec::new(),
            },
        );
        exact(
            &hex(&format!(
                "3A 9E 30 30 6D 45 56 4F 53 50 58 57 20 20 31 39 30 39 32 37 43 30 32 33 39 30 30 30 30 \
                 4E 53 50 58 20 20 20 20 20 {vxs}"
            )),
            ConstituentSymbolMapping {
                feed_symbol: sym6("00mEVO"),
                osi_symbol: Alpha::right_padded("SPXW  190927C02390000").unwrap(),
                symbol_condition: b'N',
                underlying: sym("SPX"),
                soq_identifier: Alpha::right_padded("VXS").unwrap(),
                extra: Vec::new(),
            },
        );
    }

    // "Message Types": every PITCH 2.X type, with the Total Length of its
    // table (equities layouts where the two differ).
    #[test]
    fn lengths_match_the_specification() {
        let spec: [(u8, usize); 32] = [
            (0xB1, 18),
            (0x20, 6),
            (0x97, 6),
            (0xBC, 6),
            (0xBD, 6),
            (0x21, 34),
            (0x22, 26),
            (0x2F, 41),
            (0x23, 26),
            (0x24, 38),
            (0x25, 18),
            (0x26, 16),
            (0x27, 27),
            (0x28, 19),
            (0x29, 14),
            (0x2A, 41),
            (0x2B, 33),
            (0x30, 43),
            (0x2C, 14),
            (0x2D, 6),
            (0x2E, 38),
            (0x31, 18),
            (0xD2, 19),
            (0x95, 47),
            (0xD1, 64),
            (0x96, 27),
            (0xAD, 47),
            (0xAE, 14),
            (0xAF, 34),
            (0x98, 15),
            (0x9D, 42),
            (0x9E, 58),
        ];
        assert_eq!(Message::KINDS.len(), spec.len());
        for (kind, len) in spec {
            assert_eq!(Message::length_of(kind), Some(len), "{kind:#04x}");
            let mut b = vec![b'B'; len];
            b[0] = len as u8;
            b[1] = kind;
            let m = Message::parse(&b).unwrap();
            assert_eq!(m.kind(), kind);
            assert_eq!(m.wire_len(), len);
            let mut short = b[..len - 1].to_vec();
            short[0] -= 1;
            assert_eq!(Message::parse(&short), Err(Error::Length));
        }
    }

    #[test]
    fn unknown_and_grown_messages_round_trip() {
        let unknown = [5, 0x77, 1, 2, 3];
        assert_eq!(
            Message::parse(&unknown).unwrap(),
            Message::Unknown(Unknown {
                kind: 0x77,
                body: vec![1, 2, 3]
            })
        );
        check_wire::<Message>(&unknown);
        // A defined type written as Unknown is refused.
        let fake = Message::Unknown(Unknown {
            kind: 0x29,
            body: vec![0; 12],
        });
        assert_eq!(fake.to_bytes(), Err(Error::Type(0x29)));
        // A Length byte that disagrees with the bytes.
        assert_eq!(Message::parse(&[6, 0x77, 1, 2, 3]), Err(Error::Length));
        assert_eq!(Message::parse(&[1]), Err(Error::Length));
        assert_eq!(DeleteOrder::parse(&[2, 0x86]), Err(Error::Type(0x86)));
        // Too long to write.
        let grown = DeleteOrder {
            time_offset: 0,
            order_id: 0,
            extra: vec![0; 242],
        };
        assert_eq!(grown.to_bytes(), Err(Error::Length));
        let bad_side = hex(&format!("0E 29 {OFFSET} {ORDER_ID}"));
        assert!(Message::parse(&bad_side).is_ok());
        let mut add = hex(&format!(
            "1A 22 {OFFSET} {ORDER_ID} 58 20 4E 5A 56 5A 5A 54 20 0A 28 01"
        ));
        assert_eq!(Message::parse(&add), Err(Error::Side(b'X')));
        // A byte outside printable ASCII in an alphanumeric field reads
        // and writes back as it is.
        add[14] = b'S';
        add[17] = 0x7f;
        let Message::AddOrderShort(m) = Message::parse(&add).unwrap() else {
            panic!()
        };
        assert_eq!(m.symbol.trimmed(), "");
        assert_eq!(Message::from(m).to_bytes().unwrap(), add);
        assert_eq!(Symbol6::right_padded("A\u{7f}"), Err(Error::Field));
    }

    // "Trading Status (Options)": the two Reserved bytes after the six-byte
    // symbol share the equities Symbol field. A feed that fills them, and
    // the other reserved bytes, with NUL must still read, and write back
    // the same bytes.
    #[test]
    fn options_trading_status_with_nul_reserved_bytes() {
        let mut b = hex(&format!("12 31 {OFFSET}"));
        b.extend_from_slice(b"998877");
        b.extend_from_slice(&[0, 0, b'T', 0, b'H', 0]);
        let Message::TradingStatus(t) = Message::parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(t.symbol.trimmed(), "998877");
        assert_eq!((t.trading_status, t.reserved1), (b'T', b'H'));
        assert_eq!(Message::from(t).to_bytes().unwrap(), b);
        check_wire::<Message>(&b);
    }

    #[test]
    fn prices_parse_and_print() {
        assert_eq!("0.905".parse::<Price>(), Ok(Price(9050)));
        assert_eq!(Price(9050).to_string(), "0.9050");
        assert_eq!("655.35".parse::<ShortPrice>(), Ok(ShortPrice(u16::MAX)));
        for bad in ["", ".5", "1.", "1.234", "655.36", "a"] {
            assert_eq!(bad.parse::<ShortPrice>(), Err(Error::Price), "{bad}");
        }
        assert_eq!("1.00001".parse::<Price>(), Err(Error::Price));
        assert_eq!(Symbol6::right_padded("SEVENXX"), Err(Error::Field));
        assert_eq!(sym6("AB").resized::<8>(), Ok(sym("AB")));
    }

    #[test]
    fn sequence_arithmetic_rolls_over_to_one() {
        assert_eq!(sequence_after(1, 2), 3);
        assert_eq!(sequence_after(MAX_SEQUENCE, 1), 1);
        assert_eq!(sequence_after(MAX_SEQUENCE - 1, 4), 3);
        assert_eq!(sequence_after(0, 9), 0);
        assert_eq!(sequence_distance(MAX_SEQUENCE - 1, 3), 4);
        assert_eq!(sequence_distance(3, 3), 0);
        assert_eq!(sequence_distance(4, 3), MAX_SEQUENCE - 1);
    }

    fn unit(u: u8, sequence: u32, n: usize) -> Unit {
        Unit {
            unit: u,
            sequence,
            messages: vec![vec![2, 0x86]; n],
        }
    }

    #[test]
    fn gap_detector_follows_each_unit() {
        let mut d = GapDetector::new();
        let seen = |sequenced, skip, count, gap| Seen {
            sequenced,
            skip,
            count,
            gap,
        };
        assert_eq!(d.receive(&unit(1, 10, 2)), seen(true, 0, 2, None));
        assert_eq!(d.expected(1), Some(12));
        assert_eq!(d.expected(2), None);
        // The B feed repeats it: a duplicate.
        assert_eq!(d.receive(&unit(1, 10, 2)), seen(true, 2, 0, None));
        // Overlapping: one old, two new.
        assert_eq!(d.receive(&unit(1, 11, 3)), seen(true, 1, 2, None));
        assert_eq!(d.expected(1), Some(14));
        // Ahead: 14..=16 missing.
        let gap = Gap {
            unit: 1,
            sequence: 14,
            count: 3,
        };
        assert_eq!(d.receive(&unit(1, 17, 1)), seen(true, 0, 1, Some(gap)));
        // A heartbeat names the next sequence; ahead of it is a gap too.
        assert_eq!(
            d.receive(&unit(1, 20, 0)),
            seen(
                true,
                0,
                0,
                Some(Gap {
                    unit: 1,
                    sequence: 18,
                    count: 2
                })
            )
        );
        // Unsequenced data leaves the unit alone.
        assert_eq!(d.receive(&unit(1, 0, 4)), seen(false, 0, 4, None));
        assert_eq!(d.expected(1), Some(20));
        // Other units are separate.
        assert_eq!(d.receive(&unit(2, 5, 1)), seen(true, 0, 1, None));
        d.reset(1);
        assert_eq!(d.receive(&unit(1, 1, 1)), seen(true, 0, 1, None));
    }

    // "Gap Server Rollover Usage Example": after 4,294,967,293 comes 3;
    // the request is for 4,294,967,294 with a count of 4.
    #[test]
    fn gap_detector_across_the_rollover() {
        let mut d = GapDetector::new();
        d.receive(&unit(1, MAX_SEQUENCE - 2, 1));
        let s = d.receive(&unit(1, 3, 1));
        let gap = s.gap.unwrap();
        assert_eq!(
            gap,
            Gap {
                unit: 1,
                sequence: MAX_SEQUENCE - 1,
                count: 4
            }
        );
        let requests = gap.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            Control::from(requests[0].clone()).to_bytes().unwrap(),
            [9, 3, 1, 0xfe, 0xff, 0xff, 0xff, 4, 0]
        );
        // A unit straddling the rollover moves past it.
        let mut d = GapDetector::new();
        d.receive(&unit(1, MAX_SEQUENCE, 3));
        assert_eq!(d.expected(1), Some(3));
        // A big gap splits into requests of at most 65535.
        let big = Gap {
            unit: 2,
            sequence: MAX_SEQUENCE - 10,
            count: 70_000,
        };
        let r = big.requests();
        assert_eq!(r.len(), 2);
        assert_eq!((r[0].sequence, r[0].count), (MAX_SEQUENCE - 10, 65_535));
        assert_eq!(
            (r[1].sequence, u32::from(r[1].count)),
            (sequence_after(MAX_SEQUENCE - 10, 65_535), 70_000 - 65_535)
        );
    }

    #[test]
    fn units_framer_follows_the_contract() {
        let mut bytes = Vec::new();
        for c in [
            Control::from(Login {
                session_sub_id: Alpha(*b"0001"),
                username: Alpha(*b"FIRM"),
                filler: Alpha::blank(),
                password: Alpha::blank(),
                extra: Vec::new(),
            }),
            SpinImageAvailable {
                sequence: 9,
                extra: Vec::new(),
            }
            .into(),
        ] {
            Unit::control(&c).unwrap().write(&mut bytes).unwrap();
        }
        Unit::heartbeat(0, 0).write(&mut bytes).unwrap();
        // A block that frames but does not parse is an item.
        bytes.extend_from_slice(&[9, 0, 2, 0, 0, 0, 0, 0, 0]);
        Unit::heartbeat(0, 0).write(&mut bytes).unwrap();
        check_decode(Frames::<Unit>::default, &bytes);
        check_decode(|| Frames::<Unit>::with_limit(40), &bytes);
        check_decode_with_alloc_limit(Frames::<Unit>::default, &bytes, 2 * MAX_UNIT_LENGTH);
        let (items, failure) = decode_all(Frames::<Unit>::default, &bytes);
        assert!(failure.is_none());
        assert_eq!(items.len(), 5);
        assert_eq!(items[3], Err(Error::Length));
        let (_, failure) = decode_all(|| Frames::<Unit>::with_limit(10), &bytes);
        assert_eq!(failure, Some(Fail::Protocol(Error::TooLong)));
        let (_, failure) = decode_all(Frames::<Unit>::default, &[3, 0, 0]);
        assert_eq!(failure, Some(Fail::Protocol(Error::Length)));
        let (_, failure) = decode_all(Frames::<Unit>::default, &[9, 0, 0]);
        assert_eq!(failure, Some(Fail::Truncated { unread: 3 }));
    }

    /// One value of every PITCH type, built from the length table.
    fn samples() -> Vec<Message> {
        Message::KINDS
            .iter()
            .map(|&kind| {
                let len = Message::length_of(kind).unwrap();
                let mut b = vec![b'S'; len];
                b[0] = len as u8;
                b[1] = kind;
                Message::parse(&b).unwrap()
            })
            .collect()
    }

    #[test]
    fn mutated_messages_keep_the_contract() {
        let mut bases: Vec<Vec<u8>> = samples().iter().map(|m| m.to_bytes().unwrap()).collect();
        let datagram = Unit {
            unit: 1,
            sequence: 1,
            messages: bases.clone(),
        };
        let datagram = datagram.to_bytes().unwrap();
        bases.push(datagram.clone());
        let mut rng = Lcg::new(0xc60e);
        for _ in 0..800 {
            let mut bytes = bases[rng.index(bases.len())].clone();
            for _ in 0..=rng.below(3) {
                mutate(&mut rng, &mut bytes);
            }
            check_wire::<Message>(&bytes);
            check_wire::<Control>(&bytes);
            check_wire::<Unit>(&bytes);
            check_wire::<AddOrderExpanded>(&bytes);
            if let Ok(m) = Message::parse(&bytes) {
                let mut book = Book::new(BookConfig::default()).unwrap();
                let _ = book.apply(1, &m);
            }
            if let Ok(u) = Unit::parse(&bytes) {
                let mut d = GapDetector::new();
                let s = d.receive(&u);
                assert!(s.skip + s.count == u.messages.len());
            }
        }
        for _ in 0..100 {
            let mut bytes = datagram.clone();
            for _ in 0..=rng.below(4) {
                mutate(&mut rng, &mut bytes);
            }
            check_decode(Frames::<Unit>::default, &bytes);
        }
    }

    fn add(id: u64, side: Side, price: u64, quantity: u32) -> Message {
        AddOrderLong {
            time_offset: 0,
            order_id: id,
            side,
            quantity,
            symbol: sym6("ZVZZT"),
            price: Price(price),
            flags: 1,
            extra: Vec::new(),
        }
        .into()
    }
    fn modify(id: u64, price: u64, quantity: u32) -> Message {
        ModifyOrderLong {
            time_offset: 0,
            order_id: id,
            quantity,
            price: Price(price),
            flags: 1,
            extra: Vec::new(),
        }
        .into()
    }
    fn delete(id: u64) -> Message {
        DeleteOrder {
            time_offset: 0,
            order_id: id,
            extra: Vec::new(),
        }
        .into()
    }

    #[test]
    fn book_applies_the_order_life_cycle() {
        let z = sym("ZVZZT");
        let mut book = Book::new(BookConfig::default()).unwrap();
        book.apply(1, &add(1, Side::Buy, 100, 300)).unwrap();
        book.apply(1, &add(2, Side::Buy, 100, 200)).unwrap();
        book.apply(1, &add(3, Side::Sell, 101, 50)).unwrap();
        // A short add's price is widened to four places.
        book.apply(
            1,
            &AddOrderShort {
                time_offset: 0,
                order_id: 4,
                side: Side::Sell,
                quantity: 10,
                symbol: sym6("ZVZZT"),
                price: ShortPrice(1),
                flags: 1,
                extra: Vec::new(),
            }
            .into(),
        )
        .unwrap();
        assert_eq!(book.best_ask(z).unwrap().price, Price(100));
        assert_eq!(
            book.best_bid(z),
            Some(Level {
                price: Price(100),
                quantity: 500,
                orders: 2
            })
        );
        // Execute 100 of order 1, reduce 50 of order 2.
        book.apply(
            1,
            &OrderExecuted {
                time_offset: 0,
                order_id: 1,
                executed_quantity: 100,
                execution_id: 1,
                extra: Vec::new(),
            }
            .into(),
        )
        .unwrap();
        book.apply(
            1,
            &ReduceSizeShort {
                time_offset: 0,
                order_id: 2,
                canceled_quantity: 50,
                extra: Vec::new(),
            }
            .into(),
        )
        .unwrap();
        assert_eq!(book.best_bid(z).unwrap().quantity, 350);
        // At price/size: the remaining quantity is what is left.
        book.apply(
            1,
            &OrderExecutedAtPrice {
                time_offset: 0,
                order_id: 3,
                executed_quantity: 60,
                remaining_quantity: 0,
                execution_id: 2,
                price: Price(99),
                extra: Vec::new(),
            }
            .into(),
        )
        .unwrap();
        assert_eq!(book.order(3), None);
        // Modify moves order 1 to a new price.
        book.apply(1, &modify(1, 102, 70)).unwrap();
        assert_eq!(
            book.best_bid(z),
            Some(Level {
                price: Price(102),
                quantity: 70,
                orders: 1
            })
        );
        assert_eq!(book.depth(z, Side::Buy, 9).len(), 2);
        // Same-price modify changes only the size.
        book.apply(1, &modify(2, 100, 1)).unwrap();
        assert_eq!(book.depth(z, Side::Buy, 9)[1].quantity, 1);
        book.apply(1, &delete(2)).unwrap();
        // Deleted ids may come back.
        book.apply(1, &add(2, Side::Buy, 90, 5)).unwrap();
        assert_eq!(book.order_count(), 3);
        // Unit Clear removes this unit's orders only.
        book.apply(2, &add(9, Side::Sell, 200, 1)).unwrap();
        assert_eq!(
            book.apply(
                1,
                &UnitClear {
                    time_offset: 0,
                    extra: Vec::new()
                }
                .into()
            ),
            Ok(Applied::Cleared { unit: 1, orders: 3 })
        );
        assert_eq!(book.order_count(), 1);
        assert_eq!(book.level_count(), 1);
        assert_eq!(book.best_bid(z), None);
        // Unit Clear finds the unit's orders through the per-unit index,
        // not by scanning every order; the index follows every removal.
        assert_eq!(book.by_unit.len(), 1);
        assert_eq!(book.by_unit[&2].len(), 1);
        // Trades leave the book alone.
        assert_eq!(book.apply(2, &samples()[15]), Ok(Applied::Ignored));
    }

    #[test]
    fn book_refuses_and_stays_unchanged() {
        let mut book = Book::new(BookConfig {
            max_orders: 3,
            max_levels: 2,
            max_symbols: 1,
        })
        .unwrap();
        book.apply(1, &add(1, Side::Buy, 100, 10)).unwrap();
        let before = format!("{book:?}");
        let refused = [
            (1, add(1, Side::Buy, 100, 10), Error::DuplicateOrder(1)),
            (1, add(2, Side::Buy, 100, 0), Error::Shares(2)),
            (1, delete(9), Error::UnknownOrder(9)),
            (2, delete(1), Error::Unit(1)),
            (
                1,
                ReduceSizeLong {
                    time_offset: 0,
                    order_id: 1,
                    canceled_quantity: 11,
                    extra: Vec::new(),
                }
                .into(),
                Error::Shares(1),
            ),
            (
                1,
                AddOrderExpanded {
                    time_offset: 0,
                    order_id: 5,
                    side: Side::Buy,
                    quantity: 1,
                    symbol: sym("OTHER"),
                    price: Price(1),
                    flags: 0,
                    participant_id: Alpha::blank(),
                    customer_indicator: b' ',
                    extra: Vec::new(),
                }
                .into(),
                Error::TooManySymbols,
            ),
        ];
        for (unit, m, e) in refused {
            assert_eq!(book.apply(unit, &m), Err(e));
            assert_eq!(format!("{book:?}"), before);
        }
        book.apply(1, &add(2, Side::Sell, 100, 10)).unwrap();
        assert_eq!(
            book.apply(1, &add(3, Side::Sell, 101, 10)),
            Err(Error::TooManyLevels)
        );
        book.apply(1, &add(3, Side::Sell, 100, 10)).unwrap();
        assert_eq!(
            book.apply(1, &add(4, Side::Sell, 100, 10)),
            Err(Error::TooManyOrders)
        );
        // A modify that empties its level may open another.
        book.apply(1, &modify(1, 90, 5)).unwrap();
        // One that leaves its level behind may not.
        assert_eq!(
            book.apply(1, &modify(2, 70, 5)),
            Err(Error::TooManyLevels)
        );
        // The last order of a symbol may move to a new symbol's place.
        let mut book = Book::new(BookConfig {
            max_symbols: 1,
            ..BookConfig::default()
        })
        .unwrap();
        book.apply(1, &add(1, Side::Buy, 1, 1)).unwrap();
        book.apply(1, &delete(1)).unwrap();
        assert_eq!(book.symbol_count(), 0);
        assert_eq!(
            Book::new(BookConfig {
                max_levels: 0,
                ..BookConfig::default()
            })
            .err(),
            Some(Error::Config)
        );
    }

    #[test]
    fn book_matches_a_model_under_random_messages() {
        let mut rng = Lcg::new(0xb0e);
        let config = BookConfig {
            max_orders: 30,
            max_levels: 10,
            max_symbols: 2,
        };
        let symbols = ["AAA", "BBB", "CCC"];
        let mut book = Book::new(config).unwrap();
        let mut model: HashMap<u64, Order> = HashMap::new();
        for _ in 0..5_000 {
            let id = rng.below(50);
            let unit = rng.below(2) as u8 + 1;
            let price = rng.below(6);
            let quantity = rng.below(5) as u32;
            let side = if rng.coin() { Side::Buy } else { Side::Sell };
            let symbol = symbols[rng.index(3)];
            let m: Message = match rng.below(7) {
                0 | 1 => AddOrderLong {
                    time_offset: 0,
                    order_id: id,
                    side,
                    quantity,
                    symbol: sym6(symbol),
                    price: Price(price),
                    flags: 1,
                    extra: Vec::new(),
                }
                .into(),
                2 => OrderExecuted {
                    time_offset: 0,
                    order_id: id,
                    executed_quantity: quantity,
                    execution_id: 0,
                    extra: Vec::new(),
                }
                .into(),
                3 => modify(id, price, quantity),
                4 => delete(id),
                5 => OrderExecutedAtPrice {
                    time_offset: 0,
                    order_id: id,
                    executed_quantity: 1,
                    remaining_quantity: quantity,
                    execution_id: 0,
                    price: Price(0),
                    extra: Vec::new(),
                }
                .into(),
                _ if rng.below(20) == 0 => UnitClear {
                    time_offset: 0,
                    extra: Vec::new(),
                }
                .into(),
                _ => delete(id),
            };
            let before = format!("{book:?}");
            if book.apply(unit, &m).is_err() {
                assert_eq!(format!("{book:?}"), before);
                continue;
            }
            match &m {
                Message::AddOrderLong(a) => {
                    model.insert(
                        a.order_id,
                        Order {
                            unit,
                            symbol: sym(symbol),
                            side: a.side,
                            price: a.price,
                            quantity: a.quantity,
                        },
                    );
                }
                Message::OrderExecuted(e) => {
                    let o = model.get_mut(&e.order_id).unwrap();
                    o.quantity -= e.executed_quantity;
                    if o.quantity == 0 {
                        model.remove(&e.order_id);
                    }
                }
                Message::ModifyOrderLong(x) => {
                    let o = model.get_mut(&x.order_id).unwrap();
                    (o.price, o.quantity) = (x.price, x.quantity);
                    if o.quantity == 0 {
                        model.remove(&x.order_id);
                    }
                }
                Message::OrderExecutedAtPrice(x) => {
                    let o = model.get_mut(&x.order_id).unwrap();
                    o.quantity = x.remaining_quantity;
                    if o.quantity == 0 {
                        model.remove(&x.order_id);
                    }
                }
                Message::DeleteOrder(d) => {
                    model.remove(&d.order_id).unwrap();
                }
                Message::UnitClear(_) => model.retain(|_, o| o.unit != unit),
                _ => unreachable!(),
            }
            assert!(book.order_count() <= config.max_orders);
            assert!(book.level_count() <= config.max_levels);
            assert!(book.symbol_count() <= config.max_symbols);
            assert_eq!(book.order_count(), model.len());
            for (id, o) in &model {
                assert_eq!(book.order(*id), Some(o));
            }
            let indexed: usize = book.by_unit.values().map(HashSet::len).sum();
            assert_eq!(indexed, model.len());
            for (u, ids) in &book.by_unit {
                assert!(ids.iter().all(|id| model[id].unit == *u));
            }
            let mut levels = 0;
            for s in symbols {
                for side in [Side::Buy, Side::Sell] {
                    let got = book.depth(sym(s), side, usize::MAX);
                    levels += got.len();
                    let mut want: BTreeMap<Price, (u64, usize)> = BTreeMap::new();
                    for o in model
                        .values()
                        .filter(|o| o.symbol == sym(s) && o.side == side)
                    {
                        let e = want.entry(o.price).or_default();
                        e.0 += u64::from(o.quantity);
                        e.1 += 1;
                    }
                    let mut want: Vec<Level> = want
                        .into_iter()
                        .map(|(price, (quantity, orders))| Level {
                            price,
                            quantity,
                            orders,
                        })
                        .collect();
                    if side == Side::Buy {
                        want.reverse();
                    }
                    assert_eq!(got, want);
                }
            }
            assert_eq!(levels, book.level_count());
        }
    }

    #[test]
    fn every_type_round_trips() {
        for m in samples() {
            check_wire_value(&m);
            let b = m.to_bytes().unwrap();
            assert_eq!(b.len(), m.wire_len());
            assert_eq!(b[1], m.kind());
        }
    }
}
