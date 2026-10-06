//! Nasdaq OUCH 5.0: every inbound and outbound order entry message as a
//! [`Wire`] value, with typed optional appendages, and a sans-IO
//! exchange-side state machine that tracks open orders, so a world can be
//! a fake exchange.
//!
//! OUCH is Nasdaq's native order entry protocol. A client enters,
//! replaces, cancels and modifies orders ([`Inbound`]); the exchange
//! answers with accepted, replaced, canceled, executed and rejected
//! messages ([`Outbound`]). This module follows the
//! [OUCH 5.0 Order Entry Specification](https://www.nasdaqtrader.com/content/technicalsupport/specifications/TradingProducts/Ouch5.0.pdf),
//! revision 1.05 of October 7, 2025. Section numbers below are that
//! document's.
//!
//! Each message has a type byte and fixed fields; most end with a two-byte
//! appendage length and a list of TagValue options ([`Options`], 1.2,
//! Appendix A). Where the specification makes the appendage optional, the
//! message holds `Option<Options>` and `None` means the length field is
//! absent. Integers are unsigned and big-endian; alpha fields are ASCII
//! padded on the right with spaces ([`Alpha`]); prices are eight bytes with
//! four implied decimal places ([`Price`]); timestamps are eight bytes of
//! nanoseconds since midnight. One-byte code fields are kept as the byte
//! (`u8`); [`codes`] names the listed values.
//!
//! OUCH rides SoupBinTCP: inbound messages in unsequenced data packets,
//! outbound messages in sequenced data packets (1.1). Parse each packet's
//! payload with [`Inbound::parse`] or [`Outbound::parse`]. [`Exchange`] is
//! the exchange side of one OUCH port: UserRefNum sequencing, open orders
//! by [`Token`], and the replies the specification defines; the world
//! decides what to accept, execute and cancel.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::ouch::{
//!     Action, Alpha, EnterOrder, Event, Exchange, ExchangeConfig, Inbound, Options, Outbound, Side, Token,
//! };
//! use fictionet::stdlib::soupbintcp::Packet;
//!
//! // The client's Enter Order, in a SoupBinTCP unsequenced data packet.
//! let enter = EnterOrder {
//!     user_ref: 1,
//!     side: Side::Buy,
//!     quantity: 100,
//!     symbol: Alpha::right_padded("ZVZZT")?,
//!     price: "10.25".parse()?,
//!     time_in_force: b'0',
//!     display: b'Y',
//!     capacity: b'A',
//!     intermarket_sweep: b'N',
//!     cross_type: b'N',
//!     cl_ord_id: Alpha::right_padded("ORDER1")?,
//!     options: Options::default(),
//! };
//! let packet = Packet::UnsequencedData(enter.to_bytes()?).to_bytes()?;
//!
//! // The exchange reads it and the world accepts the order.
//! let Packet::UnsequencedData(payload) = Packet::parse(&packet)? else { unreachable!() };
//! let mut exchange = Exchange::new(ExchangeConfig::default())?;
//! let actions = exchange.receive(&Inbound::parse(&payload)?, 1_000);
//! let token = Token { user_ref_idx: 0, user_ref: 1 };
//! assert_eq!(actions, [Action::Event(Event::EnterRequested(token))]);
//! let Outbound::OrderAccepted(accepted) = exchange.accept(token, 2_000)? else { unreachable!() };
//! assert_eq!((accepted.quantity, accepted.order_state), (100, b'L'));
//!
//! // A fill of 40 shares: the order stays open with 60.
//! let fill = exchange.execute(token, 40, "10.25".parse()?, b'A', 3_000)?;
//! let reply = Packet::SequencedData(fill.to_bytes()?);
//! assert_eq!(exchange.order(token).unwrap().quantity, 60);
//! # let _ = reply;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use fictionet::stdlib::codec::Wire;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::str::FromStr;

/// Bytes in a TagValue element's length and tag (1.2).
pub const TAG_HEADER: usize = 2;
/// The longest option value: a TagValue length counts the tag, in one byte.
pub const MAX_OPTION_VALUE: usize = u8::MAX as usize - 1;
/// The longest appendage the two-byte length can describe.
pub const MAX_APPENDAGE: usize = u16::MAX as usize;
/// Shares on an order or replace must be below this (2.1, 2.2).
pub const MAX_ORDER_QUANTITY: u32 = 1_000_000;
/// The special price that marks a market order for a cross (1.2).
pub const MARKET_PRICE: Price = Price(0x7fff_ffff);

/// The default most open and pending orders an [`Exchange`] tracks.
pub const DEFAULT_MAX_ORDERS: usize = 100_000;
/// The most orders an [`Exchange`] may be configured to track.
pub const MAX_ORDERS: usize = 1 << 24;
/// The default most executions an [`Exchange`] remembers for breaks.
pub const DEFAULT_MAX_EXECUTIONS: usize = 100_000;
/// The most executions an [`Exchange`] may be configured to remember.
pub const MAX_EXECUTIONS: usize = 1 << 24;
/// The most firms an [`Exchange`] can hold disabled at once.
pub const MAX_DISABLED_FIRMS: usize = 1_024;

/// Why bytes or a value were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are shorter or longer than the message's fields and
    /// appendage, or empty.
    Length,
    /// An unknown message type byte, or bytes of another type than the
    /// one asked for.
    Type(u8),
    /// An alpha field has a byte outside printable ASCII, or text longer
    /// than the field.
    Field,
    /// A side other than "B", "S", "T" or "E".
    Side(u8),
    /// A TagValue element with length 0, a known option with the wrong
    /// size, or, when writing, a value too long or an [`Opt::Other`] with
    /// a known tag.
    Option(u8),
    /// An appendage longer than [`MAX_APPENDAGE`].
    TooLong,
    /// A decimal price with more than four places, or too large.
    Price,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Length => f.write_str("OUCH message length is wrong"),
            Error::Type(t) => write!(f, "unexpected OUCH message type {t:#04x}"),
            Error::Field => f.write_str("OUCH alpha field is invalid"),
            Error::Side(s) => write!(f, "invalid OUCH side {s:#04x}"),
            Error::Option(t) => write!(f, "invalid OUCH option, tag {t}"),
            Error::TooLong => f.write_str("OUCH appendage is too long"),
            Error::Price => f.write_str("OUCH price is invalid"),
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
            const LEN: usize = std::mem::size_of::<$t>();
            fn get(b: &[u8]) -> Result<Self, Error> {
                Ok(<$t>::from_be_bytes(array(b)?))
            }
            fn put(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
        }
    )*};
}
int_field!(u8, u16, u32, u64, i32);

/// A price: eight bytes with four implied decimal places. The raw value
/// 102500 is $10.2500 (1.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Price(pub u64);
impl fmt::Display for Price {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:04}", self.0 / 10_000, self.0 % 10_000)
    }
}
impl FromStr for Price {
    type Err = Error;
    /// Reads "10.25" or "10" as dollars; refuses more than four places.
    fn from_str(s: &str) -> Result<Self, Error> {
        let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
        let digits = |t: &str| !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit());
        if !digits(whole) || (s.contains('.') && !digits(fraction)) || fraction.len() > 4 {
            return Err(Error::Price);
        }
        let whole: u64 = whole.parse().map_err(|_| Error::Price)?;
        let mut frac: u64 = if fraction.is_empty() {
            0
        } else {
            fraction.parse().map_err(|_| Error::Price)?
        };
        for _ in fraction.len()..4 {
            frac *= 10;
        }
        whole
            .checked_mul(10_000)
            .and_then(|w| w.checked_add(frac))
            .map(Self)
            .ok_or(Error::Price)
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

/// A fixed-width alpha field: `N` bytes of printable ASCII, left justified
/// and padded on the right with spaces (1.2). Padding is part of the
/// value, so fields round-trip byte for byte.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Alpha<const N: usize>([u8; N]);
impl<const N: usize> Alpha<N> {
    /// All spaces.
    pub fn blank() -> Self {
        Self([b' '; N])
    }
    /// The field's exact bytes. Refuses a byte outside 0x20..=0x7e.
    pub fn new(bytes: [u8; N]) -> Result<Self, Error> {
        if bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
            Ok(Self(bytes))
        } else {
            Err(Error::Field)
        }
    }
    /// `text` padded on the right with spaces.
    pub fn right_padded(text: &str) -> Result<Self, Error> {
        if text.len() > N {
            return Err(Error::Field);
        }
        let mut bytes = [b' '; N];
        bytes
            .get_mut(..text.len())
            .ok_or(Error::Field)?
            .copy_from_slice(text.as_bytes());
        Self::new(bytes)
    }
    /// The field's bytes, padding included.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
    /// The text without trailing spaces.
    pub fn trimmed(&self) -> &str {
        // Every byte is printable ASCII, so this is valid UTF-8.
        std::str::from_utf8(&self.0)
            .unwrap_or_default()
            .trim_end_matches(' ')
    }
    /// Whether every byte is a space.
    pub fn is_blank(&self) -> bool {
        self.0.iter().all(|b| *b == b' ')
    }
}
impl<const N: usize> fmt::Debug for Alpha<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", std::str::from_utf8(&self.0).unwrap_or_default())
    }
}
impl<const N: usize> Field for Alpha<N> {
    const LEN: usize = N;
    fn get(b: &[u8]) -> Result<Self, Error> {
        Self::new(array(b)?)
    }
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

/// An eight-byte stock symbol.
pub type Symbol = Alpha<8>;
/// A fourteen-byte customer order identifier.
pub type ClOrdId = Alpha<14>;
/// A four-byte firm identifier.
pub type Firm = Alpha<4>;

/// An order's side (2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// "B": buy.
    Buy,
    /// "S": sell.
    Sell,
    /// "T": sell short.
    SellShort,
    /// "E": sell short exempt.
    SellShortExempt,
}
impl Side {
    /// The byte on the wire.
    pub fn code(self) -> u8 {
        match self {
            Side::Buy => b'B',
            Side::Sell => b'S',
            Side::SellShort => b'T',
            Side::SellShortExempt => b'E',
        }
    }
    /// The side a byte names.
    pub fn from_code(code: u8) -> Result<Self, Error> {
        match code {
            b'B' => Ok(Side::Buy),
            b'S' => Ok(Side::Sell),
            b'T' => Ok(Side::SellShort),
            b'E' => Ok(Side::SellShortExempt),
            other => Err(Error::Side(other)),
        }
    }
}
impl Field for Side {
    const LEN: usize = 1;
    fn get(b: &[u8]) -> Result<Self, Error> {
        Side::from_code(u8::get(b)?)
    }
    fn put(&self, out: &mut Vec<u8>) {
        out.push(self.code());
    }
}

/// One optional field of an appendage, by its OptionTag (Appendix A).
/// Sizes are the value's, without the TagValue length and tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opt {
    /// Tag 1, 8 bytes: the reference number on the market data feeds.
    SecondaryOrdRefNum(u64),
    /// Tag 2, 4 bytes: the entering firm.
    Firm(Firm),
    /// Tag 3, 4 bytes: minimum quantity.
    MinQty(u32),
    /// Tag 4, 1 byte: "R" retail designated, "N" not.
    CustomerType(u8),
    /// Tag 5, 4 bytes: the displayed portion.
    MaxFloor(u32),
    /// Tag 6, 1 byte: "L" limit, "P" market peg, "M" midpoint peg, "R"
    /// primary peg, "Q" market maker peg, "m" midpoint.
    PriceType(u8),
    /// Tag 7, 4 bytes: signed peg offset, four decimal places.
    PegOffset(i32),
    /// Tag 9, 8 bytes: discretion price.
    DiscretionPrice(Price),
    /// Tag 10, 1 byte: discretion price type, as [`Opt::PriceType`].
    DiscretionPriceType(u8),
    /// Tag 11, 4 bytes: signed discretion peg offset.
    DiscretionPegOffset(i32),
    /// Tag 12, 1 byte: "P" post only, "N" no.
    PostOnly(u8),
    /// Tag 13, 4 bytes: shares for random reserves.
    RandomReserves(u32),
    /// Tag 14, 4 bytes: route.
    Route(Alpha<4>),
    /// Tag 15, 4 bytes: seconds to live, under 86400.
    ExpireTime(u32),
    /// Tag 16, 1 byte: "Y" or "N".
    TradeNow(u8),
    /// Tag 17, 1 byte: handling instructions.
    HandleInst(u8),
    /// Tag 18, 1 byte: BBO weight indicator.
    BboWeightIndicator(u8),
    /// Tag 22, 4 bytes: a restated displayed quantity.
    DisplayQuantity(u32),
    /// Tag 23, 8 bytes: a restated displayed price.
    DisplayPrice(Price),
    /// Tag 24, 2 bytes: customer group ID.
    GroupId(u16),
    /// Tag 25, 1 byte: "Y" shares located for a short sale, "N" not.
    SharesLocated(u8),
    /// Tag 26, 4 bytes: the broker the locate came from.
    LocateBroker(Alpha<4>),
    /// Tag 27, 1 byte: side.
    Side(Side),
    /// Tag 28, 1 byte: the order flow channel within the port.
    UserRefIdx(u8),
    /// Tag 29, 1 byte: self match prevention strategy.
    AiqStrategy(u8),
    /// Tag 30, 2 bytes: self match prevention group.
    AiqGroupId(Alpha<2>),
    /// A tag Appendix A does not define, kept as bytes. Writing refuses a
    /// defined tag here.
    Other {
        /// The OptionTag.
        tag: u8,
        /// The value, up to [`MAX_OPTION_VALUE`] bytes.
        value: Vec<u8>,
    },
}
impl Opt {
    /// The OptionTag.
    pub fn tag(&self) -> u8 {
        match self {
            Opt::SecondaryOrdRefNum(_) => 1,
            Opt::Firm(_) => 2,
            Opt::MinQty(_) => 3,
            Opt::CustomerType(_) => 4,
            Opt::MaxFloor(_) => 5,
            Opt::PriceType(_) => 6,
            Opt::PegOffset(_) => 7,
            Opt::DiscretionPrice(_) => 9,
            Opt::DiscretionPriceType(_) => 10,
            Opt::DiscretionPegOffset(_) => 11,
            Opt::PostOnly(_) => 12,
            Opt::RandomReserves(_) => 13,
            Opt::Route(_) => 14,
            Opt::ExpireTime(_) => 15,
            Opt::TradeNow(_) => 16,
            Opt::HandleInst(_) => 17,
            Opt::BboWeightIndicator(_) => 18,
            Opt::DisplayQuantity(_) => 22,
            Opt::DisplayPrice(_) => 23,
            Opt::GroupId(_) => 24,
            Opt::SharesLocated(_) => 25,
            Opt::LocateBroker(_) => 26,
            Opt::Side(_) => 27,
            Opt::UserRefIdx(_) => 28,
            Opt::AiqStrategy(_) => 29,
            Opt::AiqGroupId(_) => 30,
            Opt::Other { tag, .. } => *tag,
        }
    }
    /// Whether Appendix A defines `tag`.
    pub fn is_defined(tag: u8) -> bool {
        matches!(tag, 1..=7 | 9..=18 | 22..=30)
    }
    /// Bytes of the value.
    pub fn value_len(&self) -> usize {
        match self {
            Opt::SecondaryOrdRefNum(_) | Opt::DiscretionPrice(_) | Opt::DisplayPrice(_) => 8,
            Opt::Firm(_)
            | Opt::MinQty(_)
            | Opt::MaxFloor(_)
            | Opt::PegOffset(_)
            | Opt::DiscretionPegOffset(_)
            | Opt::RandomReserves(_)
            | Opt::Route(_)
            | Opt::ExpireTime(_)
            | Opt::DisplayQuantity(_)
            | Opt::LocateBroker(_) => 4,
            Opt::GroupId(_) | Opt::AiqGroupId(_) => 2,
            Opt::Other { value, .. } => value.len(),
            _ => 1,
        }
    }
    fn read(tag: u8, v: &[u8]) -> Result<Self, Error> {
        let f = |e: Error| match e {
            Error::Length => Error::Option(tag),
            other => other,
        };
        let one = || u8::get(v).map_err(f);
        Ok(match tag {
            1 => Opt::SecondaryOrdRefNum(u64::get(v).map_err(f)?),
            2 => Opt::Firm(Alpha::get(v).map_err(f)?),
            3 => Opt::MinQty(u32::get(v).map_err(f)?),
            4 => Opt::CustomerType(one()?),
            5 => Opt::MaxFloor(u32::get(v).map_err(f)?),
            6 => Opt::PriceType(one()?),
            7 => Opt::PegOffset(i32::get(v).map_err(f)?),
            9 => Opt::DiscretionPrice(Price::get(v).map_err(f)?),
            10 => Opt::DiscretionPriceType(one()?),
            11 => Opt::DiscretionPegOffset(i32::get(v).map_err(f)?),
            12 => Opt::PostOnly(one()?),
            13 => Opt::RandomReserves(u32::get(v).map_err(f)?),
            14 => Opt::Route(Alpha::get(v).map_err(f)?),
            15 => Opt::ExpireTime(u32::get(v).map_err(f)?),
            16 => Opt::TradeNow(one()?),
            17 => Opt::HandleInst(one()?),
            18 => Opt::BboWeightIndicator(one()?),
            22 => Opt::DisplayQuantity(u32::get(v).map_err(f)?),
            23 => Opt::DisplayPrice(Price::get(v).map_err(f)?),
            24 => Opt::GroupId(u16::get(v).map_err(f)?),
            25 => Opt::SharesLocated(one()?),
            26 => Opt::LocateBroker(Alpha::get(v).map_err(f)?),
            27 => Opt::Side(Side::get(v).map_err(f)?),
            28 => Opt::UserRefIdx(one()?),
            29 => Opt::AiqStrategy(one()?),
            30 => Opt::AiqGroupId(Alpha::get(v).map_err(f)?),
            _ => Opt::Other {
                tag,
                value: v.to_vec(),
            },
        })
    }
    fn put_value(&self, out: &mut Vec<u8>) {
        match self {
            Opt::SecondaryOrdRefNum(v) => v.put(out),
            Opt::Firm(v) | Opt::Route(v) | Opt::LocateBroker(v) => v.put(out),
            Opt::MinQty(v)
            | Opt::MaxFloor(v)
            | Opt::RandomReserves(v)
            | Opt::ExpireTime(v)
            | Opt::DisplayQuantity(v) => v.put(out),
            Opt::CustomerType(v)
            | Opt::PriceType(v)
            | Opt::DiscretionPriceType(v)
            | Opt::PostOnly(v)
            | Opt::TradeNow(v)
            | Opt::HandleInst(v)
            | Opt::BboWeightIndicator(v)
            | Opt::SharesLocated(v)
            | Opt::UserRefIdx(v)
            | Opt::AiqStrategy(v) => v.put(out),
            Opt::PegOffset(v) | Opt::DiscretionPegOffset(v) => v.put(out),
            Opt::DiscretionPrice(v) | Opt::DisplayPrice(v) => v.put(out),
            Opt::GroupId(v) => v.put(out),
            Opt::Side(v) => v.put(out),
            Opt::AiqGroupId(v) => v.put(out),
            Opt::Other { value, .. } => out.extend_from_slice(value),
        }
    }
}

/// An optional appendage: TagValue elements in order (1.2). Each element
/// is a length byte (counting the tag and value), the tag and the value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options(pub Vec<Opt>);
impl Options {
    /// The appendage holding only `opt`.
    pub fn of(opt: Opt) -> Self {
        Self(vec![opt])
    }
    /// The first option with `tag`.
    pub fn get(&self, tag: u8) -> Option<&Opt> {
        self.0.iter().find(|o| o.tag() == tag)
    }
    /// The UserRefIdx channel, or 0 when absent.
    pub fn user_ref_idx(&self) -> u8 {
        self.0
            .iter()
            .find_map(|o| match o {
                Opt::UserRefIdx(i) => Some(*i),
                _ => None,
            })
            .unwrap_or(0)
    }
    /// The Firm option, when present.
    pub fn firm(&self) -> Option<Firm> {
        self.0.iter().find_map(|o| match o {
            Opt::Firm(f) => Some(*f),
            _ => None,
        })
    }
    /// The Side option, when present.
    pub fn side(&self) -> Option<Side> {
        self.0.iter().find_map(|o| match o {
            Opt::Side(s) => Some(*s),
            _ => None,
        })
    }
    /// The Group ID option, when present.
    pub fn group_id(&self) -> Option<u16> {
        self.0.iter().find_map(|o| match o {
            Opt::GroupId(g) => Some(*g),
            _ => None,
        })
    }
    /// Bytes of the TagValue elements, without the appendage length.
    pub fn wire_len(&self) -> usize {
        self.0.iter().fold(0usize, |n, o| {
            n.saturating_add(TAG_HEADER).saturating_add(o.value_len())
        })
    }
    /// Reads TagValue elements filling all of `b`.
    fn read(mut b: &[u8]) -> Result<Self, Error> {
        let mut opts = Vec::new();
        while let Some((&len, rest)) = b.split_first() {
            let (&tag, rest) = rest.split_first().ok_or(Error::Length)?;
            if len == 0 {
                return Err(Error::Option(tag));
            }
            let (value, rest) = rest
                .split_at_checked(usize::from(len) - 1)
                .ok_or(Error::Length)?;
            opts.push(Opt::read(tag, value)?);
            b = rest;
        }
        Ok(Self(opts))
    }
    fn check(&self) -> Result<(), Error> {
        for o in &self.0 {
            if let Opt::Other { tag, value } = o
                && (Opt::is_defined(*tag) || value.len() > MAX_OPTION_VALUE)
            {
                return Err(Error::Option(*tag));
            }
        }
        if self.wire_len() > MAX_APPENDAGE {
            return Err(Error::TooLong);
        }
        Ok(())
    }
    fn put(&self, out: &mut Vec<u8>) {
        // `check` keeps the length within two bytes and each element's
        // within one.
        out.extend_from_slice(&(self.wire_len() as u16).to_be_bytes());
        for o in &self.0 {
            out.push((o.value_len() + 1) as u8);
            out.push(o.tag());
            o.put_value(out);
        }
    }
}

/// What follows a message's fixed fields: nothing, an appendage, or an
/// appendage whose length field may be absent.
trait Tail: Sized {
    fn get(b: &[u8]) -> Result<Self, Error>;
    fn check(&self) -> Result<(), Error>;
    fn len(&self) -> usize;
    fn put(&self, out: &mut Vec<u8>);
}
impl Tail for () {
    fn get(b: &[u8]) -> Result<Self, Error> {
        if b.is_empty() {
            Ok(())
        } else {
            Err(Error::Length)
        }
    }
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
    fn len(&self) -> usize {
        0
    }
    fn put(&self, _out: &mut Vec<u8>) {}
}
impl Tail for Options {
    fn get(b: &[u8]) -> Result<Self, Error> {
        let (len, rest) = b.split_at_checked(2).ok_or(Error::Length)?;
        let len = usize::from(u16::get(len)?);
        if rest.len() != len {
            return Err(Error::Length);
        }
        Options::read(rest)
    }
    fn check(&self) -> Result<(), Error> {
        Options::check(self)
    }
    fn len(&self) -> usize {
        2 + self.wire_len()
    }
    fn put(&self, out: &mut Vec<u8>) {
        Options::put(self, out)
    }
}
impl Tail for Option<Options> {
    fn get(b: &[u8]) -> Result<Self, Error> {
        if b.is_empty() {
            Ok(None)
        } else {
            <Options as Tail>::get(b).map(Some)
        }
    }
    fn check(&self) -> Result<(), Error> {
        self.as_ref().map_or(Ok(()), Options::check)
    }
    fn len(&self) -> usize {
        self.as_ref().map_or(0, Tail::len)
    }
    fn put(&self, out: &mut Vec<u8>) {
        if let Some(o) = self {
            Tail::put(o, out);
        }
    }
}

/// Defines one direction's messages: a struct per message with its type
/// byte, its fixed fields (their total checked at compile time against
/// the offset of the specification's Appendage Length) and its tail; then
/// the enum over them.
macro_rules! messages {
    (
        $(#[doc = $edoc:literal])*
        $enum:ident;
        $(
            $(#[doc = $doc:literal])*
            $name:ident = $kind:literal, $fixed:literal {
                $( $(#[doc = $fdoc:literal])* $field:ident: $ty:ty, )*
            } $(#[doc = $tdoc:literal])* $tail:ident: $tty:ty;
        )*
    ) => {
        $(
            $(#[doc = $doc])*
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct $name {
                $( $(#[doc = $fdoc])* pub $field: $ty, )*
                $(#[doc = $tdoc])*
                pub $tail: $tty,
            }
            impl $name {
                /// The message type byte.
                pub const KIND: u8 = $kind;
                /// Bytes before the appendage length (or all of them, for a
                /// message without one), type byte included.
                pub const FIXED: usize = $fixed;
                #[allow(unused_mut)]
                fn read_body(mut b: &[u8]) -> Result<Self, Error> {
                    $( let $field = take(&mut b)?; )*
                    let $tail = Tail::get(b)?;
                    Ok(Self { $($field,)* $tail })
                }
                /// Bytes on the wire.
                pub fn wire_len(&self) -> usize {
                    $fixed + Tail::len(&self.$tail)
                }
                fn write_body(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                    Tail::check(&self.$tail)?;
                    out.reserve(self.wire_len());
                    out.push(Self::KIND);
                    $( Field::put(&self.$field, out); )*
                    Tail::put(&self.$tail, out);
                    Ok(())
                }
            }
            const _: () = assert!(1 $(+ <$ty as Field>::LEN)* == $fixed);
            impl Wire for $name {
                type ParseError = Error;
                type WriteError = Error;
                /// Reads one whole message of this type.
                fn parse(b: &[u8]) -> Result<Self, Error> {
                    let (&kind, body) = b.split_first().ok_or(Error::Length)?;
                    if kind != $kind {
                        return Err(Error::Type(kind));
                    }
                    Self::read_body(body)
                }
                /// Writes the message. Refuses an invalid appendage.
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
        }
        impl $enum {
            /// The message type byte.
            pub fn kind(&self) -> u8 {
                match self {
                    $( $enum::$name(_) => $kind, )*
                }
            }
            /// Bytes on the wire.
            pub fn wire_len(&self) -> usize {
                match self {
                    $( $enum::$name(m) => m.wire_len(), )*
                }
            }
            /// Every message type byte, in specification order.
            pub const KINDS: &'static [u8] = &[$($kind),*];
        }
        impl Wire for $enum {
            type ParseError = Error;
            type WriteError = Error;
            /// Reads one whole message of any type of this direction.
            fn parse(b: &[u8]) -> Result<Self, Error> {
                let (&kind, body) = b.split_first().ok_or(Error::Length)?;
                match kind {
                    $( $kind => $name::read_body(body).map($enum::$name), )*
                    other => Err(Error::Type(other)),
                }
            }
            /// Writes the message. Refuses an invalid appendage.
            fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                match self {
                    $( $enum::$name(m) => m.write_body(out), )*
                }
            }
        }
    };
}

messages! {
    /// A message from the client to the exchange (2), carried in
    /// SoupBinTCP unsequenced data.
    Inbound;

    /// "O", Enter Order (2.1).
    EnterOrder = b'O', 45 {
        /// Day-unique and strictly increasing per channel.
        user_ref: u32,
        /// The side.
        side: Side,
        /// Shares, 1 to 999,999.
        quantity: u32,
        /// The symbol.
        symbol: Symbol,
        /// The limit price, or [`MARKET_PRICE`].
        price: Price,
        /// See [`codes::time_in_force`].
        time_in_force: u8,
        /// See [`codes::display`].
        display: u8,
        /// "A" agency, "P" principal, "R" riskless, "O" other.
        capacity: u8,
        /// "Y" eligible, "N" not.
        intermarket_sweep: u8,
        /// See [`codes::cross_type`].
        cross_type: u8,
        /// The client's identifier, not checked for uniqueness.
        cl_ord_id: ClOrdId,
    }
    /// Firm, MinQty, CustomerType, MaxFloor, PriceType, PegOffset,
    /// discretion, PostOnly, RandomReserves, ExpireTime, TradeNow,
    /// HandleInst, GroupID, SharesLocated, LocateBroker, UserRefIdx, AIQ.
    options: Options;

    /// "U", Replace Order Request (2.2).
    ReplaceOrder = b'U', 38 {
        /// The order replaced.
        orig_user_ref: u32,
        /// The replacement's UserRefNum, new and increasing.
        user_ref: u32,
        /// Shares liable over the whole chain, executions included.
        quantity: u32,
        /// The replacement's price.
        price: Price,
        /// See [`codes::time_in_force`].
        time_in_force: u8,
        /// See [`codes::display`].
        display: u8,
        /// "Y" eligible, "N" not.
        intermarket_sweep: u8,
        /// The replacement's client identifier.
        cl_ord_id: ClOrdId,
    }
    /// The Enter Order options except Firm and GroupID, plus Side.
    options: Options;

    /// "X", Cancel Order Request (2.3).
    CancelOrder = b'X', 9 {
        /// The order.
        user_ref: u32,
        /// The new intended order size; 0 cancels the rest.
        quantity: u32,
    }
    /// UserRefIdx. The appendage is optional on this message.
    options: Option<Options>;

    /// "M", Modify Order Request (2.4).
    ModifyOrder = b'M', 10 {
        /// The order.
        user_ref: u32,
        /// The new side: S to E, S to T or E to T.
        side: Side,
        /// The new intended order size; it may not grow.
        quantity: u32,
    }
    /// UserRefIdx, SharesLocated, LocateBroker. Optional on this message.
    options: Option<Options>;

    /// "C", Mass Cancel Request (2.5).
    MassCancel = b'C', 17 {
        /// Day-unique and strictly increasing per channel.
        user_ref: u32,
        /// The firm whose orders to cancel.
        firm: Firm,
        /// The symbol, or blank for all.
        symbol: Symbol,
    }
    /// Side, Group ID, UserRefIdx.
    options: Options;

    /// "D", Disable Order Entry Request (2.6).
    DisableOrderEntry = b'D', 9 {
        /// Day-unique and strictly increasing per channel.
        user_ref: u32,
        /// The firm to block.
        firm: Firm,
    }
    /// UserRefIdx.
    options: Options;

    /// "E", Enable Order Entry Request (2.7).
    EnableOrderEntry = b'E', 9 {
        /// Day-unique and strictly increasing per channel.
        user_ref: u32,
        /// The firm to unblock.
        firm: Firm,
    }
    /// UserRefIdx.
    options: Options;

    /// "Q", Account Query Request (2.8).
    AccountQuery = b'Q', 1 {
    }
    /// UserRefIdx. Optional on this message.
    options: Option<Options>;
}

messages! {
    /// A message from the exchange to the client (3), carried in
    /// SoupBinTCP sequenced data.
    Outbound;

    /// "S", System Event (3.1).
    SystemEvent = b'S', 10 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// "S" start of day, "E" end of day.
        event: u8,
    }
    /// No appendage.
    end: ();

    /// "A", Order Accepted (3.2).
    OrderAccepted = b'A', 62 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order's UserRefNum as entered.
        user_ref: u32,
        /// The side as entered.
        side: Side,
        /// Shares accepted.
        quantity: u32,
        /// The symbol as entered.
        symbol: Symbol,
        /// The accepted price, at least as good as entered.
        price: Price,
        /// The accepted time in force.
        time_in_force: u8,
        /// The accepted display.
        display: u8,
        /// The exchange's day-unique order reference number.
        order_ref: u64,
        /// The capacity.
        capacity: u8,
        /// "Y" eligible, "N" not.
        intermarket_sweep: u8,
        /// The cross type as entered.
        cross_type: u8,
        /// "L" live, "D" dead (accepted and canceled at once).
        order_state: u8,
        /// The client's identifier.
        cl_ord_id: ClOrdId,
    }
    /// The accepted options.
    options: Options;

    /// "U", Order Replaced (3.3).
    OrderReplaced = b'U', 66 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order replaced.
        orig_user_ref: u32,
        /// The replacement's UserRefNum.
        user_ref: u32,
        /// The side.
        side: Side,
        /// Shares left on the book after the replace.
        quantity: u32,
        /// The symbol.
        symbol: Symbol,
        /// The accepted price.
        price: Price,
        /// The accepted time in force.
        time_in_force: u8,
        /// The accepted display.
        display: u8,
        /// The replacement's order reference number.
        order_ref: u64,
        /// The capacity.
        capacity: u8,
        /// "Y" eligible, "N" not.
        intermarket_sweep: u8,
        /// The cross type.
        cross_type: u8,
        /// "L" live, "D" dead.
        order_state: u8,
        /// The replacement's client identifier.
        cl_ord_id: ClOrdId,
    }
    /// The accepted options.
    options: Options;

    /// "C", Order Canceled (3.4).
    OrderCanceled = b'C', 18 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
        /// Shares taken off, incremental.
        quantity: u32,
        /// See [`codes::cancel_reason`].
        reason: u8,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;

    /// "D", AIQ Canceled (3.5): reduced by self match prevention.
    AiqCanceled = b'D', 32 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
        /// Shares taken off, incremental.
        decrement_shares: u32,
        /// Always "Q".
        reason: u8,
        /// Shares that would have executed.
        quantity_prevented: u32,
        /// The price it would have executed at.
        execution_price: Price,
        /// The liquidity flag it would have had.
        liquidity_flag: u8,
        /// The strategy used.
        aiq_strategy: u8,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;

    /// "E", Order Executed (3.6).
    OrderExecuted = b'E', 34 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
        /// Shares executed, incremental.
        quantity: u32,
        /// The execution price.
        price: Price,
        /// See Appendix D.
        liquidity_flag: u8,
        /// Shared by both sides of the trade.
        match_number: u64,
    }
    /// UserRefIdx.
    options: Options;

    /// "B", Broken Trade (3.7).
    BrokenTrade = b'B', 36 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
        /// The execution broken.
        match_number: u64,
        /// See [`codes::broken_trade_reason`].
        reason: u8,
        /// The client's identifier.
        cl_ord_id: ClOrdId,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;

    /// "J", Rejected (3.8): an Enter or Replace was refused.
    OrderRejected = b'J', 29 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order or replacement.
        user_ref: u32,
        /// See [`codes::reject_reason`].
        reason: u16,
        /// The client's identifier.
        cl_ord_id: ClOrdId,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;

    /// "P", Cancel Pending (3.9): a cross order will be canceled after the
    /// cross.
    CancelPending = b'P', 13 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;

    /// "I", Cancel Reject (3.10): a partial cancel of a cross order was
    /// refused.
    CancelReject = b'I', 13 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;

    /// "T", Order Priority Update (3.11).
    PriorityUpdate = b'T', 30 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
        /// The limit price.
        price: Price,
        /// The new display.
        display: u8,
        /// The new order reference number.
        order_ref: u64,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;

    /// "M", Order Modified (3.12).
    OrderModified = b'M', 18 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
        /// The side as modified.
        side: Side,
        /// Shares outstanding.
        quantity: u32,
    }
    /// UserRefIdx, SharesLocated, LocateBroker; present only for a
    /// nonzero channel.
    options: Option<Options>;

    /// "R", Order Restated (3.13).
    OrderRestated = b'R', 14 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The order.
        user_ref: u32,
        /// "R" refresh of display, "P" update of displayed price.
        reason: u8,
    }
    /// Display Quantity, Display Price, SecondaryOrdRefNum, UserRefIdx.
    options: Options;

    /// "X", Mass Cancel Response (3.14).
    MassCancelResponse = b'X', 25 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The request's UserRefNum.
        user_ref: u32,
        /// The firm.
        firm: Firm,
        /// The symbol, or blank.
        symbol: Symbol,
    }
    /// Side, Group ID, UserRefIdx, as requested.
    options: Options;

    /// "G", Disable Order Entry Response (3.15).
    DisableOrderEntryResponse = b'G', 17 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The request's UserRefNum.
        user_ref: u32,
        /// The firm.
        firm: Firm,
    }
    /// UserRefIdx.
    options: Options;

    /// "K", Enable Order Entry Response (3.16).
    EnableOrderEntryResponse = b'K', 17 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The request's UserRefNum.
        user_ref: u32,
        /// The firm.
        firm: Firm,
    }
    /// UserRefIdx.
    options: Options;

    /// "Q", Account Query Response (3.17).
    AccountQueryResponse = b'Q', 13 {
        /// Nanoseconds since midnight.
        timestamp: u64,
        /// The next UserRefNum the channel may use.
        next_user_ref: u32,
    }
    /// UserRefIdx, present only for a nonzero channel.
    options: Option<Options>;
}

/// The values the specification lists for one-byte and reason fields.
pub mod codes {
    /// Time in force (2.1).
    pub mod time_in_force {
        /// "0": day, market hours.
        pub const DAY: u8 = b'0';
        /// "3": immediate or cancel.
        pub const IOC: u8 = b'3';
        /// "5": extended hours.
        pub const GTX: u8 = b'5';
        /// "6": good till time (needs ExpireTime).
        pub const GTT: u8 = b'6';
        /// "E": after hours.
        pub const AFTER_HOURS: u8 = b'E';
    }
    /// Display (2.1, 3.2).
    pub mod display {
        /// "Y": visible.
        pub const VISIBLE: u8 = b'Y';
        /// "N": hidden.
        pub const HIDDEN: u8 = b'N';
        /// "A": attributable.
        pub const ATTRIBUTABLE: u8 = b'A';
        /// "Z": conformant (outbound only).
        pub const CONFORMANT: u8 = b'Z';
    }
    /// Cross types (2.1).
    pub mod cross_type {
        /// "N": continuous market.
        pub const CONTINUOUS: u8 = b'N';
        /// "O": opening cross.
        pub const OPENING: u8 = b'O';
        /// "C": closing cross.
        pub const CLOSING: u8 = b'C';
        /// "H": halt or IPO cross.
        pub const HALT_IPO: u8 = b'H';
        /// "S": supplemental.
        pub const SUPPLEMENTAL: u8 = b'S';
        /// "R": retail (BX only).
        pub const RETAIL: u8 = b'R';
        /// "E": extended life.
        pub const EXTENDED_LIFE: u8 = b'E';
        /// "A": after hours close.
        pub const AFTER_HOURS_CLOSE: u8 = b'A';
    }
    /// Order states (3.2).
    pub mod order_state {
        /// "L": live.
        pub const LIVE: u8 = b'L';
        /// "D": dead, accepted and canceled at once.
        pub const DEAD: u8 = b'D';
    }
    /// System event codes (3.1).
    pub mod event {
        /// "S": start of day.
        pub const START_OF_DAY: u8 = b'S';
        /// "E": end of day.
        pub const END_OF_DAY: u8 = b'E';
    }
    /// Order cancel reasons (Appendix B).
    pub mod cancel_reason {
        /// "D": regulatory restriction.
        pub const REGULATORY: u8 = b'D';
        /// "E": closed.
        pub const CLOSED: u8 = b'E';
        /// "F": post only, would be price slid for NMS.
        pub const POST_ONLY_NMS: u8 = b'F';
        /// "G": post only, would be price slid by a displayed order.
        pub const POST_ONLY: u8 = b'G';
        /// "H": halted.
        pub const HALTED: u8 = b'H';
        /// "I": immediate or cancel.
        pub const IMMEDIATE_OR_CANCEL: u8 = b'I';
        /// "K": market collars.
        pub const MARKET_COLLARS: u8 = b'K';
        /// "Q": self match prevention.
        pub const SELF_MATCH_PREVENTION: u8 = b'Q';
        /// "S": supervisory.
        pub const SUPERVISORY: u8 = b'S';
        /// "T": time in force expired.
        pub const TIMEOUT: u8 = b'T';
        /// "U": user requested.
        pub const USER_REQUESTED: u8 = b'U';
        /// "X": open protection.
        pub const OPEN_PROTECTION: u8 = b'X';
        /// "Z": system cancel.
        pub const SYSTEM: u8 = b'Z';
        /// "e": direct listing capital raise order exceeds shares offered.
        pub const DLCR_EXCEEDS_OFFERED: u8 = b'e';
    }
    /// Broken trade reasons (3.7).
    pub mod broken_trade_reason {
        /// "E": clearly erroneous.
        pub const ERRONEOUS: u8 = b'E';
        /// "C": both parties consented.
        pub const CONSENT: u8 = b'C';
        /// "S": supervisory.
        pub const SUPERVISORY: u8 = b'S';
        /// "X": external third party.
        pub const EXTERNAL: u8 = b'X';
    }
    /// Order reject reasons (Appendix C), a selection.
    pub mod reject_reason {
        /// Halted.
        pub const HALTED: u16 = 0x0007;
        /// Invalid side.
        pub const INVALID_SIDE: u16 = 0x0009;
        /// Processing error.
        pub const PROCESSING_ERROR: u16 = 0x000a;
        /// Firm not authorized.
        pub const FIRM_NOT_AUTHORIZED: u16 = 0x000c;
        /// Other.
        pub const OTHER: u16 = 0x000f;
        /// Invalid quantity.
        pub const INVALID_QUANTITY: u16 = 0x0013;
        /// Replace not allowed.
        pub const REPLACE_NOT_ALLOWED: u16 = 0x0015;
        /// Invalid symbol.
        pub const INVALID_SYMBOL: u16 = 0x0017;
        /// Invalid price.
        pub const INVALID_PRICE: u16 = 0x001d;
    }
}

/// An order's identity on one port: the UserRefIdx channel (0 when the
/// option is absent) and the UserRefNum (1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token {
    /// The order flow channel.
    pub user_ref_idx: u8,
    /// The UserRefNum within the channel.
    pub user_ref: u32,
}

/// The limits and numbering of an [`Exchange`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeConfig {
    /// The firm of orders that name none.
    pub default_firm: Firm,
    /// The most open and pending orders, 1 to [`MAX_ORDERS`]. An Enter
    /// past it is rejected with Processing Error.
    pub max_orders: usize,
    /// The most executions remembered for [`Exchange::break_trade`], 1 to
    /// [`MAX_EXECUTIONS`]. The oldest are forgotten.
    pub max_executions: usize,
    /// The first order reference number assigned.
    pub first_order_ref: u64,
    /// The first match number assigned.
    pub first_match: u64,
}
impl Default for ExchangeConfig {
    fn default() -> Self {
        Self {
            default_firm: Alpha(*b"FCTN"),
            max_orders: DEFAULT_MAX_ORDERS,
            max_executions: DEFAULT_MAX_EXECUTIONS,
            first_order_ref: 1,
            first_match: 1,
        }
    }
}

/// Why an [`Exchange`] refused an operation. The exchange is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeError {
    /// A configuration value outside its named limits.
    Config,
    /// No open order, or no pending enter or replace, has this token.
    UnknownToken(Token),
    /// An execute or cancel of zero shares, or more than are open.
    Shares,
    /// No remembered execution has this match number.
    UnknownMatch(u64),
    /// Order reference or match numbers ran out.
    Exhausted,
}
impl fmt::Display for ExchangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExchangeError::Config => f.write_str("OUCH exchange configuration is out of range"),
            ExchangeError::UnknownToken(t) => write!(f, "no OUCH order {t:?}"),
            ExchangeError::Shares => f.write_str("OUCH share count is invalid"),
            ExchangeError::UnknownMatch(m) => write!(f, "no OUCH execution {m}"),
            ExchangeError::Exhausted => f.write_str("OUCH numbering is exhausted"),
        }
    }
}
impl std::error::Error for ExchangeError {}

/// An order an [`Exchange`] tracks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// The order's identity.
    pub token: Token,
    /// False until [`Exchange::accept`].
    pub live: bool,
    /// The side.
    pub side: Side,
    /// Open shares.
    pub quantity: u32,
    /// Shares executed over the order's replace chain.
    pub executed: u32,
    /// The symbol.
    pub symbol: Symbol,
    /// The price.
    pub price: Price,
    /// The time in force.
    pub time_in_force: u8,
    /// The display.
    pub display: u8,
    /// The capacity.
    pub capacity: u8,
    /// Intermarket sweep eligibility.
    pub intermarket_sweep: u8,
    /// The cross type.
    pub cross_type: u8,
    /// The client's identifier.
    pub cl_ord_id: ClOrdId,
    /// The exchange's order reference number; 0 until accepted.
    pub order_ref: u64,
    /// The firm: the Firm option, or [`ExchangeConfig::default_firm`].
    pub firm: Firm,
    /// The options as entered.
    pub options: Options,
}

/// Why a request was ignored, as the specification says to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    /// A UserRefNum not above the channel's last: a retransmission (1.2).
    Retransmission(Token),
    /// No open order has this token (2.2, 2.3).
    UnknownOrder(Token),
    /// A cancel or modify that does not reduce the order (2.3, 2.4).
    NoReduction(Token),
    /// A modify to a side change other than S to E, S to T or E to T.
    SideChange(Token),
    /// A disable request when [`MAX_DISABLED_FIRMS`] are disabled.
    TooManyFirms(Firm),
}

/// What an [`Exchange`] reports to the world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A valid Enter Order. Answer with [`Exchange::accept`] or
    /// [`Exchange::reject`].
    EnterRequested(Token),
    /// A valid Replace Order for an open order. Answer with
    /// [`Exchange::accept`] or [`Exchange::reject`] on the replacement.
    ReplaceRequested {
        /// The open order.
        original: Token,
        /// The replacement.
        replacement: Token,
    },
    /// The request was dropped without a reply.
    Ignored(Ignored),
}

/// An exchange's output, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A message to send in a SoupBinTCP sequenced data packet.
    Send(Outbound),
    /// A notification for the world.
    Event(Event),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingReplace {
    original: Token,
    request: ReplaceOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Execution {
    match_number: u64,
    token: Token,
    cl_ord_id: ClOrdId,
}

/// The exchange side of one OUCH port, without I/O.
///
/// Pass each inbound message to [`receive`](Self::receive), send every
/// [`Action::Send`] in order, and answer each [`Event::EnterRequested`]
/// and [`Event::ReplaceRequested`] with [`accept`](Self::accept) or
/// [`reject`](Self::reject). The world drives executions and its own
/// cancels with [`execute`](Self::execute), [`cancel`](Self::cancel) and
/// [`break_trade`](Self::break_trade). Timestamps are nanoseconds since
/// midnight, read by the caller.
///
/// The exchange applies the rules the specification states: UserRefNums
/// must increase per UserRefIdx channel, and a lower or repeated one is a
/// retransmission and ignored (1.2); quantities must be 1 to 999,999
/// (2.1); a replace of an order that is not open, or with a used
/// UserRefNum, is ignored, and one with an invalid quantity cancels the
/// original (2.2); a cancel sets the order's open shares and is ignored if
/// it would not reduce them (2.3); a modify may only reduce shares and
/// change S to E, S to T or E to T (2.4). Replies carry the UserRefIdx
/// option when the request's channel is not 0.
///
/// Open and pending orders are bounded by [`ExchangeConfig::max_orders`],
/// remembered executions by [`ExchangeConfig::max_executions`] and
/// disabled firms by [`MAX_DISABLED_FIRMS`]. An `Err` leaves the exchange
/// unchanged.
#[derive(Clone, Debug)]
pub struct Exchange {
    config: ExchangeConfig,
    orders: HashMap<Token, Order>,
    replaces: HashMap<Token, PendingReplace>,
    last: HashMap<u8, u32>,
    disabled: Vec<Firm>,
    executions: VecDeque<Execution>,
    next_order_ref: u64,
    next_match: u64,
}
impl Exchange {
    /// An exchange with no orders. Refuses limits outside their ranges.
    pub fn new(config: ExchangeConfig) -> Result<Self, ExchangeError> {
        if !(1..=MAX_ORDERS).contains(&config.max_orders)
            || !(1..=MAX_EXECUTIONS).contains(&config.max_executions)
        {
            return Err(ExchangeError::Config);
        }
        Ok(Self {
            config,
            orders: HashMap::new(),
            replaces: HashMap::new(),
            last: HashMap::new(),
            disabled: Vec::new(),
            executions: VecDeque::new(),
            next_order_ref: config.first_order_ref,
            next_match: config.first_match,
        })
    }
    /// An order, open or awaiting [`accept`](Self::accept).
    pub fn order(&self, token: Token) -> Option<&Order> {
        self.orders.get(&token)
    }
    /// Every tracked order, in no particular order.
    pub fn orders(&self) -> impl Iterator<Item = &Order> {
        self.orders.values()
    }
    /// The next UserRefNum the channel may use.
    pub fn next_user_ref(&self, user_ref_idx: u8) -> u32 {
        self.last
            .get(&user_ref_idx)
            .map_or(1, |n| n.saturating_add(1))
    }
    /// Whether order entry is disabled for `firm`.
    pub fn is_disabled(&self, firm: Firm) -> bool {
        self.disabled.contains(&firm)
    }

    /// Handles one inbound message.
    pub fn receive(&mut self, message: &Inbound, now: u64) -> Vec<Action> {
        match message {
            Inbound::EnterOrder(m) => self.enter(m, now),
            Inbound::ReplaceOrder(m) => self.replace(m, now),
            Inbound::CancelOrder(m) => {
                let idx = m.options.as_ref().map_or(0, Options::user_ref_idx);
                self.cancel_request(
                    Token {
                        user_ref_idx: idx,
                        user_ref: m.user_ref,
                    },
                    m.quantity,
                    now,
                )
            }
            Inbound::ModifyOrder(m) => self.modify(m, now),
            Inbound::MassCancel(m) => self.mass_cancel(m, now),
            Inbound::DisableOrderEntry(m) => self.entry(m.user_ref, m.firm, &m.options, false, now),
            Inbound::EnableOrderEntry(m) => self.entry(m.user_ref, m.firm, &m.options, true, now),
            Inbound::AccountQuery(m) => {
                let idx = m.options.as_ref().map_or(0, Options::user_ref_idx);
                vec![Action::Send(
                    AccountQueryResponse {
                        timestamp: now,
                        next_user_ref: self.next_user_ref(idx),
                        options: reply(idx),
                    }
                    .into(),
                )]
            }
        }
    }

    /// Accepts a pending enter or replace and returns the Accepted or
    /// Replaced message. A replace leaves `quantity` less the chain's
    /// executions open; with none left the reply says Order Dead.
    pub fn accept(&mut self, token: Token, now: u64) -> Result<Outbound, ExchangeError> {
        let order_ref = self.next_order_ref;
        let next = order_ref.checked_add(1).ok_or(ExchangeError::Exhausted)?;
        if let Some(pending) = self.replaces.get(&token) {
            let original = self
                .orders
                .get(&pending.original)
                .ok_or(ExchangeError::UnknownToken(pending.original))?;
            let r = &pending.request;
            let open = r.quantity.saturating_sub(original.executed);
            let order = Order {
                token,
                live: true,
                quantity: open,
                price: r.price,
                time_in_force: r.time_in_force,
                display: r.display,
                intermarket_sweep: r.intermarket_sweep,
                cl_ord_id: r.cl_ord_id,
                order_ref,
                side: r.options.side().unwrap_or(original.side),
                options: inherit(&original.options, &r.options),
                ..original.clone()
            };
            let reply = OrderReplaced {
                timestamp: now,
                orig_user_ref: pending.original.user_ref,
                user_ref: token.user_ref,
                side: order.side,
                quantity: open,
                symbol: order.symbol,
                price: order.price,
                time_in_force: order.time_in_force,
                display: order.display,
                order_ref,
                capacity: order.capacity,
                intermarket_sweep: order.intermarket_sweep,
                cross_type: order.cross_type,
                order_state: if open == 0 {
                    codes::order_state::DEAD
                } else {
                    codes::order_state::LIVE
                },
                cl_ord_id: order.cl_ord_id,
                options: r.options.clone(),
            };
            let original = pending.original;
            self.replaces.remove(&token);
            self.orders.remove(&original);
            if open > 0 {
                self.orders.insert(token, order);
            }
            self.next_order_ref = next;
            return Ok(reply.into());
        }
        let order = self
            .orders
            .get_mut(&token)
            .filter(|o| !o.live)
            .ok_or(ExchangeError::UnknownToken(token))?;
        order.live = true;
        order.order_ref = order_ref;
        self.next_order_ref = next;
        Ok(OrderAccepted {
            timestamp: now,
            user_ref: token.user_ref,
            side: order.side,
            quantity: order.quantity,
            symbol: order.symbol,
            price: order.price,
            time_in_force: order.time_in_force,
            display: order.display,
            order_ref,
            capacity: order.capacity,
            intermarket_sweep: order.intermarket_sweep,
            cross_type: order.cross_type,
            order_state: codes::order_state::LIVE,
            cl_ord_id: order.cl_ord_id,
            options: order.options.clone(),
        }
        .into())
    }

    /// Rejects a pending enter or replace with an Appendix C `reason`. A
    /// rejected replace leaves the original order as it was (2.2).
    pub fn reject(
        &mut self,
        token: Token,
        reason: u16,
        now: u64,
    ) -> Result<Outbound, ExchangeError> {
        let cl_ord_id = if let Some(p) = self.replaces.remove(&token) {
            p.request.cl_ord_id
        } else {
            let o = self
                .orders
                .get(&token)
                .filter(|o| !o.live)
                .ok_or(ExchangeError::UnknownToken(token))?;
            let id = o.cl_ord_id;
            self.orders.remove(&token);
            id
        };
        Ok(rejected(token, reason, cl_ord_id, now))
    }

    /// Executes `quantity` shares of an open order at `price` with an
    /// Appendix D liquidity flag, and returns the Executed message with a
    /// new match number. The order closes when no shares are left.
    pub fn execute(
        &mut self,
        token: Token,
        quantity: u32,
        price: Price,
        liquidity_flag: u8,
        now: u64,
    ) -> Result<Outbound, ExchangeError> {
        let order = self.open(token)?;
        if quantity == 0 || quantity > order.quantity {
            return Err(ExchangeError::Shares);
        }
        let match_number = self.next_match;
        let next = match_number
            .checked_add(1)
            .ok_or(ExchangeError::Exhausted)?;
        let cl_ord_id = order.cl_ord_id;
        self.next_match = next;
        self.take(token, quantity, true);
        if self.executions.len() >= self.config.max_executions {
            self.executions.pop_front();
        }
        self.executions.push_back(Execution {
            match_number,
            token,
            cl_ord_id,
        });
        Ok(OrderExecuted {
            timestamp: now,
            user_ref: token.user_ref,
            quantity,
            price,
            liquidity_flag,
            match_number,
            options: reply(token.user_ref_idx).unwrap_or_default(),
        }
        .into())
    }

    /// Cancels `quantity` open shares of an order for the exchange's own
    /// `reason` (Appendix B), and returns the Canceled message.
    pub fn cancel(
        &mut self,
        token: Token,
        quantity: u32,
        reason: u8,
        now: u64,
    ) -> Result<Outbound, ExchangeError> {
        let order = self.open(token)?;
        if quantity == 0 || quantity > order.quantity {
            return Err(ExchangeError::Shares);
        }
        self.take(token, quantity, false);
        Ok(canceled(token, quantity, reason, now))
    }

    /// Breaks a remembered execution and returns the Broken Trade message
    /// with an [`codes::broken_trade_reason`].
    pub fn break_trade(
        &mut self,
        match_number: u64,
        reason: u8,
        now: u64,
    ) -> Result<Outbound, ExchangeError> {
        let i = self
            .executions
            .iter()
            .position(|e| e.match_number == match_number)
            .ok_or(ExchangeError::UnknownMatch(match_number))?;
        let e = self
            .executions
            .remove(i)
            .ok_or(ExchangeError::UnknownMatch(match_number))?;
        Ok(BrokenTrade {
            timestamp: now,
            user_ref: e.token.user_ref,
            match_number,
            reason,
            cl_ord_id: e.cl_ord_id,
            options: reply(e.token.user_ref_idx),
        }
        .into())
    }

    /// A System Event message.
    pub fn system_event(&self, event: u8, now: u64) -> Outbound {
        SystemEvent {
            timestamp: now,
            event,
            end: (),
        }
        .into()
    }

    fn open(&self, token: Token) -> Result<&Order, ExchangeError> {
        self.orders
            .get(&token)
            .filter(|o| o.live)
            .ok_or(ExchangeError::UnknownToken(token))
    }
    /// Takes shares off an open order, checked by the caller, and closes
    /// it at zero, dropping any replace waiting on it.
    fn take(&mut self, token: Token, quantity: u32, executed: bool) {
        let Some(order) = self.orders.get_mut(&token) else {
            return;
        };
        order.quantity -= quantity;
        if executed {
            order.executed = order.executed.saturating_add(quantity);
        }
        if order.quantity == 0 {
            self.orders.remove(&token);
            self.replaces.retain(|_, p| p.original != token);
        }
    }
    /// Consumes a UserRefNum if it is above the channel's last.
    fn consume(&mut self, token: Token) -> bool {
        let last = self.last.entry(token.user_ref_idx).or_insert(0);
        if token.user_ref <= *last {
            return false;
        }
        *last = token.user_ref;
        true
    }
    fn fresh(&self, token: Token) -> bool {
        self.last
            .get(&token.user_ref_idx)
            .is_none_or(|last| token.user_ref > *last)
    }
    fn firm_of(&self, options: &Options) -> Firm {
        options
            .firm()
            .filter(|f| !f.is_blank())
            .unwrap_or(self.config.default_firm)
    }

    fn enter(&mut self, m: &EnterOrder, now: u64) -> Vec<Action> {
        let token = Token {
            user_ref_idx: m.options.user_ref_idx(),
            user_ref: m.user_ref,
        };
        if !self.consume(token) {
            return vec![Action::Event(Event::Ignored(Ignored::Retransmission(
                token,
            )))];
        }
        let firm = self.firm_of(&m.options);
        let reason = if m.quantity == 0 || m.quantity >= MAX_ORDER_QUANTITY {
            Some(codes::reject_reason::INVALID_QUANTITY)
        } else if self.is_disabled(firm) {
            Some(codes::reject_reason::FIRM_NOT_AUTHORIZED)
        } else if self.orders.len() + self.replaces.len() >= self.config.max_orders {
            Some(codes::reject_reason::PROCESSING_ERROR)
        } else {
            None
        };
        if let Some(reason) = reason {
            return vec![Action::Send(rejected(token, reason, m.cl_ord_id, now))];
        }
        self.orders.insert(
            token,
            Order {
                token,
                live: false,
                side: m.side,
                quantity: m.quantity,
                executed: 0,
                symbol: m.symbol,
                price: m.price,
                time_in_force: m.time_in_force,
                display: m.display,
                capacity: m.capacity,
                intermarket_sweep: m.intermarket_sweep,
                cross_type: m.cross_type,
                cl_ord_id: m.cl_ord_id,
                order_ref: 0,
                firm,
                options: m.options.clone(),
            },
        );
        vec![Action::Event(Event::EnterRequested(token))]
    }

    fn replace(&mut self, m: &ReplaceOrder, now: u64) -> Vec<Action> {
        let idx = m.options.user_ref_idx();
        let original = Token {
            user_ref_idx: idx,
            user_ref: m.orig_user_ref,
        };
        let replacement = Token {
            user_ref_idx: idx,
            user_ref: m.user_ref,
        };
        let busy = self.replaces.values().any(|p| p.original == original);
        let Some(order) = self.orders.get(&original).filter(|o| o.live && !busy) else {
            return vec![Action::Event(Event::Ignored(Ignored::UnknownOrder(
                original,
            )))];
        };
        if !self.fresh(replacement) {
            return vec![Action::Event(Event::Ignored(Ignored::Retransmission(
                replacement,
            )))];
        }
        if m.quantity == 0 || m.quantity >= MAX_ORDER_QUANTITY {
            // 2.2, case 2: the original leaves the book and the
            // replacement UserRefNum is not consumed. The specification
            // names no cancel reason; this uses System.
            let open = order.quantity;
            self.take(original, open, false);
            return vec![Action::Send(canceled(
                original,
                open,
                codes::cancel_reason::SYSTEM,
                now,
            ))];
        }
        self.consume(replacement);
        self.replaces.insert(
            replacement,
            PendingReplace {
                original,
                request: m.clone(),
            },
        );
        vec![Action::Event(Event::ReplaceRequested {
            original,
            replacement,
        })]
    }

    fn cancel_request(&mut self, token: Token, quantity: u32, now: u64) -> Vec<Action> {
        let Ok(order) = self.open(token) else {
            return vec![Action::Event(Event::Ignored(Ignored::UnknownOrder(token)))];
        };
        if quantity >= order.quantity {
            return vec![Action::Event(Event::Ignored(Ignored::NoReduction(token)))];
        }
        let decrement = order.quantity - quantity;
        self.take(token, decrement, false);
        vec![Action::Send(canceled(
            token,
            decrement,
            codes::cancel_reason::USER_REQUESTED,
            now,
        ))]
    }

    fn modify(&mut self, m: &ModifyOrder, now: u64) -> Vec<Action> {
        let idx = m.options.as_ref().map_or(0, Options::user_ref_idx);
        let token = Token {
            user_ref_idx: idx,
            user_ref: m.user_ref,
        };
        let Ok(order) = self.open(token) else {
            return vec![Action::Event(Event::Ignored(Ignored::UnknownOrder(token)))];
        };
        let allowed = order.side == m.side
            || matches!(
                (order.side, m.side),
                (Side::Sell, Side::SellShortExempt | Side::SellShort)
                    | (Side::SellShortExempt, Side::SellShort)
            );
        if !allowed {
            return vec![Action::Event(Event::Ignored(Ignored::SideChange(token)))];
        }
        if m.quantity > order.quantity {
            return vec![Action::Event(Event::Ignored(Ignored::NoReduction(token)))];
        }
        let decrement = order.quantity - m.quantity;
        if let Some(o) = self.orders.get_mut(&token) {
            o.side = m.side;
        }
        if decrement > 0 {
            self.take(token, decrement, false);
        }
        vec![Action::Send(
            OrderModified {
                timestamp: now,
                user_ref: m.user_ref,
                side: m.side,
                quantity: m.quantity,
                options: reply(idx),
            }
            .into(),
        )]
    }

    fn mass_cancel(&mut self, m: &MassCancel, now: u64) -> Vec<Action> {
        let token = Token {
            user_ref_idx: m.options.user_ref_idx(),
            user_ref: m.user_ref,
        };
        if !self.consume(token) {
            return vec![Action::Event(Event::Ignored(Ignored::Retransmission(
                token,
            )))];
        }
        let firm = if m.firm.is_blank() {
            self.config.default_firm
        } else {
            m.firm
        };
        let side = m.options.side();
        let group = m.options.group_id();
        let mut hits: Vec<(Token, u32)> = self
            .orders
            .values()
            .filter(|o| {
                o.live
                    && o.firm == firm
                    && (m.symbol.is_blank() || o.symbol == m.symbol)
                    && side.is_none_or(|s| s == o.side)
                    && group.is_none_or(|g| g == o.options.group_id().unwrap_or(0))
            })
            .map(|o| (o.token, o.quantity))
            .collect();
        hits.sort();
        let mut actions = vec![Action::Send(
            MassCancelResponse {
                timestamp: now,
                user_ref: m.user_ref,
                firm: m.firm,
                symbol: m.symbol,
                options: m.options.clone(),
            }
            .into(),
        )];
        for (t, open) in hits {
            self.take(t, open, false);
            actions.push(Action::Send(canceled(
                t,
                open,
                codes::cancel_reason::USER_REQUESTED,
                now,
            )));
        }
        actions
    }

    fn entry(
        &mut self,
        user_ref: u32,
        firm: Firm,
        options: &Options,
        enable: bool,
        now: u64,
    ) -> Vec<Action> {
        let token = Token {
            user_ref_idx: options.user_ref_idx(),
            user_ref,
        };
        if !self.consume(token) {
            return vec![Action::Event(Event::Ignored(Ignored::Retransmission(
                token,
            )))];
        }
        let target = if firm.is_blank() {
            self.config.default_firm
        } else {
            firm
        };
        let mut actions = Vec::new();
        if enable {
            self.disabled.retain(|f| *f != target);
        } else if !self.disabled.contains(&target) {
            if self.disabled.len() >= MAX_DISABLED_FIRMS {
                actions.push(Action::Event(Event::Ignored(Ignored::TooManyFirms(target))));
            } else {
                self.disabled.push(target);
            }
        }
        let options = options.clone();
        actions.insert(
            0,
            Action::Send(if enable {
                EnableOrderEntryResponse {
                    timestamp: now,
                    user_ref,
                    firm,
                    options,
                }
                .into()
            } else {
                DisableOrderEntryResponse {
                    timestamp: now,
                    user_ref,
                    firm,
                    options,
                }
                .into()
            }),
        );
        actions
    }
}

/// A replacement's options: those of the replace, and for a tag it leaves
/// out, the original order's. SharesLocated and LocateBroker are not
/// inherited; a replace must give them again (Appendix A, note 2). Firm
/// and GroupID, which a replace cannot carry, stay the original's (2.2).
fn inherit(original: &Options, replace: &Options) -> Options {
    let mut options = replace.clone();
    for o in &original.0 {
        let tag = o.tag();
        if !matches!(tag, 25 | 26) && replace.get(tag).is_none() {
            options.0.push(o.clone());
        }
    }
    options
}

/// The appendage of a reply: UserRefIdx for a nonzero channel, else none.
fn reply(user_ref_idx: u8) -> Option<Options> {
    (user_ref_idx != 0).then(|| Options::of(Opt::UserRefIdx(user_ref_idx)))
}
fn rejected(token: Token, reason: u16, cl_ord_id: ClOrdId, now: u64) -> Outbound {
    OrderRejected {
        timestamp: now,
        user_ref: token.user_ref,
        reason,
        cl_ord_id,
        options: reply(token.user_ref_idx),
    }
    .into()
}
fn canceled(token: Token, quantity: u32, reason: u8, now: u64) -> Outbound {
    OrderCanceled {
        timestamp: now,
        user_ref: token.user_ref,
        quantity,
        reason,
        options: reply(token.user_ref_idx),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{
        contract::{check_wire, check_wire_value},
        test_support::{Lcg, mutate},
    };

    fn alpha<const N: usize>(s: &str) -> Alpha<N> {
        Alpha::right_padded(s).unwrap()
    }
    fn enter(user_ref: u32, quantity: u32, options: Options) -> EnterOrder {
        EnterOrder {
            user_ref,
            side: Side::Buy,
            quantity,
            symbol: alpha("ZVZZT"),
            price: Price(102_500),
            time_in_force: codes::time_in_force::DAY,
            display: codes::display::VISIBLE,
            capacity: b'A',
            intermarket_sweep: b'N',
            cross_type: codes::cross_type::CONTINUOUS,
            cl_ord_id: alpha("ORDER1"),
            options,
        }
    }

    // 2.1: type 0, UserRefNum 1, side 5, quantity 6, symbol 10, price 18
    // (eight bytes), TIF 26, display 27, capacity 28, ISO 29, cross 30,
    // ClOrdID 31, appendage length 45, appendage 47. 1.2: a TagValue is a
    // remaining length, a tag and the value.
    #[test]
    fn enter_order_bytes() {
        let m = enter(
            0x0102_0304,
            100,
            Options(vec![Opt::Firm(alpha("ABCD")), Opt::UserRefIdx(7)]),
        );
        let mut b = vec![b'O', 1, 2, 3, 4, b'B', 0, 0, 0, 100];
        b.extend_from_slice(b"ZVZZT   ");
        b.extend_from_slice(&102_500u64.to_be_bytes());
        b.extend_from_slice(b"0YANN");
        b.extend_from_slice(b"ORDER1        ");
        assert_eq!(b.len(), 45);
        b.extend_from_slice(&[0, 9]);
        b.extend_from_slice(&[5, 2, b'A', b'B', b'C', b'D']);
        b.extend_from_slice(&[2, 28, 7]);
        assert_eq!(m.to_bytes().unwrap(), b);
        assert_eq!(Inbound::parse(&b).unwrap(), Inbound::EnterOrder(m.clone()));
        assert_eq!(m.wire_len(), b.len());
        assert_eq!(m.options.user_ref_idx(), 7);
    }

    // 2.3: Cancel Order, with and without the optional appendage.
    #[test]
    fn cancel_order_bytes() {
        let bare = CancelOrder {
            user_ref: 9,
            quantity: 0,
            options: None,
        };
        assert_eq!(bare.to_bytes().unwrap(), [b'X', 0, 0, 0, 9, 0, 0, 0, 0]);
        let empty = CancelOrder {
            options: Some(Options::default()),
            ..bare.clone()
        };
        assert_eq!(
            empty.to_bytes().unwrap(),
            [b'X', 0, 0, 0, 9, 0, 0, 0, 0, 0, 0]
        );
        for m in [bare, empty] {
            let b = m.to_bytes().unwrap();
            assert_eq!(Inbound::parse(&b).unwrap(), m.into());
        }
        // A lone byte where the appendage length would be is refused.
        assert_eq!(
            Inbound::parse(&[b'X', 0, 0, 0, 9, 0, 0, 0, 0, 0]),
            Err(Error::Length)
        );
    }

    // 3.2: Order Accepted: timestamp 1, UserRefNum 9, side 13, quantity
    // 14, symbol 18, price 26, TIF 34, display 35, order reference 36,
    // capacity 44, ISO 45, cross 46, state 47, ClOrdID 48, appendage 62.
    #[test]
    fn accepted_bytes() {
        let m = OrderAccepted {
            timestamp: 0x1122_3344_5566_7788,
            user_ref: 1,
            side: Side::SellShort,
            quantity: 500,
            symbol: alpha("AAPL"),
            price: MARKET_PRICE,
            time_in_force: b'3',
            display: b'N',
            order_ref: 0x0a0b,
            capacity: b'P',
            intermarket_sweep: b'Y',
            cross_type: b'O',
            order_state: b'D',
            cl_ord_id: alpha("X"),
            options: Options::default(),
        };
        let mut b = vec![b'A', 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        b.extend_from_slice(&[0, 0, 0, 1, b'T', 0, 0, 1, 0xf4]);
        b.extend_from_slice(b"AAPL    ");
        b.extend_from_slice(&[0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff]);
        b.extend_from_slice(b"3N");
        b.extend_from_slice(&0x0a0bu64.to_be_bytes());
        b.extend_from_slice(b"PYOD");
        b.extend_from_slice(b"X             ");
        assert_eq!(b.len(), 62);
        b.extend_from_slice(&[0, 0]);
        assert_eq!(m.to_bytes().unwrap(), b);
        assert_eq!(Outbound::parse(&b).unwrap(), m.into());
        assert_eq!(MARKET_PRICE.to_string(), "214748.3647");
    }

    // 3.8: Rejected: timestamp 1, UserRefNum 9, reason 13 (two bytes),
    // ClOrdID 15, optional appendage 29.
    #[test]
    fn rejected_bytes() {
        let m = OrderRejected {
            timestamp: 5,
            user_ref: 6,
            reason: codes::reject_reason::INVALID_QUANTITY,
            cl_ord_id: alpha("C"),
            options: Some(Options::of(Opt::UserRefIdx(3))),
        };
        let mut b = vec![b'J', 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 6, 0x00, 0x13];
        b.extend_from_slice(b"C             ");
        b.extend_from_slice(&[0, 3, 2, 28, 3]);
        assert_eq!(m.to_bytes().unwrap(), b);
        check_wire::<Outbound>(&b);
    }

    // 3.1: System Event has no appendage: ten bytes.
    #[test]
    fn system_event_bytes() {
        let m = SystemEvent {
            timestamp: 1,
            event: codes::event::START_OF_DAY,
            end: (),
        };
        assert_eq!(m.to_bytes().unwrap(), [b'S', 0, 0, 0, 0, 0, 0, 0, 1, b'S']);
        assert_eq!(
            Outbound::parse(&[b'S', 0, 0, 0, 0, 0, 0, 0, 1, b'S', 0, 0]),
            Err(Error::Length)
        );
    }

    // Appendix A: sizes of every defined option.
    #[test]
    fn options_have_their_sizes() {
        let all = Options(vec![
            Opt::SecondaryOrdRefNum(1),
            Opt::Firm(alpha("F")),
            Opt::MinQty(100),
            Opt::CustomerType(b'R'),
            Opt::MaxFloor(10),
            Opt::PriceType(b'm'),
            Opt::PegOffset(-100),
            Opt::DiscretionPrice(Price(5)),
            Opt::DiscretionPriceType(b'L'),
            Opt::DiscretionPegOffset(i32::MIN),
            Opt::PostOnly(b'P'),
            Opt::RandomReserves(7),
            Opt::Route(alpha("RTE")),
            Opt::ExpireTime(86_399),
            Opt::TradeNow(b'Y'),
            Opt::HandleInst(b'I'),
            Opt::BboWeightIndicator(b'3'),
            Opt::DisplayQuantity(4),
            Opt::DisplayPrice(Price(6)),
            Opt::GroupId(0xbeef),
            Opt::SharesLocated(b'Y'),
            Opt::LocateBroker(alpha("LB")),
            Opt::Side(Side::SellShortExempt),
            Opt::UserRefIdx(255),
            Opt::AiqStrategy(b'*'),
            Opt::AiqGroupId(alpha("**")),
            Opt::Other {
                tag: 99,
                value: vec![1, 2, 3],
            },
        ]);
        let sizes: Vec<(u8, usize)> = all.0.iter().map(|o| (o.tag(), o.value_len())).collect();
        assert_eq!(
            sizes,
            [
                (1, 8),
                (2, 4),
                (3, 4),
                (4, 1),
                (5, 4),
                (6, 1),
                (7, 4),
                (9, 8),
                (10, 1),
                (11, 4),
                (12, 1),
                (13, 4),
                (14, 4),
                (15, 4),
                (16, 1),
                (17, 1),
                (18, 1),
                (22, 4),
                (23, 8),
                (24, 2),
                (25, 1),
                (26, 4),
                (27, 1),
                (28, 1),
                (29, 1),
                (30, 2),
                (99, 3),
            ]
        );
        let m = Outbound::OrderRestated(OrderRestated {
            timestamp: 0,
            user_ref: 1,
            reason: b'R',
            options: all.clone(),
        });
        check_wire_value(&m);
        let b = m.to_bytes().unwrap();
        // PegOffset -100 is two's complement.
        let peg = b
            .windows(6)
            .position(|w| w == [5, 7, 0xff, 0xff, 0xff, 0x9c]);
        assert!(peg.is_some());
        assert_eq!(all.group_id(), Some(0xbeef));
        assert_eq!(all.side(), Some(Side::SellShortExempt));
    }

    #[test]
    fn refuses_bad_appendages() {
        let base = CancelOrder {
            user_ref: 1,
            quantity: 0,
            options: Some(Options::default()),
        };
        let with = |opts: &[u8]| {
            let mut b = base.to_bytes().unwrap();
            b.truncate(9);
            b.extend_from_slice(&(opts.len() as u16).to_be_bytes());
            b.extend_from_slice(opts);
            Inbound::parse(&b)
        };
        assert_eq!(with(&[0, 28]), Err(Error::Option(28)));
        assert_eq!(with(&[3, 28, 1, 2]), Err(Error::Option(28)));
        assert_eq!(with(&[2, 27, b'X']), Err(Error::Side(b'X')));
        assert_eq!(with(&[5, 2, b'A', 0, b'C', b'D']), Err(Error::Field));
        assert_eq!(with(&[4, 28, 1]), Err(Error::Length));
        assert_eq!(with(&[2]), Err(Error::Length));
        assert!(with(&[2, 28, 1, 1, 8]).is_ok());
        // Length field disagreeing with the bytes.
        let mut b = base.to_bytes().unwrap();
        b.extend_from_slice(&[2, 28, 1]);
        assert_eq!(Inbound::parse(&b), Err(Error::Length));
        // Writers refuse what the parser would read differently.
        for bad in [
            Opt::Other {
                tag: 28,
                value: vec![1],
            },
            Opt::Other {
                tag: 200,
                value: vec![0; MAX_OPTION_VALUE + 1],
            },
        ] {
            let m = CancelOrder {
                options: Some(Options::of(bad.clone())),
                ..base.clone()
            };
            check_wire_value(&m);
            assert_eq!(m.to_bytes(), Err(Error::Option(bad.tag())));
        }
        let huge = CancelOrder {
            options: Some(Options(vec![
                Opt::Other {
                    tag: 200,
                    value: vec![0; 254]
                };
                300
            ])),
            ..base.clone()
        };
        check_wire_value(&huge);
        assert_eq!(huge.to_bytes(), Err(Error::TooLong));
        assert_eq!(Inbound::parse(&[]), Err(Error::Length));
        assert_eq!(Inbound::parse(b"A"), Err(Error::Type(b'A')));
        assert_eq!(Outbound::parse(b"O"), Err(Error::Type(b'O')));
        assert_eq!(EnterOrder::parse(b"X"), Err(Error::Type(b'X')));
        for bad in ["", "1.23456", "x", "1.", ".1", "1844674407370955.1616"] {
            assert_eq!(bad.parse::<Price>(), Err(Error::Price), "{bad}");
        }
        assert_eq!("10.25".parse::<Price>(), Ok(Price(102_500)));
    }

    /// One value of every message type, inbound then outbound.
    fn samples() -> (Vec<Inbound>, Vec<Outbound>) {
        let idx = Some(Options::of(Opt::UserRefIdx(2)));
        let opts = Options(vec![Opt::Firm(alpha("ABCD")), Opt::GroupId(3)]);
        let inbound = vec![
            enter(1, 100, opts.clone()).into(),
            ReplaceOrder {
                orig_user_ref: 1,
                user_ref: 2,
                quantity: 200,
                price: Price(1),
                time_in_force: b'0',
                display: b'Y',
                intermarket_sweep: b'N',
                cl_ord_id: alpha("R"),
                options: Options::of(Opt::Side(Side::Sell)),
            }
            .into(),
            CancelOrder {
                user_ref: 2,
                quantity: 0,
                options: idx.clone(),
            }
            .into(),
            ModifyOrder {
                user_ref: 2,
                side: Side::SellShort,
                quantity: 5,
                options: None,
            }
            .into(),
            MassCancel {
                user_ref: 3,
                firm: alpha("ABCD"),
                symbol: Alpha::blank(),
                options: Options::default(),
            }
            .into(),
            DisableOrderEntry {
                user_ref: 4,
                firm: alpha("ABCD"),
                options: Options::default(),
            }
            .into(),
            EnableOrderEntry {
                user_ref: 5,
                firm: alpha("ABCD"),
                options: Options::default(),
            }
            .into(),
            AccountQuery {
                options: idx.clone(),
            }
            .into(),
        ];
        let outbound: Vec<Outbound> = vec![
            SystemEvent {
                timestamp: 1,
                event: b'E',
                end: (),
            }
            .into(),
            OrderAccepted {
                timestamp: 1,
                user_ref: 1,
                side: Side::Buy,
                quantity: 1,
                symbol: alpha("A"),
                price: Price(1),
                time_in_force: b'0',
                display: b'Z',
                order_ref: 1,
                capacity: b'A',
                intermarket_sweep: b'N',
                cross_type: b'N',
                order_state: b'L',
                cl_ord_id: alpha("C"),
                options: opts.clone(),
            }
            .into(),
            OrderReplaced {
                timestamp: 1,
                orig_user_ref: 1,
                user_ref: 2,
                side: Side::Buy,
                quantity: 1,
                symbol: alpha("A"),
                price: Price(1),
                time_in_force: b'0',
                display: b'Y',
                order_ref: 2,
                capacity: b'A',
                intermarket_sweep: b'N',
                cross_type: b'N',
                order_state: b'L',
                cl_ord_id: alpha("C"),
                options: Options::default(),
            }
            .into(),
            OrderCanceled {
                timestamp: 1,
                user_ref: 2,
                quantity: 1,
                reason: b'U',
                options: None,
            }
            .into(),
            AiqCanceled {
                timestamp: 1,
                user_ref: 2,
                decrement_shares: 1,
                reason: b'Q',
                quantity_prevented: 1,
                execution_price: Price(1),
                liquidity_flag: b'A',
                aiq_strategy: b'O',
                options: idx.clone(),
            }
            .into(),
            OrderExecuted {
                timestamp: 1,
                user_ref: 2,
                quantity: 1,
                price: Price(1),
                liquidity_flag: b'R',
                match_number: 9,
                options: Options::default(),
            }
            .into(),
            BrokenTrade {
                timestamp: 1,
                user_ref: 2,
                match_number: 9,
                reason: b'E',
                cl_ord_id: alpha("C"),
                options: None,
            }
            .into(),
            OrderRejected {
                timestamp: 1,
                user_ref: 3,
                reason: 1,
                cl_ord_id: alpha("C"),
                options: None,
            }
            .into(),
            CancelPending {
                timestamp: 1,
                user_ref: 2,
                options: None,
            }
            .into(),
            CancelReject {
                timestamp: 1,
                user_ref: 2,
                options: idx.clone(),
            }
            .into(),
            PriorityUpdate {
                timestamp: 1,
                user_ref: 2,
                price: Price(2),
                display: b'Y',
                order_ref: 3,
                options: None,
            }
            .into(),
            OrderModified {
                timestamp: 1,
                user_ref: 2,
                side: Side::Sell,
                quantity: 1,
                options: None,
            }
            .into(),
            OrderRestated {
                timestamp: 1,
                user_ref: 2,
                reason: b'P',
                options: Options::of(Opt::DisplayPrice(Price(3))),
            }
            .into(),
            MassCancelResponse {
                timestamp: 1,
                user_ref: 3,
                firm: alpha("ABCD"),
                symbol: alpha("A"),
                options: Options::default(),
            }
            .into(),
            DisableOrderEntryResponse {
                timestamp: 1,
                user_ref: 4,
                firm: alpha("ABCD"),
                options: Options::default(),
            }
            .into(),
            EnableOrderEntryResponse {
                timestamp: 1,
                user_ref: 5,
                firm: alpha("ABCD"),
                options: Options::default(),
            }
            .into(),
            AccountQueryResponse {
                timestamp: 1,
                next_user_ref: 6,
                options: idx,
            }
            .into(),
        ];
        (inbound, outbound)
    }

    // Fixed lengths: the offset of each message's Appendage Length field,
    // or its whole length when it has none.
    #[test]
    fn every_type_round_trips() {
        let (inbound, outbound) = samples();
        assert_eq!(
            inbound.iter().map(Inbound::kind).collect::<Vec<_>>(),
            Inbound::KINDS
        );
        assert_eq!(
            outbound.iter().map(Outbound::kind).collect::<Vec<_>>(),
            Outbound::KINDS
        );
        assert_eq!(
            [
                EnterOrder::FIXED,
                ReplaceOrder::FIXED,
                CancelOrder::FIXED,
                ModifyOrder::FIXED,
                MassCancel::FIXED,
                DisableOrderEntry::FIXED,
                EnableOrderEntry::FIXED,
                AccountQuery::FIXED
            ],
            [45, 38, 9, 10, 17, 9, 9, 1]
        );
        assert_eq!(
            [
                SystemEvent::FIXED,
                OrderAccepted::FIXED,
                OrderReplaced::FIXED,
                OrderCanceled::FIXED,
                AiqCanceled::FIXED,
                OrderExecuted::FIXED,
                BrokenTrade::FIXED,
                OrderRejected::FIXED,
                CancelPending::FIXED,
                CancelReject::FIXED,
                PriorityUpdate::FIXED,
                OrderModified::FIXED,
                OrderRestated::FIXED,
                MassCancelResponse::FIXED,
                DisableOrderEntryResponse::FIXED,
                EnableOrderEntryResponse::FIXED,
                AccountQueryResponse::FIXED
            ],
            [
                10, 62, 66, 18, 32, 34, 36, 29, 13, 13, 30, 18, 14, 25, 17, 17, 13
            ]
        );
        for m in &inbound {
            check_wire_value(m);
            let b = m.to_bytes().unwrap();
            assert_eq!(b.len(), m.wire_len());
            check_wire::<Inbound>(&b);
        }
        for m in &outbound {
            check_wire_value(m);
            let b = m.to_bytes().unwrap();
            assert_eq!(b.len(), m.wire_len());
            check_wire::<Outbound>(&b);
        }
    }

    #[test]
    fn mutated_messages_keep_the_contract() {
        let (inbound, outbound) = samples();
        let bases: Vec<Vec<u8>> = inbound
            .iter()
            .map(|m| m.to_bytes().unwrap())
            .chain(outbound.iter().map(|m| m.to_bytes().unwrap()))
            .collect();
        let mut rng = Lcg::new(0x0c4);
        let mut exchange = Exchange::new(ExchangeConfig {
            max_orders: 8,
            ..ExchangeConfig::default()
        })
        .unwrap();
        for i in 0..1_500u64 {
            let mut bytes = bases[rng.index(bases.len())].clone();
            for _ in 0..=rng.below(3) {
                mutate(&mut rng, &mut bytes);
            }
            check_wire::<Inbound>(&bytes);
            check_wire::<Outbound>(&bytes);
            check_wire::<EnterOrder>(&bytes);
            if let Ok(m) = Inbound::parse(&bytes) {
                for action in exchange.receive(&m, i) {
                    match action {
                        Action::Send(out) => check_wire_value(&out),
                        Action::Event(Event::EnterRequested(t)) => {
                            let out = if rng.coin() {
                                exchange.accept(t, i).unwrap()
                            } else {
                                exchange.reject(t, 1, i).unwrap()
                            };
                            check_wire_value(&out);
                        }
                        Action::Event(Event::ReplaceRequested { replacement, .. }) => {
                            check_wire_value(&exchange.accept(replacement, i).unwrap());
                        }
                        Action::Event(Event::Ignored(_)) => {}
                    }
                }
            }
            assert!(exchange.orders().count() <= 8);
        }
    }

    fn sends(actions: Vec<Action>) -> Vec<Outbound> {
        actions
            .into_iter()
            .filter_map(|a| match a {
                Action::Send(m) => Some(m),
                Action::Event(_) => None,
            })
            .collect()
    }
    fn token(user_ref: u32) -> Token {
        Token {
            user_ref_idx: 0,
            user_ref,
        }
    }

    #[test]
    fn exchange_enters_executes_and_cancels() {
        let mut x = Exchange::new(ExchangeConfig {
            first_order_ref: 1000,
            ..ExchangeConfig::default()
        })
        .unwrap();
        let e = enter(1, 500, Options::default());
        assert_eq!(
            x.receive(&e.clone().into(), 1),
            [Action::Event(Event::EnterRequested(token(1)))]
        );
        assert!(!x.order(token(1)).unwrap().live);
        // Executing or canceling before accept is refused.
        assert_eq!(
            x.execute(token(1), 1, Price(1), b'A', 1),
            Err(ExchangeError::UnknownToken(token(1)))
        );
        let Outbound::OrderAccepted(a) = x.accept(token(1), 2).unwrap() else {
            panic!()
        };
        assert_eq!(
            (a.order_ref, a.quantity, a.order_state, a.user_ref),
            (1000, 500, b'L', 1)
        );
        assert_eq!(
            x.accept(token(1), 2),
            Err(ExchangeError::UnknownToken(token(1)))
        );
        // 1.2: a repeat of the same UserRefNum is a retransmission.
        assert_eq!(
            x.receive(&e.into(), 3),
            [Action::Event(Event::Ignored(Ignored::Retransmission(
                token(1)
            )))]
        );
        // A partial fill, then the client reduces the order to 100 open.
        let Outbound::OrderExecuted(f) = x.execute(token(1), 100, Price(102_500), b'A', 4).unwrap()
        else {
            panic!()
        };
        assert_eq!((f.match_number, f.quantity), (1, 100));
        assert_eq!(
            x.execute(token(1), 401, Price(1), b'A', 4),
            Err(ExchangeError::Shares)
        );
        let out = sends(
            x.receive(
                &CancelOrder {
                    user_ref: 1,
                    quantity: 100,
                    options: None,
                }
                .into(),
                5,
            ),
        );
        assert_eq!(
            out,
            [OrderCanceled {
                timestamp: 5,
                user_ref: 1,
                quantity: 300,
                reason: b'U',
                options: None
            }
            .into()]
        );
        assert_eq!(x.order(token(1)).unwrap().quantity, 100);
        // A cancel that would not reduce is ignored (2.3).
        assert_eq!(
            x.receive(
                &CancelOrder {
                    user_ref: 1,
                    quantity: 100,
                    options: None
                }
                .into(),
                6
            ),
            [Action::Event(Event::Ignored(Ignored::NoReduction(token(
                1
            ))))]
        );
        // The exchange's own cancel closes it.
        x.cancel(token(1), 100, codes::cancel_reason::TIMEOUT, 7)
            .unwrap();
        assert_eq!(x.order(token(1)), None);
        // The fill can still be broken.
        let Outbound::BrokenTrade(b) = x.break_trade(1, b'E', 8).unwrap() else {
            panic!()
        };
        assert_eq!((b.user_ref, b.cl_ord_id), (1, alpha("ORDER1")));
        assert_eq!(
            x.break_trade(1, b'E', 8),
            Err(ExchangeError::UnknownMatch(1))
        );
        // Account query: next UserRefNum on channel 0.
        let out = sends(x.receive(&AccountQuery { options: None }.into(), 9));
        assert_eq!(
            out,
            [AccountQueryResponse {
                timestamp: 9,
                next_user_ref: 2,
                options: None
            }
            .into()]
        );
    }

    #[test]
    fn exchange_rejects_bad_quantities_and_limits() {
        let mut x = Exchange::new(ExchangeConfig {
            max_orders: 1,
            ..ExchangeConfig::default()
        })
        .unwrap();
        let out = sends(x.receive(&enter(1, MAX_ORDER_QUANTITY, Options::default()).into(), 1));
        let Outbound::OrderRejected(r) = &out[0] else {
            panic!()
        };
        assert_eq!(r.reason, codes::reject_reason::INVALID_QUANTITY);
        // The rejected UserRefNum is consumed (3.8).
        assert_eq!(x.next_user_ref(0), 2);
        x.receive(&enter(2, 1, Options::default()).into(), 2);
        let out = sends(x.receive(&enter(3, 1, Options::default()).into(), 3));
        let Outbound::OrderRejected(r) = &out[0] else {
            panic!()
        };
        assert_eq!(r.reason, codes::reject_reason::PROCESSING_ERROR);
        // The world rejects a pending enter.
        let Outbound::OrderRejected(r) = x
            .reject(token(2), codes::reject_reason::INVALID_SYMBOL, 4)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(r.user_ref, 2);
        assert_eq!(x.order(token(2)), None);
        assert_eq!(
            x.reject(token(2), 1, 4),
            Err(ExchangeError::UnknownToken(token(2)))
        );
        assert_eq!(
            Exchange::new(ExchangeConfig {
                max_orders: 0,
                ..ExchangeConfig::default()
            })
            .err(),
            Some(ExchangeError::Config)
        );
    }

    #[test]
    fn exchange_replaces_per_the_four_cases() {
        let mut x = Exchange::new(ExchangeConfig::default()).unwrap();
        x.receive(&enter(10, 500, Options::default()).into(), 1);
        x.accept(token(10), 1).unwrap();
        x.execute(token(10), 100, Price(1), b'A', 2).unwrap();
        let replace = |orig, new, quantity| ReplaceOrder {
            orig_user_ref: orig,
            user_ref: new,
            quantity,
            price: Price(200_000),
            time_in_force: b'0',
            display: b'Y',
            intermarket_sweep: b'N',
            cl_ord_id: alpha("R"),
            options: Options::default(),
        };
        // Case 1: an unknown original or a used UserRefNum is ignored.
        assert_eq!(
            x.receive(&replace(99, 11, 500).into(), 3),
            [Action::Event(Event::Ignored(Ignored::UnknownOrder(token(
                99
            ))))]
        );
        assert_eq!(
            x.receive(&replace(10, 10, 500).into(), 3),
            [Action::Event(Event::Ignored(Ignored::Retransmission(
                token(10)
            )))]
        );
        // Case 4: replaced. Shares are liable over the chain: 500 less the
        // 100 executed leaves 400 (2.2, 3.3).
        assert_eq!(
            x.receive(&replace(10, 11, 500).into(), 4),
            [Action::Event(Event::ReplaceRequested {
                original: token(10),
                replacement: token(11)
            })]
        );
        let Outbound::OrderReplaced(r) = x.accept(token(11), 5).unwrap() else {
            panic!()
        };
        assert_eq!(
            (r.orig_user_ref, r.user_ref, r.quantity, r.order_state),
            (10, 11, 400, b'L')
        );
        assert_eq!(x.order(token(10)), None);
        let o = x.order(token(11)).unwrap();
        assert_eq!(
            (o.quantity, o.executed, o.price, o.cl_ord_id),
            (400, 100, Price(200_000), alpha("R"))
        );
        // Case 3: the world rejects the replace; the original is intact and
        // the UserRefNum is consumed.
        x.receive(&replace(11, 12, 300).into(), 6);
        x.reject(token(12), codes::reject_reason::REPLACE_NOT_ALLOWED, 6)
            .unwrap();
        assert_eq!(x.order(token(11)).unwrap().quantity, 400);
        assert_eq!(x.next_user_ref(0), 13);
        // A replace to no more than the executed shares is dead on arrival.
        x.receive(&replace(11, 13, 100).into(), 7);
        let Outbound::OrderReplaced(r) = x.accept(token(13), 7).unwrap() else {
            panic!()
        };
        assert_eq!((r.quantity, r.order_state), (0, b'D'));
        assert_eq!(x.order(token(11)), None);
        assert_eq!(x.order(token(13)), None);
        // Case 2: an invalid quantity cancels the original; the
        // replacement UserRefNum is not consumed.
        x.receive(&enter(14, 50, Options::default()).into(), 8);
        x.accept(token(14), 8).unwrap();
        let out = sends(x.receive(&replace(14, 15, 0).into(), 9));
        assert_eq!(
            out,
            [OrderCanceled {
                timestamp: 9,
                user_ref: 14,
                quantity: 50,
                reason: b'Z',
                options: None
            }
            .into()]
        );
        assert_eq!(x.next_user_ref(0), 15);
    }

    #[test]
    fn exchange_modifies_and_channels_echo_user_ref_idx() {
        let mut x = Exchange::new(ExchangeConfig::default()).unwrap();
        let idx = |i| Some(Options::of(Opt::UserRefIdx(i)));
        let mut e = enter(1, 100, Options::of(Opt::UserRefIdx(4)));
        e.side = Side::Sell;
        x.receive(&e.into(), 1);
        // UserRefNums run per channel: 1 is fresh on channel 0 too.
        assert_eq!(
            x.receive(&enter(1, 100, Options::default()).into(), 1),
            [Action::Event(Event::EnterRequested(token(1)))]
        );
        let t = Token {
            user_ref_idx: 4,
            user_ref: 1,
        };
        x.accept(t, 1).unwrap();
        let modify = |side, quantity| ModifyOrder {
            user_ref: 1,
            side,
            quantity,
            options: idx(4),
        };
        assert_eq!(
            x.receive(&modify(Side::Buy, 100).into(), 2),
            [Action::Event(Event::Ignored(Ignored::SideChange(t)))]
        );
        assert_eq!(
            x.receive(&modify(Side::Sell, 101).into(), 2),
            [Action::Event(Event::Ignored(Ignored::NoReduction(t)))]
        );
        let out = sends(x.receive(&modify(Side::SellShortExempt, 60).into(), 3));
        assert_eq!(
            out,
            [OrderModified {
                timestamp: 3,
                user_ref: 1,
                side: Side::SellShortExempt,
                quantity: 60,
                options: idx(4)
            }
            .into()]
        );
        let o = x.order(t).unwrap();
        assert_eq!((o.side, o.quantity), (Side::SellShortExempt, 60));
        // E to T is allowed, T to E is not.
        x.receive(&modify(Side::SellShort, 60).into(), 4);
        assert_eq!(
            x.receive(&modify(Side::SellShortExempt, 60).into(), 4),
            [Action::Event(Event::Ignored(Ignored::SideChange(t)))]
        );
        // The fill on channel 4 echoes the channel.
        let Outbound::OrderExecuted(f) = x.execute(t, 10, Price(1), b'R', 5).unwrap() else {
            panic!()
        };
        assert_eq!(f.options, Options::of(Opt::UserRefIdx(4)));
        let out = sends(x.receive(&AccountQuery { options: idx(4) }.into(), 6));
        assert_eq!(
            out,
            [AccountQueryResponse {
                timestamp: 6,
                next_user_ref: 2,
                options: idx(4)
            }
            .into()]
        );
    }

    #[test]
    fn exchange_mass_cancels_and_disables_firms() {
        let mut x = Exchange::new(ExchangeConfig::default()).unwrap();
        let firm = |f: &str| Options::of(Opt::Firm(alpha(f)));
        for (n, f) in [(1, "AAAA"), (2, "AAAA"), (3, "BBBB")] {
            x.receive(&enter(n, 10, firm(f)).into(), 1);
            x.accept(token(n), 1).unwrap();
        }
        let out = sends(
            x.receive(
                &MassCancel {
                    user_ref: 4,
                    firm: alpha("AAAA"),
                    symbol: Alpha::blank(),
                    options: Options::default(),
                }
                .into(),
                2,
            ),
        );
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].kind(), b'X');
        assert_eq!(
            out[1],
            OrderCanceled {
                timestamp: 2,
                user_ref: 1,
                quantity: 10,
                reason: b'U',
                options: None
            }
            .into()
        );
        assert_eq!(x.orders().count(), 1);
        // Disable firm BBBB: its next order is rejected; enable it again.
        let out = sends(
            x.receive(
                &DisableOrderEntry {
                    user_ref: 5,
                    firm: alpha("BBBB"),
                    options: Options::default(),
                }
                .into(),
                3,
            ),
        );
        assert_eq!(out[0].kind(), b'G');
        assert!(x.is_disabled(alpha("BBBB")));
        let out = sends(x.receive(&enter(6, 10, firm("BBBB")).into(), 4));
        let Outbound::OrderRejected(r) = &out[0] else {
            panic!()
        };
        assert_eq!(r.reason, codes::reject_reason::FIRM_NOT_AUTHORIZED);
        let out = sends(
            x.receive(
                &EnableOrderEntry {
                    user_ref: 7,
                    firm: alpha("BBBB"),
                    options: Options::default(),
                }
                .into(),
                5,
            ),
        );
        assert_eq!(out[0].kind(), b'K');
        assert_eq!(
            x.receive(&enter(8, 10, firm("BBBB")).into(), 6),
            [Action::Event(Event::EnterRequested(token(8)))]
        );
    }

    // A replace cannot carry GroupID or Firm, and tags it leaves out keep
    // the original's values (2.2, Appendix A note 2), so a mass cancel by
    // group still finds the replacement.
    #[test]
    fn replacement_inherits_options_for_mass_cancel() {
        let mut x = Exchange::new(ExchangeConfig::default()).unwrap();
        let options = Options(vec![
            Opt::GroupId(7),
            Opt::MinQty(100),
            Opt::SharesLocated(b'Y'),
        ]);
        x.receive(&enter(1, 300, options).into(), 1);
        x.accept(token(1), 1).unwrap();
        let replace = ReplaceOrder {
            orig_user_ref: 1,
            user_ref: 2,
            quantity: 300,
            price: Price(200_000),
            time_in_force: b'0',
            display: b'Y',
            intermarket_sweep: b'N',
            cl_ord_id: alpha("R"),
            options: Options::of(Opt::MinQty(200)),
        };
        x.receive(&replace.into(), 2);
        let Outbound::OrderReplaced(r) = x.accept(token(2), 3).unwrap() else {
            panic!()
        };
        // The reply echoes the replace's options.
        assert_eq!(r.options, Options::of(Opt::MinQty(200)));
        let kept = &x.order(token(2)).unwrap().options;
        assert_eq!(kept.get(3), Some(&Opt::MinQty(200)));
        assert_eq!(kept.group_id(), Some(7));
        assert_eq!(kept.get(25), None);
        let out = sends(
            x.receive(
                &MassCancel {
                    user_ref: 3,
                    firm: Alpha::blank(),
                    symbol: Alpha::blank(),
                    options: Options::of(Opt::GroupId(7)),
                }
                .into(),
                4,
            ),
        );
        assert_eq!(out.len(), 2);
        assert_eq!(x.orders().count(), 0);
    }

    #[test]
    fn exchange_runs_over_soupbintcp() {
        use fictionet::stdlib::codec::{Stream, pump};
        use fictionet::stdlib::soupbintcp::{
            Action as SAction, Alpha as SAlpha, Client, Event as SEvent, Frames, Login, Packet,
            Server, Timers,
        };
        let login = Login {
            username: SAlpha::right_padded("ALICE").unwrap(),
            password: SAlpha::right_padded("PW").unwrap(),
            session: SAlpha::blank(),
            sequence: 1,
        };
        let mut client = Client::new(login, Timers::default(), 0).unwrap();
        let mut server = Server::new(Timers::default(), 0).unwrap();
        let packets = |actions: Vec<SAction>| -> Vec<Packet> {
            actions
                .into_iter()
                .filter_map(|a| match a {
                    SAction::Send(p) => Some(p),
                    SAction::Event(_) => None,
                })
                .collect()
        };
        for p in packets(client.start(0).unwrap()) {
            server.receive(&p, 0).unwrap();
        }
        for p in packets(
            server
                .accept(SAlpha::left_padded("1").unwrap(), 1, 0)
                .unwrap(),
        ) {
            client.receive(&p, 0).unwrap();
        }
        let mut exchange = Exchange::new(ExchangeConfig::default()).unwrap();
        // The client's Enter Order crosses as unsequenced data bytes.
        let wire = client
            .send(&enter(1, 100, Options::default()).to_bytes().unwrap(), 1)
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut frames = Stream::new(Frames::default());
        let mut inbound = Vec::new();
        pump(&mut frames, &wire, |f| inbound.push(f)).unwrap();
        let Ok(Packet::UnsequencedData(payload)) = &inbound[0] else {
            panic!()
        };
        assert_eq!(
            server.receive(&inbound[0].clone().unwrap(), 1).unwrap(),
            [SAction::Event(SEvent::Unsequenced)]
        );
        let actions = exchange.receive(&Inbound::parse(payload).unwrap(), 1);
        assert_eq!(actions, [Action::Event(Event::EnterRequested(token(1)))]);
        // The Accepted goes back as sequenced message 1.
        let accepted = exchange.accept(token(1), 2).unwrap();
        let packet = server.send(&accepted.to_bytes().unwrap(), 2).unwrap();
        let events = client.receive(&packet, 2).unwrap();
        assert_eq!(events, [SAction::Event(SEvent::Sequenced { sequence: 1 })]);
        let Packet::SequencedData(payload) = packet else {
            panic!()
        };
        assert_eq!(Outbound::parse(&payload).unwrap(), accepted);
    }
}
