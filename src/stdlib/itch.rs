//! Nasdaq TotalView-ITCH 5.0: every message type as a fixed-layout
//! [`Wire`] value, a framer for length-prefixed message streams, and a
//! bounded order book that applies the order messages, with no I/O.
//! Message tables use [`codec::layout!`](fictionet::stdlib::codec::layout!).
//!
//! `Book` is feed state, not a client or server session. The module supplies no
//! feed recovery, `Service`, or live transport. Callers supply MoldUDP64 or
//! SoupBinTCP payloads, or use the length-prefixed stream decoder.
//!
//! ITCH is Nasdaq's outbound market data feed: a sequence of binary
//! messages that describe the day (system events, the stock directory,
//! trading actions) and every displayed order's life (add, execute,
//! cancel, delete, replace), plus trades, crosses and imbalances. This
//! module follows the
//! [Nasdaq TotalView-ITCH 5.0 specification](https://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/NQTVITCHspecification.pdf),
//! revision of April 28, 2023, which added the Direct Listing with Capital
//! Raise message. Section numbers below are that document's.
//!
//! Every message starts with a type byte, a two-byte stock locate, a
//! two-byte tracking number and a six-byte timestamp in nanoseconds since
//! midnight ([`Header`]). Integers are unsigned and big-endian; alpha
//! fields are ASCII padded on the right with spaces ([`Alpha`]); prices
//! are integers with four implied decimal places ([`Price4`]), except the
//! circuit breaker levels, which have eight ([`Price8`]) ("Data Types").
//! One-byte code fields are kept as the byte (`u8`), so a code Nasdaq adds
//! later still parses; [`codes`] names the values the specification lists.
//!
//! Messages travel one per MoldUDP64 message block, one per SoupBinTCP
//! sequenced data packet, or in a binary file where each message has a
//! two-byte length in front ([`codec::Frames<Message>`](fictionet::stdlib::codec::Frames)). Parse each block or payload
//! with [`Message::parse`]. [`Book`] applies the order messages to
//! per-stock bid and ask price levels, within named limits.
//!
//! ```
//! use fictionet::stdlib::codec::Wire;
//! use fictionet::stdlib::itch::{AddOrder, Alpha, Book, BookConfig, Header, Message, OrderDelete, Price4, Side, Timestamp};
//! use fictionet::stdlib::moldudp64::{Body, Downstream, Session};
//!
//! let header = Header { locate: 7, tracking: 0, timestamp: Timestamp::new(34_200_000_000_000)? };
//! let add = AddOrder {
//!     header,
//!     order_ref: 1,
//!     side: Side::Buy,
//!     shares: 300,
//!     stock: Alpha::right_padded("ZXZZT")?,
//!     price: "10.25".parse()?,
//! };
//! let delete = OrderDelete { header, order_ref: 1 };
//!
//! // Two messages in one MoldUDP64 packet, as a listener receives them.
//! let packet = Downstream {
//!     session: Session::left_padded("20261006").unwrap(),
//!     sequence: 1,
//!     body: Body::Messages(vec![add.to_bytes()?, delete.to_bytes()?]),
//! };
//! let mut book = Book::new(BookConfig::default())?;
//! let mut messages = packet.messages().iter().map(|block| Message::parse(block));
//! book.apply(&messages.next().unwrap()?)?;
//! let best = book.best_bid(7).unwrap();
//! assert_eq!((best.price, best.shares), (Price4(102_500), 300));
//! book.apply(&messages.next().unwrap()?)?;
//! assert_eq!(book.best_bid(7), None);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::field;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;

/// Bytes in the common header after the type byte: stock locate, tracking
/// number and timestamp.
pub const HEADER_LENGTH: usize = 10;
/// The longest ITCH 5.0 message: the NOII message (1.6).
pub const MAX_MESSAGE_LENGTH: usize = 50;
/// Bytes in the length prefix of a framed message.
pub const LENGTH_PREFIX: usize = 2;
/// The largest frame [`codec::Frames<Message>`](fictionet::stdlib::codec::Frames) can describe.
pub const MAX_FRAME: usize = u16::MAX as usize;
/// The largest timestamp the six-byte field holds.
pub const MAX_TIMESTAMP: u64 = (1 << 48) - 1;

/// The default most live orders a [`Book`] holds.
pub const DEFAULT_MAX_ORDERS: usize = 1 << 20;
/// The most live orders a [`Book`] may be configured to hold.
pub const MAX_ORDERS: usize = 1 << 26;
/// The default most price levels, over every stock and side, of a [`Book`].
pub const DEFAULT_MAX_LEVELS: usize = 1 << 18;
/// The most price levels a [`Book`] may be configured to hold.
pub const MAX_LEVELS: usize = 1 << 24;
/// The default most stocks a [`Book`] tracks.
pub const DEFAULT_MAX_STOCKS: usize = 16_384;
/// The most stocks a [`Book`] can track: one per locate code.
pub const MAX_STOCKS: usize = 1 << 16;

/// Why bytes or a value were refused, or why a [`Book`] refused a
/// message. A refused message leaves the book unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not the length the message type fixes, or are empty.
    Length,
    /// An unknown message type byte, or bytes of another type than the
    /// one asked for.
    Type(u8),
    /// An alpha field has a byte outside printable ASCII, or text longer
    /// than the field.
    Field,
    /// A buy/sell indicator other than "B" or "S".
    Side(u8),
    /// A timestamp over [`MAX_TIMESTAMP`].
    Timestamp,
    /// A decimal price with more places than the field, or too large.
    Price,
    /// A frame length prefix over the [`codec::Frames<Message>`](fictionet::stdlib::codec::Frames) limit.
    TooLong,
    /// A configuration value outside its named limits.
    Config,
    /// An execute, cancel, delete or replace names an order not on the
    /// book.
    UnknownOrder(u64),
    /// An add or replace reuses a reference number already on the book.
    DuplicateOrder(u64),
    /// An add or replace with zero shares, or an execute or cancel of
    /// more shares than the order has.
    Shares(u64),
    /// The message's locate differs from the order's.
    Locate(u64),
    /// The book holds [`BookConfig::max_orders`] orders.
    TooManyOrders,
    /// The book holds [`BookConfig::max_levels`] price levels.
    TooManyLevels,
    /// The book tracks [`BookConfig::max_stocks`] stocks.
    TooManyStocks,
}
fictionet::error_display!(Error, f, {
    Error::Length => f.write_str("ITCH message length is wrong"),
    Error::Type(t) => write!(f, "unexpected ITCH message type {t:#04x}"),
    Error::Field => f.write_str("ITCH alpha field is invalid"),
    Error::Side(s) => write!(f, "invalid ITCH buy/sell indicator {s:#04x}"),
    Error::Timestamp => f.write_str("ITCH timestamp does not fit six bytes"),
    Error::Price => f.write_str("ITCH price is invalid"),
    Error::TooLong => f.write_str("ITCH frame is too long"),
    Error::Config => f.write_str("ITCH book configuration is out of range"),
    Error::UnknownOrder(r) => write!(f, "ITCH order {r} is not on the book"),
    Error::DuplicateOrder(r) => write!(f, "ITCH order {r} is already on the book"),
    Error::Shares(r) => write!(f, "ITCH order {r} share count is invalid"),
    Error::Locate(r) => write!(f, "ITCH order {r} belongs to another locate"),
    Error::TooManyOrders => f.write_str("ITCH book order limit reached"),
    Error::TooManyLevels => f.write_str("ITCH book price level limit reached"),
    Error::TooManyStocks => f.write_str("ITCH book stock limit reached"),
});

fictionet::fixed_fields!(Field, take, array; Error, Error::Length;
    from_be_bytes, to_be_bytes; u16, u32, u64);
impl Field for u8 {
    const LEN: usize = 1;
    fn get(b: &[u8]) -> Result<Self, Error> {
        b.first().copied().ok_or(Error::Length)
    }
    fn put(&self, out: &mut Vec<u8>) {
        out.push(*self);
    }
}

/// Nanoseconds since midnight, in six bytes ("Data Types").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);
impl Timestamp {
    /// A timestamp. Refuses one over [`MAX_TIMESTAMP`].
    pub fn new(nanos: u64) -> Result<Self, Error> {
        if nanos <= MAX_TIMESTAMP {
            Ok(Self(nanos))
        } else {
            Err(Error::Timestamp)
        }
    }
    /// Nanoseconds since midnight.
    pub fn nanos(self) -> u64 {
        self.0
    }
}
impl Field for Timestamp {
    const LEN: usize = 6;
    fn get(b: &[u8]) -> Result<Self, Error> {
        let b: [u8; 6] = array(b)?;
        let mut wide = [0; 8];
        wide[2..].copy_from_slice(&b);
        Ok(Self(u64::from_be_bytes(wide)))
    }
    fn put(&self, out: &mut Vec<u8>) {
        // The constructor keeps the value within 48 bits.
        out.extend_from_slice(&self.0.to_be_bytes()[2..]);
    }
}

/// A Price (4) field: four bytes with four implied decimal places. The
/// raw value 102500 is $10.2500 ("Data Types").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Price4(pub u32);
impl fmt::Display for Price4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        field::write_decimal(f, u64::from(self.0), 4)
    }
}
impl FromStr for Price4 {
    type Err = Error;
    /// Reads "10.25" or "10" as dollars; refuses more than four places.
    fn from_str(s: &str) -> Result<Self, Error> {
        u32::try_from(field::parse_decimal(s, 4).map_err(|_| Error::Price)?)
            .map(Self)
            .map_err(|_| Error::Price)
    }
}
impl Field for Price4 {
    const LEN: usize = 4;
    fn get(b: &[u8]) -> Result<Self, Error> {
        u32::get(b).map(Self)
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
    }
}

/// A Price (8) field: eight bytes with eight implied decimal places, used
/// for the circuit breaker levels (1.2.5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Price8(pub u64);
impl fmt::Display for Price8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        field::write_decimal(f, self.0, 8)
    }
}
impl FromStr for Price8 {
    type Err = Error;
    /// Reads a decimal with at most eight places.
    fn from_str(s: &str) -> Result<Self, Error> {
        field::parse_decimal(s, 8)
            .map_err(|_| Error::Price)
            .map(Self)
    }
}
impl Field for Price8 {
    const LEN: usize = 8;
    fn get(b: &[u8]) -> Result<Self, Error> {
        u64::get(b).map(Self)
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
    }
}

/// A fixed-width alpha field: `N` bytes of printable ASCII, left justified
/// and padded on the right with spaces ("Data Types"). Padding is part of
/// the value, so fields round-trip byte for byte.
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

/// A buy/sell indicator (1.3, 1.5.1).
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

/// The fields every message carries after its type byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Header {
    /// The stock locate code from the day's Stock Directory, or 0 for
    /// messages about no stock ("Architecture").
    pub locate: u16,
    /// Nasdaq's internal tracking number.
    pub tracking: u16,
    /// Nanoseconds since midnight.
    pub timestamp: Timestamp,
}
impl Field for Header {
    const LEN: usize = HEADER_LENGTH;
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            locate: take(&mut b)?,
            tracking: take(&mut b)?,
            timestamp: take(&mut b)?,
        })
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.locate.put(out);
        self.tracking.put(out);
        self.timestamp.put(out);
    }
}

/// An eight-byte stock symbol, padded on the right with spaces.
pub type Stock = Alpha<8>;
/// A four-byte market participant identifier.
pub type Mpid = Alpha<4>;

fn envelope(b: &[u8]) -> Result<(u8, &[u8]), Error> {
    let (&kind, body) = b.split_first().ok_or(Error::Length)?;
    Ok((kind, body))
}

fn check_length(b: &[u8], len: usize) -> Result<(), Error> {
    if b.len() != len {
        return Err(Error::Length);
    }
    Ok(())
}

fn write_head(kind: u8, len: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    out.reserve(len);
    out.push(kind);
    Ok(())
}

fictionet::stdlib::codec::layout! {
    error = Error; type_error = Error::Type;
    field = Field; take = take; put = Field::put; prefix = 1;
    read = envelope; check = check_length; write = write_head;
    unknown = |kind, _| Err(Error::Type(kind));
    message = { [#[derive(Clone, Copy, Debug, PartialEq, Eq)]]
        /// Bytes on the wire, type byte included.
        const LEN; fn wire_len;
    };
    header = { /// Stock locate, tracking number and timestamp.
        header: Header,
    }; tail = {}; tail_ops = ();
    items = []; access = { /// Stock locate, tracking number and timestamp.
        header(&self) -> header: Header;
    };
    length = { /// The specified length for a known message type.
        length_of
    }; variants = {};
    /// Any ITCH 5.0 message.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    Message;

    /// "S", System Event (1.1): a market or feed event. The locate is 0.
    SystemEvent = b'S', 12 {
        /// See [`codes::event`].
        event: u8,
    }

    /// "R", Stock Directory (1.2.1): one active symbol, sent at the start
    /// of the day. It assigns the day's locate code.
    StockDirectory = b'R', 39 {
        /// The symbol.
        stock: Stock,
        /// The listing market or tier: "Q", "G", "S" (Nasdaq), "N", "A",
        /// "P", "Z", "V", or a space.
        market_category: u8,
        /// The Financial Status Indicator: "D", "E", "Q", "S", "G", "H",
        /// "J", "K", "C", "N", or a space.
        financial_status: u8,
        /// Shares in a round lot.
        round_lot_size: u32,
        /// "Y" if Nasdaq accepts only round lots, else "N".
        round_lots_only: u8,
        /// The issue classification (Appendix D).
        issue_classification: u8,
        /// The issue sub-type (Appendix E).
        issue_sub_type: Alpha<2>,
        /// "P" live/production or "T" test.
        authenticity: u8,
        /// Rule 203(b)(3) threshold: "Y", "N", or a space.
        short_sale_threshold: u8,
        /// "Y" if set up as a new IPO, "N", or a space.
        ipo_flag: u8,
        /// LULD reference price tier: "1", "2", or a space.
        luld_reference_price_tier: u8,
        /// "Y" for an exchange traded product, "N", or a space.
        etp_flag: u8,
        /// The ETP's leverage factor, as an integer.
        etp_leverage_factor: u32,
        /// "Y" for an inverse ETP, else "N".
        inverse_indicator: u8,
    }

    /// "H", Stock Trading Action (1.2.2): a stock's trading state.
    StockTradingAction = b'H', 25 {
        /// The symbol.
        stock: Stock,
        /// See [`codes::trading_state`].
        trading_state: u8,
        /// Reserved.
        reserved: u8,
        /// The trading action reason (Appendix C), padded with spaces.
        reason: Alpha<4>,
    }

    /// "Y", Reg SHO Short Sale Price Test Restricted Indicator (1.2.3).
    RegShoRestriction = b'Y', 20 {
        /// The symbol.
        stock: Stock,
        /// "0" no price test, "1" restriction in effect after an intraday
        /// drop, "2" restriction remains in effect.
        action: u8,
    }

    /// "L", Market Participant Position (1.2.4).
    MarketParticipantPosition = b'L', 26 {
        /// The market participant.
        mpid: Mpid,
        /// The symbol.
        stock: Stock,
        /// "Y" primary market maker, "N" not.
        primary_market_maker: u8,
        /// "N" normal, "P" passive, "S" syndicate, "R" pre-syndicate,
        /// "L" penalty.
        market_maker_mode: u8,
        /// "A" active, "E" excused, "W" withdrawn, "S" suspended,
        /// "D" deleted.
        market_participant_state: u8,
    }

    /// "V", MWCB Decline Level (1.2.5.1): the day's market-wide circuit
    /// breaker levels. The locate is 0.
    MwcbDeclineLevel = b'V', 35 {
        /// Level 1.
        level1: Price8,
        /// Level 2.
        level2: Price8,
        /// Level 3.
        level3: Price8,
    }

    /// "W", MWCB Status (1.2.5.2): a circuit breaker level was breached.
    MwcbStatus = b'W', 12 {
        /// "1", "2" or "3".
        breached_level: u8,
    }

    /// "K", IPO Quoting Period Update (1.2.6).
    IpoQuotingPeriodUpdate = b'K', 28 {
        /// The symbol.
        stock: Stock,
        /// The quotation release time, in seconds since midnight; 0 when
        /// canceled or postponed.
        release_time: u32,
        /// "A" anticipated release time, "C" canceled or postponed.
        release_qualifier: u8,
        /// The IPO price; 0 when canceled or postponed.
        ipo_price: Price4,
    }

    /// "J", LULD Auction Collar (1.2.7).
    LuldAuctionCollar = b'J', 35 {
        /// The symbol.
        stock: Stock,
        /// The reference price the collars are set from.
        reference_price: Price4,
        /// The upper auction collar.
        upper_price: Price4,
        /// The lower auction collar.
        lower_price: Price4,
        /// How many times the reopening auction has been extended.
        extension: u32,
    }

    /// "h", Operational Halt (1.2.8): a halt on one Nasdaq market center.
    OperationalHalt = b'h', 21 {
        /// The symbol.
        stock: Stock,
        /// "Q" Nasdaq, "B" BX, "X" PSX.
        market_code: u8,
        /// "H" halted, "T" resumed.
        action: u8,
    }

    /// "A", Add Order without MPID attribution (1.3.1): a new displayed
    /// order on the book.
    AddOrder = b'A', 36 {
        /// The day-unique order reference number.
        order_ref: u64,
        /// The side of the book.
        side: Side,
        /// Displayed shares.
        shares: u32,
        /// The symbol.
        stock: Stock,
        /// The display price.
        price: Price4,
    }

    /// "F", Add Order with MPID attribution (1.3.2).
    AddOrderAttributed = b'F', 40 {
        /// The day-unique order reference number.
        order_ref: u64,
        /// The side of the book.
        side: Side,
        /// Displayed shares.
        shares: u32,
        /// The symbol.
        stock: Stock,
        /// The display price.
        price: Price4,
        /// The market participant the order is attributed to.
        attribution: Mpid,
    }

    /// "E", Order Executed (1.4.1): shares of a book order executed at its
    /// display price.
    OrderExecuted = b'E', 31 {
        /// The order executed.
        order_ref: u64,
        /// Shares executed; subtract from the order.
        executed_shares: u32,
        /// The day-unique match number.
        match_number: u64,
    }

    /// "C", Order Executed With Price (1.4.2): shares of a book order
    /// executed at a price other than its display price.
    OrderExecutedWithPrice = b'C', 36 {
        /// The order executed.
        order_ref: u64,
        /// Shares executed; subtract from the order.
        executed_shares: u32,
        /// The day-unique match number.
        match_number: u64,
        /// "Y" printable, "N" non-printable (counted in a later print).
        printable: u8,
        /// The execution price.
        execution_price: Price4,
    }

    /// "X", Order Cancel (1.4.3): a partial cancel.
    OrderCancel = b'X', 23 {
        /// The order reduced.
        order_ref: u64,
        /// Shares removed from the order.
        cancelled_shares: u32,
    }

    /// "D", Order Delete (1.4.4): the order leaves the book.
    OrderDelete = b'D', 19 {
        /// The order removed.
        order_ref: u64,
    }

    /// "U", Order Replace (1.4.5): the order leaves the book and a new one
    /// with the same side, stock and attribution takes its place.
    OrderReplace = b'U', 35 {
        /// The order removed.
        original_ref: u64,
        /// The replacement's reference number.
        new_ref: u64,
        /// The replacement's displayed shares.
        shares: u32,
        /// The replacement's display price.
        price: Price4,
    }

    /// "P", Trade, non-cross (1.5.1): an execution of a non-displayed
    /// order. It does not change the book.
    Trade = b'P', 44 {
        /// Always zero since December 6, 2010.
        order_ref: u64,
        /// Always "B" since July 14, 2014.
        side: Side,
        /// Shares matched.
        shares: u32,
        /// The symbol.
        stock: Stock,
        /// The match price.
        price: Price4,
        /// The day-unique match number.
        match_number: u64,
    }

    /// "Q", Cross Trade (1.5.2): the bulk print of a cross.
    CrossTrade = b'Q', 40 {
        /// Shares matched in the cross.
        shares: u64,
        /// The symbol.
        stock: Stock,
        /// The cross price.
        cross_price: Price4,
        /// The day-unique match number.
        match_number: u64,
        /// See [`codes::cross_type`].
        cross_type: u8,
    }

    /// "B", Broken Trade / Order Execution (1.5.3).
    BrokenTrade = b'B', 19 {
        /// The match number of the execution broken.
        match_number: u64,
    }

    /// "I", Net Order Imbalance Indicator (1.6).
    Noii = b'I', 50 {
        /// Shares paired at the current reference price.
        paired_shares: u64,
        /// Shares not paired at the current reference price.
        imbalance_shares: u64,
        /// "B" buy, "S" sell, "N" none, "O" insufficient orders, "P"
        /// paused.
        imbalance_direction: u8,
        /// The symbol.
        stock: Stock,
        /// The hypothetical clearing price for cross orders only.
        far_price: Price4,
        /// The hypothetical clearing price for cross and continuous
        /// orders.
        near_price: Price4,
        /// The price the shares are calculated at.
        current_reference_price: Price4,
        /// See [`codes::cross_type`].
        cross_type: u8,
        /// The near price's deviation from the reference: "L", "1" to
        /// "9", "A", "B", "C", or a space.
        price_variation: u8,
    }

    /// "N", Retail Price Improvement Indicator (1.7).
    Rpii = b'N', 20 {
        /// The symbol.
        stock: Stock,
        /// "B" buy side, "S" sell side, "A" both, "N" none.
        interest_flag: u8,
    }

    /// "O", Direct Listing with Capital Raise Price Discovery (1.8).
    DirectListing = b'O', 48 {
        /// The symbol.
        stock: Stock,
        /// "Y" eligible to be released for trading, "N" not.
        open_eligibility: u8,
        /// The minimum allowable price.
        minimum_price: Price4,
        /// The maximum allowable price.
        maximum_price: Price4,
        /// The reference price when the volatility test passed.
        near_execution_price: Price4,
        /// When the near execution price was set. The specification gives
        /// an eight-byte integer and no unit.
        near_execution_time: u64,
        /// The lower auction collar.
        lower_collar: Price4,
        /// The upper auction collar.
        upper_collar: Price4,
    }
}

/// The values the specification lists for one-byte code fields.
pub mod codes {
    /// System event codes (1.1).
    pub mod event {
        /// Start of messages: the first message of the day.
        pub const START_OF_MESSAGES: u8 = b'O';
        /// Start of system hours: Nasdaq accepts orders.
        pub const START_OF_SYSTEM_HOURS: u8 = b'S';
        /// Start of market hours.
        pub const START_OF_MARKET_HOURS: u8 = b'Q';
        /// End of market hours.
        pub const END_OF_MARKET_HOURS: u8 = b'M';
        /// End of system hours: no new orders today.
        pub const END_OF_SYSTEM_HOURS: u8 = b'E';
        /// End of messages: the last message of the day.
        pub const END_OF_MESSAGES: u8 = b'C';
    }
    /// Stock trading states (1.2.2).
    pub mod trading_state {
        /// Halted across all U.S. equity markets.
        pub const HALTED: u8 = b'H';
        /// Paused across all U.S. equity markets.
        pub const PAUSED: u8 = b'P';
        /// Quotation only period.
        pub const QUOTATION_ONLY: u8 = b'Q';
        /// Trading on Nasdaq.
        pub const TRADING: u8 = b'T';
    }
    /// Cross types (1.5.2, 1.6).
    pub mod cross_type {
        /// Nasdaq Opening Cross.
        pub const OPENING: u8 = b'O';
        /// Nasdaq Closing Cross.
        pub const CLOSING: u8 = b'C';
        /// Cross for IPO and halted or paused securities.
        pub const HALT_OR_IPO: u8 = b'H';
        /// Extended Trading Close (NOII only).
        pub const EXTENDED_TRADING_CLOSE: u8 = b'A';
    }
}

fictionet::prefixed! {
    /// Reads length-prefixed messages (a two-byte big-endian length, then the
    /// message) from a byte stream, without holding input. This is the layout
    /// of Nasdaq's binary ITCH files, and of MoldUDP64 message blocks.
    ///
    /// Each item is one message, parsed: `Err` for a frame that does not
    /// parse (an unknown type, a length that does not match the type), so
    /// the caller decides whether to skip it. A length prefix over the limit
    /// ends the stream with [`Error::TooLong`], read from the prefix alone.
    ///
    /// ```
    /// use fictionet::stdlib::codec::Frames;
    /// use fictionet::stdlib::codec::{finish, pump, Stream, Wire};
    /// use fictionet::stdlib::itch::{Header, Message, MwcbStatus};
    ///
    /// let status = MwcbStatus { header: Header::default(), breached_level: b'1' };
    /// let mut file = vec![0, 12];
    /// status.write(&mut file)?;
    /// let mut stream = Stream::new(Frames::<Message>::default());
    /// let mut messages = Vec::new();
    /// pump(&mut stream, &file[..5], |m| messages.push(m))?;
    /// pump(&mut stream, &file[5..], |m| messages.push(m))?;
    /// finish(&mut stream, |m| messages.push(m))?;
    /// assert_eq!(messages, [Ok(Message::MwcbStatus(status))]);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    Message => (Result<Message, Error>, Error, usize);
    name = "ITCH";
    default { MAX_FRAME }
    normalize(limit) { limit.min(MAX_FRAME) }
    capacity(limit) { let limit = *limit;
        LENGTH_PREFIX + limit }

    #[inline]
    fn parse_prefix(
        input: &[u8],
        limit: &Self::Limit,
    ) -> Result<Option<(Self::Item, usize)>, Self::Error> {
        let limit = *limit;
        let Some((prefix, rest)) = input.split_at_checked(LENGTH_PREFIX) else {
            return Ok(None);
        };
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        if length > limit {
            return Err(Error::TooLong);
        }
        let Some(body) = rest.get(..length) else {
            return Ok(None);
        };
        Ok(Some((Message::parse(body), LENGTH_PREFIX + length)))
    }
}

/// The limits of a [`Book`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BookConfig {
    /// The most live orders, 1 to [`MAX_ORDERS`].
    pub max_orders: usize,
    /// The most price levels over every stock and side, 1 to
    /// [`MAX_LEVELS`].
    pub max_levels: usize,
    /// The most stocks with orders or a directory entry, 1 to
    /// [`MAX_STOCKS`].
    pub max_stocks: usize,
}
impl Default for BookConfig {
    fn default() -> Self {
        Self {
            max_orders: DEFAULT_MAX_ORDERS,
            max_levels: DEFAULT_MAX_LEVELS,
            max_stocks: DEFAULT_MAX_STOCKS,
        }
    }
}

/// A live order on a [`Book`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Order {
    /// The stock's locate code.
    pub locate: u16,
    /// The side of the book.
    pub side: Side,
    /// The display price.
    pub price: Price4,
    /// Displayed shares left.
    pub shares: u32,
}

/// One price level of one side of a stock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Level {
    /// The price.
    pub price: Price4,
    /// Displayed shares at this price.
    pub shares: u64,
    /// Orders at this price.
    pub orders: usize,
}

/// What [`Book::apply`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The message does not change the book: trades, crosses, events,
    /// and an execute or cancel of zero shares of an order on the book.
    Ignored,
    /// The message changed this side of this stock.
    Changed {
        /// The stock's locate code.
        locate: u16,
        /// The side changed.
        side: Side,
    },
    /// A Stock Directory entry recorded the locate's symbol.
    Directory {
        /// The locate code assigned.
        locate: u16,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Aggregate {
    shares: u64,
    orders: usize,
}

#[derive(Clone, Debug, Default)]
struct StockBook {
    symbol: Option<Stock>,
    bids: BTreeMap<Price4, Aggregate>,
    asks: BTreeMap<Price4, Aggregate>,
}
impl StockBook {
    fn side(&self, side: Side) -> &BTreeMap<Price4, Aggregate> {
        match side {
            Side::Buy => &self.bids,
            Side::Sell => &self.asks,
        }
    }
    fn side_mut(&mut self, side: Side) -> &mut BTreeMap<Price4, Aggregate> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }
}

/// A full-depth order book built from ITCH order messages, without I/O.
///
/// [`apply`](Self::apply) each message in sequence order. Add Order ("A",
/// "F") puts an order on the book; Order Executed ("E", "C") and Order
/// Cancel ("X") take shares off it, removing it at zero; Order Delete
/// ("D") removes it; Order Replace ("U") removes it and adds the
/// replacement on the same side and stock (1.3, 1.4). Stock Directory
/// ("R") records each locate's symbol. Other messages leave the book as
/// it is. Prices are display prices: an execution at another price ("C")
/// takes shares from the order's level.
///
/// Orders, price levels and stocks are each bounded by [`BookConfig`]. A
/// message that would pass a limit, or that does not fit the book (an
/// unknown order, too many shares), is refused and the book is unchanged.
#[derive(Clone, Debug)]
pub struct Book {
    config: BookConfig,
    orders: HashMap<u64, Order>,
    stocks: HashMap<u16, StockBook>,
    levels: usize,
}
impl Book {
    /// An empty book. Refuses limits outside their named ranges.
    pub fn new(config: BookConfig) -> Result<Self, Error> {
        if !(1..=MAX_ORDERS).contains(&config.max_orders)
            || !(1..=MAX_LEVELS).contains(&config.max_levels)
            || !(1..=MAX_STOCKS).contains(&config.max_stocks)
        {
            return Err(Error::Config);
        }
        Ok(Self {
            config,
            orders: HashMap::new(),
            stocks: HashMap::new(),
            levels: 0,
        })
    }
    /// Live orders.
    pub fn order_count(&self) -> usize {
        self.orders.len()
    }
    /// Price levels over every stock and side.
    pub fn level_count(&self) -> usize {
        self.levels
    }
    /// Stocks with orders or a directory entry.
    pub fn stock_count(&self) -> usize {
        self.stocks.len()
    }
    /// A live order by reference number.
    pub fn order(&self, order_ref: u64) -> Option<&Order> {
        self.orders.get(&order_ref)
    }
    /// The symbol a Stock Directory message gave `locate`.
    pub fn symbol(&self, locate: u16) -> Option<Stock> {
        self.stocks.get(&locate).and_then(|s| s.symbol)
    }
    /// The highest bid of `locate`.
    pub fn best_bid(&self, locate: u16) -> Option<Level> {
        let (price, a) = self.stocks.get(&locate)?.bids.last_key_value()?;
        Some(level(*price, a))
    }
    /// The lowest ask of `locate`.
    pub fn best_ask(&self, locate: u16) -> Option<Level> {
        let (price, a) = self.stocks.get(&locate)?.asks.first_key_value()?;
        Some(level(*price, a))
    }
    /// Up to `n` levels of one side of `locate`, best first.
    pub fn depth(&self, locate: u16, side: Side, n: usize) -> Vec<Level> {
        let Some(stock) = self.stocks.get(&locate) else {
            return Vec::new();
        };
        let map = stock.side(side);
        let levels = map.iter().map(|(p, a)| level(*p, a));
        match side {
            Side::Buy => levels.rev().take(n).collect(),
            Side::Sell => levels.take(n).collect(),
        }
    }

    /// Applies one message. See [`Book`] for which messages change it.
    pub fn apply(&mut self, message: &Message) -> Result<Applied, Error> {
        let locate = message.header().locate;
        match message {
            Message::AddOrder(m) => self.add(m.order_ref, locate, m.side, m.price, m.shares),
            Message::AddOrderAttributed(m) => {
                self.add(m.order_ref, locate, m.side, m.price, m.shares)
            }
            Message::OrderExecuted(m) => self.reduce(m.order_ref, locate, m.executed_shares),
            Message::OrderExecutedWithPrice(m) => {
                self.reduce(m.order_ref, locate, m.executed_shares)
            }
            Message::OrderCancel(m) => self.reduce(m.order_ref, locate, m.cancelled_shares),
            Message::OrderDelete(m) => {
                let order = self.live(m.order_ref, locate)?;
                self.reduce(m.order_ref, locate, order.shares)
            }
            Message::OrderReplace(m) => self.replace(m, locate),
            Message::StockDirectory(m) => {
                if !self.stocks.contains_key(&locate) && self.stocks.len() >= self.config.max_stocks
                {
                    return Err(Error::TooManyStocks);
                }
                self.stocks.entry(locate).or_default().symbol = Some(m.stock);
                Ok(Applied::Directory { locate })
            }
            _ => Ok(Applied::Ignored),
        }
    }

    fn live(&self, order_ref: u64, locate: u16) -> Result<Order, Error> {
        let order = *self
            .orders
            .get(&order_ref)
            .ok_or(Error::UnknownOrder(order_ref))?;
        if order.locate != locate {
            return Err(Error::Locate(order_ref));
        }
        Ok(order)
    }
    fn has_level(&self, locate: u16, side: Side, price: Price4) -> bool {
        self.stocks
            .get(&locate)
            .is_some_and(|s| s.side(side).contains_key(&price))
    }
    /// Checks that an order can be added after `freed`, the order a
    /// replace takes off the book first, is gone.
    fn check_add(
        &self,
        order_ref: u64,
        order: Order,
        freed: Option<(u64, Order)>,
    ) -> Result<(), Error> {
        if order.shares == 0 {
            return Err(Error::Shares(order_ref));
        }
        let reused = freed.is_some_and(|(r, _)| r == order_ref);
        if self.orders.contains_key(&order_ref) && !reused {
            return Err(Error::DuplicateOrder(order_ref));
        }
        let orders = self.orders.len() - usize::from(freed.is_some());
        if orders >= self.config.max_orders {
            return Err(Error::TooManyOrders);
        }
        if !self.stocks.contains_key(&order.locate) && self.stocks.len() >= self.config.max_stocks {
            return Err(Error::TooManyStocks);
        }
        let mut levels = self.levels;
        let mut joins = self.has_level(order.locate, order.side, order.price);
        if let Some((_, old)) = freed {
            let empties = self
                .stocks
                .get(&old.locate)
                .and_then(|s| s.side(old.side).get(&old.price))
                .is_some_and(|a| a.orders == 1);
            if empties {
                levels -= 1;
                if (old.locate, old.side, old.price) == (order.locate, order.side, order.price) {
                    joins = false;
                }
            }
        }
        if !joins && levels >= self.config.max_levels {
            return Err(Error::TooManyLevels);
        }
        Ok(())
    }
    fn insert(&mut self, order_ref: u64, order: Order) {
        let stock = self.stocks.entry(order.locate).or_default();
        let level = stock
            .side_mut(order.side)
            .entry(order.price)
            .or_insert_with(|| {
                self.levels += 1;
                Aggregate::default()
            });
        level.shares = level.shares.saturating_add(u64::from(order.shares));
        level.orders = level.orders.saturating_add(1);
        self.orders.insert(order_ref, order);
    }
    /// Takes `shares` off a live order's level, and the order off the
    /// book when none are left. A stock with no levels left and no
    /// directory entry is forgotten. The caller has checked the shares.
    fn take_shares(&mut self, order_ref: u64, order: Order, shares: u32) {
        let left = order.shares - shares;
        if let Some(stock) = self.stocks.get_mut(&order.locate) {
            let map = stock.side_mut(order.side);
            if let Some(level) = map.get_mut(&order.price) {
                level.shares = level.shares.saturating_sub(u64::from(shares));
                if left == 0 {
                    level.orders = level.orders.saturating_sub(1);
                    if level.orders == 0 {
                        map.remove(&order.price);
                        self.levels = self.levels.saturating_sub(1);
                    }
                }
            }
            if stock.symbol.is_none() && stock.bids.is_empty() && stock.asks.is_empty() {
                self.stocks.remove(&order.locate);
            }
        }
        if left == 0 {
            self.orders.remove(&order_ref);
        } else if let Some(o) = self.orders.get_mut(&order_ref) {
            o.shares = left;
        }
    }
    fn add(
        &mut self,
        order_ref: u64,
        locate: u16,
        side: Side,
        price: Price4,
        shares: u32,
    ) -> Result<Applied, Error> {
        let order = Order {
            locate,
            side,
            price,
            shares,
        };
        self.check_add(order_ref, order, None)?;
        self.insert(order_ref, order);
        Ok(Applied::Changed { locate, side })
    }
    fn reduce(&mut self, order_ref: u64, locate: u16, shares: u32) -> Result<Applied, Error> {
        let order = self.live(order_ref, locate)?;
        if shares > order.shares {
            return Err(Error::Shares(order_ref));
        }
        if shares == 0 {
            return Ok(Applied::Ignored);
        }
        self.take_shares(order_ref, order, shares);
        Ok(Applied::Changed {
            locate,
            side: order.side,
        })
    }
    fn replace(&mut self, m: &OrderReplace, locate: u16) -> Result<Applied, Error> {
        let old = self.live(m.original_ref, locate)?;
        let new = Order {
            locate,
            side: old.side,
            price: m.price,
            shares: m.shares,
        };
        self.check_add(m.new_ref, new, Some((m.original_ref, old)))?;
        self.take_shares(m.original_ref, old, old.shares);
        self.insert(m.new_ref, new);
        Ok(Applied::Changed {
            locate,
            side: old.side,
        })
    }
}
fn level(price: Price4, a: &Aggregate) -> Level {
    Level {
        price,
        shares: a.shares,
        orders: a.orders,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg};
    use fictionet::stdlib::test_support::contract::{
        check_decode, check_decode_with_alloc_limit, check_wire, check_wire_value,
    };
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn replace_order(
        header: Header,
        original_ref: u64,
        new_ref: u64,
        shares: u32,
        price: Price4,
    ) -> OrderReplace {
        OrderReplace {
            header,
            original_ref,
            new_ref,
            shares,
            price,
        }
    }

    fn cancel_order(header: Header, order_ref: u64, cancelled_shares: u32) -> OrderCancel {
        OrderCancel {
            header,
            order_ref,
            cancelled_shares,
        }
    }

    fn delete_order(header: Header, order_ref: u64) -> OrderDelete {
        OrderDelete { header, order_ref }
    }

    fn ts(n: u64) -> Timestamp {
        Timestamp::new(n).unwrap()
    }
    fn header(locate: u16) -> Header {
        Header {
            locate,
            tracking: 2,
            timestamp: ts(0x0102_0304_0506),
        }
    }
    fn stock(s: &str) -> Stock {
        Alpha::right_padded(s).unwrap()
    }
    /// The common header bytes for `header(locate)`.
    fn head(kind: u8, locate: u16) -> Vec<u8> {
        let mut b = vec![kind];
        b.extend_from_slice(&locate.to_be_bytes());
        b.extend_from_slice(&[0, 2, 1, 2, 3, 4, 5, 6]);
        b
    }

    // Lengths from each message's table: the offset plus the length of
    // its last field.
    #[test]
    fn lengths_match_the_specification() {
        let spec: [(u8, usize); 23] = [
            (b'S', 12), // 1.1: Event Code at 11, 1
            (b'R', 39), // 1.2.1: Inverse Indicator at 38, 1
            (b'H', 25), // 1.2.2: Reason at 21, 4
            (b'Y', 20), // 1.2.3: Reg SHO Action at 19, 1
            (b'L', 26), // 1.2.4: Market Participant State at 25, 1
            (b'V', 35), // 1.2.5.1: Level 3 at 27, 8
            (b'W', 12), // 1.2.5.2: Breached Level at 11, 1
            (b'K', 28), // 1.2.6: IPO Price at 24, 4
            (b'J', 35), // 1.2.7: Auction Collar Extension at 31, 4
            (b'h', 21), // 1.2.8: Operational Halt Action at 20, 1
            (b'A', 36), // 1.3.1: Price at 32, 4
            (b'F', 40), // 1.3.2: Attribution at 36, 4
            (b'E', 31), // 1.4.1: Match Number at 23, 8
            (b'C', 36), // 1.4.2: Execution Price at 32, 4
            (b'X', 23), // 1.4.3: Cancelled Shares at 19, 4
            (b'D', 19), // 1.4.4: Order Reference Number at 11, 8
            (b'U', 35), // 1.4.5: Price at 31, 4
            (b'P', 44), // 1.5.1: Match Number at 36, 8
            (b'Q', 40), // 1.5.2: Cross Type at 39, 1
            (b'B', 19), // 1.5.3: Match Number at 11, 8
            (b'I', 50), // 1.6: Price Variation Indicator at 49, 1
            (b'N', 20), // 1.7: Interest Flag at 19, 1
            (b'O', 48), // 1.8: Upper Price Range Collar at 44, 4
        ];
        assert_eq!(Message::KINDS.len(), spec.len());
        for (kind, len) in spec {
            assert_eq!(Message::length_of(kind), Some(len), "{}", kind as char);
            // An all-zero body refuses only on fields with value rules.
            let mut b = vec![b' '; len];
            b[0] = kind;
            let _ = Message::parse(&b);
            assert_eq!(Message::parse(&b[..len - 1]), Err(Error::Length));
        }
        assert_eq!(Message::length_of(b'Z'), None);
        assert_eq!(spec.iter().map(|s| s.1).max(), Some(MAX_MESSAGE_LENGTH));
    }

    // 1.1: S, locate 0, tracking, timestamp, event code at 11.
    #[test]
    fn system_event_bytes() {
        let m = SystemEvent {
            header: header(0),
            event: codes::event::START_OF_MESSAGES,
        };
        let mut b = head(b'S', 0);
        b.push(b'O');
        assert_eq!(m.to_bytes().unwrap(), b);
        assert_eq!(Message::parse(&b).unwrap(), Message::SystemEvent(m));
    }

    // 1.3.2: F, order ref at 11, side at 19, shares at 20, stock at 24,
    // price at 32, attribution at 36.
    #[test]
    fn add_order_attributed_bytes() {
        let m = AddOrderAttributed {
            header: header(0x1234),
            order_ref: 0x0a0b_0c0d_0e0f_1011,
            side: Side::Sell,
            shares: 100,
            stock: stock("AAPL"),
            price: "199.99".parse().unwrap(),
            attribution: Alpha::right_padded("NSDQ").unwrap(),
        };
        let mut b = head(b'F', 0x1234);
        b.extend_from_slice(&[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11]);
        b.push(b'S');
        b.extend_from_slice(&[0, 0, 0, 100]);
        b.extend_from_slice(b"AAPL    ");
        b.extend_from_slice(&1_999_900u32.to_be_bytes());
        b.extend_from_slice(b"NSDQ");
        assert_eq!(b.len(), 40);
        assert_eq!(m.to_bytes().unwrap(), b);
        assert_eq!(AddOrderAttributed::parse(&b).unwrap(), m);
        assert_eq!(m.price.to_string(), "199.9900");
        // The same bytes as another type are refused by the type's parser.
        assert_eq!(AddOrder::parse(&b), Err(Error::Type(b'F')));
    }

    // 1.4.2: C, order ref 11, shares 19, match 23, printable 31, price 32.
    #[test]
    fn executed_with_price_bytes() {
        let m = OrderExecutedWithPrice {
            header: header(5),
            order_ref: 9,
            executed_shares: 0x0102_0304,
            match_number: 0x1122_3344_5566_7788,
            printable: b'Y',
            execution_price: Price4(0x7735_9400),
        };
        let mut b = head(b'C', 5);
        b.extend_from_slice(&9u64.to_be_bytes());
        b.extend_from_slice(&[1, 2, 3, 4]);
        b.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        b.push(b'Y');
        b.extend_from_slice(&[0x77, 0x35, 0x94, 0x00]);
        assert_eq!(m.to_bytes().unwrap(), b);
        assert_eq!(Message::parse(&b).unwrap(), m.into());
        // "Data Types": the maximum Price (4) is 200,000.0000.
        assert_eq!(m.execution_price.to_string(), "200000.0000");
    }

    // 1.4.5: U, original ref 11, new ref 19, shares 27, price 31.
    #[test]
    fn replace_bytes() {
        let m = replace_order(header(1), 1, 2, 3, Price4(4));
        let mut b = head(b'U', 1);
        b.extend_from_slice(&1u64.to_be_bytes());
        b.extend_from_slice(&2u64.to_be_bytes());
        b.extend_from_slice(&3u32.to_be_bytes());
        b.extend_from_slice(&4u32.to_be_bytes());
        assert_eq!(m.to_bytes().unwrap(), b);
        check_wire::<Message>(&b);
    }

    // 1.6: I, paired 11, imbalance 19, direction 27, stock 28, far 36,
    // near 40, reference 44, cross type 48, variation 49.
    #[test]
    fn noii_bytes() {
        let m = Noii {
            header: header(3),
            paired_shares: 1,
            imbalance_shares: 2,
            imbalance_direction: b'P',
            stock: stock("ZVZZT"),
            far_price: Price4(3),
            near_price: Price4(4),
            current_reference_price: Price4(5),
            cross_type: codes::cross_type::EXTENDED_TRADING_CLOSE,
            price_variation: b' ',
        };
        let mut b = head(b'I', 3);
        b.extend_from_slice(&1u64.to_be_bytes());
        b.extend_from_slice(&2u64.to_be_bytes());
        b.push(b'P');
        b.extend_from_slice(b"ZVZZT   ");
        for p in [3u32, 4, 5] {
            b.extend_from_slice(&p.to_be_bytes());
        }
        b.extend_from_slice(b"A ");
        assert_eq!(m.to_bytes().unwrap(), b);
        assert_eq!(Noii::parse(&b).unwrap(), m);
    }

    // 1.2.1: R, stock 11, category 19, FSI 20, round lot 21, round lots
    // only 25, classification 26, sub-type 27, authenticity 29, short sale
    // 30, IPO 31, LULD tier 32, ETP 33, leverage 34, inverse 38.
    #[test]
    fn stock_directory_bytes() {
        let m = StockDirectory {
            header: header(7),
            stock: stock("ZXZZT"),
            market_category: b'Q',
            financial_status: b'N',
            round_lot_size: 100,
            round_lots_only: b'N',
            issue_classification: b'C',
            issue_sub_type: Alpha::right_padded("Z").unwrap(),
            authenticity: b'T',
            short_sale_threshold: b'N',
            ipo_flag: b'N',
            luld_reference_price_tier: b'1',
            etp_flag: b'N',
            etp_leverage_factor: 0,
            inverse_indicator: b'N',
        };
        let mut b = head(b'R', 7);
        b.extend_from_slice(b"ZXZZT   QN");
        b.extend_from_slice(&100u32.to_be_bytes());
        b.extend_from_slice(b"NCZ TNN1N");
        b.extend_from_slice(&0u32.to_be_bytes());
        b.push(b'N');
        assert_eq!(m.to_bytes().unwrap(), b);
        assert_eq!(StockDirectory::parse(&b).unwrap(), m);
        assert_eq!(m.stock.trimmed(), "ZXZZT");
    }

    // 1.2.5.1: V, three Price (8) levels at 11, 19, 27.
    #[test]
    fn mwcb_levels_have_eight_places() {
        let m = MwcbDeclineLevel {
            header: header(0),
            level1: "5000.12345678".parse().unwrap(),
            level2: Price8(1),
            level3: Price8(u64::MAX),
        };
        let b = m.to_bytes().unwrap();
        assert_eq!(&b[11..19], &500_012_345_678u64.to_be_bytes());
        assert_eq!(m.level1.to_string(), "5000.12345678");
        assert_eq!(m.level2.to_string(), "0.00000001");
        check_wire_value(&Message::from(m));
    }

    // 1.8: O, the DLCR message.
    #[test]
    fn direct_listing_bytes() {
        let m = DirectListing {
            header: header(9),
            stock: stock("NEWCO"),
            open_eligibility: b'Y',
            minimum_price: Price4(80_000),
            maximum_price: Price4(180_000),
            near_execution_price: Price4(100_000),
            near_execution_time: 0xdead_beef,
            lower_collar: Price4(90_000),
            upper_collar: Price4(110_000),
        };
        let b = m.to_bytes().unwrap();
        assert_eq!(b.len(), 48);
        assert_eq!(b[19], b'Y');
        assert_eq!(&b[32..40], &0xdead_beefu64.to_be_bytes());
        assert_eq!(&b[44..48], &110_000u32.to_be_bytes());
        check_wire::<Message>(&b);
    }

    #[test]
    fn refuses_bad_fields() {
        let add = AddOrder {
            header: header(1),
            order_ref: 1,
            side: Side::Buy,
            shares: 1,
            stock: stock("A"),
            price: Price4(1),
        };
        let good = add.to_bytes().unwrap();
        let mut bad = good.clone();
        bad[19] = b'X';
        assert_eq!(Message::parse(&bad), Err(Error::Side(b'X')));
        let mut bad = good.clone();
        bad[24] = 0;
        assert_eq!(Message::parse(&bad), Err(Error::Field));
        let mut long = good.clone();
        long.push(0);
        assert_eq!(Message::parse(&long), Err(Error::Length));
        assert_eq!(Message::parse(&[]), Err(Error::Length));
        assert_eq!(Message::parse(b"z"), Err(Error::Type(b'z')));
        assert_eq!(Timestamp::new(MAX_TIMESTAMP + 1), Err(Error::Timestamp));
        assert_eq!(
            Timestamp::new(MAX_TIMESTAMP).unwrap().nanos(),
            MAX_TIMESTAMP
        );
        assert_eq!(Stock::right_padded("NINECHARS"), Err(Error::Field));
        for bad in ["", ".5", "1.", "1.23456", "4294967.2960", "a", "1.-1"] {
            assert_eq!(bad.parse::<Price4>(), Err(Error::Price), "{bad}");
        }
        assert_eq!("429496.7295".parse::<Price4>(), Ok(Price4(u32::MAX)));
        assert_eq!("7".parse::<Price4>(), Ok(Price4(70_000)));
        assert_eq!("0.0001".parse::<Price4>(), Ok(Price4(1)));
    }

    /// One value of every message type.
    fn samples() -> Vec<Message> {
        let h = header(42);
        let s = stock("ZVZZT");
        vec![
            SystemEvent {
                header: h,
                event: b'C',
            }
            .into(),
            StockDirectory {
                header: h,
                stock: s,
                market_category: b' ',
                financial_status: b' ',
                round_lot_size: 1,
                round_lots_only: b'Y',
                issue_classification: b'A',
                issue_sub_type: Alpha::right_padded("EM").unwrap(),
                authenticity: b'P',
                short_sale_threshold: b' ',
                ipo_flag: b' ',
                luld_reference_price_tier: b'2',
                etp_flag: b'Y',
                etp_leverage_factor: 3,
                inverse_indicator: b'Y',
            }
            .into(),
            StockTradingAction {
                header: h,
                stock: s,
                trading_state: b'T',
                reserved: b' ',
                reason: Alpha::right_padded("LUDP").unwrap(),
            }
            .into(),
            RegShoRestriction {
                header: h,
                stock: s,
                action: b'1',
            }
            .into(),
            MarketParticipantPosition {
                header: h,
                mpid: Alpha::right_padded("GSCO").unwrap(),
                stock: s,
                primary_market_maker: b'Y',
                market_maker_mode: b'N',
                market_participant_state: b'A',
            }
            .into(),
            MwcbDeclineLevel {
                header: h,
                level1: Price8(1),
                level2: Price8(2),
                level3: Price8(3),
            }
            .into(),
            MwcbStatus {
                header: h,
                breached_level: b'2',
            }
            .into(),
            IpoQuotingPeriodUpdate {
                header: h,
                stock: s,
                release_time: 34_200,
                release_qualifier: b'A',
                ipo_price: Price4(200_000),
            }
            .into(),
            LuldAuctionCollar {
                header: h,
                stock: s,
                reference_price: Price4(1),
                upper_price: Price4(2),
                lower_price: Price4(0),
                extension: 1,
            }
            .into(),
            OperationalHalt {
                header: h,
                stock: s,
                market_code: b'Q',
                action: b'H',
            }
            .into(),
            AddOrder {
                header: h,
                order_ref: 1,
                side: Side::Buy,
                shares: 100,
                stock: s,
                price: Price4(10),
            }
            .into(),
            AddOrderAttributed {
                header: h,
                order_ref: 2,
                side: Side::Sell,
                shares: 100,
                stock: s,
                price: Price4(11),
                attribution: Alpha::right_padded("NSDQ").unwrap(),
            }
            .into(),
            OrderExecuted {
                header: h,
                order_ref: 1,
                executed_shares: 10,
                match_number: 1,
            }
            .into(),
            OrderExecutedWithPrice {
                header: h,
                order_ref: 1,
                executed_shares: 10,
                match_number: 2,
                printable: b'N',
                execution_price: Price4(9),
            }
            .into(),
            cancel_order(h, 2, 50).into(),
            delete_order(h, 2).into(),
            replace_order(h, 1, 3, 70, Price4(12)).into(),
            Trade {
                header: h,
                order_ref: 0,
                side: Side::Buy,
                shares: 5,
                stock: s,
                price: Price4(10),
                match_number: 3,
            }
            .into(),
            CrossTrade {
                header: h,
                stock: s,
                shares: 1 << 40,
                cross_price: Price4(10),
                match_number: 4,
                cross_type: b'O',
            }
            .into(),
            BrokenTrade {
                header: h,
                match_number: 4,
            }
            .into(),
            Noii {
                header: h,
                paired_shares: 0,
                imbalance_shares: 0,
                imbalance_direction: b'N',
                stock: s,
                far_price: Price4(0),
                near_price: Price4(0),
                current_reference_price: Price4(0),
                cross_type: b'C',
                price_variation: b'L',
            }
            .into(),
            Rpii {
                header: h,
                stock: s,
                interest_flag: b'A',
            }
            .into(),
            DirectListing {
                header: h,
                stock: s,
                open_eligibility: b'N',
                minimum_price: Price4(1),
                maximum_price: Price4(2),
                near_execution_price: Price4(3),
                near_execution_time: 4,
                lower_collar: Price4(5),
                upper_collar: Price4(6),
            }
            .into(),
        ]
    }

    #[test]
    fn every_type_round_trips() {
        let samples = samples();
        let kinds: Vec<u8> = samples.iter().map(Message::kind).collect();
        assert_eq!(kinds, Message::KINDS);
        for m in &samples {
            check_wire_value(m);
            let b = m.to_bytes().unwrap();
            assert_eq!(b.len(), m.wire_len());
            assert_eq!(b[0], m.kind());
            assert_eq!(m.header().locate, 42);
            check_wire::<Message>(&b);
        }
    }

    fn framed(messages: &[Message]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in messages {
            out.extend_from_slice(&(m.wire_len() as u16).to_be_bytes());
            m.write(&mut out).unwrap();
        }
        out
    }

    #[test]
    fn framer_follows_the_contract() {
        let samples = samples();
        let mut bytes = framed(&samples);
        // An unknown type frames as an Err item; the stream goes on.
        bytes.extend_from_slice(&[0, 3, b'z', 1, 2]);
        bytes.extend_from_slice(&framed(&samples[..1]));
        check_decode(Frames::<Message>::default, &bytes);
        check_decode(|| Frames::<Message>::with_limit(MAX_MESSAGE_LENGTH), &bytes);
        check_decode_with_alloc_limit(Frames::<Message>::default, &bytes, 2 * (MAX_FRAME + 2));
        let (items, failure) = decode_all(Frames::<Message>::default, &bytes);
        assert!(failure.is_none());
        assert_eq!(items.len(), samples.len() + 2);
        assert_eq!(items[samples.len()], Err(Error::Type(b'z')));
        for (item, m) in items.iter().zip(&samples) {
            assert_eq!(item, &Ok(*m));
        }
        let (_, failure) = decode_all(|| Frames::<Message>::with_limit(10), &bytes);
        assert_eq!(failure, Some(Fail::Protocol(Error::TooLong)));
        let (_, failure) = decode_all(Frames::<Message>::default, &[0, 12, b'S']);
        assert_eq!(failure, Some(Fail::Truncated { unread: 3 }));
    }

    #[test]
    fn messages_ride_moldudp64_blocks() {
        use fictionet::stdlib::moldudp64::{Blocks, Body, Downstream, Session};
        let samples = samples();
        let packet = Downstream {
            session: Session::left_padded("ITCH").unwrap(),
            sequence: 1,
            body: Body::Messages(samples.iter().map(|m| m.to_bytes().unwrap()).collect()),
        };
        let datagram = packet.to_bytes().unwrap();
        let back = Downstream::parse(&datagram).unwrap();
        let parsed: Vec<Message> = back
            .messages()
            .iter()
            .map(|b| Message::parse(b).unwrap())
            .collect();
        assert_eq!(parsed, samples);
        // The block layout after the header is the file layout.
        let (from_messages, _) = decode_all(Frames::<Message>::default, &datagram[20..]);
        let (from_blocks, _) = decode_all(|| Blocks, &datagram[20..]);
        assert_eq!(from_messages.len(), from_blocks.len());
        for (m, b) in from_messages.iter().zip(&from_blocks) {
            assert_eq!(m, &Message::parse(b));
        }
    }

    #[test]
    fn mutated_messages_keep_the_contract() {
        let samples = samples();
        let bases: Vec<Vec<u8>> = samples.iter().map(|m| m.to_bytes().unwrap()).collect();
        let file = framed(&samples);
        let mut rng = Lcg::new(0x17c4);
        for _ in 0..600 {
            let mut bytes = bases[rng.index(bases.len())].clone();
            for _ in 0..=rng.below(3) {
                mutate(&mut rng, &mut bytes);
            }
            check_wire::<Message>(&bytes);
            check_wire::<AddOrder>(&bytes);
            check_wire::<Noii>(&bytes);
            if let Ok(m) = Message::parse(&bytes) {
                let mut book = Book::new(BookConfig::default()).unwrap();
                let _ = book.apply(&m);
            }
        }
        for _ in 0..100 {
            let mut bytes = file.clone();
            for _ in 0..=rng.below(4) {
                mutate(&mut rng, &mut bytes);
            }
            check_decode(Frames::<Message>::default, &bytes);
        }
    }

    fn add(order_ref: u64, locate: u16, side: Side, price: u32, shares: u32) -> Message {
        AddOrder {
            header: header(locate),
            order_ref,
            side,
            shares,
            stock: stock("ZVZZT"),
            price: Price4(price),
        }
        .into()
    }

    #[test]
    fn book_applies_the_order_life_cycle() {
        let mut book = Book::new(BookConfig::default()).unwrap();
        let changed = |side| Ok(Applied::Changed { locate: 1, side });
        fictionet::assert_cases!(|message| book.apply(message);
            first_bid: &add(1, 1, Side::Buy, 100, 300) => changed(Side::Buy),
            second_bid: &add(2, 1, Side::Buy, 100, 200) => changed(Side::Buy),
            lower_bid: &add(3, 1, Side::Buy, 99, 50) => changed(Side::Buy),
            first_ask: &add(4, 1, Side::Sell, 101, 10) => changed(Side::Sell),
            higher_ask: &add(5, 1, Side::Sell, 102, 20) => changed(Side::Sell),
        );
        assert_eq!(
            book.best_bid(1),
            Some(Level {
                price: Price4(100),
                shares: 500,
                orders: 2
            })
        );
        assert_eq!(
            book.best_ask(1),
            Some(Level {
                price: Price4(101),
                shares: 10,
                orders: 1
            })
        );
        fictionet::assert_cases!(
            |locate, side, count| book.depth(locate, side, count)
                .iter()
                .map(|l| l.price.0)
                .collect::<Vec<_>>();
            (1, Side::Buy, 5) => [100, 99],
            (1, Side::Sell, 1) => [101],
        );
        assert_eq!(book.level_count(), 4);

        // Execute part of order 1, then all of order 4.
        let h = header(1);
        book.apply(
            &OrderExecuted {
                header: h,
                order_ref: 1,
                executed_shares: 100,
                match_number: 1,
            }
            .into(),
        )
        .unwrap();
        assert_eq!(book.order(1).unwrap().shares, 200);
        assert_eq!(book.best_bid(1).unwrap().shares, 400);
        book.apply(
            &OrderExecutedWithPrice {
                header: h,
                order_ref: 4,
                executed_shares: 10,
                match_number: 2,
                printable: b'Y',
                execution_price: Price4(100),
            }
            .into(),
        )
        .unwrap();
        assert_eq!(book.order(4), None);
        assert_eq!(book.best_ask(1).unwrap().price, Price4(102));
        // Cancel part of 2, delete 3.
        book.apply(&cancel_order(h, 2, 150).into()).unwrap();
        assert_eq!(book.best_bid(1).unwrap().shares, 250);
        book.apply(&delete_order(h, 3).into()).unwrap();
        assert_eq!(book.depth(1, Side::Buy, 9).len(), 1);
        // Replace 1 to a new price: side and stock carry over.
        book.apply(&replace_order(h, 1, 6, 75, Price4(103)).into())
            .unwrap();
        assert_eq!(book.order(1), None);
        assert_eq!(
            book.order(6),
            Some(&Order {
                locate: 1,
                side: Side::Buy,
                price: Price4(103),
                shares: 75
            })
        );
        assert_eq!(
            book.best_bid(1).unwrap(),
            Level {
                price: Price4(103),
                shares: 75,
                orders: 1
            }
        );
        assert_eq!(book.order_count(), 3);
        assert_eq!(book.level_count(), 3);
        // Trades and events do not touch the book.
        assert_eq!(book.apply(&samples()[17]), Ok(Applied::Ignored));
        assert_eq!(book.apply(&samples()[0]), Ok(Applied::Ignored));
        assert_eq!(
            book.apply(&samples()[1]),
            Ok(Applied::Directory { locate: 42 })
        );
        assert_eq!(book.symbol(42), Some(stock("ZVZZT")));
    }

    #[test]
    fn book_ignores_zero_shares_and_forgets_empty_stocks() {
        let mut book = Book::new(BookConfig {
            max_stocks: 1,
            ..BookConfig::default()
        })
        .unwrap();
        book.apply(&add(1, 1, Side::Buy, 100, 10)).unwrap();
        let h = header(1);
        let before = format!("{book:?}");
        for zero in [
            Message::from(OrderExecuted {
                header: h,
                order_ref: 1,
                executed_shares: 0,
                match_number: 1,
            }),
            cancel_order(h, 1, 0).into(),
        ] {
            assert_eq!(book.apply(&zero), Ok(Applied::Ignored));
        }
        assert_eq!(format!("{book:?}"), before);
        // Zero shares of an order not on the book is still refused.
        assert_eq!(
            book.apply(&cancel_order(h, 9, 0).into()),
            Err(Error::UnknownOrder(9))
        );
        // Once its last order goes, a stock without a directory entry is
        // forgotten and its slot is free for another.
        book.apply(&delete_order(h, 1).into()).unwrap();
        assert_eq!(book.stock_count(), 0);
        book.apply(&add(2, 2, Side::Sell, 100, 10)).unwrap();
        assert_eq!(book.stock_count(), 1);
        // A directory entry keeps the stock.
        let mut book = Book::new(BookConfig::default()).unwrap();
        book.apply(&samples()[1]).unwrap();
        book.apply(&add(1, 42, Side::Buy, 100, 10)).unwrap();
        book.apply(&delete_order(header(42), 1).into()).unwrap();
        assert_eq!(book.symbol(42), Some(stock("ZVZZT")));
        assert_eq!(book.stock_count(), 1);
    }

    #[test]
    fn book_refuses_and_stays_unchanged() {
        let mut book = Book::new(BookConfig {
            max_orders: 3,
            max_levels: 2,
            max_stocks: 2,
        })
        .unwrap();
        book.apply(&add(1, 1, Side::Buy, 100, 10)).unwrap();
        let h = header(1);
        let before = format!("{book:?}");
        let refused: [(Message, Error); 8] = [
            (add(1, 1, Side::Buy, 100, 10), Error::DuplicateOrder(1)),
            (add(2, 1, Side::Buy, 100, 0), Error::Shares(2)),
            (delete_order(h, 9).into(), Error::UnknownOrder(9)),
            (cancel_order(h, 1, 11).into(), Error::Shares(1)),
            (delete_order(header(2), 1).into(), Error::Locate(1)),
            (
                replace_order(h, 1, 1, 0, Price4(1)).into(),
                Error::Shares(1),
            ),
            (
                replace_order(h, 9, 1, 1, Price4(1)).into(),
                Error::UnknownOrder(9),
            ),
            (
                OrderExecuted {
                    header: h,
                    order_ref: 1,
                    executed_shares: 11,
                    match_number: 0,
                }
                .into(),
                Error::Shares(1),
            ),
        ];
        for (m, e) in refused {
            assert_eq!(book.apply(&m), Err(e));
            assert_eq!(format!("{book:?}"), before);
        }
        // Levels: two allowed.
        book.apply(&add(2, 1, Side::Sell, 100, 10)).unwrap();
        assert_eq!(
            book.apply(&add(3, 1, Side::Sell, 101, 10)),
            Err(Error::TooManyLevels)
        );
        // Joining an existing level needs no new one.
        book.apply(&add(3, 1, Side::Sell, 100, 10)).unwrap();
        assert_eq!(
            book.apply(&add(4, 1, Side::Sell, 100, 10)),
            Err(Error::TooManyOrders)
        );
        // A replace that empties its level may open another.
        book.apply(&replace_order(h, 1, 1, 5, Price4(90)).into())
            .unwrap();
        book.apply(&replace_order(h, 1, 7, 5, Price4(80)).into())
            .unwrap();
        assert_eq!(book.best_bid(1).unwrap().price, Price4(80));
        // But not one that leaves its level behind.
        assert_eq!(
            book.apply(&replace_order(h, 2, 8, 5, Price4(70)).into()),
            Err(Error::TooManyLevels)
        );
        // Stocks: one allowed, directory entries included.
        let mut book = Book::new(BookConfig {
            max_stocks: 1,
            ..BookConfig::default()
        })
        .unwrap();
        book.apply(
            &SystemEvent {
                header: header(0),
                event: b'O',
            }
            .into(),
        )
        .unwrap();
        book.apply(&add(1, 1, Side::Buy, 1, 1)).unwrap();
        assert_eq!(
            book.apply(&add(2, 2, Side::Buy, 1, 1)),
            Err(Error::TooManyStocks)
        );
        assert_eq!(book.apply(&samples()[1]), Err(Error::TooManyStocks));
        assert_eq!(book.stock_count(), 1);
        fictionet::assert_cases!(|config| Book::new(config).err();
            zero_orders: BookConfig { max_orders: 0, ..BookConfig::default() } =>
                Some(Error::Config),
            excess_stocks: BookConfig { max_stocks: MAX_STOCKS + 1, ..BookConfig::default() } =>
                Some(Error::Config),
        );
    }

    #[test]
    fn book_matches_a_model_under_random_messages() {
        let mut rng = Lcg::new(0xb00c);
        let config = BookConfig {
            max_orders: 40,
            max_levels: 12,
            max_stocks: 3,
        };
        let mut book = Book::new(config).unwrap();
        // Model: every live order, by reference.
        let mut model: HashMap<u64, Order> = HashMap::new();
        for _ in 0..5_000 {
            let order_ref = rng.below(60);
            let locate = rng.below(4) as u16;
            let h = header(locate);
            let price = Price4(rng.below(8) as u32);
            let shares = rng.below(5) as u32;
            let side = if rng.coin() { Side::Buy } else { Side::Sell };
            let m: Message = match rng.below(6) {
                0 | 1 => add(order_ref, locate, side, price.0, shares),
                2 => OrderExecuted {
                    header: h,
                    order_ref,
                    executed_shares: shares,
                    match_number: 0,
                }
                .into(),
                3 => cancel_order(h, order_ref, shares).into(),
                4 => delete_order(h, order_ref).into(),
                _ => replace_order(h, order_ref, rng.below(60), shares, price).into(),
            };
            let before = format!("{book:?}");
            if book.apply(&m).is_err() {
                assert_eq!(format!("{book:?}"), before);
                continue;
            }
            match m {
                Message::AddOrder(a) => {
                    model.insert(
                        a.order_ref,
                        Order {
                            locate,
                            side: a.side,
                            price: a.price,
                            shares: a.shares,
                        },
                    );
                }
                Message::OrderExecuted(OrderExecuted {
                    order_ref,
                    executed_shares: n,
                    ..
                })
                | Message::OrderCancel(OrderCancel {
                    order_ref,
                    cancelled_shares: n,
                    ..
                }) => {
                    let o = model.get_mut(&order_ref).unwrap();
                    o.shares -= n;
                    if o.shares == 0 {
                        model.remove(&order_ref);
                    }
                }
                Message::OrderDelete(d) => {
                    model.remove(&d.order_ref).unwrap();
                }
                Message::OrderReplace(r) => {
                    let old = model.remove(&r.original_ref).unwrap();
                    model.insert(
                        r.new_ref,
                        Order {
                            price: r.price,
                            shares: r.shares,
                            ..old
                        },
                    );
                }
                _ => unreachable!(),
            }
            assert!(book.order_count() <= config.max_orders);
            assert!(book.level_count() <= config.max_levels);
            assert!(book.stock_count() <= config.max_stocks);
            assert_eq!(book.order_count(), model.len());
            for (r, o) in &model {
                assert_eq!(book.order(*r), Some(o));
            }
            // Levels are the sum of the model's orders.
            let mut levels = 0;
            for locate in 0..4u16 {
                for side in [Side::Buy, Side::Sell] {
                    let got = book.depth(locate, side, usize::MAX);
                    levels += got.len();
                    let mut want: BTreeMap<Price4, (u64, usize)> = BTreeMap::new();
                    for o in model
                        .values()
                        .filter(|o| o.locate == locate && o.side == side)
                    {
                        let e = want.entry(o.price).or_default();
                        e.0 += u64::from(o.shares);
                        e.1 += 1;
                    }
                    let mut want: Vec<Level> = want
                        .into_iter()
                        .map(|(price, (shares, orders))| Level {
                            price,
                            shares,
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
}
