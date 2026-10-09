//! Cboe Binary Order Entry (BOE) for US equities: every session and order
//! message as a [`Wire`] value with its bitfield-driven optional fields, a
//! framer, a caller-driven client and exchange-side session, and an
//! exchange-side order tracker, with no I/O and no clocks.
//! Message tables use [`codec::layout!`](fictionet::stdlib::codec::layout!).
//!
//! BOE is Cboe's native order entry protocol for the BYX, BZX, EDGA and
//! EDGX equities exchanges. A member logs in with the last sequence number
//! it received per matching unit, Cboe replays what it missed, and orders
//! flow as New Order, Cancel Order, Modify Order and Purge Orders
//! ([`Inbound`]); Cboe answers with acknowledgments, rejects, executions
//! and cancels ([`Outbound`]). This module follows the
//! [Cboe Titanium U.S. Equities BOE Specification](https://cdn.cboe.com/resources/techspec/technical-specifications-cboe-titanium-u-s-equities-boe-specification.pdf),
//! version 2.4.58 of October 5, 2026: BOE version 2, not BOE3. Section
//! names below are that document's.
//!
//! Every message has a ten-byte header: StartOfMessage `BA BA`, a two-byte
//! MessageLength that counts everything after StartOfMessage, a type byte,
//! the MatchingUnit and a SequenceNumber ("Message Headers"). Binary
//! values are little-endian; text is printable ASCII filled on the right
//! with NUL ([`Text`]); prices are signed with four implied decimal places
//! ([`Price`]) ("Data Types"). Most order messages end with a count of
//! bitfields, the bitfields, and the optional fields whose bits are set,
//! in bit order ("Optional Fields and Bit fields"). [`Optional`] holds
//! them, typed ([`Opt`]), for one of the specification's bitfield tables:
//! one per input message ([`NewOrderTable`], [`CancelOrderTable`],
//! [`ModifyOrderTable`], [`PurgeOrdersTable`]) and one shared by every
//! return message ([`ReturnTable`]). A bit whose field the specification
//! gives no size for US equities is refused, since the bytes after it
//! cannot be read.
//!
//! [`Client`] and [`Server`] are the session rules: login with unit
//! sequences and return bitfields, replay and Replay Complete, inbound
//! sequence numbers that may skip forward but never back, outbound
//! sequence numbers per matching unit, heartbeats after a second of
//! silence and a five-second timeout ("Login, Replay and Sequencing",
//! "Heartbeats", "Logging Out"). [`Exchange`] is the order side of a fake
//! exchange: it checks requests, tracks live orders by ClOrdID, fills the
//! return fields each login asked for, and leaves accepting, executing and
//! canceling to the world.
//!
//! ```
//! use fictionet::stdlib::session::Action;
//! use fictionet::stdlib::cboe_boe::{
//!     Client, ClientConfig, Event, Exchange, ExchangeConfig, FieldId, Inbound, NewOrder,
//!     Opt, Optional, OrderEvent, Outbound, Server, Text, Timers, UnitSequence,
//! };
//! use fictionet::stdlib::codec::Wire;
//!
//! let config = ClientConfig {
//!     session_sub_id: Text::new("0001")?,
//!     username: Text::new("TEST")?,
//!     password: Text::new("TESTING")?,
//!     no_unspecified_unit_replay: false,
//!     returns: vec![(0x25, vec![0, 0x41])], // Acks echo Symbol, Capacity.
//!     timers: Timers::default(),
//! };
//! let mut client = Client::new(config, &[], 0)?;
//! let mut server = Server::new(Timers::default(), 0)?;
//!
//! // Login: the request crosses as bytes; the world accepts it.
//! for action in client.start(0)? {
//!     if let Action::Send(m) = action {
//!         let login = Inbound::parse(&m.to_bytes()?)?;
//!         let events = server.receive(&login, 1)?;
//!         assert!(matches!(&events[..], [Action::Event(Event::LoginRequested(_))]));
//!     }
//! }
//! for action in server.accept(0, &[UnitSequence { unit: 1, sequence: 0 }], 2)? {
//!     if let Action::Send(m) = action {
//!         client.receive(&m, 3)?;
//!     }
//! }
//!
//! // A New Order, numbered by the client, checked by the exchange.
//! let order = NewOrder {
//!     header: Default::default(),
//!     cl_ord_id: Text::new("ABC123")?,
//!     side: b'1',
//!     order_qty: 1000,
//!     fields: Optional::new()
//!         .with(Opt::Price("123.45".parse()?))?
//!         .with(Opt::Symbol(Text::new("MSFT")?))?
//!         .with(Opt::Capacity(b'P'))?,
//! };
//! let sent = client.send(order.into(), 4)?;
//! assert_eq!(sent.header().sequence, 1);
//! assert_eq!(server.receive(&sent, 5)?, [Action::Event(Event::Application)]);
//! let mut exchange = Exchange::new(ExchangeConfig::default(), server.returns().clone())?;
//! let id = Text::new("ABC123")?;
//! assert_eq!(exchange.receive(&sent, 6), [Action::Event(OrderEvent::NewOrderRequested(id))]);
//!
//! // The world accepts it on unit 1; the server numbers the ack.
//! let ack = server.send(exchange.accept(id, 1, 7)?, 7)?;
//! assert_eq!((ack.header().unit, ack.header().sequence), (1, 1));
//! let Outbound::OrderAcknowledgment(a) = &ack else { unreachable!() };
//! assert_eq!(a.fields.get(FieldId::Capacity), Some(&Opt::Capacity(b'P')));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

//!
//! Reads whole messages of one direction from a byte stream. Each item
//! is one message, parsed: `Err` for one that frames but does not parse.
//! A stream that does not start with `BA BA` at a message boundary, or a
//! MessageLength below the header or over the limit, ends the stream,
//! read from the first four bytes.
//!
//! ```
//! use fictionet::stdlib::codec::Frames;
//! use fictionet::stdlib::cboe_boe::{ClientHeartbeat, Inbound};
//! use fictionet::stdlib::codec::{finish, pump, Stream, Wire};
//!
//! let bytes = ClientHeartbeat::default().to_bytes()?;
//! assert_eq!(bytes, [0xBA, 0xBA, 8, 0, 3, 0, 0, 0, 0, 0]);
//! let mut stream = Stream::new(Frames::<Inbound>::default());
//! let mut items = Vec::new();
//! pump(&mut stream, &bytes[..3], |m| items.push(m))?;
//! pump(&mut stream, &bytes[3..], |m| items.push(m))?;
//! finish(&mut stream, |m| items.push(m))?;
//! assert_eq!(items, [Ok(Inbound::ClientHeartbeat(ClientHeartbeat::default()))]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#[cfg(test)]
use fictionet::stdlib::codec::Frames;
use fictionet::stdlib::codec::Prefixed;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::field;
use fictionet::stdlib::session::Action;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

/// The two bytes every message starts with.
pub const START_OF_MESSAGE: [u8; 2] = [0xBA, 0xBA];
/// Bytes in the message header, StartOfMessage included.
pub const HEADER_LENGTH: usize = 10;
/// The longest message: StartOfMessage plus the most MessageLength counts.
pub const MAX_MESSAGE: usize = 2 + u16::MAX as usize;
/// The most shares an order may have ("New Order Message Fields").
pub const MAX_ORDER_QTY: u32 = 999_999;
/// The most Modify Order requests one order may take in a day.
pub const MAX_MODIFIES: u16 = 1_295;
/// The most RiskGroupIDs one Purge Orders may name.
pub const MAX_RISK_GROUP_IDS: usize = 10;
/// Silence after which a side sends a heartbeat ("Heartbeats").
pub const HEARTBEAT_INTERVAL_MS: u64 = 1_000;
/// Receiving silence after which Cboe logs a member out ("Heartbeats").
pub const IDLE_TIMEOUT_MS: u64 = 5_000;
/// Time allowed from connection to a completed login. The specification
/// names none; this is the default of [`Timers`].
pub const LOGIN_TIMEOUT_MS: u64 = 30_000;
/// The longest timer [`Timers`] accepts.
pub const MAX_TIMER_MS: u64 = 86_400_000;

/// The default most live and pending orders an [`Exchange`] tracks.
pub const DEFAULT_MAX_ORDERS: usize = 100_000;
/// The most orders an [`Exchange`] may be configured to track.
pub const MAX_ORDERS: usize = 1 << 24;
/// The default most executions an [`Exchange`] remembers for busts.
pub const DEFAULT_MAX_EXECUTIONS: usize = 100_000;
/// The most executions an [`Exchange`] may be configured to remember.
pub const MAX_EXECUTIONS: usize = 1 << 24;

/// Why bytes, a value or an operation were refused. An [`Exchange`] that
/// refuses an operation is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The message does not start with `BA BA`.
    Start,
    /// MessageLength disagrees with the bytes, or the bytes are shorter or
    /// longer than the message's fields.
    Length,
    /// An unknown message type, or bytes of another type than asked for.
    Type(u8),
    /// A text field has a byte outside printable ASCII before its NUL
    /// fill, a byte other than NUL after it, or text longer than the field.
    Field,
    /// A set bit whose field the bitfield table does not size. Bytes and
    /// bits count from 0.
    Bitfield {
        /// The bitfield, from 0.
        byte: u8,
        /// The bit, from 0 (the lowest order bit).
        bit: u8,
    },
    /// A field the message's bitfield table does not hold.
    Unsupported(FieldId),
    /// A parameter group that does not parse, or one written as
    /// [`ParamGroup::Other`] with a type this module defines.
    Group(u8),
    /// More list entries than a one-byte count holds.
    Count,
    /// A decimal price with more than four places, or too large.
    Price,
    /// A message longer than [`MAX_MESSAGE`] or the framer's limit.
    TooLong,
    /// A timer or limit outside its named range.
    Config,
    /// An operation the session's state or the message's kind does not
    /// allow.
    State,
    /// Time went backwards.
    Time,
    /// A sequence number that ran out, or one a replay may not carry.
    Sequence,
    /// An [`Exchange`] configuration value outside its named limits, a
    /// return table it cannot fill, or matching unit 0.
    ExchangeConfig,
    /// No live order, or no pending New Order, has this ClOrdID.
    UnknownOrder(ClOrdId),
    /// An execute or restatement of zero shares, or more than are open.
    Shares,
    /// No remembered execution has this ExecID.
    UnknownExecution(u64),
    /// OrderIDs or ExecIDs ran out.
    Exhausted,
    /// Exchange text too long or not printable.
    Text,
}
fictionet::error_display!(Error, f, {
    Error::Start => f.write_str("BOE message does not start with BA BA"),
    Error::Length => f.write_str("BOE message length is wrong"),
    Error::Type(t) => write!(f, "unexpected BOE message type {t:#04x}"),
    Error::Field => f.write_str("BOE text field is invalid"),
    Error::Bitfield { byte, bit } => {
        write!(f, "BOE bitfield {byte} bit {bit} names no known field")
    }
    Error::Unsupported(id) => write!(f, "BOE message cannot carry {id:?}"),
    Error::Group(t) => write!(f, "invalid BOE parameter group {t:#04x}"),
    Error::Count => f.write_str("BOE list is too long"),
    Error::Price => f.write_str("BOE price is invalid"),
    Error::TooLong => f.write_str("BOE message is too long"),
    Error::Config => f.write_str("BOE configuration is out of range"),
    Error::State => f.write_str("BOE operation not allowed now"),
    Error::Time => f.write_str("BOE time went backwards"),
    Error::Sequence => f.write_str("BOE sequence number is invalid"),
    Error::ExchangeConfig => f.write_str("BOE exchange configuration is out of range"),
    Error::UnknownOrder(c) => write!(f, "no BOE order {c:?}"),
    Error::Shares => f.write_str("BOE share count is invalid"),
    Error::UnknownExecution(e) => write!(f, "no BOE execution {e}"),
    Error::Exhausted => f.write_str("BOE numbering is exhausted"),
    Error::Text => f.write_str("BOE text is invalid"),
});

fictionet::fixed_fields!(Field, take, array; Error, Error::Length;
    from_le_bytes, to_le_bytes; u8, u16, u32, u64, i16);

/// A Binary Price: eight signed bytes with four implied decimal places.
/// The raw value 123400 is $12.34 ("Data Types").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Price(pub i64);
impl fmt::Display for Price {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.0 < 0 { "-" } else { "" };
        let raw = self.0.unsigned_abs();
        write!(f, "{sign}{}.{:04}", raw / 10_000, raw % 10_000)
    }
}
impl FromStr for Price {
    type Err = Error;
    /// Reads "12.34", "-12.34" or "12" as dollars; refuses more than four
    /// places.
    fn from_str(s: &str) -> Result<Self, Error> {
        let (negative, digits) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let raw = i64::try_from(field::parse_decimal(digits, 4).map_err(|_| Error::Price)?)
            .map_err(|_| Error::Price)?;
        Ok(Self(if negative { -raw } else { raw }))
    }
}
impl Field for Price {
    const LEN: usize = 8;
    fn get(b: &[u8]) -> Result<Self, Error> {
        Ok(Self(i64::from_le_bytes(array(b)?)))
    }
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_le_bytes());
    }
}

/// A fixed-width text field: printable ASCII, left justified and filled
/// on the right with NUL ("Data Types"). All NUL is the empty value. The
/// fill is part of the value, so fields round-trip byte for byte.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text<const N: usize>([u8; N]);
impl<const N: usize> Default for Text<N> {
    fn default() -> Self {
        Self([0; N])
    }
}
impl<const N: usize> Text<N> {
    /// The field's exact bytes. Refuses a byte outside 0x20..=0x7e before
    /// the first NUL, or anything but NUL after it.
    pub fn from_bytes(bytes: [u8; N]) -> Result<Self, Error> {
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(N);
        let (text, fill) = bytes.split_at(end);
        if text.iter().all(|b| (0x20..=0x7e).contains(b)) && fill.iter().all(|b| *b == 0) {
            Ok(Self(bytes))
        } else {
            Err(Error::Field)
        }
    }
    /// `text` filled on the right with NUL.
    pub fn new(text: &str) -> Result<Self, Error> {
        if text.len() > N {
            return Err(Error::Field);
        }
        let mut bytes = [0; N];
        bytes
            .get_mut(..text.len())
            .ok_or(Error::Field)?
            .copy_from_slice(text.as_bytes());
        Self::from_bytes(bytes)
    }
    /// The field's bytes, fill included.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
    /// The text before the NUL fill.
    pub fn as_str(&self) -> &str {
        let end = self.0.iter().position(|b| *b == 0).unwrap_or(N);
        // Every byte before the fill is printable ASCII.
        std::str::from_utf8(self.0.get(..end).unwrap_or_default()).unwrap_or_default()
    }
    /// Whether the field is all NUL.
    pub fn is_empty(&self) -> bool {
        self.0.first().is_none_or(|b| *b == 0)
    }
}
impl<const N: usize> fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}
impl<const N: usize> Field for Text<N> {
    const LEN: usize = N;
    fn get(b: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(array(b)?)
    }
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

/// A client order identifier: 20 bytes of text.
pub type ClOrdId = Text<20>;
/// Human-readable reject or logout text: 60 bytes.
pub type ReasonText = Text<60>;

/// The MatchingUnit and SequenceNumber every message carries after its
/// type ("Message Headers"). Both are 0 on session messages, on unsequenced
/// application messages, and on member messages' unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Header {
    /// The matching unit.
    pub unit: u8,
    /// The sequence number.
    pub sequence: u32,
}
impl Field for Header {
    const LEN: usize = 5;
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            unit: take(&mut b)?,
            sequence: take(&mut b)?,
        })
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.unit.put(out);
        self.sequence.put(out);
    }
}

/// Defines the optional fields ("List of Optional Fields"): an id per
/// field with its size, and a typed value.
macro_rules! optional_fields {
    ($( $(#[doc = $doc:literal])* $name:ident: $ty:ty, )*) => {
        /// An optional field's name.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum FieldId {
            $( $(#[doc = $doc])* $name, )*
        }
        impl FieldId {
            /// Bytes the field takes on the wire.
            pub fn size(self) -> usize {
                match self {
                    $( FieldId::$name => <$ty as Field>::LEN, )*
                }
            }
            /// Every field, in the specification's order.
            pub const ALL: &'static [FieldId] = &[$(FieldId::$name),*];
        }
        /// An optional field's value.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub enum Opt {
            $( $(#[doc = $doc])* $name($ty), )*
        }
        impl Opt {
            /// The field this value is for.
            pub fn id(&self) -> FieldId {
                match self {
                    $( Opt::$name(_) => FieldId::$name, )*
                }
            }
            /// The all-zero value Cboe sends for a requested field that
            /// does not apply ("Optional Fields and Bit fields").
            pub fn zero(id: FieldId) -> Self {
                match id {
                    $( FieldId::$name => Opt::$name(<$ty>::default()), )*
                }
            }
            fn read(id: FieldId, b: &[u8]) -> Result<Self, Error> {
                match id {
                    $( FieldId::$name => <$ty as Field>::get(b).map(Opt::$name), )*
                }
            }
            fn put(&self, out: &mut Vec<u8>) {
                match self {
                    $( Opt::$name(v) => v.put(out), )*
                }
            }
        }
    };
}

optional_fields! {
    /// Account: 16 bytes of text.
    Account: Text<16>,
    /// AttributedQuote: "N", "Y" or "R".
    AttributedQuote: u8,
    /// BaseLiquidityIndicator: "A", "R", "X", "C" or "W".
    BaseLiquidityIndicator: u8,
    /// CancelOrigOnReject: "N" or "Y".
    CancelOrigOnReject: u8,
    /// Capacity: "A", "P" or "R".
    Capacity: u8,
    /// ClearingAccount: 4 bytes of text.
    ClearingAccount: Text<4>,
    /// ClearingFirm: the MPID that clears the trade.
    ClearingFirm: Text<4>,
    /// CmcMatchQty: matched size of a CMC session.
    CmcMatchQty: u32,
    /// CmcSessions: first and last CMC session.
    CmcSessions: Text<2>,
    /// CrossTradeFlag (BYX): "0", "1" or "2".
    CrossTradeFlag: u8,
    /// DiscretionAmount: two implied decimal places, -9999 to 9999. The
    /// specification calls it Binary but allows negative values; it is
    /// read as signed.
    DiscretionAmount: i16,
    /// DisplayIndicator.
    DisplayIndicator: u8,
    /// DisplayPrice.
    DisplayPrice: Price,
    /// DisplayRange: random replenishment range.
    DisplayRange: u32,
    /// EchoText: 64 bytes of free text.
    EchoText: Text<64>,
    /// ExDestination.
    ExDestination: u8,
    /// ExecInst.
    ExecInst: u8,
    /// ExpireTime: nanoseconds since the Unix epoch, UTC.
    ExpireTime: u64,
    /// ExtExecInst.
    ExtExecInst: u8,
    /// FeeCode: two characters.
    FeeCode: Text<2>,
    /// LastPx.
    LastPx: Price,
    /// LastShares.
    LastShares: u32,
    /// LeavesQty: shares still open; 0 means the order is done.
    LeavesQty: u32,
    /// LocateBroker.
    LocateBroker: Text<4>,
    /// LocateReqd: "N" or "Y".
    LocateReqd: u8,
    /// MassCancelID.
    MassCancelId: Text<20>,
    /// MassCancelInst: filter, acknowledgment style, lockout.
    MassCancelInst: Text<16>,
    /// MatchingUnit a Purge Orders is sent toward.
    MatchingUnit: u8,
    /// MaxFloor: shares to display.
    MaxFloor: u32,
    /// MinQty.
    MinQty: u32,
    /// OrderQty.
    OrderQty: u32,
    /// OrdType: "1" market, "2" limit, "3" stop, "4" stop limit, "P" peg.
    OrdType: u8,
    /// OrigClOrdID.
    OrigClOrdId: ClOrdId,
    /// PegDifference: a signed price.
    PegDifference: Price,
    /// PreventMatch: three characters.
    PreventMatch: Text<3>,
    /// Price: the limit price.
    Price: Price,
    /// RiskGroupID.
    RiskGroupId: u16,
    /// RiskReset.
    RiskReset: Text<8>,
    /// RouteDeliveryMethod: "RTI" or "RTF".
    RouteDeliveryMethod: Text<3>,
    /// RoutingInst.
    RoutingInst: Text<4>,
    /// RoutStrategy.
    RoutStrategy: Text<6>,
    /// SecondaryOrderID.
    SecondaryOrderId: u64,
    /// Side: "1" buy, "2" sell, "5" sell short, "6" sell short exempt.
    Side: u8,
    /// StepUpAmount (BYX).
    StepUpAmount: Price,
    /// StopPx.
    StopPx: Price,
    /// SubLiquidityIndicator.
    SubLiquidityIndicator: u8,
    /// Symbol.
    Symbol: Text<8>,
    /// SymbolSfx.
    SymbolSfx: Text<8>,
    /// TimeInForce.
    TimeInForce: u8,
    /// WorkingPrice.
    WorkingPrice: Price,
}

/// One message's bitfield layout: bitfield `i`, bit `b` (mask `1 << b`)
/// names `MAP[i][b]`, or `None` for a bit US equities does not use.
pub trait Table {
    /// The message the table is for.
    const NAME: &'static str;
    /// The layout.
    const MAP: &'static [[Option<FieldId>; 8]];
}
macro_rules! tables {
    ($( $(#[doc = $doc:literal])* $name:ident = $title:literal [ $( [ $($f:tt),* ] ),* ] )*) => {
        $(
            $(#[doc = $doc])*
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
            pub struct $name;
            impl Table for $name {
                const NAME: &'static str = $title;
                const MAP: &'static [[Option<FieldId>; 8]] = &[ $( [ $( tables!(@f $f) ),* ] ),* ];
            }
        )*
    };
    (@f _) => { None };
    (@f $f:ident) => { Some(FieldId::$f) };
}

tables! {
    /// New Order input bitfields ("Input Bitfields Per Message"): the
    /// fields marked R or O for US equities.
    NewOrderTable = "New Order" [
        [ClearingFirm, ClearingAccount, Price, ExecInst, OrdType, TimeInForce, MinQty, MaxFloor],
        [Symbol, SymbolSfx, _, _, _, _, Capacity, RoutingInst],
        [Account, DisplayIndicator, _, DiscretionAmount, PegDifference, PreventMatch, LocateReqd, ExpireTime],
        [_, _, _, RiskReset, _, _, _, _],
        [_, AttributedQuote, _, ExtExecInst, _, _, _, _],
        [DisplayRange, StopPx, RoutStrategy, RouteDeliveryMethod, ExDestination, EchoText, _, _],
        [_, RiskGroupId, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, CrossTradeFlag, _],
        [_, LocateBroker, CmcSessions, StepUpAmount, _, _, _, _]
    ]
    /// Cancel Order input bitfields.
    CancelOrderTable = "Cancel Order" [
        [ClearingFirm, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _]
    ]
    /// Modify Order input bitfields.
    ModifyOrderTable = "Modify Order" [
        [ClearingFirm, _, OrderQty, Price, OrdType, CancelOrigOnReject, ExecInst, Side],
        [MaxFloor, StopPx, _, _, _, _, _, LocateBroker]
    ]
    /// Purge Orders input bitfields.
    PurgeOrdersTable = "Purge Orders" [
        [ClearingFirm, _, MassCancelInst, _, MassCancelId, _, _, _],
        [Symbol, SymbolSfx, _, _, _, _, _, MatchingUnit]
    ]
    /// Return bitfields, one layout for every Cboe to Member message
    /// ("Return Bitfields Per Message"): the fields the List of Optional
    /// Fields sizes. Bits for fields Cboe Equities does not use are `None`.
    ReturnTable = "Return" [
        [Side, PegDifference, Price, ExecInst, OrdType, TimeInForce, MinQty, _],
        [Symbol, SymbolSfx, _, _, _, _, Capacity, _],
        [Account, ClearingFirm, ClearingAccount, DisplayIndicator, MaxFloor, DiscretionAmount, OrderQty, PreventMatch],
        [_, _, _, _, _, _, _, _],
        [OrigClOrdId, LeavesQty, LastShares, LastPx, DisplayPrice, WorkingPrice, BaseLiquidityIndicator, ExpireTime],
        [SecondaryOrderId, _, _, AttributedQuote, ExtExecInst, _, _, _],
        [SubLiquidityIndicator, _, _, _, _, _, _, _],
        [FeeCode, EchoText, StopPx, RoutingInst, RoutStrategy, RouteDeliveryMethod, ExDestination, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, MassCancelId, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, _, _, _, _, _],
        [_, _, _, CrossTradeFlag, _, _, LocateBroker, _],
        [_, _, _, CmcSessions, _, CmcMatchQty, StepUpAmount, _]
    ]
}

/// Where `id` sits in table `T`: (bitfield, bit).
fn position<T: Table>(id: FieldId) -> Option<(u8, u8)> {
    T::MAP.iter().enumerate().find_map(|(byte, bits)| {
        let bit = bits.iter().position(|f| *f == Some(id))?;
        Some((u8::try_from(byte).ok()?, u8::try_from(bit).ok()?))
    })
}

/// A message's optional fields for bitfield table `T`: how many bitfields
/// it sends and the values of the set bits, kept in wire order.
///
/// The count is kept apart from the values because a message may send
/// bitfields that are all zero (as in the Order Modified example, which
/// sends five bitfields for two fields). [`with`](Self::with) and
/// [`set`](Self::set) raise it as needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Optional<T> {
    count: u8,
    fields: Vec<Opt>,
    table: PhantomData<T>,
}
impl<T: Table> Default for Optional<T> {
    fn default() -> Self {
        Self::new()
    }
}
impl<T: Table> Optional<T> {
    /// No bitfields.
    pub fn new() -> Self {
        Self {
            count: 0,
            fields: Vec::new(),
            table: PhantomData,
        }
    }
    /// `self` with `value` set.
    pub fn with(mut self, value: Opt) -> Result<Self, Error> {
        self.set(value)?;
        Ok(self)
    }
    /// Sets a field, replacing any earlier value. Refuses a field the
    /// table does not hold.
    pub fn set(&mut self, value: Opt) -> Result<(), Error> {
        let (byte, bit) = position::<T>(value.id()).ok_or(Error::Unsupported(value.id()))?;
        let at = self
            .fields
            .iter()
            .position(|f| position::<T>(f.id()) >= Some((byte, bit)))
            .unwrap_or(self.fields.len());
        match self.fields.get_mut(at) {
            Some(f) if f.id() == value.id() => *f = value,
            _ => self.fields.insert(at, value),
        }
        self.count = self.count.max(byte + 1);
        Ok(())
    }
    /// Removes a field.
    pub fn remove(&mut self, id: FieldId) -> Option<Opt> {
        let at = self.fields.iter().position(|f| f.id() == id)?;
        Some(self.fields.remove(at))
    }
    /// A field's value.
    pub fn get(&self, id: FieldId) -> Option<&Opt> {
        self.fields.iter().find(|f| f.id() == id)
    }
    /// The values, in wire order.
    pub fn fields(&self) -> &[Opt] {
        &self.fields
    }
    /// How many bitfields are sent.
    pub fn bitfield_count(&self) -> u8 {
        self.count
    }
    /// Sends `count` bitfields; those past the last set bit are zero.
    /// Refuses fewer than the fields need.
    pub fn set_bitfield_count(&mut self, count: u8) -> Result<(), Error> {
        let needed = self
            .fields
            .iter()
            .filter_map(|f| position::<T>(f.id()))
            .map(|(byte, _)| byte + 1)
            .max()
            .unwrap_or(0);
        if count < needed {
            return Err(Error::Count);
        }
        self.count = count;
        Ok(())
    }
    /// The bitfields.
    pub fn bitfields(&self) -> Vec<u8> {
        let mut bits = vec![0u8; usize::from(self.count)];
        for f in &self.fields {
            if let Some((byte, bit)) = position::<T>(f.id())
                && let Some(b) = bits.get_mut(usize::from(byte))
            {
                *b |= 1 << bit;
            }
        }
        bits
    }
    /// Zero values for every bit set in `bitfields`, as Cboe fills a
    /// requested field that does not apply. Refuses a bit the table does
    /// not size.
    pub fn requested(bitfields: &[u8]) -> Result<Self, Error> {
        let count = u8::try_from(bitfields.len()).map_err(|_| Error::Count)?;
        let mut fields = Vec::new();
        for (id, _) in Self::ids(bitfields)? {
            fields.push(Opt::zero(id));
        }
        Ok(Self {
            count,
            fields,
            table: PhantomData,
        })
    }
    /// The field of every set bit, in wire order.
    fn ids(bitfields: &[u8]) -> Result<Vec<(FieldId, usize)>, Error> {
        let mut ids = Vec::new();
        for (byte, bits) in bitfields.iter().enumerate() {
            for bit in 0..8u8 {
                if bits & (1 << bit) == 0 {
                    continue;
                }
                let id = T::MAP
                    .get(byte)
                    .and_then(|row| row[usize::from(bit)])
                    .ok_or(Error::Bitfield {
                        byte: u8::try_from(byte).unwrap_or(u8::MAX),
                        bit,
                    })?;
                ids.push((id, id.size()));
            }
        }
        Ok(ids)
    }
    /// Bytes on the wire: the count, the bitfields and the values.
    pub fn wire_len(&self) -> usize {
        1 + usize::from(self.count) + self.fields.iter().map(|f| f.id().size()).sum::<usize>()
    }
    /// Reads the count and bitfields.
    fn read_bitfields(b: &mut &[u8]) -> Result<Vec<u8>, Error> {
        let count: u8 = take(b)?;
        let (bits, rest) = b
            .split_at_checked(usize::from(count))
            .ok_or(Error::Length)?;
        *b = rest;
        Ok(bits.to_vec())
    }
    /// Reads the values `bitfields` name.
    fn read_values(bitfields: &[u8], b: &mut &[u8]) -> Result<Self, Error> {
        let mut fields = Vec::new();
        for (id, size) in Self::ids(bitfields)? {
            let (value, rest) = b.split_at_checked(size).ok_or(Error::Length)?;
            fields.push(Opt::read(id, value)?);
            *b = rest;
        }
        Ok(Self {
            count: u8::try_from(bitfields.len()).map_err(|_| Error::Count)?,
            fields,
            table: PhantomData,
        })
    }
    fn put_bitfields(&self, out: &mut Vec<u8>) {
        out.push(self.count);
        out.extend_from_slice(&self.bitfields());
    }
    fn put_values(&self, out: &mut Vec<u8>) {
        for f in &self.fields {
            f.put(out);
        }
    }
    /// A typed field, by pattern.
    fn find<V>(&self, f: impl Fn(&Opt) -> Option<V>) -> Option<V> {
        self.fields.iter().find_map(f)
    }
    /// The Symbol field.
    pub fn symbol(&self) -> Option<Text<8>> {
        self.find(|o| match o {
            Opt::Symbol(s) => Some(*s),
            _ => None,
        })
    }
    /// The Price field.
    pub fn price(&self) -> Option<Price> {
        self.find(|o| match o {
            Opt::Price(p) => Some(*p),
            _ => None,
        })
    }
    /// The OrderQty field.
    pub fn order_qty(&self) -> Option<u32> {
        self.find(|o| match o {
            Opt::OrderQty(q) => Some(*q),
            _ => None,
        })
    }
    /// The LeavesQty field.
    pub fn leaves_qty(&self) -> Option<u32> {
        self.find(|o| match o {
            Opt::LeavesQty(q) => Some(*q),
            _ => None,
        })
    }
    /// A one-byte code field: Capacity, OrdType, Side, TimeInForce and the
    /// like.
    pub fn code(&self, id: FieldId) -> Option<u8> {
        self.find(|o| match o {
            Opt::Capacity(c)
            | Opt::OrdType(c)
            | Opt::Side(c)
            | Opt::TimeInForce(c)
            | Opt::ExecInst(c)
            | Opt::AttributedQuote(c)
            | Opt::BaseLiquidityIndicator(c)
            | Opt::CancelOrigOnReject(c)
            | Opt::CrossTradeFlag(c)
            | Opt::DisplayIndicator(c)
            | Opt::ExDestination(c)
            | Opt::ExtExecInst(c)
            | Opt::LocateReqd(c)
            | Opt::MatchingUnit(c)
            | Opt::SubLiquidityIndicator(c)
                if o.id() == id =>
            {
                Some(*c)
            }
            _ => None,
        })
    }
}

/// What follows a message's fixed fields.
trait Tail: Sized {
    fn get(b: &[u8]) -> Result<Self, Error>;
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
    fn len(&self) -> usize {
        0
    }
    fn put(&self, _out: &mut Vec<u8>) {}
}
impl<T: Table> Tail for Optional<T> {
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        let bits = Self::read_bitfields(&mut b)?;
        let fields = Self::read_values(&bits, &mut b)?;
        <() as Tail>::get(b)?;
        Ok(fields)
    }
    fn len(&self) -> usize {
        self.wire_len()
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.put_bitfields(out);
        self.put_values(out);
    }
}

/// The tail of a Purge Orders: bitfields, RiskGroupIDs, then the optional
/// fields ("Purge Orders").
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeFields {
    /// The optional fields.
    pub fields: Optional<PurgeOrdersTable>,
    /// RiskGroupIDs to purge; the specification allows at most
    /// [`MAX_RISK_GROUP_IDS`], which [`Exchange`] enforces.
    pub risk_group_ids: Vec<u16>,
}
impl Tail for PurgeFields {
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        let bits = Optional::<PurgeOrdersTable>::read_bitfields(&mut b)?;
        let n: u8 = take(&mut b)?;
        let mut risk_group_ids = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            risk_group_ids.push(take(&mut b)?);
        }
        let fields = Optional::read_values(&bits, &mut b)?;
        <() as Tail>::get(b)?;
        Ok(Self {
            fields,
            risk_group_ids,
        })
    }
    fn len(&self) -> usize {
        self.fields.wire_len() + 1 + 2 * self.risk_group_ids.len()
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.fields.put_bitfields(out);
        // `check` keeps the list within a one-byte count.
        out.push(self.risk_group_ids.len() as u8);
        for id in &self.risk_group_ids {
            id.put(out);
        }
        self.fields.put_values(out);
    }
}

/// A matching unit and a sequence number, as login and logout list them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitSequence {
    /// The unit.
    pub unit: u8,
    /// The sequence number.
    pub sequence: u32,
}
impl Field for UnitSequence {
    const LEN: usize = 5;
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            unit: take(&mut b)?,
            sequence: take(&mut b)?,
        })
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.unit.put(out);
        self.sequence.put(out);
    }
}
fn read_units(b: &mut &[u8]) -> Result<Vec<UnitSequence>, Error> {
    let n: u8 = take(b)?;
    let mut units = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        units.push(take(b)?);
    }
    Ok(units)
}
fn put_units(units: &[UnitSequence], out: &mut Vec<u8>) {
    // Callers check the count fits a byte.
    out.push(units.len() as u8);
    for u in units {
        u.put(out);
    }
}

/// Parameter group type of the Unit Sequences group.
pub const UNIT_SEQUENCES: u8 = 0x80;
/// Parameter group type of the Return Bitfields group.
pub const RETURN_BITFIELDS: u8 = 0x81;

/// One parameter group of a Login Request, echoed in the Login Response
/// ("Login Request Message Fields").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamGroup {
    /// 0x80: the last sequence received per unit.
    UnitSequences {
        /// 1 to suppress replay of units not listed, 0 to replay them.
        no_unspecified_unit_replay: u8,
        /// The units.
        units: Vec<UnitSequence>,
    },
    /// 0x81: the optional fields to return on one message type.
    ReturnBitfields {
        /// The return message type, as 0x25 for Order Acknowledgment.
        message_type: u8,
        /// Bitfields in the [`ReturnTable`] layout.
        bitfields: Vec<u8>,
    },
    /// A group type this module does not define; Cboe may add them.
    Other {
        /// The group type.
        kind: u8,
        /// The bytes after the type.
        data: Vec<u8>,
    },
}
impl ParamGroup {
    fn len(&self) -> usize {
        3 + match self {
            ParamGroup::UnitSequences { units, .. } => 2 + 5 * units.len(),
            ParamGroup::ReturnBitfields { bitfields, .. } => 2 + bitfields.len(),
            ParamGroup::Other { data, .. } => data.len(),
        }
    }
    fn get(b: &mut &[u8]) -> Result<Self, Error> {
        let len = usize::from(take::<u16>(b)?);
        let kind: u8 = take(b)?;
        let data_len = len.checked_sub(3).ok_or(Error::Group(kind))?;
        let (mut data, rest) = b.split_at_checked(data_len).ok_or(Error::Length)?;
        *b = rest;
        let group = match kind {
            UNIT_SEQUENCES => {
                let no_unspecified_unit_replay = take(&mut data)?;
                let units = read_units(&mut data)?;
                ParamGroup::UnitSequences {
                    no_unspecified_unit_replay,
                    units,
                }
            }
            RETURN_BITFIELDS => {
                let message_type = take(&mut data)?;
                let n: u8 = take(&mut data)?;
                let (bits, after) = data
                    .split_at_checked(usize::from(n))
                    .ok_or(Error::Group(kind))?;
                let group = ParamGroup::ReturnBitfields {
                    message_type,
                    bitfields: bits.to_vec(),
                };
                data = after;
                group
            }
            _ => {
                let group = ParamGroup::Other {
                    kind,
                    data: data.to_vec(),
                };
                data = &[];
                group
            }
        };
        if !data.is_empty() {
            return Err(Error::Group(kind));
        }
        Ok(group)
    }
    fn check(&self) -> Result<(), Error> {
        match self {
            ParamGroup::UnitSequences { units, .. } if units.len() > 255 => Err(Error::Count),
            ParamGroup::ReturnBitfields { bitfields, .. } if bitfields.len() > 255 => {
                Err(Error::Count)
            }
            ParamGroup::Other { kind, .. }
                if matches!(*kind, UNIT_SEQUENCES | RETURN_BITFIELDS) =>
            {
                Err(Error::Group(*kind))
            }
            _ if self.len() > usize::from(u16::MAX) => Err(Error::TooLong),
            _ => Ok(()),
        }
    }
    fn put(&self, out: &mut Vec<u8>) {
        // `check` keeps the length within two bytes.
        (self.len() as u16).put(out);
        match self {
            ParamGroup::UnitSequences {
                no_unspecified_unit_replay,
                units,
            } => {
                out.push(UNIT_SEQUENCES);
                out.push(*no_unspecified_unit_replay);
                put_units(units, out);
            }
            ParamGroup::ReturnBitfields {
                message_type,
                bitfields,
            } => {
                out.push(RETURN_BITFIELDS);
                out.push(*message_type);
                out.push(bitfields.len() as u8);
                out.extend_from_slice(bitfields);
            }
            ParamGroup::Other { kind, data } => {
                out.push(*kind);
                out.extend_from_slice(data);
            }
        }
    }
}

/// A count and the parameter groups after it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParamGroups(pub Vec<ParamGroup>);
impl ParamGroups {
    fn read(b: &mut &[u8]) -> Result<Self, Error> {
        let n: u8 = take(b)?;
        let mut groups = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            groups.push(ParamGroup::get(b)?);
        }
        Ok(Self(groups))
    }
    fn check(&self) -> Result<(), Error> {
        if self.0.len() > 255 {
            return Err(Error::Count);
        }
        self.0.iter().try_for_each(ParamGroup::check)
    }
    fn wire_len(&self) -> usize {
        1 + self.0.iter().map(ParamGroup::len).sum::<usize>()
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.0.len() as u8);
        for g in &self.0 {
            g.put(out);
        }
    }
}
impl Tail for ParamGroups {
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        let groups = Self::read(&mut b)?;
        <() as Tail>::get(b)?;
        Ok(groups)
    }
    fn len(&self) -> usize {
        self.wire_len()
    }
    fn put(&self, out: &mut Vec<u8>) {
        self.write(out);
    }
}

/// A count and the unit sequences after it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Units(pub Vec<UnitSequence>);
impl Tail for Units {
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        let units = read_units(&mut b)?;
        <() as Tail>::get(b)?;
        Ok(Self(units))
    }
    fn len(&self) -> usize {
        1 + 5 * self.0.len()
    }
    fn put(&self, out: &mut Vec<u8>) {
        put_units(&self.0, out);
    }
}

/// The tail of a Login Response: every unit's highest sequence, then the
/// echoed parameter groups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitsAndGroups {
    /// The highest sequence available per unit, one pair per unit.
    pub units: Vec<UnitSequence>,
    /// The Login Request's parameter groups, echoed.
    pub groups: ParamGroups,
}
impl Tail for UnitsAndGroups {
    fn get(mut b: &[u8]) -> Result<Self, Error> {
        let units = read_units(&mut b)?;
        let groups = ParamGroups::read(&mut b)?;
        <() as Tail>::get(b)?;
        Ok(Self { units, groups })
    }
    fn len(&self) -> usize {
        1 + 5 * self.units.len() + self.groups.wire_len()
    }
    fn put(&self, out: &mut Vec<u8>) {
        put_units(&self.units, out);
        self.groups.write(out);
    }
}

/// Checks a tail's lists fit their counts.
trait Check {
    fn check(&self) -> Result<(), Error>;
}
impl Check for () {
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
}
impl<T: Table> Check for Optional<T> {
    fn check(&self) -> Result<(), Error> {
        Ok(())
    }
}
impl Check for PurgeFields {
    fn check(&self) -> Result<(), Error> {
        if self.risk_group_ids.len() > 255 {
            Err(Error::Count)
        } else {
            Ok(())
        }
    }
}
impl Check for ParamGroups {
    fn check(&self) -> Result<(), Error> {
        ParamGroups::check(self)
    }
}
impl Check for Units {
    fn check(&self) -> Result<(), Error> {
        if self.0.len() > 255 {
            Err(Error::Count)
        } else {
            Ok(())
        }
    }
}
impl Check for UnitsAndGroups {
    fn check(&self) -> Result<(), Error> {
        if self.units.len() > 255 {
            return Err(Error::Count);
        }
        self.groups.check()
    }
}

/// Checks StartOfMessage and MessageLength, and returns the type and the
/// bytes after it.
fn envelope(b: &[u8]) -> Result<(u8, &[u8]), Error> {
    if b.len() < HEADER_LENGTH {
        return Err(Error::Length);
    }
    if b[..2] != START_OF_MESSAGE {
        return Err(Error::Start);
    }
    let length = usize::from(u16::from_le_bytes([b[2], b[3]]));
    if length + 2 != b.len() {
        return Err(Error::Length);
    }
    Ok((b[4], &b[5..]))
}

macro_rules! prefixed {
    ($item:ty) => {
        impl Prefixed for $item {
            type Item = Result<Self, Error>;
            type Error = Error;
            type Limit = usize;
            const NAME: &'static str = "BOE";
            #[inline]
            fn default_limit() -> usize {
                MAX_MESSAGE
            }
            #[inline]
            fn normalize_limit(limit: usize) -> usize {
                limit.clamp(HEADER_LENGTH, MAX_MESSAGE)
            }
            #[inline]
            fn capacity(limit: &usize) -> usize {
                *limit
            }
            fn parse_prefix(
                input: &[u8],
                limit: &usize,
            ) -> Result<Option<(Self::Item, usize)>, Error> {
                let Some(head) = input.get(..4) else {
                    if input.first().is_some_and(|b| *b != 0xBA) {
                        return Err(Error::Start);
                    }
                    return Ok(None);
                };
                if head[..2] != START_OF_MESSAGE {
                    return Err(Error::Start);
                }
                let length = usize::from(u16::from_le_bytes([head[2], head[3]]));
                if length + 2 < HEADER_LENGTH {
                    return Err(Error::Length);
                }
                let total = length + 2;
                if total > *limit {
                    return Err(Error::TooLong);
                }
                let Some(message) = input.get(..total) else {
                    return Ok(None);
                };
                Ok(Some((Self::parse(message), total)))
            }
        }
    };
}

fn write_head(kind: u8, len: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    let length = u16::try_from(len - 2).map_err(|_| Error::TooLong)?;
    out.reserve(len);
    out.extend_from_slice(&START_OF_MESSAGE);
    length.put(out);
    out.push(kind);
    Ok(())
}

fictionet::stdlib::codec::layout! {
    error = Error; type_error = Error::Type;
    field = Field; take = take; put = Field::put; prefix = 5;
    read = envelope; check = |_, _| Ok(()); write = write_head;
    unknown = |kind, _| Err(Error::Type(kind));
    message = { [#[derive(Clone, Debug, Default, PartialEq, Eq)]]
        /// Bytes before the tail, StartOfMessage included: the
        /// specification's offset of the first variable field.
        const FIXED; pub fn wire_len;
    };
    header = { /// MatchingUnit and SequenceNumber.
        header: Header,
    }; tail = {}; tail_ops = (Tail::get, Check::check, Tail::len, Tail::put);
    items = [prefixed]; access = { /// MatchingUnit and SequenceNumber.
        header(&self) -> header: Header;
        /// MatchingUnit and SequenceNumber, to set.
        header_mut(&mut self) -> header: Header;
    };
    length = { /// The offset of the tail of messages of type `kind`.
        fixed_of
    }; variants = {};
    /// Any Member to Cboe message ("List of Message Types").
    #[derive(Clone, Debug, PartialEq, Eq)]
    Inbound;

    /// 0x37, Login Request: the first message on a connection.
    LoginRequest = 0x37, 28 {
        /// The session sub-identifier supplied by Cboe.
        session_sub_id: Text<4>,
        /// The username supplied by Cboe.
        username: Text<4>,
        /// The password supplied by Cboe.
        password: Text<10>,
    } => /// Unit Sequences and Return Bitfields groups.
    params: ParamGroups;

    /// 0x02, Logout Request.
    LogoutRequest = 0x02, 10 {
    } => /// Nothing.
    end: ();

    /// 0x03, Client Heartbeat.
    ClientHeartbeat = 0x03, 10 {
    } => /// Nothing.
    end: ();

    /// 0x38, New Order.
    NewOrder = 0x38, 35 {
        /// The client's identifier for the order.
        cl_ord_id: ClOrdId,
        /// "1" buy, "2" sell, "5" sell short, "6" sell short exempt.
        side: u8,
        /// Shares, at most [`MAX_ORDER_QTY`].
        order_qty: u32,
    } => /// Optional fields: Symbol and Capacity are required.
    fields: Optional<NewOrderTable>;

    /// 0x39, Cancel Order.
    CancelOrder = 0x39, 30 {
        /// The ClOrdID of the order to cancel.
        orig_cl_ord_id: ClOrdId,
    } => /// Optional fields.
    fields: Optional<CancelOrderTable>;

    /// 0x3A, Modify Order.
    ModifyOrder = 0x3A, 50 {
        /// The order's new ClOrdID.
        cl_ord_id: ClOrdId,
        /// The ClOrdID of the order to modify.
        orig_cl_ord_id: ClOrdId,
    } => /// Optional fields: OrderQty and Price are required.
    fields: Optional<ModifyOrderTable>;

    /// 0x47, Purge Orders (purge ports only).
    PurgeOrders = 0x47, 11 {
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Bitfields, RiskGroupIDs and optional fields.
    purge: PurgeFields;
}

fictionet::stdlib::codec::layout! {
    error = Error; type_error = Error::Type;
    field = Field; take = take; put = Field::put; prefix = 5;
    read = envelope; check = |_, _| Ok(()); write = write_head;
    unknown = |kind, _| Err(Error::Type(kind));
    message = { [#[derive(Clone, Debug, Default, PartialEq, Eq)]]
        /// Bytes before the tail, StartOfMessage included: the
        /// specification's offset of the first variable field.
        const FIXED; pub fn wire_len;
    };
    header = { /// MatchingUnit and SequenceNumber.
        header: Header,
    }; tail = {}; tail_ops = (Tail::get, Check::check, Tail::len, Tail::put);
    items = [prefixed]; access = { /// MatchingUnit and SequenceNumber.
        header(&self) -> header: Header;
        /// MatchingUnit and SequenceNumber, to set.
        header_mut(&mut self) -> header: Header;
    };
    length = { /// The offset of the tail of messages of type `kind`.
        fixed_of
    }; variants = {};
    /// Any Cboe to Member message ("List of Message Types").
    #[derive(Clone, Debug, PartialEq, Eq)]
    Outbound;

    /// 0x24, Login Response.
    LoginResponse = 0x24, 76 {
        /// See [`codes::login_status`].
        status: u8,
        /// Why a login was refused.
        text: ReasonText,
        /// Echoed from the Login Request.
        no_unspecified_unit_replay: u8,
        /// The last inbound sequence number Cboe processed.
        last_received_sequence: u32,
    } => /// Units and echoed parameter groups.
    tail: UnitsAndGroups;

    /// 0x08, Logout.
    Logout = 0x08, 75 {
        /// See [`codes::logout_reason`].
        reason: u8,
        /// More about the reason.
        text: ReasonText,
        /// The last inbound sequence number Cboe processed.
        last_received_sequence: u32,
    } => /// The last sequence sent per unit.
    units: Units;

    /// 0x09, Server Heartbeat.
    ServerHeartbeat = 0x09, 10 {
    } => /// Nothing.
    end: ();

    /// 0x13, Replay Complete.
    ReplayComplete = 0x13, 10 {
    } => /// Nothing.
    end: ();

    /// 0x25, Order Acknowledgment (sequenced).
    OrderAcknowledgment = 0x25, 47 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// Cboe's order identifier, as on PITCH.
        order_id: u64,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x26, Order Rejected (unsequenced).
    OrderRejected = 0x26, 100 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// See [`codes::reason`].
        reason: u8,
        /// More about the reason.
        text: ReasonText,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x27, Order Modified (sequenced).
    OrderModified = 0x27, 47 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The Modify Order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// Cboe's order identifier, unchanged by modifies.
        order_id: u64,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x28, Order Restated (sequenced).
    OrderRestated = 0x28, 48 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// Cboe's order identifier.
        order_id: u64,
        /// See [`codes::restatement_reason`].
        restatement_reason: u8,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x29, User Modify Rejected (unsequenced).
    UserModifyRejected = 0x29, 100 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The Modify Order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// See [`codes::reason`].
        reason: u8,
        /// More about the reason.
        text: ReasonText,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x2A, Order Cancelled (sequenced).
    OrderCancelled = 0x2A, 40 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// See [`codes::reason`].
        reason: u8,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x2B, Cancel Rejected (unsequenced).
    CancelRejected = 0x2B, 100 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// See [`codes::reason`].
        reason: u8,
        /// More about the reason.
        text: ReasonText,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x2C, Order Execution (sequenced).
    OrderExecution = 0x2C, 69 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// The execution identifier, unique across units for the day.
        exec_id: u64,
        /// Shares executed.
        last_shares: u32,
        /// The fill price.
        last_px: Price,
        /// Shares still open; 0 means done.
        leaves_qty: u32,
        /// "A", "C", "R", "W" or "X".
        base_liquidity_indicator: u8,
        /// See the specification; NUL for none.
        sub_liquidity_indicator: u8,
        /// The away venue of a routed fill.
        contra_broker: Text<4>,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x2D, Trade Cancel or Correct (sequenced).
    TradeCancelOrCorrect = 0x2D, 93 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// The order's ClOrdID.
        cl_ord_id: ClOrdId,
        /// Cboe's order identifier.
        order_id: u64,
        /// The ExecID of the fill.
        exec_ref_id: u64,
        /// The order's side.
        side: u8,
        /// The fill's liquidity indicator.
        base_liquidity_indicator: u8,
        /// Echoed from the order.
        clearing_firm: Text<4>,
        /// Echoed from the order.
        clearing_account: Text<4>,
        /// Shares of the trade.
        last_shares: u32,
        /// The trade's price.
        last_px: Price,
        /// The corrected price, or 0 for a cancel.
        corrected_price: Price,
        /// When the trade happened, nanoseconds since the Unix epoch.
        orig_time: u64,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;

    /// 0x36, Mass Cancel Acknowledgment (unsequenced, purge ports).
    MassCancelAcknowledgment = 0x36, 43 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// From the Purge Orders.
        mass_cancel_id: Text<20>,
        /// Orders canceled.
        cancelled_order_count: u32,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Nothing.
    end: ();

    /// 0x48, Purge Rejected (unsequenced, purge ports).
    PurgeRejected = 0x48, 80 {
        /// Nanoseconds since the Unix epoch, UTC.
        transaction_time: u64,
        /// See [`codes::reason`].
        reason: u8,
        /// More about the reason.
        text: ReasonText,
        /// Reserved for Cboe.
        reserved_internal: u8,
    } => /// Return fields.
    fields: Optional<ReturnTable>;
}

impl Inbound {
    /// Whether this is an application message, which carries the member's
    /// sequence number.
    pub fn is_application(&self) -> bool {
        matches!(
            self,
            Inbound::NewOrder(_)
                | Inbound::CancelOrder(_)
                | Inbound::ModifyOrder(_)
                | Inbound::PurgeOrders(_)
        )
    }
}
impl Outbound {
    /// Whether messages of type `kind` are sequenced per matching unit.
    pub fn is_sequenced_kind(kind: u8) -> bool {
        matches!(kind, 0x25 | 0x27 | 0x28 | 0x2A | 0x2C | 0x2D)
    }
    /// Whether this message is sequenced per matching unit.
    pub fn is_sequenced(&self) -> bool {
        Self::is_sequenced_kind(self.kind())
    }
    /// Whether this is a session message (login, logout, heartbeat,
    /// replay complete).
    pub fn is_session(&self) -> bool {
        matches!(
            self,
            Outbound::LoginResponse(_)
                | Outbound::Logout(_)
                | Outbound::ServerHeartbeat(_)
                | Outbound::ReplayComplete(_)
        )
    }
    /// Whether messages of type `kind` may carry return fields, and so
    /// may be named in a Return Bitfields group.
    pub fn has_return_fields(kind: u8) -> bool {
        matches!(kind, 0x25..=0x2D | 0x48)
    }
}

/// The values the specification lists for one-byte code fields.
pub mod codes {
    /// LoginResponseStatus values.
    pub mod login_status {
        /// Login accepted.
        pub const ACCEPTED: u8 = b'A';
        /// Not authorized.
        pub const NOT_AUTHORIZED: u8 = b'N';
        /// Session disabled.
        pub const DISABLED: u8 = b'D';
        /// Session in use.
        pub const IN_USE: u8 = b'B';
        /// Invalid session.
        pub const INVALID_SESSION: u8 = b'S';
        /// A unit sequence ahead of what Cboe sent.
        pub const SEQUENCE_AHEAD: u8 = b'Q';
        /// An invalid unit.
        pub const INVALID_UNIT: u8 = b'I';
        /// An invalid return bitfield.
        pub const INVALID_RETURN_BITFIELD: u8 = b'F';
        /// An invalid Login Request structure.
        pub const INVALID_MESSAGE: u8 = b'M';
    }
    /// LogoutReason values.
    pub mod logout_reason {
        /// User requested.
        pub const USER: u8 = b'U';
        /// End of day.
        pub const END_OF_DAY: u8 = b'E';
        /// Administrative.
        pub const ADMINISTRATIVE: u8 = b'A';
        /// Protocol violation.
        pub const PROTOCOL_VIOLATION: u8 = b'!';
    }
    /// RestatementReason values.
    pub mod restatement_reason {
        /// Cboe Market Close.
        pub const MARKET_CLOSE: u8 = b'C';
        /// Reload.
        pub const RELOAD: u8 = b'L';
        /// Peg or price sliding reprice.
        pub const REPRICE: u8 = b'P';
        /// Liquidity updated.
        pub const LIQUIDITY_UPDATED: u8 = b'Q';
        /// Reroute.
        pub const REROUTE: u8 = b'R';
        /// OrderQty reduced for SWP.
        pub const SWP: u8 = b'S';
        /// Wash or MTP decrement.
        pub const WASH: u8 = b'W';
    }
    /// Reason codes ("Reason Codes"), shared by rejects and cancels.
    pub mod reason {
        /// Admin.
        pub const ADMIN: u8 = b'A';
        /// Capacity undefined.
        pub const CAPACITY_UNDEFINED: u8 = b'C';
        /// Duplicate identifier.
        pub const DUPLICATE: u8 = b'D';
        /// Halted.
        pub const HALTED: u8 = b'H';
        /// Too late to cancel.
        pub const TOO_LATE: u8 = b'J';
        /// Order size exceeded.
        pub const SIZE_EXCEEDED: u8 = b'M';
        /// Ran out of liquidity.
        pub const NO_LIQUIDITY: u8 = b'N';
        /// ClOrdID does not match a known order.
        pub const UNKNOWN_ORDER: u8 = b'O';
        /// Can't modify an order that is pending fill.
        pub const PENDING_FILL: u8 = b'P';
        /// User requested.
        pub const USER_REQUESTED: u8 = b'U';
        /// Order expired.
        pub const EXPIRED: u8 = b'X';
        /// Symbol not supported.
        pub const UNKNOWN_SYMBOL: u8 = b'Y';
        /// Unforeseen reason.
        pub const UNFORESEEN: u8 = b'Z';
        /// Max open orders count exceeded.
        pub const MAX_OPEN_ORDERS: u8 = b'o';
        /// Order received by Cboe during replay.
        pub const DURING_REPLAY: u8 = b'y';
    }
}

/// The timers a session runs on. [`Timers::default`] is the
/// specification's: a heartbeat after a second of sending nothing, and a
/// five-second receive timeout ("Heartbeats"); the login timeout is this
/// module's choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timers {
    /// Sending silence after which a heartbeat goes out.
    pub heartbeat_ms: u64,
    /// Receiving silence, once logged in, after which the session ends.
    pub idle_timeout_ms: u64,
    /// Time from creation or [`Client::start`] to a Login Response.
    pub login_timeout_ms: u64,
}
impl Default for Timers {
    fn default() -> Self {
        Self {
            heartbeat_ms: HEARTBEAT_INTERVAL_MS,
            idle_timeout_ms: IDLE_TIMEOUT_MS,
            login_timeout_ms: LOGIN_TIMEOUT_MS,
        }
    }
}
impl Timers {
    fn validate(&self) -> Result<(), Error> {
        let ok = |ms: u64| (1..=MAX_TIMER_MS).contains(&ms);
        if ok(self.heartbeat_ms) && ok(self.idle_timeout_ms) && ok(self.login_timeout_ms) {
            Ok(())
        } else {
            Err(Error::Config)
        }
    }
}

/// The time of the last message each way, and the monotonic time guard.
#[derive(Clone, Copy, Debug)]
struct Clock {
    timers: Timers,
    now: u64,
    since: u64,
    received: u64,
    sent: u64,
}
impl Clock {
    fn new(timers: Timers, now: u64) -> Result<Self, Error> {
        timers.validate()?;
        Ok(Self {
            timers,
            now,
            since: now,
            received: now,
            sent: now,
        })
    }
    fn advance(&mut self, now: u64) -> Result<(), Error> {
        if now < self.now {
            return Err(Error::Time);
        }
        self.now = now;
        Ok(())
    }
    fn heartbeat_due(&self) -> bool {
        self.now.saturating_sub(self.sent) >= self.timers.heartbeat_ms
    }
    fn idle(&self) -> bool {
        self.now.saturating_sub(self.received) >= self.timers.idle_timeout_ms
    }
    fn login_expired(&self) -> bool {
        self.now.saturating_sub(self.since) >= self.timers.login_timeout_ms
    }
}

/// Why a session ended. The caller closes the connection after writing
/// any messages that came before this event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// A Logout was sent or received.
    Logout,
    /// The login was refused.
    Rejected,
    /// Login did not complete within [`Timers::login_timeout_ms`].
    LoginTimeout,
    /// Nothing arrived within [`Timers::idle_timeout_ms`].
    IdleTimeout,
    /// The peer sent a message that does not parse, or one its role or
    /// the session's state does not allow.
    Protocol,
}

/// What a session reports to its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Client: the login was accepted. Replay follows.
    LoggedIn {
        /// The last of this member's sequence numbers Cboe processed;
        /// the client numbers from the next.
        last_received_sequence: u32,
        /// The highest sequence Cboe has per unit.
        units: Vec<UnitSequence>,
    },
    /// Client: the login was refused. `Disconnected` follows.
    Rejected {
        /// The LoginResponseStatus.
        status: u8,
        /// The text.
        text: ReasonText,
    },
    /// Client: replay is over; orders may be sent.
    ReplayComplete,
    /// Client: the message passed in is the next on its unit.
    Sequenced(UnitSequence),
    /// Client: the message passed in was already received; ignore it.
    Duplicate(UnitSequence),
    /// Client: the message passed in skips sequence numbers on its unit.
    Gap {
        /// The unit.
        unit: u8,
        /// The sequence expected.
        expected: u32,
        /// The sequence received.
        received: u32,
    },
    /// Client: the message passed in is unsequenced.
    Unsequenced,
    /// Client: Cboe logged the session out. `Disconnected` follows.
    LoggedOut {
        /// The LogoutReason.
        reason: u8,
        /// The text.
        text: ReasonText,
    },
    /// Server: a member asks to log in. Answer with [`Server::accept`] or
    /// [`Server::reject`].
    LoginRequested(LoginRequest),
    /// Server: replay `unit` from `after + 1` through `through` with
    /// [`Server::replay`], then call [`Server::replay_complete`].
    Replay {
        /// The unit.
        unit: u8,
        /// The member's last received sequence.
        after: u32,
        /// The highest sequence sent.
        through: u32,
    },
    /// Server: the application message passed in is for the order side.
    Application,
    /// The session is over; close the connection.
    Disconnected(CloseReason),
}

/// Where a [`Client`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientPhase {
    /// Created; [`Client::start`] sends the Login Request.
    Connected,
    /// Login Request sent.
    LoginSent,
    /// Logged in; Cboe is replaying missed messages.
    Replaying,
    /// Logged in and replay complete; orders flow.
    LoggedIn,
    /// Logout Request sent; waiting for Cboe's Logout.
    LoggingOut,
    /// The session is over.
    Closed,
}

/// How a [`Client`] logs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    /// The session sub-identifier supplied by Cboe.
    pub session_sub_id: Text<4>,
    /// The username supplied by Cboe.
    pub username: Text<4>,
    /// The password supplied by Cboe.
    pub password: Text<10>,
    /// Ask Cboe not to replay units the login does not name.
    pub no_unspecified_unit_replay: bool,
    /// Return bitfields per return message type, sent as Return Bitfields
    /// groups.
    pub returns: Vec<(u8, Vec<u8>)>,
    /// The timers.
    pub timers: Timers,
}

/// The member side of one BOE connection, without I/O.
///
/// Pass every message read to [`receive`](Self::receive), call
/// [`tick`](Self::tick) at least every few hundred milliseconds, and write
/// every [`Action::Send`] message in order. Messages returned directly
/// ([`send`](Self::send)) must be written too. Times are milliseconds from
/// a monotonic clock. An `Err` leaves the client unchanged.
///
/// The client numbers its application messages from one past the Login
/// Response's LastReceivedSequenceNumber, and tracks the last sequence
/// received per unit. Persist [`last_received`](Self::last_received) to
/// log in again after a broken connection.
#[derive(Clone, Debug)]
pub struct Client {
    config: ClientConfig,
    phase: ClientPhase,
    clock: Clock,
    last: BTreeMap<u8, u32>,
    next: u32,
}
impl Client {
    /// A client that will log in having received through `last_received`
    /// on each unit. Refuses timers out of range and more than 255 units
    /// or return groups.
    pub fn new(
        config: ClientConfig,
        last_received: &[UnitSequence],
        now_ms: u64,
    ) -> Result<Self, Error> {
        if last_received.len() > 255 || config.returns.len() > 254 {
            return Err(Error::Count);
        }
        let clock = Clock::new(config.timers, now_ms)?;
        Ok(Self {
            config,
            phase: ClientPhase::Connected,
            clock,
            last: last_received.iter().map(|u| (u.unit, u.sequence)).collect(),
            next: 1,
        })
    }
    /// Where the session is.
    pub fn phase(&self) -> ClientPhase {
        self.phase
    }
    /// The last sequence received per unit.
    pub fn last_received(&self) -> Vec<UnitSequence> {
        self.last
            .iter()
            .map(|(&unit, &sequence)| UnitSequence { unit, sequence })
            .collect()
    }
    /// The sequence number the next application message carries.
    pub fn next_sequence(&self) -> u32 {
        self.next
    }
    /// Sends the Login Request.
    pub fn start(&mut self, now_ms: u64) -> Result<Vec<Action<Inbound, Event>>, Error> {
        if self.phase != ClientPhase::Connected {
            return Err(Error::State);
        }
        let mut groups = Vec::new();
        if !self.last.is_empty() || self.config.no_unspecified_unit_replay {
            groups.push(ParamGroup::UnitSequences {
                no_unspecified_unit_replay: u8::from(self.config.no_unspecified_unit_replay),
                units: self.last_received(),
            });
        }
        for (message_type, bitfields) in &self.config.returns {
            groups.push(ParamGroup::ReturnBitfields {
                message_type: *message_type,
                bitfields: bitfields.clone(),
            });
        }
        let login = LoginRequest {
            header: Header::default(),
            session_sub_id: self.config.session_sub_id,
            username: self.config.username,
            password: self.config.password,
            params: ParamGroups(groups),
        };
        Check::check(&login.params)?;
        self.clock.advance(now_ms)?;
        self.phase = ClientPhase::LoginSent;
        self.clock.since = now_ms;
        self.clock.sent = now_ms;
        Ok(vec![Action::Send(login.into())])
    }
    /// Handles one message from Cboe. A message out of turn closes the
    /// session with [`CloseReason::Protocol`]. Refuses a closed session.
    pub fn receive(
        &mut self,
        message: &Outbound,
        now_ms: u64,
    ) -> Result<Vec<Action<Inbound, Event>>, Error> {
        // Both refusals come before any change, so nothing is staged: a
        // copy of the client (its configuration and unit map) per message
        // would cost more than the message.
        if self.phase == ClientPhase::Closed {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        Ok(self.receive_inner(message))
    }
    /// [`receive`](Self::receive) for a [`codec::Frames`](fictionet::stdlib::codec::Frames) item. A message that did
    /// not parse closes the session with [`CloseReason::Protocol`].
    pub fn receive_frame(
        &mut self,
        frame: &Result<Outbound, Error>,
        now_ms: u64,
    ) -> Result<Vec<Action<Inbound, Event>>, Error> {
        match frame {
            Ok(m) => self.receive(m, now_ms),
            Err(_) => {
                if self.phase == ClientPhase::Closed {
                    return Err(Error::State);
                }
                self.clock.advance(now_ms)?;
                Ok(self.close(CloseReason::Protocol))
            }
        }
    }
    fn receive_inner(&mut self, message: &Outbound) -> Vec<Action<Inbound, Event>> {
        use ClientPhase as S;
        self.clock.received = self.clock.now;
        let in_session = matches!(self.phase, S::Replaying | S::LoggedIn | S::LoggingOut);
        match (self.phase, message) {
            (S::LoginSent, Outbound::LoginResponse(r))
                if r.status == codes::login_status::ACCEPTED =>
            {
                let Some(next) = r.last_received_sequence.checked_add(1) else {
                    return self.close(CloseReason::Protocol);
                };
                self.next = next;
                self.phase = S::Replaying;
                self.clock.sent = self.clock.now;
                vec![Action::Event(Event::LoggedIn {
                    last_received_sequence: r.last_received_sequence,
                    units: r.tail.units.clone(),
                })]
            }
            (S::LoginSent, Outbound::LoginResponse(r)) => {
                let mut actions = vec![Action::Event(Event::Rejected {
                    status: r.status,
                    text: r.text,
                })];
                actions.extend(self.close(CloseReason::Rejected));
                actions
            }
            (S::Replaying, Outbound::ReplayComplete(_)) => {
                self.phase = S::LoggedIn;
                vec![Action::Event(Event::ReplayComplete)]
            }
            (_, Outbound::ServerHeartbeat(_)) if in_session => Vec::new(),
            (_, Outbound::Logout(l)) if in_session => {
                let mut actions = vec![Action::Event(Event::LoggedOut {
                    reason: l.reason,
                    text: l.text,
                })];
                actions.extend(self.close(CloseReason::Logout));
                actions
            }
            (_, m) if in_session && !m.is_session() => {
                if !m.is_sequenced() {
                    return vec![Action::Event(Event::Unsequenced)];
                }
                let Header { unit, sequence } = *m.header();
                if unit == 0 || sequence == 0 {
                    return self.close(CloseReason::Protocol);
                }
                let last = self.last.get(&unit).copied().unwrap_or(0);
                if sequence <= last {
                    return vec![Action::Event(Event::Duplicate(UnitSequence {
                        unit,
                        sequence,
                    }))];
                }
                self.last.insert(unit, sequence);
                let expected = last.saturating_add(1);
                vec![Action::Event(if sequence == expected {
                    Event::Sequenced(UnitSequence { unit, sequence })
                } else {
                    Event::Gap {
                        unit,
                        expected,
                        received: sequence,
                    }
                })]
            }
            _ => self.close(CloseReason::Protocol),
        }
    }
    /// Numbers an application message (New Order, Cancel Order, Modify
    /// Order, Purge Orders) and returns it to write. Only once logged in
    /// and replay is complete: Cboe rejects orders during replay.
    pub fn send(&mut self, mut message: Inbound, now_ms: u64) -> Result<Inbound, Error> {
        if !message.is_application() || self.phase != ClientPhase::LoggedIn {
            return Err(Error::State);
        }
        let sequence = self.next;
        let next = sequence.checked_add(1).ok_or(Error::Sequence)?;
        self.clock.advance(now_ms)?;
        *message.header_mut() = Header { unit: 0, sequence };
        self.next = next;
        self.clock.sent = now_ms;
        Ok(message)
    }
    /// Sends a Logout Request. Cboe answers with a Logout and closes.
    pub fn logout(&mut self, now_ms: u64) -> Result<Vec<Action<Inbound, Event>>, Error> {
        if !matches!(self.phase, ClientPhase::Replaying | ClientPhase::LoggedIn) {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.phase = ClientPhase::LoggingOut;
        self.clock.sent = now_ms;
        Ok(vec![Action::Send(LogoutRequest::default().into())])
    }
    /// Runs the timers: the login timeout, the idle timeout, and a Client
    /// Heartbeat after [`Timers::heartbeat_ms`] of sending nothing.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<Action<Inbound, Event>>, Error> {
        use ClientPhase as S;
        self.clock.advance(now_ms)?;
        Ok(match self.phase {
            S::Connected | S::Closed => Vec::new(),
            S::LoginSent if self.clock.login_expired() => self.close(CloseReason::LoginTimeout),
            S::LoginSent => Vec::new(),
            _ if self.clock.idle() => self.close(CloseReason::IdleTimeout),
            _ if self.clock.heartbeat_due() => {
                self.clock.sent = now_ms;
                vec![Action::Send(ClientHeartbeat::default().into())]
            }
            _ => Vec::new(),
        })
    }
    fn close(&mut self, reason: CloseReason) -> Vec<Action<Inbound, Event>> {
        self.phase = ClientPhase::Closed;
        vec![Action::Event(Event::Disconnected(reason))]
    }
}

/// Where a [`Server`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerPhase {
    /// Waiting for the Login Request.
    AwaitingLogin,
    /// A Login Request arrived; the caller must accept or reject it.
    LoginPending,
    /// Logged in; the caller is replaying missed messages.
    Replaying,
    /// Logged in; orders flow.
    LoggedIn,
    /// The session is over.
    Closed,
}

/// The exchange side of one BOE connection, without I/O.
///
/// On [`Event::LoginRequested`] the caller checks the credentials and
/// calls [`accept`](Self::accept) with the highest sequence it has sent
/// per unit, or [`reject`](Self::reject). The server checks the request's
/// units and return bitfields, answers, and asks for a replay of each unit
/// the member is behind on ([`Event::Replay`]); the caller owns the store
/// of sent messages. Application messages during replay are rejected with
/// reason "y"; afterwards each is reported as [`Event::Application`] for
/// the order side ([`Exchange`]). [`send`](Self::send) numbers sequenced
/// messages per unit.
///
/// Inbound sequence numbers may skip forward or be 0, but one not above
/// the last is a protocol violation: the server sends a Logout with
/// reason "!" and closes. Driving rules are those of [`Client`].
#[derive(Clone, Debug)]
pub struct Server {
    phase: ServerPhase,
    clock: Clock,
    request: Option<LoginRequest>,
    returns: BTreeMap<u8, Vec<u8>>,
    last_inbound: u32,
    sent: BTreeMap<u8, u32>,
}
impl Server {
    /// A server for a connection accepted at `now_ms`.
    pub fn new(timers: Timers, now_ms: u64) -> Result<Self, Error> {
        Ok(Self {
            phase: ServerPhase::AwaitingLogin,
            clock: Clock::new(timers, now_ms)?,
            request: None,
            returns: BTreeMap::new(),
            last_inbound: 0,
            sent: BTreeMap::new(),
        })
    }
    /// Where the session is.
    pub fn phase(&self) -> ServerPhase {
        self.phase
    }
    /// The return bitfields the login asked for, per message type.
    pub fn returns(&self) -> &BTreeMap<u8, Vec<u8>> {
        &self.returns
    }
    /// The last inbound sequence number processed. Persist it.
    pub fn last_inbound(&self) -> u32 {
        self.last_inbound
    }
    /// The last sequence sent per unit. Persist it.
    pub fn sent(&self) -> Vec<UnitSequence> {
        self.sent
            .iter()
            .map(|(&unit, &sequence)| UnitSequence { unit, sequence })
            .collect()
    }
    /// Handles one message from the member. Refuses a closed session.
    pub fn receive(
        &mut self,
        message: &Inbound,
        now_ms: u64,
    ) -> Result<Vec<Action<Outbound, Event>>, Error> {
        use ServerPhase as S;
        if self.phase == S::Closed {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.received = now_ms;
        Ok(match (self.phase, message) {
            (S::AwaitingLogin, Inbound::LoginRequest(login)) => {
                self.phase = S::LoginPending;
                self.request = Some(login.clone());
                vec![Action::Event(Event::LoginRequested(login.clone()))]
            }
            (S::AwaitingLogin | S::LoginPending, _) => self.close(CloseReason::Protocol),
            (_, Inbound::ClientHeartbeat(_)) => Vec::new(),
            (_, Inbound::LogoutRequest(_)) => {
                self.logout_now(codes::logout_reason::USER, "User", CloseReason::Logout)
            }
            (_, Inbound::LoginRequest(_)) => self.violation("Login while logged in"),
            (state, m) => {
                let Header { unit, sequence } = *m.header();
                if unit != 0 {
                    return Ok(self.violation("Unit must be 0"));
                }
                if sequence != 0 {
                    if sequence <= self.last_inbound {
                        return Ok(self.violation("Sequence went backwards"));
                    }
                    self.last_inbound = sequence;
                }
                if state == S::Replaying {
                    let reject = self.during_replay(m);
                    self.clock.sent = now_ms;
                    vec![Action::Send(reject)]
                } else {
                    vec![Action::Event(Event::Application)]
                }
            }
        })
    }
    /// [`receive`](Self::receive) for a [`codec::Frames`](fictionet::stdlib::codec::Frames) item. A message that did
    /// not parse is a protocol violation.
    pub fn receive_frame(
        &mut self,
        frame: &Result<Inbound, Error>,
        now_ms: u64,
    ) -> Result<Vec<Action<Outbound, Event>>, Error> {
        match frame {
            Ok(m) => self.receive(m, now_ms),
            Err(_) => {
                if self.phase == ServerPhase::Closed {
                    return Err(Error::State);
                }
                self.clock.advance(now_ms)?;
                Ok(match self.phase {
                    ServerPhase::AwaitingLogin | ServerPhase::LoginPending => {
                        self.close(CloseReason::Protocol)
                    }
                    _ => self.violation("Invalid message"),
                })
            }
        }
    }
    fn during_replay(&self, m: &Inbound) -> Outbound {
        let reason = codes::reason::DURING_REPLAY;
        let text = Text::new("Order received during replay").unwrap_or_default();
        let time = 0;
        match m {
            Inbound::CancelOrder(c) => CancelRejected {
                header: Header::default(),
                transaction_time: time,
                cl_ord_id: c.orig_cl_ord_id,
                reason,
                text,
                reserved_internal: 0,
                fields: self.zero_returns(CancelRejected::KIND),
            }
            .into(),
            Inbound::ModifyOrder(c) => UserModifyRejected {
                header: Header::default(),
                transaction_time: time,
                cl_ord_id: c.cl_ord_id,
                reason,
                text,
                reserved_internal: 0,
                fields: self.zero_returns(UserModifyRejected::KIND),
            }
            .into(),
            Inbound::PurgeOrders(_) => PurgeRejected {
                header: Header::default(),
                transaction_time: time,
                reason,
                text,
                reserved_internal: 0,
                fields: self.zero_returns(PurgeRejected::KIND),
            }
            .into(),
            other => OrderRejected {
                header: Header::default(),
                transaction_time: time,
                cl_ord_id: match other {
                    Inbound::NewOrder(n) => n.cl_ord_id,
                    _ => ClOrdId::default(),
                },
                reason,
                text,
                reserved_internal: 0,
                fields: self.zero_returns(OrderRejected::KIND),
            }
            .into(),
        }
    }
    fn zero_returns(&self, kind: u8) -> Optional<ReturnTable> {
        self.returns
            .get(&kind)
            .and_then(|bits| Optional::requested(bits).ok())
            .unwrap_or_default()
    }
    /// Accepts the pending login. `last_inbound` is the last of the
    /// member's sequence numbers processed (0 at the start of the day);
    /// `available` is the highest sequence sent on every unit. A request
    /// naming a unit not in `available` with a nonzero sequence, a
    /// sequence ahead of it, or a return bitfield this module cannot fill
    /// is refused with status "I", "Q" or "F" instead.
    pub fn accept(
        &mut self,
        last_inbound: u32,
        available: &[UnitSequence],
        now_ms: u64,
    ) -> Result<Vec<Action<Outbound, Event>>, Error> {
        if self.phase != ServerPhase::LoginPending {
            return Err(Error::State);
        }
        if available.len() > 255 {
            return Err(Error::Count);
        }
        let Some(request) = self.request.clone() else {
            return Err(Error::State);
        };
        self.clock.advance(now_ms)?;
        let highest: BTreeMap<u8, u32> = available.iter().map(|u| (u.unit, u.sequence)).collect();
        let mut no_unspecified = 0;
        let mut asked = BTreeMap::new();
        let mut returns = BTreeMap::new();
        for group in &request.params.0 {
            match group {
                ParamGroup::UnitSequences {
                    no_unspecified_unit_replay,
                    units,
                } => {
                    no_unspecified = *no_unspecified_unit_replay;
                    for u in units {
                        match highest.get(&u.unit) {
                            None if u.sequence != 0 => {
                                return Ok(
                                    self.refuse(codes::login_status::INVALID_UNIT, "Invalid unit")
                                );
                            }
                            Some(h) if u.sequence > *h => {
                                return Ok(self.refuse(
                                    codes::login_status::SEQUENCE_AHEAD,
                                    "Sequence ahead",
                                ));
                            }
                            _ => {
                                asked.insert(u.unit, u.sequence);
                            }
                        }
                    }
                }
                ParamGroup::ReturnBitfields {
                    message_type,
                    bitfields,
                } => {
                    if !Outbound::has_return_fields(*message_type)
                        || Optional::<ReturnTable>::requested(bitfields).is_err()
                    {
                        return Ok(self.refuse(
                            codes::login_status::INVALID_RETURN_BITFIELD,
                            "Invalid return bitfield",
                        ));
                    }
                    returns.insert(*message_type, bitfields.clone());
                }
                ParamGroup::Other { .. } => {}
            }
        }
        let response = LoginResponse {
            header: Header::default(),
            status: codes::login_status::ACCEPTED,
            text: Text::new("Accepted").unwrap_or_default(),
            no_unspecified_unit_replay: no_unspecified,
            last_received_sequence: last_inbound,
            tail: UnitsAndGroups {
                units: available.to_vec(),
                groups: request.params.clone(),
            },
        };
        let mut actions = vec![Action::Send(response.into())];
        for (&unit, &through) in &highest {
            let after = match asked.get(&unit) {
                Some(s) => *s,
                None if no_unspecified != 0 => continue,
                None => 0,
            };
            if after < through {
                actions.push(Action::Event(Event::Replay {
                    unit,
                    after,
                    through,
                }));
            }
        }
        self.returns = returns;
        self.last_inbound = last_inbound;
        self.sent = highest;
        self.clock.sent = now_ms;
        self.clock.received = now_ms;
        if actions.len() == 1 {
            actions.push(Action::Send(ReplayComplete::default().into()));
            self.phase = ServerPhase::LoggedIn;
        } else {
            self.phase = ServerPhase::Replaying;
        }
        Ok(actions)
    }
    /// Refuses the pending login with a status other than "A", and closes.
    pub fn reject(
        &mut self,
        status: u8,
        text: &str,
        now_ms: u64,
    ) -> Result<Vec<Action<Outbound, Event>>, Error> {
        if self.phase != ServerPhase::LoginPending || status == codes::login_status::ACCEPTED {
            return Err(Error::State);
        }
        Text::<60>::new(text)?;
        self.clock.advance(now_ms)?;
        Ok(self.refuse(status, text))
    }
    fn refuse(&mut self, status: u8, text: &str) -> Vec<Action<Outbound, Event>> {
        let request = self.request.take().unwrap_or_default();
        let no_unspecified = request
            .params
            .0
            .iter()
            .find_map(|g| match g {
                ParamGroup::UnitSequences {
                    no_unspecified_unit_replay,
                    ..
                } => Some(*no_unspecified_unit_replay),
                _ => None,
            })
            .unwrap_or(0);
        let response = LoginResponse {
            header: Header::default(),
            status,
            text: Text::new(text).unwrap_or_default(),
            no_unspecified_unit_replay: no_unspecified,
            last_received_sequence: 0,
            tail: UnitsAndGroups {
                units: Vec::new(),
                groups: request.params,
            },
        };
        self.clock.sent = self.clock.now;
        let mut actions = vec![Action::Send(response.into())];
        actions.extend(self.close(CloseReason::Rejected));
        actions
    }
    /// Passes a stored sequenced message through during replay. Refuses a
    /// message that is not sequenced, or whose unit and sequence were
    /// never sent.
    pub fn replay(&mut self, message: &Outbound, now_ms: u64) -> Result<Outbound, Error> {
        if self.phase != ServerPhase::Replaying {
            return Err(Error::State);
        }
        let Header { unit, sequence } = *message.header();
        let sent = self.sent.get(&unit).copied().unwrap_or(0);
        if !message.is_sequenced() || unit == 0 || sequence == 0 || sequence > sent {
            return Err(Error::Sequence);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        Ok(message.clone())
    }
    /// Ends the replay with Replay Complete.
    pub fn replay_complete(&mut self, now_ms: u64) -> Result<Vec<Action<Outbound, Event>>, Error> {
        if self.phase != ServerPhase::Replaying {
            return Err(Error::State);
        }
        self.clock.advance(now_ms)?;
        self.clock.sent = now_ms;
        self.phase = ServerPhase::LoggedIn;
        Ok(vec![Action::Send(ReplayComplete::default().into())])
    }
    /// Numbers an application message and returns it to write. A
    /// sequenced message takes the next sequence of the unit in its header
    /// (1 to 255); an unsequenced one gets unit and sequence 0. Refuses
    /// session messages, which the server sends itself.
    pub fn send(&mut self, mut message: Outbound, now_ms: u64) -> Result<Outbound, Error> {
        if self.phase != ServerPhase::LoggedIn || message.is_session() {
            return Err(Error::State);
        }
        if message.is_sequenced() {
            let unit = message.header().unit;
            if unit == 0 {
                return Err(Error::Sequence);
            }
            let sequence = self
                .sent
                .get(&unit)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(Error::Sequence)?;
            self.clock.advance(now_ms)?;
            self.sent.insert(unit, sequence);
            *message.header_mut() = Header { unit, sequence };
        } else {
            self.clock.advance(now_ms)?;
            *message.header_mut() = Header::default();
        }
        self.clock.sent = now_ms;
        Ok(message)
    }
    /// Sends a Logout with `reason` and closes: "E" at the end of the day,
    /// "A" for administrative reasons.
    pub fn logout(
        &mut self,
        reason: u8,
        text: &str,
        now_ms: u64,
    ) -> Result<Vec<Action<Outbound, Event>>, Error> {
        if !matches!(self.phase, ServerPhase::Replaying | ServerPhase::LoggedIn) {
            return Err(Error::State);
        }
        Text::<60>::new(text)?;
        self.clock.advance(now_ms)?;
        Ok(self.logout_now(reason, text, CloseReason::Logout))
    }
    fn logout_now(
        &mut self,
        reason: u8,
        text: &str,
        close: CloseReason,
    ) -> Vec<Action<Outbound, Event>> {
        let logout = Logout {
            header: Header::default(),
            reason,
            text: Text::new(text).unwrap_or_default(),
            last_received_sequence: self.last_inbound,
            units: Units(self.sent()),
        };
        self.clock.sent = self.clock.now;
        let mut actions = vec![Action::Send(logout.into())];
        actions.extend(self.close(close));
        actions
    }
    fn violation(&mut self, text: &str) -> Vec<Action<Outbound, Event>> {
        self.logout_now(
            codes::logout_reason::PROTOCOL_VIOLATION,
            text,
            CloseReason::Protocol,
        )
    }
    /// Runs the timers: the login timeout, the idle timeout (a Logout with
    /// reason "!"), and a Server Heartbeat after [`Timers::heartbeat_ms`]
    /// of sending nothing.
    pub fn tick(&mut self, now_ms: u64) -> Result<Vec<Action<Outbound, Event>>, Error> {
        use ServerPhase as S;
        self.clock.advance(now_ms)?;
        Ok(match self.phase {
            S::Closed => Vec::new(),
            S::AwaitingLogin | S::LoginPending if self.clock.login_expired() => {
                self.close(CloseReason::LoginTimeout)
            }
            S::AwaitingLogin | S::LoginPending => Vec::new(),
            _ if self.clock.idle() => self.logout_now(
                codes::logout_reason::PROTOCOL_VIOLATION,
                "Heartbeat timeout",
                CloseReason::IdleTimeout,
            ),
            _ if self.clock.heartbeat_due() => {
                self.clock.sent = now_ms;
                vec![Action::Send(ServerHeartbeat::default().into())]
            }
            _ => Vec::new(),
        })
    }
    fn close(&mut self, reason: CloseReason) -> Vec<Action<Outbound, Event>> {
        self.phase = ServerPhase::Closed;
        vec![Action::Event(Event::Disconnected(reason))]
    }
}

/// The limits and numbering of an [`Exchange`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeConfig {
    /// The most live and pending orders, 1 to [`MAX_ORDERS`]. A New Order
    /// past it is rejected with reason "o".
    pub max_orders: usize,
    /// The most executions remembered for [`Exchange::bust`], 1 to
    /// [`MAX_EXECUTIONS`]. The oldest are forgotten.
    pub max_executions: usize,
    /// The first OrderID assigned.
    pub first_order_id: u64,
    /// The first ExecID assigned.
    pub first_exec_id: u64,
}
impl Default for ExchangeConfig {
    fn default() -> Self {
        Self {
            max_orders: DEFAULT_MAX_ORDERS,
            max_executions: DEFAULT_MAX_EXECUTIONS,
            first_order_id: 1,
            first_exec_id: 1,
        }
    }
}

/// An order an [`Exchange`] tracks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// The current ClOrdID.
    pub cl_ord_id: ClOrdId,
    /// The ClOrdID before the last modify, if any.
    pub orig_cl_ord_id: Option<ClOrdId>,
    /// False until [`Exchange::accept`].
    pub live: bool,
    /// Cboe's OrderID; 0 until accepted.
    pub order_id: u64,
    /// The matching unit; 0 until accepted.
    pub unit: u8,
    /// The side.
    pub side: u8,
    /// OrderQty.
    pub order_qty: u32,
    /// Shares open.
    pub leaves_qty: u32,
    /// Shares executed.
    pub cum_qty: u32,
    /// The limit price, if any.
    pub price: Option<Price>,
    /// OrdType: "2" (limit) unless the order said otherwise.
    pub ord_type: u8,
    /// The symbol.
    pub symbol: Text<8>,
    /// The capacity.
    pub capacity: u8,
    /// Modifies applied.
    pub modifies: u16,
    /// The New Order's optional fields, kept to echo them.
    pub fields: Optional<NewOrderTable>,
}

/// What an [`Exchange`] reports to the world.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderEvent {
    /// A valid New Order. Answer with [`Exchange::accept`] or
    /// [`Exchange::reject`].
    NewOrderRequested(ClOrdId),
    /// A live order was canceled at the member's request.
    Cancelled(ClOrdId),
    /// A live order was modified; it now has this ClOrdID, or is done if
    /// its LeavesQty reached 0.
    Modified(ClOrdId),
    /// A Purge Orders canceled this many orders.
    Purged {
        /// Orders canceled.
        count: usize,
        /// Whether the request asked for a lockout, which this module
        /// leaves to the world.
        lockout: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Execution {
    exec_id: u64,
    cl_ord_id: ClOrdId,
    order_id: u64,
    unit: u8,
    side: u8,
    shares: u32,
    price: Price,
    liquidity: u8,
    time: u64,
    clearing_firm: Text<4>,
    clearing_account: Text<4>,
}

/// What a return field is filled from.
#[derive(Clone, Copy, Default)]
struct Context<'a> {
    order: Option<&'a Order>,
    last_shares: u32,
    last_px: Price,
    liquidity: u8,
    mass_cancel_id: Option<Text<20>>,
}

/// The order side of a fake BOE exchange, without I/O.
///
/// Pass each application message the [`Server`] reports to
/// [`receive`](Self::receive) and send every [`Action::Send`] through
/// [`Server::send`], which numbers it. The world answers each
/// [`OrderEvent::NewOrderRequested`] with [`accept`](Self::accept) or
/// [`reject`](Self::reject), and drives fills, its own cancels,
/// restatements and trade busts with [`execute`](Self::execute),
/// [`cancel`](Self::cancel), [`restate`](Self::restate) and
/// [`bust`](Self::bust). Times are nanoseconds since the Unix epoch.
///
/// The exchange applies the rules the specification states: a New Order
/// needs a Symbol and a Capacity, a price unless it is a market or pegged
/// order and none if it is a market order, and 1 to 999,999 shares; a
/// ClOrdID may not repeat a live one ("New Order Message Fields"). A
/// cancel of an unknown ClOrdID is rejected with "O". A modify needs
/// OrderQty and Price (Price may be absent for a market order), may reuse
/// the ClOrdID only to reduce, applies the OrderQty change to LeavesQty
/// and ends the order at zero, and is limited to [`MAX_MODIFIES`] per
/// order ("Modify Order Message Fields"). A Purge Orders cancels live
/// orders matching its ClearingFirm, Symbol or RiskGroupIDs, acknowledged
/// as its MassCancelInst asks ("Purge Orders"). Every reply carries the
/// return fields the member's login asked for, filled from the order, or
/// zero where nothing applies.
///
/// Orders are bounded by [`ExchangeConfig::max_orders`] and remembered
/// executions by [`ExchangeConfig::max_executions`]. An `Err` leaves the
/// exchange unchanged.
#[derive(Clone, Debug)]
pub struct Exchange {
    config: ExchangeConfig,
    returns: BTreeMap<u8, Vec<u8>>,
    orders: BTreeMap<ClOrdId, Order>,
    /// Remembered executions by ExecID. ExecIDs only grow, so the first
    /// entry is the oldest.
    executions: BTreeMap<u64, Execution>,
    next_order_id: u64,
    next_exec_id: u64,
}
impl Exchange {
    /// An exchange with no orders that fills the return fields in
    /// `returns`, as [`Server::returns`] gives them. Refuses limits out of
    /// range and bitfields the [`ReturnTable`] cannot fill.
    pub fn new(config: ExchangeConfig, returns: BTreeMap<u8, Vec<u8>>) -> Result<Self, Error> {
        if !(1..=MAX_ORDERS).contains(&config.max_orders)
            || !(1..=MAX_EXECUTIONS).contains(&config.max_executions)
            || returns
                .values()
                .any(|b| Optional::<ReturnTable>::requested(b).is_err())
        {
            return Err(Error::ExchangeConfig);
        }
        Ok(Self {
            config,
            returns,
            orders: BTreeMap::new(),
            executions: BTreeMap::new(),
            next_order_id: config.first_order_id,
            next_exec_id: config.first_exec_id,
        })
    }
    /// An order, live or awaiting [`accept`](Self::accept).
    pub fn order(&self, cl_ord_id: ClOrdId) -> Option<&Order> {
        self.orders.get(&cl_ord_id)
    }
    /// Every tracked order, in ascending ClOrdId byte order.
    pub fn orders(&self) -> impl Iterator<Item = &Order> {
        self.orders.values()
    }

    /// Handles one application message. Session messages are ignored.
    pub fn receive(&mut self, message: &Inbound, now: u64) -> Vec<Action<Outbound, OrderEvent>> {
        match message {
            Inbound::NewOrder(m) => self.new_order(m, now),
            Inbound::CancelOrder(m) => self.cancel_request(m, now),
            Inbound::ModifyOrder(m) => self.modify(m, now),
            Inbound::PurgeOrders(m) => self.purge(m, now),
            _ => Vec::new(),
        }
    }

    fn returns(&self, kind: u8, fcx: Context<'_>) -> Optional<ReturnTable> {
        let Some(mut out) = self
            .returns
            .get(&kind)
            .and_then(|bits| Optional::<ReturnTable>::requested(bits).ok())
        else {
            return Optional::new();
        };
        for f in &mut out.fields {
            if let Some(v) = value(f.id(), &fcx) {
                *f = v;
            }
        }
        out
    }

    fn new_order(&mut self, m: &NewOrder, now: u64) -> Vec<Action<Outbound, OrderEvent>> {
        use codes::reason as r;
        let ord_type = m.fields.code(FieldId::OrdType).unwrap_or(b'2');
        let price = m.fields.price();
        let symbol = m.fields.symbol().filter(|s| !s.is_empty());
        let capacity = m.fields.code(FieldId::Capacity);
        let refuse = |reason, text| vec![Action::Send(self.rejected(m, reason, text, now))];
        if !valid_cl_ord_id(&m.cl_ord_id) {
            return refuse(r::UNFORESEEN, "Invalid ClOrdID");
        }
        if self.orders.contains_key(&m.cl_ord_id) {
            return refuse(r::DUPLICATE, "Duplicate ClOrdID");
        }
        let Some(symbol) = symbol else {
            return refuse(r::UNKNOWN_SYMBOL, "Symbol required");
        };
        let Some(capacity) = capacity else {
            return refuse(r::CAPACITY_UNDEFINED, "Capacity required");
        };
        if m.order_qty == 0 || m.order_qty > MAX_ORDER_QTY {
            return refuse(r::SIZE_EXCEEDED, "Invalid OrderQty");
        }
        match (ord_type, price) {
            (b'1', Some(_)) => return refuse(r::UNFORESEEN, "Price on market order"),
            (b'1' | b'P', _) | (_, Some(_)) => {}
            (_, None) => return refuse(r::UNFORESEEN, "Price required"),
        }
        if self.orders.len() >= self.config.max_orders {
            return refuse(r::MAX_OPEN_ORDERS, "Max open orders exceeded");
        }
        self.orders.insert(
            m.cl_ord_id,
            Order {
                cl_ord_id: m.cl_ord_id,
                orig_cl_ord_id: None,
                live: false,
                order_id: 0,
                unit: 0,
                side: m.side,
                order_qty: m.order_qty,
                leaves_qty: m.order_qty,
                cum_qty: 0,
                price,
                ord_type,
                symbol,
                capacity,
                modifies: 0,
                fields: m.fields.clone(),
            },
        );
        vec![Action::Event(OrderEvent::NewOrderRequested(m.cl_ord_id))]
    }
    fn rejected(&self, m: &NewOrder, reason: u8, text: &str, now: u64) -> Outbound {
        let probe = Order {
            cl_ord_id: m.cl_ord_id,
            orig_cl_ord_id: None,
            live: false,
            order_id: 0,
            unit: 0,
            side: m.side,
            order_qty: m.order_qty,
            leaves_qty: 0,
            cum_qty: 0,
            price: m.fields.price(),
            ord_type: m.fields.code(FieldId::OrdType).unwrap_or(b'2'),
            symbol: m.fields.symbol().unwrap_or_default(),
            capacity: m.fields.code(FieldId::Capacity).unwrap_or(0),
            modifies: 0,
            fields: m.fields.clone(),
        };
        OrderRejected {
            header: Header::default(),
            transaction_time: now,
            cl_ord_id: m.cl_ord_id,
            reason,
            text: Text::new(text).unwrap_or_default(),
            reserved_internal: 0,
            fields: self.returns(
                OrderRejected::KIND,
                Context {
                    order: Some(&probe),
                    ..Context::default()
                },
            ),
        }
        .into()
    }

    /// Accepts a pending New Order on matching unit `unit` (1 to 255) and
    /// returns its Order Acknowledgment, for [`Server::send`] to number.
    pub fn accept(&mut self, cl_ord_id: ClOrdId, unit: u8, now: u64) -> Result<Outbound, Error> {
        let order_id = self.next_order_id;
        let next = order_id.checked_add(1).ok_or(Error::Exhausted)?;
        if unit == 0 {
            return Err(Error::ExchangeConfig);
        }
        let order = self
            .orders
            .get_mut(&cl_ord_id)
            .filter(|o| !o.live)
            .ok_or(Error::UnknownOrder(cl_ord_id))?;
        order.live = true;
        order.order_id = order_id;
        order.unit = unit;
        self.next_order_id = next;
        let order = self
            .orders
            .get(&cl_ord_id)
            .ok_or(Error::UnknownOrder(cl_ord_id))?;
        Ok(OrderAcknowledgment {
            header: Header { unit, sequence: 0 },
            transaction_time: now,
            cl_ord_id,
            order_id,
            reserved_internal: 0,
            fields: self.returns(
                OrderAcknowledgment::KIND,
                Context {
                    order: Some(order),
                    ..Context::default()
                },
            ),
        }
        .into())
    }
    /// Rejects a pending New Order with a reason code and text.
    pub fn reject(
        &mut self,
        cl_ord_id: ClOrdId,
        reason: u8,
        text: &str,
        now: u64,
    ) -> Result<Outbound, Error> {
        let text = Text::new(text).map_err(|_| Error::Text)?;
        let order = self
            .orders
            .get(&cl_ord_id)
            .filter(|o| !o.live)
            .ok_or(Error::UnknownOrder(cl_ord_id))?;
        let reply = OrderRejected {
            header: Header::default(),
            transaction_time: now,
            cl_ord_id,
            reason,
            text,
            reserved_internal: 0,
            fields: self.returns(
                OrderRejected::KIND,
                Context {
                    order: Some(order),
                    ..Context::default()
                },
            ),
        };
        self.orders.remove(&cl_ord_id);
        Ok(reply.into())
    }

    fn live(&self, cl_ord_id: ClOrdId) -> Result<&Order, Error> {
        self.orders
            .get(&cl_ord_id)
            .filter(|o| o.live)
            .ok_or(Error::UnknownOrder(cl_ord_id))
    }
    fn cancelled(&self, order: &Order, reason: u8, now: u64) -> Outbound {
        OrderCancelled {
            header: Header {
                unit: order.unit,
                sequence: 0,
            },
            transaction_time: now,
            cl_ord_id: order.cl_ord_id,
            reason,
            reserved_internal: 0,
            fields: self.returns(
                OrderCancelled::KIND,
                Context {
                    order: Some(&Order {
                        leaves_qty: 0,
                        ..order.clone()
                    }),
                    ..Context::default()
                },
            ),
        }
        .into()
    }

    /// Executes `shares` of a live order at `price` with a
    /// BaseLiquidityIndicator, and returns the Order Execution with a new
    /// ExecID. The order is done when no shares are left.
    pub fn execute(
        &mut self,
        cl_ord_id: ClOrdId,
        shares: u32,
        price: Price,
        liquidity: u8,
        now: u64,
    ) -> Result<Outbound, Error> {
        let order = self.live(cl_ord_id)?;
        if shares == 0 || shares > order.leaves_qty {
            return Err(Error::Shares);
        }
        let exec_id = self.next_exec_id;
        let next = exec_id.checked_add(1).ok_or(Error::Exhausted)?;
        let after = Order {
            leaves_qty: order.leaves_qty - shares,
            cum_qty: order.cum_qty.saturating_add(shares),
            ..order.clone()
        };
        let text4 = |id| match order.fields.get(id) {
            Some(Opt::ClearingFirm(t) | Opt::ClearingAccount(t)) => *t,
            _ => Text::default(),
        };
        let execution = Execution {
            exec_id,
            cl_ord_id,
            order_id: order.order_id,
            unit: order.unit,
            side: order.side,
            shares,
            price,
            liquidity,
            time: now,
            clearing_firm: text4(FieldId::ClearingFirm),
            clearing_account: text4(FieldId::ClearingAccount),
        };
        let reply = OrderExecution {
            header: Header {
                unit: order.unit,
                sequence: 0,
            },
            transaction_time: now,
            cl_ord_id,
            exec_id,
            last_shares: shares,
            last_px: price,
            leaves_qty: after.leaves_qty,
            base_liquidity_indicator: liquidity,
            sub_liquidity_indicator: 0,
            contra_broker: Text::default(),
            reserved_internal: 0,
            fields: self.returns(
                OrderExecution::KIND,
                Context {
                    order: Some(&after),
                    last_shares: shares,
                    last_px: price,
                    liquidity,
                    mass_cancel_id: None,
                },
            ),
        };
        self.next_exec_id = next;
        if after.leaves_qty == 0 {
            self.orders.remove(&cl_ord_id);
        } else {
            self.orders.insert(cl_ord_id, after);
        }
        if self.executions.len() >= self.config.max_executions {
            self.executions.pop_first();
        }
        self.executions.insert(exec_id, execution);
        Ok(reply.into())
    }
    /// Cancels a live order for the exchange's own `reason`, and returns
    /// the Order Cancelled.
    pub fn cancel(&mut self, cl_ord_id: ClOrdId, reason: u8, now: u64) -> Result<Outbound, Error> {
        let order = self.live(cl_ord_id)?;
        let reply = self.cancelled(order, reason, now);
        self.orders.remove(&cl_ord_id);
        Ok(reply)
    }
    /// Restates a live order's open shares, as after a reserve reload or a
    /// wash decrement, and returns the Order Restated. Zero ends the order.
    pub fn restate(
        &mut self,
        cl_ord_id: ClOrdId,
        leaves_qty: u32,
        reason: u8,
        now: u64,
    ) -> Result<Outbound, Error> {
        let order = self.live(cl_ord_id)?;
        if leaves_qty > order.order_qty.saturating_sub(order.cum_qty) {
            return Err(Error::Shares);
        }
        let after = Order {
            leaves_qty,
            ..order.clone()
        };
        let reply = OrderRestated {
            header: Header {
                unit: order.unit,
                sequence: 0,
            },
            transaction_time: now,
            cl_ord_id,
            order_id: order.order_id,
            restatement_reason: reason,
            reserved_internal: 0,
            fields: self.returns(
                OrderRestated::KIND,
                Context {
                    order: Some(&after),
                    ..Context::default()
                },
            ),
        };
        if leaves_qty == 0 {
            self.orders.remove(&cl_ord_id);
        } else {
            self.orders.insert(cl_ord_id, after);
        }
        Ok(reply.into())
    }
    /// Cancels (`corrected` 0) or corrects a remembered execution, and
    /// returns the Trade Cancel or Correct. The order's shares are not
    /// restored, as a bust does not reopen an order.
    pub fn bust(&mut self, exec_id: u64, corrected: Price, now: u64) -> Result<Outbound, Error> {
        let e = self
            .executions
            .remove(&exec_id)
            .ok_or(Error::UnknownExecution(exec_id))?;
        let order = self.orders.get(&e.cl_ord_id);
        Ok(TradeCancelOrCorrect {
            header: Header {
                unit: e.unit,
                sequence: 0,
            },
            transaction_time: now,
            cl_ord_id: e.cl_ord_id,
            order_id: e.order_id,
            exec_ref_id: e.exec_id,
            side: e.side,
            base_liquidity_indicator: e.liquidity,
            clearing_firm: e.clearing_firm,
            clearing_account: e.clearing_account,
            last_shares: e.shares,
            last_px: e.price,
            corrected_price: corrected,
            orig_time: e.time,
            reserved_internal: 0,
            fields: self.returns(
                TradeCancelOrCorrect::KIND,
                Context {
                    order,
                    last_shares: e.shares,
                    last_px: e.price,
                    liquidity: e.liquidity,
                    mass_cancel_id: None,
                },
            ),
        }
        .into())
    }

    fn cancel_request(&mut self, m: &CancelOrder, now: u64) -> Vec<Action<Outbound, OrderEvent>> {
        let Ok(order) = self.live(m.orig_cl_ord_id) else {
            let reply = CancelRejected {
                header: Header::default(),
                transaction_time: now,
                cl_ord_id: m.orig_cl_ord_id,
                reason: codes::reason::UNKNOWN_ORDER,
                text: Text::new("Unknown order").unwrap_or_default(),
                reserved_internal: 0,
                fields: self.returns(CancelRejected::KIND, Context::default()),
            };
            return vec![Action::Send(reply.into())];
        };
        let reply = self.cancelled(order, codes::reason::USER_REQUESTED, now);
        self.orders.remove(&m.orig_cl_ord_id);
        vec![
            Action::Send(reply),
            Action::Event(OrderEvent::Cancelled(m.orig_cl_ord_id)),
        ]
    }

    fn modify(&mut self, m: &ModifyOrder, now: u64) -> Vec<Action<Outbound, OrderEvent>> {
        use codes::reason as r;
        let refuse = |this: &Self, order: Option<&Order>, reason, text: &str| {
            let reply = UserModifyRejected {
                header: Header::default(),
                transaction_time: now,
                cl_ord_id: m.cl_ord_id,
                reason,
                text: Text::new(text).unwrap_or_default(),
                reserved_internal: 0,
                fields: this.returns(
                    UserModifyRejected::KIND,
                    Context {
                        order,
                        ..Context::default()
                    },
                ),
            };
            vec![Action::Send(reply.into())]
        };
        let Ok(order) = self.live(m.orig_cl_ord_id) else {
            return refuse(self, None, r::UNKNOWN_ORDER, "Unknown order");
        };
        let Some(order_qty) = m.fields.order_qty() else {
            return refuse(self, Some(order), r::UNFORESEEN, "OrderQty required");
        };
        let ord_type = m.fields.code(FieldId::OrdType).unwrap_or(order.ord_type);
        let price = m.fields.price();
        if price.is_none() && ord_type != b'1' {
            return refuse(self, Some(order), r::UNFORESEEN, "Price required");
        }
        if !valid_cl_ord_id(&m.cl_ord_id) {
            return refuse(self, Some(order), r::UNFORESEEN, "Invalid ClOrdID");
        }
        if m.cl_ord_id == m.orig_cl_ord_id {
            if order_qty >= order.order_qty {
                return refuse(
                    self,
                    Some(order),
                    r::DUPLICATE,
                    "ClOrdID reuse may only reduce",
                );
            }
        } else if self.orders.contains_key(&m.cl_ord_id) {
            return refuse(self, Some(order), r::DUPLICATE, "Duplicate ClOrdID");
        }
        if order_qty == 0 || order_qty > MAX_ORDER_QTY {
            return refuse(self, Some(order), r::SIZE_EXCEEDED, "Invalid OrderQty");
        }
        if order.modifies >= MAX_MODIFIES {
            return refuse(self, Some(order), r::UNFORESEEN, "Too many modifies");
        }
        // The OrderQty change applies to LeavesQty ("Modify Order Message
        // Fields"); at or below zero the order is done.
        let leaves =
            i64::from(order.leaves_qty) + i64::from(order_qty) - i64::from(order.order_qty);
        let leaves_qty = u32::try_from(leaves.max(0)).unwrap_or(0);
        let mut fields = order.fields.clone();
        for id in [FieldId::MaxFloor, FieldId::StopPx, FieldId::ExecInst] {
            if let Some(v) = m.fields.get(id) {
                let _ = fields.set(v.clone());
            }
        }
        let after = Order {
            cl_ord_id: m.cl_ord_id,
            orig_cl_ord_id: Some(m.orig_cl_ord_id),
            order_qty,
            leaves_qty,
            price: price.or(if ord_type == b'1' { None } else { order.price }),
            ord_type,
            side: m.fields.code(FieldId::Side).unwrap_or(order.side),
            modifies: order.modifies + 1,
            fields,
            ..order.clone()
        };
        let reply = OrderModified {
            header: Header {
                unit: order.unit,
                sequence: 0,
            },
            transaction_time: now,
            cl_ord_id: m.cl_ord_id,
            order_id: order.order_id,
            reserved_internal: 0,
            fields: self.returns(
                OrderModified::KIND,
                Context {
                    order: Some(&after),
                    ..Context::default()
                },
            ),
        };
        self.orders.remove(&m.orig_cl_ord_id);
        if leaves_qty > 0 {
            self.orders.insert(m.cl_ord_id, after);
        }
        vec![
            Action::Send(reply.into()),
            Action::Event(OrderEvent::Modified(m.cl_ord_id)),
        ]
    }

    fn purge(&mut self, m: &PurgeOrders, now: u64) -> Vec<Action<Outbound, OrderEvent>> {
        let f = &m.purge.fields;
        let refuse = |this: &Self, text: &str| {
            let reply = PurgeRejected {
                header: Header::default(),
                transaction_time: now,
                reason: codes::reason::UNFORESEEN,
                text: Text::new(text).unwrap_or_default(),
                reserved_internal: 0,
                fields: this.returns(
                    PurgeRejected::KIND,
                    Context {
                        mass_cancel_id: f.get(FieldId::MassCancelId).and_then(|o| match o {
                            Opt::MassCancelId(t) => Some(*t),
                            _ => None,
                        }),
                        ..Context::default()
                    },
                ),
            };
            vec![Action::Send(reply.into())]
        };
        let Some(Opt::MassCancelInst(inst)) = f.get(FieldId::MassCancelInst) else {
            return refuse(self, "MassCancelInst required");
        };
        let inst = inst.as_bytes();
        let by_firm = inst[0] == b'F';
        let ack = match inst[1] {
            0 => b'M',
            c => c,
        };
        let lockout = inst[2] == b'L';
        let firm = match f.get(FieldId::ClearingFirm) {
            Some(Opt::ClearingFirm(t)) => Some(*t),
            _ => None,
        };
        let mass_cancel_id = match f.get(FieldId::MassCancelId) {
            Some(Opt::MassCancelId(t)) => Some(*t),
            _ => None,
        };
        let symbol = f.symbol();
        if !matches!(inst[0], b'A' | b'F') || !matches!(ack, b'M' | b'S' | b'B') {
            return refuse(self, "Invalid MassCancelInst");
        }
        if by_firm && firm.is_none() {
            return refuse(self, "ClearingFirm required");
        }
        if ack != b'M' && mass_cancel_id.is_none() {
            return refuse(self, "MassCancelID required");
        }
        if m.purge.risk_group_ids.len() > MAX_RISK_GROUP_IDS
            || (symbol.is_some() && !m.purge.risk_group_ids.is_empty())
        {
            return refuse(self, "Invalid filter");
        }
        let mut hit: Vec<&Order> = self
            .orders
            .values()
            .filter(|o| o.live)
            .filter(|o| {
                let firm_ok = match firm.filter(|t| by_firm && !t.is_empty()) {
                    Some(t) => o.fields.get(FieldId::ClearingFirm) == Some(&Opt::ClearingFirm(t)),
                    None => true,
                };
                let symbol_ok = symbol.is_none_or(|s| o.symbol == s);
                let group_ok = m.purge.risk_group_ids.is_empty()
                    || matches!(o.fields.get(FieldId::RiskGroupId),
                        Some(Opt::RiskGroupId(g)) if m.purge.risk_group_ids.contains(g));
                firm_ok && symbol_ok && group_ok
            })
            .collect();
        hit.sort_by_key(|o| o.order_id);
        let mut actions = Vec::new();
        if ack != b'S' {
            for o in &hit {
                actions.push(Action::Send(self.cancelled(
                    o,
                    codes::reason::USER_REQUESTED,
                    now,
                )));
            }
        }
        if ack != b'M' {
            actions.push(Action::Send(
                MassCancelAcknowledgment {
                    header: Header::default(),
                    transaction_time: now,
                    mass_cancel_id: mass_cancel_id.unwrap_or_default(),
                    cancelled_order_count: u32::try_from(hit.len()).unwrap_or(u32::MAX),
                    reserved_internal: 0,
                    end: (),
                }
                .into(),
            ));
        }
        let count = hit.len();
        let ids: Vec<ClOrdId> = hit.iter().map(|o| o.cl_ord_id).collect();
        for id in ids {
            self.orders.remove(&id);
        }
        actions.push(Action::Event(OrderEvent::Purged { count, lockout }));
        actions
    }
}

/// ClOrdID characters: ASCII 33 to 126 except comma, semicolon, pipe, at
/// and double quote ("New Order Message Fields"), and not empty.
fn valid_cl_ord_id(id: &ClOrdId) -> bool {
    let s = id.as_str();
    !s.is_empty()
        && s.bytes()
            .all(|b| (33..=126).contains(&b) && !b",;|@\"".contains(&b))
}

/// The value of return field `id` from what is known, if anything is.
fn value(id: FieldId, fcx: &Context<'_>) -> Option<Opt> {
    let o = fcx.order;
    Some(match id {
        FieldId::Side => Opt::Side(o?.side),
        FieldId::Price => Opt::Price(o?.price.unwrap_or_default()),
        FieldId::OrdType => Opt::OrdType(o?.ord_type),
        FieldId::Symbol => Opt::Symbol(o?.symbol),
        FieldId::Capacity => Opt::Capacity(o?.capacity),
        FieldId::OrderQty => Opt::OrderQty(o?.order_qty),
        FieldId::LeavesQty => Opt::LeavesQty(o?.leaves_qty),
        FieldId::OrigClOrdId => Opt::OrigClOrdId(o?.orig_cl_ord_id?),
        FieldId::LastShares => Opt::LastShares(fcx.last_shares),
        FieldId::LastPx => Opt::LastPx(fcx.last_px),
        FieldId::BaseLiquidityIndicator => Opt::BaseLiquidityIndicator(fcx.liquidity),
        FieldId::MassCancelId => Opt::MassCancelId(fcx.mass_cancel_id?),
        FieldId::DisplayPrice | FieldId::WorkingPrice => {
            let p = o?.price.unwrap_or_default();
            if id == FieldId::DisplayPrice {
                Opt::DisplayPrice(p)
            } else {
                Opt::WorkingPrice(p)
            }
        }
        // Echoed from the New Order where it had the field.
        other => o?.fields.get(other)?.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::{Fail, Lcg};
    use fictionet::stdlib::test_support::contract::{
        check_decode, check_decode_with_alloc_limit, check_wire, check_wire_value,
    };
    use fictionet::stdlib::test_support::hex;
    use fictionet::stdlib::test_support::{decode_all, mutate};

    fn header(unit: u8, sequence: u32) -> Header {
        Header { unit, sequence }
    }

    fn unit_sequence(unit: u8, sequence: u32) -> UnitSequence {
        UnitSequence { unit, sequence }
    }

    fn text<const N: usize>(s: &str) -> Text<N> {
        Text::new(s).unwrap()
    }
    const TIME: &str = "E0 FA 20 F7 36 71 F8 11";
    const T: u64 = 1_294_909_373_757_324_000;
    const ABC123: &str = "41 42 43 31 32 33 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    const ORDER_ID: &str = "05 10 1E B7 5E 39 2F 02";
    const OID: u64 = 0x022f_395e_b71e_1005;
    fn nul_text(s: &str) -> String {
        let mut out: Vec<String> = s.bytes().map(|b| format!("{b:02X}")).collect();
        out.resize(60, "00".to_string());
        out.join(" ")
    }
    fn inbound(bytes: &[u8], want: Inbound) {
        assert_eq!(Inbound::parse(bytes).unwrap(), want);
        assert_eq!(want.to_bytes().unwrap(), bytes);
        check_wire::<Inbound>(bytes);
    }
    fn outbound(bytes: &[u8], want: Outbound) {
        assert_eq!(Outbound::parse(bytes).unwrap(), want);
        assert_eq!(want.to_bytes().unwrap(), bytes);
        check_wire::<Outbound>(bytes);
    }
    fn returns(fields: Vec<Opt>) -> Optional<ReturnTable> {
        let mut o = Optional::new();
        for f in fields {
            o.set(f).unwrap();
        }
        o
    }

    // "Login Request Message Example". (The notes say two unit pairs; the
    // bytes hold three.)
    #[test]
    fn login_request_example() {
        let bytes = hex("BA BA 43 00 37 00 00 00 00 00 30 30 30 31 54 45 53 54 \
             54 45 53 54 49 4E 47 00 00 00 03 \
             14 00 80 01 03 01 4A BB 01 00 02 00 00 00 00 04 79 A1 00 00 \
             08 00 81 25 03 00 41 05 \
             0C 00 81 2C 07 00 41 07 00 40 00 01");
        let units = vec![
            unit_sequence(1, 113_482),
            unit_sequence(2, 0),
            unit_sequence(4, 41_337),
        ];
        let want = LoginRequest {
            header: Header::default(),
            session_sub_id: text("0001"),
            username: text("TEST"),
            password: text("TESTING"),
            params: ParamGroups(vec![
                ParamGroup::UnitSequences {
                    no_unspecified_unit_replay: 1,
                    units,
                },
                ParamGroup::ReturnBitfields {
                    message_type: 0x25,
                    bitfields: vec![0, 0x41, 0x05],
                },
                ParamGroup::ReturnBitfields {
                    message_type: 0x2C,
                    bitfields: vec![0, 0x41, 0x07, 0, 0x40, 0, 0x01],
                },
            ]),
        };
        inbound(&bytes, want.into());
        // The return bitfields name fields this module can fill.
        let exec = Optional::<ReturnTable>::requested(&[0, 0x41, 0x07, 0, 0x40, 0, 0x01]).unwrap();
        let ids: Vec<FieldId> = exec.fields().iter().map(Opt::id).collect();
        assert_eq!(
            ids,
            [
                FieldId::Symbol,
                FieldId::Capacity,
                FieldId::Account,
                FieldId::ClearingFirm,
                FieldId::ClearingAccount,
                FieldId::BaseLiquidityIndicator,
                FieldId::SubLiquidityIndicator
            ]
        );
    }

    // "Login Response Message Example". Its unit numbers read 01 02 02 02
    // where the notes say units 1 to 4; the bytes are kept.
    #[test]
    fn login_response_example() {
        let bytes = hex(&format!(
            "BA BA 88 00 24 00 00 00 00 00 41 {} 01 54 4A 02 00 04 \
             01 4A BB 01 00 02 00 00 00 00 02 00 00 00 00 02 79 A1 00 00 03 \
             14 00 80 01 03 01 4A BB 01 00 02 00 00 00 00 04 79 A1 00 00 \
             08 00 81 25 03 00 41 05 \
             0C 00 81 2C 07 00 41 07 00 40 00 01",
            nul_text("Accepted")
        ));
        let Outbound::LoginResponse(r) = Outbound::parse(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(r.status, b'A');
        assert_eq!(r.text.as_str(), "Accepted");
        assert_eq!(r.last_received_sequence, 150_100);
        assert_eq!(r.tail.units.len(), 4);
        assert_eq!(r.tail.units[3].sequence, 41_337);
        assert_eq!(r.tail.groups.0.len(), 3);
        assert_eq!(Outbound::from(r).to_bytes().unwrap(), bytes);
        check_wire::<Outbound>(&bytes);
    }

    // "Logout Response Message Example". Its MessageLength reads 55 00
    // (85) but the fields total 91 bytes, 89 after StartOfMessage; 59 00
    // is used here. Its LastReceived bytes, 54 5A 02 00, are 154,196, not
    // the 150,100 of the notes.
    #[test]
    fn logout_example() {
        let bytes = hex(&format!(
            "BA BA 59 00 08 00 00 00 00 00 55 {} 54 5A 02 00 03 \
             01 4A BB 01 00 02 00 00 00 00 04 79 A1 00 00",
            nul_text("User")
        ));
        outbound(
            &bytes,
            Logout {
                header: Header::default(),
                reason: b'U',
                text: text("User"),
                last_received_sequence: 154_196,
                units: Units(vec![
                    unit_sequence(1, 113_482),
                    unit_sequence(2, 0),
                    unit_sequence(4, 41_337),
                ]),
            }
            .into(),
        );
        let mut printed = bytes.clone();
        printed[2] = 0x55;
        assert_eq!(Outbound::parse(&printed), Err(Error::Length));
    }

    #[test]
    fn session_message_examples() {
        inbound(
            &hex("BA BA 08 00 02 00 00 00 00 00"),
            LogoutRequest::default().into(),
        );
        inbound(
            &hex("BA BA 08 00 03 00 00 00 00 00"),
            ClientHeartbeat::default().into(),
        );
        outbound(
            &hex("BA BA 08 00 09 00 00 00 00 00"),
            ServerHeartbeat::default().into(),
        );
        outbound(
            &hex("BA BA 08 00 13 00 00 00 00 00"),
            ReplayComplete::default().into(),
        );
    }

    // "New Order Message Example". MessageLength 4A 00 is 74; the note's
    // 73 is off by one.
    #[test]
    fn new_order_example() {
        let bytes = hex(&format!(
            "BA BA 4A 00 38 00 64 00 00 00 {ABC123} 31 E8 03 00 00 03 04 C1 01 \
             44 D6 12 00 00 00 00 00 4D 53 46 54 00 00 00 00 50 52 00 00 00 \
             44 45 46 47 00 00 00 00 00 00 00 00 00 00 00 00"
        ));
        let fields = Optional::new()
            .with(Opt::Price("123.45".parse().unwrap()))
            .unwrap()
            .with(Opt::Symbol(text("MSFT")))
            .unwrap()
            .with(Opt::Capacity(b'P'))
            .unwrap()
            .with(Opt::RoutingInst(text("R")))
            .unwrap()
            .with(Opt::Account(text("DEFG")))
            .unwrap();
        let want = NewOrder {
            header: header(0, 100),
            cl_ord_id: text("ABC123"),
            side: b'1',
            order_qty: 1000,
            fields,
        };
        assert_eq!(want.fields.bitfields(), [0x04, 0xC1, 0x01]);
        inbound(&bytes, want.into());
    }

    #[test]
    fn cancel_modify_and_purge_examples() {
        inbound(
            &hex(&format!(
                "BA BA 22 00 39 00 64 00 00 00 {ABC123} 01 01 54 45 53 54"
            )),
            CancelOrder {
                header: header(0, 100),
                orig_cl_ord_id: text("ABC123"),
                fields: Optional::new()
                    .with(Opt::ClearingFirm(text("TEST")))
                    .unwrap(),
            }
            .into(),
        );
        inbound(
            &hex(&format!(
                "BA BA 3E 00 3A 00 64 00 00 00 \
                 41 42 43 31 32 34 00 00 00 00 00 00 00 00 00 00 00 00 00 00 {ABC123} \
                 01 0C E0 2E 00 00 08 E2 01 00 00 00 00 00"
            )),
            ModifyOrder {
                header: header(0, 100),
                cl_ord_id: text("ABC124"),
                orig_cl_ord_id: text("ABC123"),
                fields: Optional::new()
                    .with(Opt::Price("12.34".parse().unwrap()))
                    .unwrap()
                    .with(Opt::OrderQty(12_000))
                    .unwrap(),
            }
            .into(),
        );
        // "Purge Orders Message with RiskGroupID and Lockout Example". Its
        // MessageLength reads 29 00 (41) with a note of 58 bytes; the
        // fields total 58 bytes, 56 (38 00) after StartOfMessage.
        let mass = "46 53 4C 00 00 00 00 00 00 00 00 00 00 00 00 00";
        let bytes = hex(&format!(
            "BA BA 38 00 47 00 64 00 00 00 00 01 15 02 BF BE C0 BE 54 45 53 54 {mass} {ABC123}"
        ));
        inbound(
            &bytes,
            PurgeOrders {
                header: header(0, 100),
                reserved_internal: 0,
                purge: PurgeFields {
                    fields: Optional::new()
                        .with(Opt::ClearingFirm(text("TEST")))
                        .unwrap()
                        .with(Opt::MassCancelInst(text("FSL")))
                        .unwrap()
                        .with(Opt::MassCancelId(text("ABC123")))
                        .unwrap(),
                    risk_group_ids: vec![48_831, 48_832],
                },
            }
            .into(),
        );
        // "... with Symbol and Lockout Example": 63 bytes in all, so 3D 00.
        let bytes = hex(&format!(
            "BA BA 3D 00 47 00 64 00 00 00 00 02 15 01 00 54 45 53 54 {mass} {ABC123} \
             41 42 43 44 45 00 00 00"
        ));
        let Inbound::PurgeOrders(p) = Inbound::parse(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(p.purge.fields.symbol(), Some(text("ABCDE")));
        assert!(p.purge.risk_group_ids.is_empty());
        check_wire::<Inbound>(&bytes);
    }

    #[test]
    fn acknowledgment_examples() {
        let ack = |fields| -> Outbound {
            OrderAcknowledgment {
                header: header(3, 100),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                order_id: OID,
                reserved_internal: 0,
                fields,
            }
            .into()
        };
        outbound(
            &hex(&format!(
                "BA BA 4E 00 25 03 64 00 00 00 {TIME} {ABC123} {ORDER_ID} 00 03 00 41 05 \
                 4D 53 46 54 00 00 00 00 50 41 42 43 00 00 00 00 00 00 00 00 00 00 00 00 00 \
                 00 00 00 00"
            )),
            ack(returns(vec![
                Opt::Symbol(text("MSFT")),
                Opt::Capacity(b'P'),
                Opt::Account(text("ABC")),
                Opt::ClearingAccount(Text::default()),
            ])),
        );
        outbound(
            &hex(&format!(
                "BA BA 2E 00 25 03 64 00 00 00 {TIME} {ABC123} {ORDER_ID} 00 00"
            )),
            ack(Optional::new()),
        );
    }

    #[test]
    fn reject_examples() {
        outbound(
            &hex(&format!(
                "BA BA 76 00 26 00 00 00 00 00 {TIME} {ABC123} 44 {} 00 03 00 01 06 \
                 4D 53 46 54 00 00 00 00 54 45 53 54 00 00 00 00",
                nul_text("Duplicate ClOrdID")
            )),
            OrderRejected {
                header: Header::default(),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                reason: b'D',
                text: text("Duplicate ClOrdID"),
                reserved_internal: 0,
                fields: returns(vec![
                    Opt::Symbol(text("MSFT")),
                    Opt::ClearingFirm(text("TEST")),
                    Opt::ClearingAccount(Text::default()),
                ]),
            }
            .into(),
        );
        outbound(
            &hex(&format!(
                "BA BA 63 00 29 00 00 00 00 00 {TIME} {ABC123} 50 {} 00 00",
                nul_text("Pending")
            )),
            UserModifyRejected {
                header: Header::default(),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                reason: b'P',
                text: text("Pending"),
                reserved_internal: 0,
                fields: Optional::new(),
            }
            .into(),
        );
        outbound(
            &hex(&format!(
                "BA BA 63 00 2B 00 00 00 00 00 {TIME} {ABC123} 4A {} 00 00",
                nul_text("TOO LATE")
            )),
            CancelRejected {
                header: Header::default(),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                reason: b'J',
                text: text("TOO LATE"),
                reserved_internal: 0,
                fields: Optional::new(),
            }
            .into(),
        );
        let mut bits = Optional::new();
        bits.set(Opt::MassCancelId(text("TEST"))).unwrap();
        assert_eq!(bits.bitfield_count(), 15);
        outbound(
            &hex(&format!(
                "BA BA 72 00 48 00 00 00 00 00 {TIME} 41 {} 00 0F \
                 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 \
                 54 45 53 54 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                nul_text("ADMIN")
            )),
            PurgeRejected {
                header: Header::default(),
                transaction_time: T,
                reason: b'A',
                text: text("ADMIN"),
                reserved_internal: 0,
                fields: bits,
            }
            .into(),
        );
    }

    #[test]
    fn modified_restated_cancelled_examples() {
        // "Order Modified Message Example": five bitfields for two fields,
        // so the count is kept. Its MessageLength reads 35 00 (53) where
        // the note and the fields make 63 (3F 00).
        let mut fields = returns(vec![
            Opt::Price("12.34".parse().unwrap()),
            Opt::LeavesQty(0),
        ]);
        fields.set_bitfield_count(5).unwrap();
        assert_eq!(fields.set_bitfield_count(4), Err(Error::Count));
        outbound(
            &hex(&format!(
                "BA BA 3F 00 27 03 64 00 00 00 {TIME} {ABC123} {ORDER_ID} 00 05 04 00 00 00 02 \
                 08 E2 01 00 00 00 00 00 00 00 00 00"
            )),
            OrderModified {
                header: header(3, 100),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                order_id: OID,
                reserved_internal: 0,
                fields,
            }
            .into(),
        );
        let mut fields = returns(vec![Opt::LeavesQty(100), Opt::SecondaryOrderId(OID + 5)]);
        fields.set_bitfield_count(6).unwrap();
        outbound(
            &hex(&format!(
                "BA BA 41 00 28 03 64 00 00 00 {TIME} {ABC123} {ORDER_ID} 4C 00 06 00 00 00 00 02 01 \
                 64 00 00 00 0A 10 1E B7 5E 39 2F 02"
            )),
            OrderRestated {
                header: header(3, 100),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                order_id: OID,
                restatement_reason: b'L',
                reserved_internal: 0,
                fields,
            }
            .into(),
        );
        outbound(
            &hex(&format!(
                "BA BA 48 00 2A 03 64 00 00 00 {TIME} {ABC123} 55 00 05 00 00 06 00 01 \
                 54 45 53 54 31 32 33 34 41 42 43 31 32 31 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            )),
            OrderCancelled {
                header: header(3, 100),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                reason: b'U',
                reserved_internal: 0,
                fields: returns(vec![
                    Opt::ClearingFirm(text("TEST")),
                    Opt::ClearingAccount(text("1234")),
                    Opt::OrigClOrdId(text("ABC121")),
                ]),
            }
            .into(),
        );
    }

    #[test]
    fn execution_and_trade_examples() {
        let exec_id = "01 F0 B7 D9 71 21 00 00";
        let eid = 0x2171_d9b7_f001;
        outbound(
            &hex(&format!(
                "BA BA 53 00 2C 03 64 00 00 00 {TIME} {ABC123} {exec_id} 64 00 00 00 \
                 08 E2 01 00 00 00 00 00 14 00 00 00 41 00 42 41 54 53 00 03 00 00 46 \
                 54 45 53 54 31 32 33 43 78 00 00 00"
            )),
            OrderExecution {
                header: header(3, 100),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                exec_id: eid,
                last_shares: 100,
                last_px: Price(123_400),
                leaves_qty: 20,
                base_liquidity_indicator: b'A',
                sub_liquidity_indicator: 0,
                contra_broker: text("BATS"),
                reserved_internal: 0,
                fields: returns(vec![
                    Opt::ClearingFirm(text("TEST")),
                    Opt::ClearingAccount(text("123C")),
                    Opt::OrderQty(120),
                ]),
            }
            .into(),
        );
        outbound(
            &hex(&format!(
                "BA BA 66 00 2D 03 64 00 00 00 {TIME} {ABC123} {ORDER_ID} {exec_id} 31 41 \
                 54 45 53 54 00 00 00 00 C4 09 00 00 5C 13 04 00 00 00 00 00 \
                 00 00 00 00 00 00 00 00 E0 BA 75 95 15 4C EB 11 00 02 00 01 \
                 4D 53 46 54 00 00 00 00"
            )),
            TradeCancelOrCorrect {
                header: header(3, 100),
                transaction_time: T,
                cl_ord_id: text("ABC123"),
                order_id: OID,
                exec_ref_id: eid,
                side: b'1',
                base_liquidity_indicator: b'A',
                clearing_firm: text("TEST"),
                clearing_account: Text::default(),
                last_shares: 2_500,
                last_px: "26.71".parse().unwrap(),
                corrected_price: Price(0),
                orig_time: 1_291_209_373_757_324_000,
                reserved_internal: 0,
                fields: returns(vec![Opt::Symbol(text("MSFT"))]),
            }
            .into(),
        );
        // "Mass Cancel Acknowledgement Message Example". It prints one
        // StartOfMessage byte; both are used.
        outbound(
            &hex(&format!(
                "BA BA 29 00 36 00 00 00 00 00 {TIME} {ABC123} 63 00 00 00 00"
            )),
            MassCancelAcknowledgment {
                header: Header::default(),
                transaction_time: T,
                mass_cancel_id: text("ABC123"),
                cancelled_order_count: 99,
                reserved_internal: 0,
                end: (),
            }
            .into(),
        );
    }

    #[test]
    fn prices_and_text() {
        // "Data Types": 08 E2 01 00 ... is 12.34; F8 1D FE FF ... is -12.34.
        assert_eq!(
            Price::get(&hex("F8 1D FE FF FF FF FF FF")),
            Ok(Price(-123_400))
        );
        assert_eq!(Price(-123_400).to_string(), "-12.3400");
        assert_eq!("-12.34".parse::<Price>(), Ok(Price(-123_400)));
        for bad in ["", "-", "1.", "1.23456", "a", "--1"] {
            assert_eq!(bad.parse::<Price>(), Err(Error::Price), "{bad}");
        }
        assert_eq!(Text::<4>::new("TESTS"), Err(Error::Field));
        assert_eq!(Text::<4>::from_bytes(*b"A\0B\0"), Err(Error::Field));
        assert_eq!(Text::<4>::from_bytes(*b"A\x01\0\0"), Err(Error::Field));
        assert!(Text::<4>::default().is_empty());
        assert_eq!(text::<4>("AB").as_str(), "AB");
    }

    #[test]
    fn price_magnitude_bound() {
        assert_eq!("922337203685477.5807".parse::<Price>(), Ok(Price(i64::MAX)));
        assert_eq!(
            "-922337203685477.5807".parse::<Price>(),
            Ok(Price(-i64::MAX))
        );
        assert_eq!(Price(i64::MIN).to_string(), "-922337203685477.5808");
        assert_eq!("-0".parse::<Price>(), Ok(Price(0)));
        for bad in [
            "922337203685477.5808",
            "-922337203685477.5808",
            "-9223372036854775808",
            "+1",
            "-+1",
        ] {
            assert_eq!(bad.parse::<Price>(), Err(Error::Price), "{bad}");
        }
    }

    #[test]
    fn refuses_bad_messages() {
        let hb = ClientHeartbeat::default().to_bytes().unwrap();
        let mut bad = hb.clone();
        bad[0] = 0xBB;
        assert_eq!(Inbound::parse(&bad), Err(Error::Start));
        assert_eq!(Inbound::parse(&hb[..9]), Err(Error::Length));
        let mut bad = hb.clone();
        bad[4] = 0x99;
        assert_eq!(Inbound::parse(&bad), Err(Error::Type(0x99)));
        assert_eq!(LogoutRequest::parse(&hb), Err(Error::Type(0x03)));
        let mut long = hb.clone();
        long.push(0);
        long[2] = 9;
        assert_eq!(Inbound::parse(&long), Err(Error::Length));
        // A New Order bit the equities table does not use (Currency).
        let order = NewOrder {
            header: Header::default(),
            cl_ord_id: text("A"),
            side: b'1',
            order_qty: 1,
            fields: Optional::new(),
        };
        let mut b = order.to_bytes().unwrap();
        assert_eq!(b.len(), 36);
        b[35] = 2;
        b.extend_from_slice(&[0, 0b100]);
        b[2] += 2;
        assert_eq!(Inbound::parse(&b), Err(Error::Bitfield { byte: 1, bit: 2 }));
        // A return field the table does not hold.
        assert_eq!(
            Optional::<CancelOrderTable>::new().with(Opt::Symbol(text("A"))),
            Err(Error::Unsupported(FieldId::Symbol))
        );
        assert_eq!(
            Optional::<ReturnTable>::requested(&[0, 0x04]),
            Err(Error::Bitfield { byte: 1, bit: 2 })
        );
        // A defined parameter group type written as Other.
        let login = LoginRequest {
            params: ParamGroups(vec![ParamGroup::Other {
                kind: 0x80,
                data: vec![],
            }]),
            ..LoginRequest::default()
        };
        assert_eq!(login.to_bytes(), Err(Error::Group(0x80)));
        let login = LoginRequest {
            params: ParamGroups(vec![ParamGroup::Other {
                kind: 0x99,
                data: vec![1, 2],
            }]),
            ..LoginRequest::default()
        };
        check_wire_value(&Inbound::from(login));
        let purge = PurgeOrders {
            purge: PurgeFields {
                fields: Optional::new(),
                risk_group_ids: vec![0; 256],
            },
            ..PurgeOrders::default()
        };
        assert_eq!(purge.to_bytes(), Err(Error::Count));
    }

    #[test]
    fn frames_follow_the_contract() {
        let mut bytes = Vec::new();
        for m in [
            Outbound::from(ServerHeartbeat::default()),
            ReplayComplete::default().into(),
        ] {
            m.write(&mut bytes).unwrap();
        }
        // A message that frames but does not parse is an item.
        bytes.extend_from_slice(&[0xBA, 0xBA, 8, 0, 0x99, 0, 0, 0, 0, 0]);
        ServerHeartbeat::default().write(&mut bytes).unwrap();
        MassCancelAcknowledgment::default()
            .write(&mut bytes)
            .unwrap();
        check_decode(Frames::<Outbound>::default, &bytes);
        check_decode(|| Frames::<Outbound>::with_limit(12), &bytes);
        check_decode_with_alloc_limit(Frames::<Outbound>::default, &bytes, 2 * MAX_MESSAGE);
        let (items, failure) = decode_all(Frames::<Outbound>::default, &bytes);
        assert!(failure.is_none());
        assert_eq!(items.len(), 5);
        assert_eq!(items[2], Err(Error::Type(0x99)));
        let (_, failure) = decode_all(Frames::<Outbound>::default, &[0xBA, 0xBB, 8, 0]);
        assert_eq!(failure, Some(Fail::Protocol(Error::Start)));
        let (_, failure) = decode_all(Frames::<Outbound>::default, &[0x00]);
        assert_eq!(failure, Some(Fail::Protocol(Error::Start)));
        let (_, failure) = decode_all(Frames::<Outbound>::default, &[0xBA, 0xBA, 7, 0]);
        assert_eq!(failure, Some(Fail::Protocol(Error::Length)));
        let (_, failure) = decode_all(|| Frames::<Outbound>::with_limit(11), &bytes);
        assert_eq!(failure, Some(Fail::Protocol(Error::TooLong)));
    }

    fn config() -> ClientConfig {
        ClientConfig {
            session_sub_id: text("0001"),
            username: text("TEST"),
            password: text("TESTING"),
            no_unspecified_unit_replay: false,
            returns: vec![
                (0x25, vec![0x04, 0x41, 0x05]),
                (0x2C, vec![0, 0, 0x46, 0, 0x02]),
                (0x27, vec![0, 0, 0, 0, 0x03]),
                (0x2A, vec![0, 0, 0, 0, 0x03]),
            ],
            timers: Timers::default(),
        }
    }
    /// Delivers every Send through bytes; returns the events.
    fn deliver_to_client(
        client: &mut Client,
        actions: Vec<Action<Outbound, Event>>,
        now: u64,
    ) -> Vec<Event> {
        let mut events = Vec::new();
        for a in actions {
            match a {
                Action::Send(m) => {
                    let back = Outbound::parse(&m.to_bytes().unwrap()).unwrap();
                    for e in client.receive(&back, now).unwrap() {
                        if let Action::Event(e) = e {
                            events.push(e);
                        }
                    }
                }
                Action::Event(e) => events.push(e),
            }
        }
        events
    }
    fn login(client: &mut Client, server: &mut Server, available: &[UnitSequence]) -> Vec<Event> {
        let Action::Send(req) = client.start(0).unwrap().remove(0) else {
            panic!()
        };
        let req = Inbound::parse(&req.to_bytes().unwrap()).unwrap();
        let ev = server.receive(&req, 1).unwrap();
        assert!(matches!(&ev[..], [Action::Event(Event::LoginRequested(_))]));
        let actions = server.accept(150, available, 2).unwrap();
        deliver_to_client(client, actions, 3)
    }

    #[test]
    fn login_replay_and_sequencing() {
        let mut client = Client::new(config(), &[unit_sequence(1, 5)], 0).unwrap();
        let mut server = Server::new(Timers::default(), 0).unwrap();
        let events = login(
            &mut client,
            &mut server,
            &[unit_sequence(1, 7), unit_sequence(2, 3)],
        );
        // Unit 1 from 6, unit 2 (unspecified) from 1.
        assert_eq!(
            events,
            [
                Event::LoggedIn {
                    last_received_sequence: 150,
                    units: vec![unit_sequence(1, 7), unit_sequence(2, 3)]
                },
                Event::Replay {
                    unit: 1,
                    after: 5,
                    through: 7
                },
                Event::Replay {
                    unit: 2,
                    after: 0,
                    through: 3
                },
            ]
        );
        assert_eq!(server.phase(), ServerPhase::Replaying);
        assert_eq!(client.phase(), ClientPhase::Replaying);
        assert_eq!(client.next_sequence(), 151);
        // Orders are refused during replay, on both sides.
        let order: Inbound = NewOrder {
            cl_ord_id: text("X"),
            ..NewOrder::default()
        }
        .into();
        assert_eq!(client.send(order.clone(), 4), Err(Error::State));
        let replies = server.receive(&order, 4).unwrap();
        let [Action::Send(Outbound::OrderRejected(r))] = &replies[..] else {
            panic!("{replies:?}")
        };
        assert_eq!(r.reason, b'y');
        // Replay one stored message per unit, then complete.
        let stored = |unit, sequence| -> Outbound {
            OrderCancelled {
                header: header(unit, sequence),
                ..OrderCancelled::default()
            }
            .into()
        };
        assert_eq!(server.replay(&stored(1, 8), 5), Err(Error::Sequence));
        assert_eq!(server.send(stored(1, 0), 5), Err(Error::State));
        for (u, s) in [(1, 6), (1, 7), (2, 1)] {
            let m = server.replay(&stored(u, s), 5).unwrap();
            let ev = client.receive(&m, 5).unwrap();
            assert_eq!(ev, [Action::Event(Event::Sequenced(unit_sequence(u, s)))]);
        }
        // The client skips what it has.
        assert_eq!(
            client.receive(&stored(1, 6), 5).unwrap(),
            [Action::Event(Event::Duplicate(unit_sequence(1, 6)))]
        );
        let done = server.replay_complete(6).unwrap();
        assert_eq!(
            deliver_to_client(&mut client, done, 6),
            [Event::ReplayComplete]
        );
        // Application numbering: client from 151, server per unit.
        let sent = client.send(order.clone(), 7).unwrap();
        assert_eq!(sent.header().sequence, 151);
        assert_eq!(
            server.receive(&sent, 7).unwrap(),
            [Action::Event(Event::Application)]
        );
        let a = server.send(stored(2, 0), 8).unwrap();
        assert_eq!(*a.header(), header(2, 4));
        let b = server.send(stored(1, 0), 8).unwrap();
        assert_eq!(*b.header(), header(1, 8));
        // Unit 3 starts at 1. A gap on the client is reported.
        let c = server.send(stored(3, 0), 8).unwrap();
        assert_eq!(c.header().sequence, 1);
        let skip = stored(2, 9);
        assert_eq!(
            client.receive(&skip, 9).unwrap(),
            [Action::Event(Event::Gap {
                unit: 2,
                expected: 2,
                received: 9
            })]
        );
        // Unsequenced replies get unit and sequence 0.
        let rej = server.send(CancelRejected::default().into(), 9).unwrap();
        assert_eq!(*rej.header(), Header::default());
        assert_eq!(
            client.receive(&rej, 9).unwrap(),
            [Action::Event(Event::Unsequenced)]
        );
        assert_eq!(
            server.send(ServerHeartbeat::default().into(), 9),
            Err(Error::State)
        );
        // Forward gaps are allowed; going back is a violation.
        let mut ahead = order.clone();
        *ahead.header_mut() = header(0, 500);
        assert_eq!(
            server.receive(&ahead, 10).unwrap(),
            [Action::Event(Event::Application)]
        );
        let actions = server.receive(&sent, 10).unwrap();
        let [
            Action::Send(Outbound::Logout(l)),
            Action::Event(Event::Disconnected(CloseReason::Protocol)),
        ] = &actions[..]
        else {
            panic!("{actions:?}")
        };
        assert_eq!((l.reason, l.last_received_sequence), (b'!', 500));
        assert_eq!(server.receive(&sent, 11), Err(Error::State));
        let events = deliver_to_client(&mut client, actions, 11);
        assert_eq!(
            events[0],
            Event::LoggedOut {
                reason: b'!',
                text: text("Sequence went backwards")
            }
        );
        assert_eq!(client.phase(), ClientPhase::Closed);
        assert_eq!(
            client.last_received(),
            [unit_sequence(1, 7), unit_sequence(2, 9)]
        );
    }

    #[test]
    fn login_refusals() {
        let refuse = |last: &[UnitSequence], cfg: ClientConfig, status| {
            let mut client = Client::new(cfg, last, 0).unwrap();
            let mut server = Server::new(Timers::default(), 0).unwrap();
            let events = login(&mut client, &mut server, &[unit_sequence(1, 10)]);
            assert!(
                matches!(&events[..], [Event::Rejected { status: s, .. }, Event::Disconnected(CloseReason::Rejected), ..] if *s == status),
                "{events:?}"
            );
            assert_eq!(server.phase(), ServerPhase::Closed);
        };
        let one = |unit, sequence| [unit_sequence(unit, sequence)];
        refuse(&one(1, 11), config(), b'Q');
        refuse(&one(2, 1), config(), b'I');
        let mut bad = config();
        bad.returns.push((0x25, vec![0, 0x04]));
        refuse(&[], bad, b'F');
        let mut bad = config();
        bad.returns.push((0x37, vec![1]));
        refuse(&[], bad, b'F');
        // A unit sent with 0 is fine; the caller may also refuse.
        let mut client = Client::new(config(), &one(2, 0), 0).unwrap();
        let mut server = Server::new(Timers::default(), 0).unwrap();
        let events = login(&mut client, &mut server, &one(1, 0));
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(client.phase(), ClientPhase::LoggedIn);
        let mut server = Server::new(Timers::default(), 0).unwrap();
        assert_eq!(server.reject(b'N', "x", 0), Err(Error::State));
        server.receive(&LoginRequest::default().into(), 0).unwrap();
        assert_eq!(server.reject(b'A', "x", 0), Err(Error::State));
        let out = server.reject(b'N', "Not authorized", 1).unwrap();
        assert!(matches!(&out[0], Action::Send(Outbound::LoginResponse(r)) if r.status == b'N'));
        // Anything before login closes.
        let mut server = Server::new(Timers::default(), 0).unwrap();
        assert_eq!(
            server
                .receive(&ClientHeartbeat::default().into(), 0)
                .unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::Protocol))]
        );
    }

    #[test]
    fn heartbeats_timeouts_and_logout() {
        let mut client = Client::new(config(), &[], 0).unwrap();
        let mut server = Server::new(Timers::default(), 0).unwrap();
        login(&mut client, &mut server, &[]);
        assert_eq!(client.phase(), ClientPhase::LoggedIn);
        assert_eq!(client.tick(500).unwrap(), []);
        assert_eq!(
            client.tick(1_003).unwrap(),
            [Action::Send(ClientHeartbeat::default().into())]
        );
        assert_eq!(
            server.tick(1_002).unwrap(),
            [Action::Send(ServerHeartbeat::default().into())]
        );
        assert_eq!(
            fictionet::stdlib::test_support::check_atomic(
                &mut server,
                |s| s.tick(1_000),
                |s| format!("{s:?}")
            ),
            Err(Error::Time)
        );
        server
            .receive(&ClientHeartbeat::default().into(), 1_003)
            .unwrap();
        // Five seconds without input: Logout "!" and close.
        let out = server.tick(6_003).unwrap();
        assert!(matches!(
            &out[..],
            [Action::Send(Outbound::Logout(l)), Action::Event(Event::Disconnected(CloseReason::IdleTimeout))]
                if l.reason == b'!'
        ));
        assert_eq!(
            client.tick(5_003).unwrap(),
            [Action::Event(Event::Disconnected(CloseReason::IdleTimeout))]
        );
        // A polite logout.
        let mut client = Client::new(config(), &[], 0).unwrap();
        let mut server = Server::new(Timers::default(), 0).unwrap();
        login(&mut client, &mut server, &[]);
        let Action::Send(req) = client.logout(10).unwrap().remove(0) else {
            panic!()
        };
        assert_eq!(client.phase(), ClientPhase::LoggingOut);
        let out = server.receive(&req, 11).unwrap();
        let events = deliver_to_client(&mut client, out, 12);
        assert_eq!(
            events,
            [
                Event::LoggedOut {
                    reason: b'U',
                    text: text("User")
                },
                Event::Disconnected(CloseReason::Logout),
                Event::Disconnected(CloseReason::Logout)
            ]
        );
        // Login timeout.
        let mut client = Client::new(config(), &[], 0).unwrap();
        client.start(0).unwrap();
        assert_eq!(
            client.tick(LOGIN_TIMEOUT_MS).unwrap(),
            [Action::Event(Event::Disconnected(
                CloseReason::LoginTimeout
            ))]
        );
        let mut server = Server::new(Timers::default(), 0).unwrap();
        assert_eq!(
            server.tick(LOGIN_TIMEOUT_MS).unwrap(),
            [Action::Event(Event::Disconnected(
                CloseReason::LoginTimeout
            ))]
        );
        assert!(
            Client::new(
                ClientConfig {
                    timers: Timers {
                        heartbeat_ms: 0,
                        ..Timers::default()
                    },
                    ..config()
                },
                &[],
                0
            )
            .is_err()
        );
    }

    fn new_order(id: &str, qty: u32, fields: Vec<Opt>) -> Inbound {
        let mut o = Optional::new();
        for f in fields {
            o.set(f).unwrap();
        }
        NewOrder {
            header: Header::default(),
            cl_ord_id: text(id),
            side: b'1',
            order_qty: qty,
            fields: o,
        }
        .into()
    }
    fn good(id: &str, qty: u32) -> Inbound {
        new_order(
            id,
            qty,
            vec![
                Opt::Price("10".parse().unwrap()),
                Opt::Symbol(text("ZVZZT")),
                Opt::Capacity(b'A'),
                Opt::ClearingFirm(text("FIRM")),
                Opt::RiskGroupId(7),
            ],
        )
    }
    fn exchange() -> Exchange {
        let returns = config().returns.into_iter().collect();
        Exchange::new(ExchangeConfig::default(), returns).unwrap()
    }
    fn reply(actions: &[Action<Outbound, OrderEvent>]) -> &Outbound {
        match actions.first() {
            Some(Action::Send(m)) => m,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn orders_follow_client_order_id_order() {
        let mut x = exchange();
        for id in ["Z9", "A2", "M3", "A10", "B1"] {
            assert_eq!(
                x.receive(&good(id, 100), 0),
                [Action::Event(OrderEvent::NewOrderRequested(text(id)))]
            );
        }
        x.accept(text("M3"), 2, 0).unwrap();
        assert_eq!(
            x.orders().map(|o| o.cl_ord_id).collect::<Vec<_>>(),
            ["A10", "A2", "B1", "M3", "Z9"].map(text)
        );
    }

    #[test]
    fn exchange_order_life_cycle() {
        let mut x = exchange();
        let id = text("A1");
        assert_eq!(
            x.receive(&good("A1", 300), 1),
            [Action::Event(OrderEvent::NewOrderRequested(id))]
        );
        let Outbound::OrderAcknowledgment(ack) = x.accept(id, 2, 2).unwrap() else {
            panic!()
        };
        assert_eq!((ack.header.unit, ack.order_id), (2, 1));
        // Price, Symbol, Capacity, Account, ClearingAccount as asked: the
        // order had no Account, so it is zero.
        assert_eq!(
            ack.fields.fields(),
            [
                Opt::Price(Price(100_000)),
                Opt::Symbol(text("ZVZZT")),
                Opt::Capacity(b'A'),
                Opt::Account(Text::default()),
                Opt::ClearingAccount(Text::default()),
            ]
        );
        check_wire_value(&Outbound::from(ack));
        assert_eq!(x.accept(id, 2, 2), Err(Error::UnknownOrder(id)));
        // Fill 100: ClearingFirm, ClearingAccount, OrderQty, LeavesQty.
        let Outbound::OrderExecution(e) = x.execute(id, 100, Price(99_000), b'A', 3).unwrap()
        else {
            panic!()
        };
        assert_eq!((e.leaves_qty, e.exec_id), (200, 1));
        assert_eq!(
            e.fields.fields(),
            [
                Opt::ClearingFirm(text("FIRM")),
                Opt::ClearingAccount(Text::default()),
                Opt::OrderQty(300),
                Opt::LeavesQty(200),
            ]
        );
        assert_eq!(x.execute(id, 201, Price(1), b'A', 3), Err(Error::Shares));
        // Modify to 250 shares: LeavesQty 200 + (250 - 300) = 150.
        let modify: Inbound = ModifyOrder {
            header: Header::default(),
            cl_ord_id: text("A2"),
            orig_cl_ord_id: id,
            fields: Optional::new()
                .with(Opt::OrderQty(250))
                .unwrap()
                .with(Opt::Price("10.5".parse().unwrap()))
                .unwrap(),
        }
        .into();
        let out = x.receive(&modify, 4);
        let Outbound::OrderModified(m) = reply(&out) else {
            panic!("{out:?}")
        };
        assert_eq!(
            m.fields.fields(),
            [Opt::OrigClOrdId(id), Opt::LeavesQty(150)]
        );
        assert!(x.order(id).is_none());
        let a2 = x.order(text("A2")).unwrap();
        assert_eq!(
            (a2.leaves_qty, a2.price, a2.order_id),
            (150, Some(Price(105_000)), 1)
        );
        // Bust the fill.
        let Outbound::TradeCancelOrCorrect(t) = x.bust(1, Price(0), 5).unwrap() else {
            panic!()
        };
        assert_eq!((t.last_shares, t.clearing_firm), (100, text("FIRM")));
        assert_eq!(x.bust(1, Price(0), 5), Err(Error::UnknownExecution(1)));
        // Restate, then cancel at the member's request.
        let Outbound::OrderRestated(r) = x.restate(text("A2"), 100, b'L', 6).unwrap() else {
            panic!()
        };
        assert_eq!(r.restatement_reason, b'L');
        let cancel: Inbound = CancelOrder {
            header: Header::default(),
            orig_cl_ord_id: text("A2"),
            fields: Optional::new(),
        }
        .into();
        let out = x.receive(&cancel, 7);
        let Outbound::OrderCancelled(c) = reply(&out) else {
            panic!()
        };
        assert_eq!(c.fields.fields(), [Opt::OrigClOrdId(id), Opt::LeavesQty(0)]);
        assert_eq!(out[1], Action::Event(OrderEvent::Cancelled(text("A2"))));
        // Now unknown.
        let out = x.receive(&cancel, 8);
        assert!(matches!(reply(&out), Outbound::CancelRejected(r) if r.reason == b'O'));
        assert_eq!(x.orders().count(), 0);
    }

    // Busts find the execution by ExecID in the bounded store (not by a
    // scan), the oldest is forgotten first, and each bust removes it.
    #[test]
    fn exchange_busts_by_exec_id_within_the_limit() {
        let returns = config().returns.into_iter().collect();
        let config = ExchangeConfig {
            max_executions: 2,
            first_exec_id: 10,
            ..ExchangeConfig::default()
        };
        let mut x = Exchange::new(config, returns).unwrap();
        x.receive(&good("A1", 300), 1);
        x.accept(text("A1"), 1, 1).unwrap();
        for _ in 0..3 {
            x.execute(text("A1"), 1, Price(1), b'A', 2).unwrap();
        }
        assert_eq!(x.executions.len(), 2);
        assert_eq!(x.bust(10, Price(0), 3), Err(Error::UnknownExecution(10)));
        let Outbound::TradeCancelOrCorrect(t) = x.bust(12, Price(0), 3).unwrap() else {
            panic!()
        };
        assert_eq!(t.exec_ref_id, 12);
        assert_eq!(x.bust(12, Price(0), 3), Err(Error::UnknownExecution(12)));
        assert!(x.bust(11, Price(0), 3).is_ok());
        assert!(x.executions.is_empty());
    }

    #[test]
    fn exchange_refuses_bad_orders() {
        let mut x = exchange();
        x.receive(&good("DUP", 1), 0);
        let cases: Vec<(Inbound, u8)> = vec![
            (good("DUP", 1), b'D'),
            (good("Q0", 0), b'M'),
            (good("QBIG", MAX_ORDER_QTY + 1), b'M'),
            (good("bad,id", 1), b'Z'),
            (
                new_order("NOSYM", 1, vec![Opt::Capacity(b'A'), Opt::Price(Price(1))]),
                b'Y',
            ),
            (
                new_order(
                    "NOCAP",
                    1,
                    vec![Opt::Symbol(text("Z")), Opt::Price(Price(1))],
                ),
                b'C',
            ),
            (
                new_order("NOPX", 1, vec![Opt::Symbol(text("Z")), Opt::Capacity(b'A')]),
                b'Z',
            ),
            (
                new_order(
                    "MKTPX",
                    1,
                    vec![
                        Opt::Symbol(text("Z")),
                        Opt::Capacity(b'A'),
                        Opt::OrdType(b'1'),
                        Opt::Price(Price(1)),
                    ],
                ),
                b'Z',
            ),
        ];
        for (m, reason) in cases {
            let before = format!("{:?}", x.orders);
            let out = x.receive(&m, 1);
            assert!(
                matches!(reply(&out), Outbound::OrderRejected(r) if r.reason == reason),
                "{out:?}"
            );
            assert_eq!(format!("{:?}", x.orders), before);
        }
        // A market order needs no price.
        let market = new_order(
            "MKT",
            1,
            vec![
                Opt::Symbol(text("Z")),
                Opt::Capacity(b'A'),
                Opt::OrdType(b'1'),
            ],
        );
        assert!(matches!(
            &x.receive(&market, 1)[..],
            [Action::Event(OrderEvent::NewOrderRequested(_))]
        ));
        // The world rejects a pending order.
        let Outbound::OrderRejected(r) = x.reject(text("MKT"), b'H', "Halted", 2).unwrap() else {
            panic!()
        };
        assert_eq!(r.reason, b'H');
        assert!(x.order(text("MKT")).is_none());
        // Order limit.
        let mut small = Exchange::new(
            ExchangeConfig {
                max_orders: 1,
                ..ExchangeConfig::default()
            },
            BTreeMap::new(),
        )
        .unwrap();
        small.receive(&good("A", 1), 0);
        assert!(
            matches!(reply(&small.receive(&good("B", 1), 0)), Outbound::OrderRejected(r) if r.reason == b'o')
        );
        assert!(
            Exchange::new(
                ExchangeConfig::default(),
                [(0x25, vec![0, 0x04])].into_iter().collect()
            )
            .is_err()
        );
    }

    #[test]
    fn exchange_modify_rules() {
        let mut x = exchange();
        x.receive(&good("A", 100), 0);
        x.accept(text("A"), 1, 0).unwrap();
        x.receive(&good("B", 100), 0);
        x.accept(text("B"), 1, 0).unwrap();
        let modify = |cl: &str, orig: &str, fields: Vec<Opt>| -> Inbound {
            let mut o = Optional::new();
            for f in fields {
                o.set(f).unwrap();
            }
            ModifyOrder {
                header: Header::default(),
                cl_ord_id: text(cl),
                orig_cl_ord_id: text(orig),
                fields: o,
            }
            .into()
        };
        let qp = |q| vec![Opt::OrderQty(q), Opt::Price(Price(1))];
        for (m, reason) in [
            (modify("C", "Z", qp(1)), b'O'),
            (modify("C", "A", vec![Opt::Price(Price(1))]), b'Z'),
            (modify("C", "A", vec![Opt::OrderQty(1)]), b'Z'),
            (modify("B", "A", qp(1)), b'D'),
            (modify("A", "A", qp(100)), b'D'),
            (modify("C", "A", qp(0)), b'M'),
        ] {
            let out = x.receive(&m, 1);
            assert!(
                matches!(reply(&out), Outbound::UserModifyRejected(r) if r.reason == reason),
                "{reason} {out:?}"
            );
        }
        // Reuse of the ClOrdID to reduce is allowed.
        let out = x.receive(&modify("A", "A", qp(60)), 2);
        assert!(matches!(reply(&out), Outbound::OrderModified(_)));
        assert_eq!(x.order(text("A")).unwrap().leaves_qty, 60);
        // A side change carries over.
        let mut f = qp(60);
        f.push(Opt::Side(b'5'));
        x.receive(&modify("A3", "A", f), 3);
        assert_eq!(x.order(text("A3")).unwrap().side, b'5');
        // Filled 50 of B, then a modify to 40 leaves nothing: done.
        x.execute(text("B"), 50, Price(1), b'R', 4).unwrap();
        let out = x.receive(&modify("B2", "B", qp(40)), 5);
        let Outbound::OrderModified(m) = reply(&out) else {
            panic!()
        };
        assert_eq!(m.fields.leaves_qty(), Some(0));
        assert!(x.order(text("B2")).is_none());
    }

    #[test]
    fn exchange_purges() {
        let mut x = exchange();
        for (id, sym, firm, group) in [
            ("A", "AAA", "FIRM", 1u16),
            ("B", "BBB", "FIRM", 2),
            ("C", "AAA", "OTHR", 1),
        ] {
            x.receive(
                &new_order(
                    id,
                    10,
                    vec![
                        Opt::Price(Price(1)),
                        Opt::Symbol(text(sym)),
                        Opt::Capacity(b'A'),
                        Opt::ClearingFirm(text(firm)),
                        Opt::RiskGroupId(group),
                    ],
                ),
                0,
            );
            x.accept(text(id), 1, 0).unwrap();
        }
        let purge = |inst: &str, fields: Vec<Opt>, groups: Vec<u16>| -> Inbound {
            let mut o = Optional::new()
                .with(Opt::MassCancelInst(text(inst)))
                .unwrap();
            for f in fields {
                o.set(f).unwrap();
            }
            PurgeOrders {
                header: Header::default(),
                reserved_internal: 0,
                purge: PurgeFields {
                    fields: o,
                    risk_group_ids: groups,
                },
            }
            .into()
        };
        // Refusals.
        for m in [
            purge("F", vec![], vec![]),
            purge("AS", vec![], vec![]),
            purge("Q", vec![], vec![]),
            purge("A", vec![Opt::Symbol(text("AAA"))], vec![1]),
            purge("A", vec![], vec![0; 11]),
        ] {
            let out = x.receive(&m, 1);
            assert!(matches!(reply(&out), Outbound::PurgeRejected(_)), "{out:?}");
        }
        // By firm and group 1, single ack: only A.
        let out = x.receive(
            &purge(
                "FSL",
                vec![
                    Opt::ClearingFirm(text("FIRM")),
                    Opt::MassCancelId(text("M1")),
                ],
                vec![1],
            ),
            2,
        );
        assert_eq!(out.len(), 2);
        let Outbound::MassCancelAcknowledgment(a) = reply(&out) else {
            panic!()
        };
        assert_eq!(a.cancelled_order_count, 1);
        assert_eq!(
            out[1],
            Action::Event(OrderEvent::Purged {
                count: 1,
                lockout: true
            })
        );
        // Everything, both acks.
        let out = x.receive(&purge("AB", vec![Opt::MassCancelId(text("M2"))], vec![]), 3);
        assert_eq!(out.len(), 4);
        assert!(matches!(&out[0], Action::Send(Outbound::OrderCancelled(_))));
        assert!(
            matches!(&out[2], Action::Send(Outbound::MassCancelAcknowledgment(a)) if a.cancelled_order_count == 2)
        );
        assert_eq!(x.orders().count(), 0);
    }

    /// One value of every inbound and outbound type.
    fn samples() -> (Vec<Inbound>, Vec<Outbound>) {
        let mut inbound = vec![
            LoginRequest::default().into(),
            LogoutRequest::default().into(),
            ClientHeartbeat::default().into(),
            good("A", 1),
            CancelOrder::default().into(),
            ModifyOrder::default().into(),
            PurgeOrders::default().into(),
        ];
        let Inbound::LoginRequest(l) = &mut inbound[0] else {
            unreachable!()
        };
        l.params = ParamGroups(vec![
            ParamGroup::UnitSequences {
                no_unspecified_unit_replay: 0,
                units: vec![UnitSequence::default()],
            },
            ParamGroup::ReturnBitfields {
                message_type: 0x25,
                bitfields: vec![0xff],
            },
        ]);
        let outbound = vec![
            LoginResponse::default().into(),
            Logout::default().into(),
            ServerHeartbeat::default().into(),
            ReplayComplete::default().into(),
            OrderAcknowledgment {
                fields: Optional::requested(&[0x7f, 0x41, 0xff, 0, 0xff, 0x19, 1, 0x7f]).unwrap(),
                ..OrderAcknowledgment::default()
            }
            .into(),
            OrderRejected::default().into(),
            OrderModified::default().into(),
            OrderRestated::default().into(),
            UserModifyRejected::default().into(),
            OrderCancelled::default().into(),
            CancelRejected::default().into(),
            OrderExecution::default().into(),
            TradeCancelOrCorrect::default().into(),
            MassCancelAcknowledgment::default().into(),
            PurgeRejected {
                fields: Optional::requested(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0x48, 0x68,
                ])
                .unwrap(),
                ..PurgeRejected::default()
            }
            .into(),
        ];
        (inbound, outbound)
    }

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
        for m in &inbound {
            check_wire_value(m);
            let b = m.to_bytes().unwrap();
            assert_eq!(b.len(), m.wire_len());
            assert_eq!(
                Inbound::fixed_of(m.kind()).map(|f| f <= b.len()),
                Some(true)
            );
        }
        for m in &outbound {
            check_wire_value(m);
            assert_eq!(m.to_bytes().unwrap().len(), m.wire_len());
        }
        // Every field in a table has a size and reads its zero value.
        for id in FieldId::ALL {
            let zero = Opt::zero(*id);
            let mut b = Vec::new();
            zero.put(&mut b);
            assert_eq!(b.len(), id.size());
            assert_eq!(Opt::read(*id, &b), Ok(zero));
        }
    }

    #[test]
    fn mutated_messages_keep_the_contract() {
        let (inbound, outbound) = samples();
        let mut bases: Vec<Vec<u8>> = inbound.iter().map(|m| m.to_bytes().unwrap()).collect();
        bases.extend(outbound.iter().map(|m| m.to_bytes().unwrap()));
        let stream: Vec<u8> = bases.concat();
        let mut rng = Lcg::new(0xb0e5);
        for _ in 0..800 {
            let mut bytes = bases[rng.index(bases.len())].clone();
            for _ in 0..=rng.below(3) {
                mutate(&mut rng, &mut bytes);
            }
            check_wire::<Inbound>(&bytes);
            check_wire::<Outbound>(&bytes);
            check_wire::<NewOrder>(&bytes);
            check_wire::<LoginResponse>(&bytes);
            if let Ok(m) = Inbound::parse(&bytes) {
                let mut x = exchange();
                for a in x.receive(&m, 0) {
                    if let Action::Send(out) = a {
                        check_wire_value(&out);
                    }
                }
                let mut server = Server::new(Timers::default(), 0).unwrap();
                let _ = server.receive(&m, 0);
            }
        }
        for _ in 0..100 {
            let mut bytes = stream.clone();
            for _ in 0..=rng.below(4) {
                mutate(&mut rng, &mut bytes);
            }
            check_decode(Frames::<Inbound>::default, &bytes);
            check_decode(Frames::<Outbound>::default, &bytes);
        }
    }

    // Random operations on a logged-in pair: an `Err` changes nothing,
    // and every message sent writes and reads back.
    #[test]
    fn sessions_stay_consistent_under_random_drives() {
        let mut rng = Lcg::new(0x5e55);
        for _ in 0..40 {
            let mut client = Client::new(config(), &[], 0).unwrap();
            let mut server = Server::new(Timers::default(), 0).unwrap();
            login(&mut client, &mut server, &[unit_sequence(1, 0)]);
            let mut x = Exchange::new(ExchangeConfig::default(), server.returns().clone()).unwrap();
            let mut now = 3;
            for step in 0..60u32 {
                now += rng.below(800);
                if rng.below(10) == 0 && now > 2 {
                    now -= 2;
                }
                let (cb, sb) = (format!("{client:?}"), format!("{server:?}"));
                let id = format!("O{}", rng.below(5));
                let m = match rng.below(4) {
                    0 => good(&id, rng.below(50) as u32),
                    1 => CancelOrder {
                        orig_cl_ord_id: text(&id),
                        ..CancelOrder::default()
                    }
                    .into(),
                    2 => ModifyOrder {
                        cl_ord_id: text(&format!("M{step}")),
                        orig_cl_ord_id: text(&id),
                        fields: Optional::new()
                            .with(Opt::OrderQty(rng.below(40) as u32))
                            .unwrap()
                            .with(Opt::Price(Price(1)))
                            .unwrap(),
                        ..ModifyOrder::default()
                    }
                    .into(),
                    _ => ClientHeartbeat::default().into(),
                };
                let sent = if m.is_application() {
                    client.send(m, now)
                } else {
                    Ok(m)
                };
                let Ok(sent) = sent else {
                    assert_eq!(format!("{client:?}"), cb);
                    continue;
                };
                let Ok(actions) = server.receive(&sent, now) else {
                    assert_eq!(format!("{server:?}"), sb);
                    continue;
                };
                let mut outs = Vec::new();
                if actions == [Action::Event(Event::Application)] {
                    for a in x.receive(&sent, u64::from(step)) {
                        match a {
                            Action::Send(o) => outs.push(o),
                            Action::Event(OrderEvent::NewOrderRequested(c)) => {
                                outs.push(x.accept(c, 1, 0).unwrap());
                                if let Ok(e) = x.execute(c, 1, Price(1), b'A', 0) {
                                    outs.push(e);
                                }
                            }
                            Action::Event(_) => {}
                        }
                    }
                }
                for o in outs {
                    let Ok(o) = server.send(o, now) else { continue };
                    let back = Outbound::parse(&o.to_bytes().unwrap()).unwrap();
                    assert_eq!(back, o);
                    let _ = client.receive(&back, now);
                }
                let _ = client.tick(now);
                let _ = server.tick(now);
            }
        }
    }
}
