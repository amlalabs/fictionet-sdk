//! Clocks a world's time server can describe in its NTP replies
//! ([`ServerInfo`]).
//!
//! ```
//! use fictionet::stdlib::protocols::ntp::{Packet, Timestamp, server_reply};
//! use fictionet_extras::ntp;
//!
//! let now = Timestamp::from_unix(1_700_000_000, 0);
//! let request = Packet::client_request(now);
//! let server = ntp::gps_clock(Timestamp::from_unix(1_699_999_984, 0));
//! let reply = server_reply(&request, &server, now, now).unwrap();
//! assert_eq!(reply.reference_id, *b"GPS\0");
//! ```

use fictionet::stdlib::protocols::ntp::{Leap, ServerInfo, Timestamp};

/// A stratum 1 server with a GPS receiver as its reference clock, precise
/// to about a microsecond, with no leap second coming. `reference` is when
/// its clock was last set from the receiver: a few seconds before the
/// replies, as a real server's would be.
pub fn gps_clock(reference: Timestamp) -> ServerInfo {
    ServerInfo {
        leap: Leap::None,
        stratum: 1,
        precision: -20,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: *b"GPS\0",
        reference,
    }
}
