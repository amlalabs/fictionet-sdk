//! Linux transport choices for worlds that emulate a Linux host.
//!
//! Based on Linux v6.12: `net/ipv4/tcp_output.c` (`tcp_options_write`,
//! `tcp_select_initial_window`), `net/ipv4/syncookies.c`,
//! `net/ipv6/syncookies.c`, and `include/net/tcp.h` (`TCP_TIMEWAIT_LEN`).
//! The window values assume an Ethernet MTU of 1500 and default receive
//! memory settings. Linux sysctls and route metrics can change them.
//!
//! Sources: [TCP output](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_output.c),
//! [IPv4 cookies](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/syncookies.c),
//! [IPv6 cookies](https://github.com/torvalds/linux/blob/v6.12/net/ipv6/syncookies.c),
//! [TCP timers](https://github.com/torvalds/linux/blob/v6.12/include/net/tcp.h),
//! and [MPTCP options](https://github.com/torvalds/linux/blob/v6.12/net/mptcp/options.c).

use fictionet::Cx;
use fictionet::stdlib::network::tcp::{
    self, CookieInput, CookieReply, CookieState, SynCookies, TcpOption,
};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;
use std::net::IpAddr;
use std::time::Duration;

/// TCP settings for a Linux server with the default Ethernet window.
pub fn tcp() -> tcp::Options {
    tcp::Options::default().settings(settings())
}

/// Linux choices, available separately for worlds with custom buffer limits.
pub fn settings() -> tcp::Settings {
    let socket = tcp::SocketSettings {
        layout: tcp::OptionLayout {
            order: tcp::OptionOrder::WindowAfterTimestamp,
            align: true,
        },
        syn_window: Some(64240),
        syn_window_with_timestamps: Some(65160),
        window_scale: Some(7),
        time_wait: Duration::from_secs(60).into(),
        repeat_syn_ack: true,
        minimum_mss: 48,
        ack_segments: 1,
        ack_inclusive: false,
        window_update_ratio: 2,
    };
    tcp::Settings {
        socket,
        cookies: Some(&Cookies),
        timestamp_offset: Some(offset),
        timestamp_clock: Some(|now| (now.total_micros() / 1000) as u32),
        handshake_timeout: Duration::from_secs(63),
        orphan_timeout: Duration::from_secs(60),
        reset_full_queue: false,
        ignore_malformed_options: true,
    }
}

fn offset(cx: &Cx) -> u32 {
    let mut bytes = [0; 4];
    cx.fill_random(&mut bytes);
    u32::from_le_bytes(bytes)
}

/// Linux SYN cookie encoding, including options in the timestamp echo.
#[derive(Debug)]
pub struct Cookies;

const MSS: [[u16; 4]; 2] = [[536, 1300, 1440, 1460], [1220, 1420, 1440, 8940]];
const MASK: u32 = 0x00ff_ffff;

fn hash(input: &CookieInput<'_>, count: u32, key: usize) -> u32 {
    let bytes: &[u8; 16] = input.key[key * 16..key * 16 + 16].try_into().unwrap();
    let mut hash = SipHasher24::new_with_key(bytes);
    match (input.remote.ip(), input.local.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            hash.write(&src.octets());
            hash.write(&dst.octets());
            // siphash_4u32 packs the source port in the high half word.
            hash.write(&input.local.port().to_be_bytes());
            hash.write(&input.remote.port().to_be_bytes());
            hash.write(&count.to_le_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            hash.write(&src.octets());
            hash.write(&dst.octets());
            hash.write(&count.to_le_bytes());
            hash.write(&input.remote.port().to_be_bytes());
            hash.write(&input.local.port().to_be_bytes());
        }
        _ => unreachable!("a TCP tuple has one address family"),
    }
    hash.finish() as u32
}

fn timestamp_offset(input: &CookieInput<'_>) -> u32 {
    // A secret-derived offset can be recovered without retaining the SYN.
    let mut hash = SipHasher24::new_with_key(input.key[..16].try_into().unwrap());
    hash.write(b"timestamp");
    for address in [input.local.ip(), input.remote.ip()] {
        match address {
            IpAddr::V4(a) => hash.write(&a.octets()),
            IpAddr::V6(a) => hash.write(&a.octets()),
        }
    }
    hash.finish() as u32
}

impl SynCookies for Cookies {
    fn issue(&self, input: &CookieInput<'_>) -> CookieReply {
        let table = MSS[usize::from(input.local.is_ipv6())];
        let mss = input
            .options
            .iter()
            .find_map(|o| match o {
                TcpOption::MaxSegmentSize(mss) => Some(*mss),
                _ => None,
            })
            .unwrap_or(table[0]);
        let index = table.iter().rposition(|&n| n <= mss).unwrap_or(0) as u32;
        let count = (input.now.as_secs() / 60) as u32;
        let cookie = hash(input, 0, 0)
            .wrapping_add(input.sequence)
            .wrapping_add(count << 24)
            .wrapping_add(hash(input, count, 1).wrapping_add(index) & MASK);
        let mut options = Vec::new();
        let mut ecn = false;
        if let Some(remote) = input.options.iter().find_map(|o| match o {
            TcpOption::Timestamps { tsval, .. } => Some(*tsval),
            _ => None,
        }) {
            let scale = input.options.iter().find_map(|o| match o {
                TcpOption::WindowScale(scale) => Some((*scale).min(14)),
                _ => None,
            });
            let sack = input.options.contains(&TcpOption::SackPermitted);
            ecn = input.ecn;
            let bits = u32::from(scale.unwrap_or(15))
                | if sack { 16 } else { 0 }
                | if ecn { 32 } else { 0 };
            let now = input.now.as_millis() as u32;
            let mut stamp = (now & !63) | bits;
            if stamp > now {
                stamp = stamp.wrapping_sub(64);
            }
            if sack {
                options.push(TcpOption::SackPermitted);
            } else {
                options.extend([TcpOption::NoOperation, TcpOption::NoOperation]);
            }
            options.push(TcpOption::Timestamps {
                tsval: stamp.wrapping_add(timestamp_offset(input)),
                tsecr: remote,
            });
            if scale.is_some() {
                options.extend([TcpOption::NoOperation, TcpOption::WindowScale(7)]);
            }
        }
        CookieReply {
            sequence: cookie,
            options,
            ecn,
        }
    }

    fn validate(&self, input: &CookieInput<'_>, cookie: u32) -> Option<CookieState> {
        let count = (input.now.as_secs() / 60) as u32;
        let value = cookie
            .wrapping_sub(hash(input, 0, 0))
            .wrapping_sub(input.sequence);
        let age = count.wrapping_sub(value >> 24) & 255;
        if age >= 2 {
            return None;
        }
        let index = value.wrapping_sub(hash(input, count.wrapping_sub(age), 1)) & MASK;
        let mss = *MSS[usize::from(input.local.is_ipv6())].get(index as usize)?;
        let mut state = CookieState {
            mss,
            scale: None,
            sack: false,
            ecn: false,
            timestamp: None,
        };
        if let Some((remote, echo)) = input.options.iter().find_map(|o| match o {
            TcpOption::Timestamps { tsval, tsecr } => Some((*tsval, *tsecr)),
            _ => None,
        }) {
            let offset = timestamp_offset(input);
            let bits = echo.wrapping_sub(offset);
            state.scale = (bits & 15 != 15).then_some((bits & 15) as u8);
            state.sack = bits & 16 != 0;
            state.ecn = bits & 32 != 0;
            state.timestamp = Some((offset, remote));
        }
        Some(state)
    }
}

/// Outgoing Data ACK width used by Linux (`net/mptcp/options.c`).
pub fn mptcp_ack_width() -> fictionet::stdlib::protocols::mptcp::AckWidth {
    fictionet::stdlib::protocols::mptcp::AckWidth::MatchMapping
}
