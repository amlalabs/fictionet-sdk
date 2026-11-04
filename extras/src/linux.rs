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
use fictionet::stdlib::network::ip::{Ipv4Option, Ipv4Reply};
use fictionet::stdlib::network::tcp::{
    self, CookieInput, CookieReply, CookieState, SynCookies, TcpOption,
};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::Duration;

/// IPv4 reply options following Linux receive compilation, option echo and build.
///
/// The input is the options as received, before local RR and Timestamp updates.
/// `timestamp` is milliseconds since midnight UTC. `is_unicast` supplies the
/// world's route classification: local, broadcast and multicast addresses must
/// return false, just as Linux's `inet_addr_type` does for those routes.
/// Invalid or duplicate route and timestamp options cannot produce a reply.
/// Unknown options are not echoed. Source routes return their first hop
/// separately; TCP's checksum still uses the original peer address.
///
/// See [Linux option handling](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/ip_options.c),
/// [IPv4 options](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1), and
/// [source routes](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.4.1).
pub fn ipv4_options(
    options: &[Ipv4Option],
    local: Ipv4Addr,
    remote: Ipv4Addr,
    timestamp: u32,
    is_unicast: impl Fn(Ipv4Addr) -> bool,
) -> Option<Ipv4Reply> {
    let mut rr = None;
    let mut ts = None;
    let mut sr = None;
    for option in options {
        let slot = match option {
            Ipv4Option::EndOfList => break,
            Ipv4Option::Malformed { .. } => return None,
            Ipv4Option::RecordRoute { .. } => &mut rr,
            Ipv4Option::Timestamp { .. } => &mut ts,
            Ipv4Option::LooseSourceRoute { .. } | Ipv4Option::StrictSourceRoute { .. } => &mut sr,
            _ => continue,
        };
        if slot.replace(option.clone()).is_some() {
            return None;
        }
    }
    let mut reply = Ipv4Reply::default();
    for option in [rr, ts].into_iter().flatten() {
        let mut bytes = fictionet::stdlib::network::ip::encode_ipv4_options(&[option]).ok()?;
        let len = usize::from(bytes[1]);
        bytes.truncate(len);
        let mut pointer = usize::from(bytes[2]);
        let flags = if bytes[0] == 68 { bytes[3] & 15 } else { 0 };
        if pointer > len && bytes[0] == 68 && flags != 3 {
            let overflow = bytes[3] >> 4;
            if overflow == 15 {
                return None;
            }
            bytes[3] += 16;
        }
        // Compile the receive option, then reserve and fill the reply slot.
        for _ in 0..2 {
            if pointer > len {
                break;
            }
            if pointer + 3 > len {
                return None;
            }
            let offset = pointer - 1;
            let advance = if bytes[0] == 7 {
                bytes[offset..offset + 4].copy_from_slice(&local.octets());
                4
            } else {
                match flags {
                    0 => {
                        bytes[offset..offset + 4].copy_from_slice(&timestamp.to_be_bytes());
                        4
                    }
                    1 | 3 => {
                        if pointer + 7 > len {
                            // Echo may leave a prespecified trailing partial slot untouched.
                            if flags == 3 && pointer != usize::from(bytes[2]) {
                                break;
                            }
                            return None;
                        }
                        if flags == 3 {
                            let address = Ipv4Addr::from(
                                <[u8; 4]>::try_from(&bytes[offset..offset + 4]).ok()?,
                            );
                            if is_unicast(address) {
                                break;
                            }
                        } else {
                            bytes[offset..offset + 4].copy_from_slice(&local.octets());
                        }
                        bytes[offset + 4..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
                        8
                    }
                    _ => break,
                }
            };
            pointer += advance;
        }
        bytes[2] = pointer as u8;
        reply
            .options
            .push(fictionet::stdlib::network::ip::Ipv4Options::new(&bytes).next()?);
    }
    if let Some(route) = sr {
        let bytes = fictionet::stdlib::network::ip::encode_ipv4_options(&[route]).ok()?;
        let len = usize::from(bytes[1]);
        let mut offset = usize::from(bytes[2]).min(len + 1) - 4;
        if offset > 3 {
            let first = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[offset - 1..offset + 3]).ok()?);
            let mut reversed = Vec::new();
            offset -= 4;
            while offset > 3 {
                reversed.extend_from_slice(&bytes[offset - 1..offset + 3]);
                offset -= 4;
            }
            if bytes[offset + 3..offset + 7] == remote.octets() {
                if reversed.is_empty() {
                    return Some(reply);
                }
                reversed.truncate(reversed.len() - 4);
            }
            reversed.extend_from_slice(&remote.octets());
            let mut result = vec![bytes[0], (3 + reversed.len()) as u8, 4];
            result.extend(reversed);
            reply.destination = Some(first);
            reply
                .options
                .push(fictionet::stdlib::network::ip::Ipv4Options::new(&result).next()?);
        }
    }
    Some(reply)
}

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
