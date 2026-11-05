//! Linux transport choices for worlds that emulate a Linux host.
//!
//! Based on Linux v6.8: `net/ipv4/tcp_output.c` (`tcp_options_write`,
//! `tcp_select_initial_window`), `net/ipv4/syncookies.c`,
//! `net/ipv6/syncookies.c`, and `include/net/tcp.h` (`TCP_TIMEWAIT_LEN`).
//! The window values assume an Ethernet MTU of 1500 and default receive
//! memory settings. Linux sysctls and route metrics can change them.
//!
//! Sources: [TCP output](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_output.c),
//! [IPv4 cookies](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/syncookies.c),
//! [IPv6 cookies](https://github.com/torvalds/linux/blob/v6.8/net/ipv6/syncookies.c),
//! [TCP timers](https://github.com/torvalds/linux/blob/v6.8/include/net/tcp.h),
//! [timestamp offsets](https://github.com/torvalds/linux/blob/v6.8/net/core/secure_seq.c),
//! [challenge ACKs](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/tcp_input.c),
//! and [MPTCP options](https://github.com/torvalds/linux/blob/v6.8/net/mptcp/options.c).

pub mod mptcp;

use fictionet::stdlib::network::ip::{Ipv4Option, Ipv4Reply, Ipv4Timestamp};
use fictionet::stdlib::network::tcp::{
    self, CookieInput, CookieReply, CookieState, SynCookies, TcpOption,
};
use siphasher::sip::SipHasher24;
use std::hash::Hasher;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

/// Adds Linux's IPv4 SYN reply options to a port's handshake policy.
/// `timestamp` supplies milliseconds since midnight UTC in the world's clock.
/// The underlying service still chooses its TCP options and backlog.
pub fn with_ipv4_options<S, F>(
    server: S,
    timestamp: F,
) -> impl fictionet::stdlib::world::net::PortServer
where
    S: fictionet::stdlib::world::net::PortServer,
    F: Fn() -> u32 + Send + Sync + 'static,
{
    Ipv4Server {
        server,
        timestamp: Arc::new(timestamp),
    }
}

struct Ipv4Server<S, F> {
    server: S,
    timestamp: Arc<F>,
}

impl<S, F> fictionet::stdlib::world::net::PortServer for Ipv4Server<S, F>
where
    S: fictionet::stdlib::world::net::PortServer,
    F: Fn() -> u32 + Send + Sync + 'static,
{
    fn serve(
        &self,
        fcx: fictionet::Cx,
        arrival: fictionet::stdlib::world::net::Arrival,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        self.server.serve(fcx, arrival)
    }

    fn backlog(&self) -> Option<usize> {
        self.server.backlog()
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        self.server.alpn()
    }

    fn answer(&self) -> Option<Box<dyn tcp::Answer>> {
        Some(Box::new(Ipv4Answers {
            inner: self.server.answer(),
            timestamp: self.timestamp.clone(),
        }))
    }
}

struct Ipv4Answers<F> {
    inner: Option<Box<dyn tcp::Answer>>,
    timestamp: Arc<F>,
}

impl<F: Fn() -> u32 + Send + Sync> tcp::Answer for Ipv4Answers<F> {
    fn syn(&self, syn: &tcp::Syn<'_>) -> tcp::SynAnswer {
        self.inner.as_ref().map_or_else(
            || tcp::SynAnswer::Accept(Vec::new()),
            |inner| inner.syn(syn),
        )
    }

    fn ipv4_options(&self, syn: &tcp::Syn<'_>) -> Option<Ipv4Reply> {
        syn_ipv4_options(syn, (self.timestamp)())
    }

    fn retransmit_ipv4_options(&self, handshake: &tcp::Handshake) -> Option<Vec<Ipv4Option>> {
        handshake_ipv4_options(handshake, (self.timestamp)())
    }

    fn cookie(&self, from: std::net::SocketAddr, handshake: &tcp::Handshake) -> Option<tcp::Kept> {
        self.inner.as_ref()?.cookie(from, handshake)
    }

    fn ack(&self, handshake: &tcp::Handshake) -> tcp::AckAnswer {
        self.inner
            .as_ref()
            .map_or(tcp::AckAnswer::Accept, |inner| inner.ack(handshake))
    }

    fn segments(&self, handshake: &tcp::Handshake) -> Option<Box<dyn tcp::Segments>> {
        self.inner.as_ref()?.segments(handshake)
    }
}

// Both plain TCP and MPTCP use the same address classification and clock input.
fn syn_ipv4_options(syn: &tcp::Syn<'_>, timestamp: u32) -> Option<Ipv4Reply> {
    let (IpAddr::V4(local), IpAddr::V4(remote)) = (syn.to.ip(), syn.from.ip()) else {
        return Some(Ipv4Reply::default());
    };
    ipv4_options(syn.ipv4_options, local, remote, timestamp, |address| {
        address != local
            && !address.is_unspecified()
            && !address.is_loopback()
            && !address.is_multicast()
            && !address.is_broadcast()
    })
}

fn handshake_ipv4_options(handshake: &tcp::Handshake, timestamp: u32) -> Option<Vec<Ipv4Option>> {
    retransmit_ipv4_options(
        handshake.syn_ipv4.as_deref()?,
        handshake.syn_ack_ipv4.as_deref()?,
        timestamp,
    )
}

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
/// See [Linux option handling](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/ip_options.c),
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

/// Refreshes the send timestamp in a retained IPv4 SYN-ACK's options.
///
/// `syn` is the original received option list and `reply` is its first
/// [`ipv4_options`] result. Only a timestamp slot reserved for sending is
/// updated. The receive timestamp, pointers, overflow, addresses and unused
/// slots retain their first values. `None` means there is no send timestamp.
pub fn retransmit_ipv4_options(
    syn: &[Ipv4Option],
    reply: &[Ipv4Option],
    timestamp: u32,
) -> Option<Vec<Ipv4Option>> {
    let received = syn
        .iter()
        .take_while(|option| !matches!(option, Ipv4Option::EndOfList))
        .find_map(|option| match option {
            Ipv4Option::Timestamp { pointer, .. } => Some(u16::from(*pointer)),
            _ => None,
        })?;
    let mut refreshed = reply.to_vec();
    for option in &mut refreshed {
        let Ipv4Option::Timestamp {
            pointer,
            timestamps,
            ..
        } = option
        else {
            continue;
        };
        let step = match timestamps {
            Ipv4Timestamp::Timestamps(_) => 4,
            Ipv4Timestamp::Addresses(_) | Ipv4Timestamp::Prespecified(_) => 8,
            Ipv4Timestamp::Unknown { .. } => return None,
        };
        if u16::from(*pointer) != received + 2 * step {
            return None;
        }
        let end = usize::from(*pointer) - 1;
        let mut bytes =
            fictionet::stdlib::network::ip::encode_ipv4_options(std::slice::from_ref(option))
                .ok()?;
        bytes
            .get_mut(end.checked_sub(4)?..end)?
            .copy_from_slice(&timestamp.to_be_bytes());
        *option = fictionet::stdlib::network::ip::Ipv4Options::new(&bytes).next()?;
        return Some(refreshed);
    }
    None
}

/// TCP settings for a Linux server with the default Ethernet window.
pub fn tcp() -> tcp::Options {
    tcp::Options::default().settings(settings())
}

/// ICMP replies for the Ubuntu generic kernel on a host with two GiB of RAM.
///
/// IPv4 echo replies preserve the request's TOS and code. Errors use Internet
/// Control precedence. Both use the shared hashed identification counters,
/// with random perturbation below the elapsed number of 1000 Hz ticks.
/// The 32768 buckets match Linux's allocation of one bucket per 64 KiB.
/// See [ICMP replies](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/icmp.c)
/// and [identification allocation](https://github.com/torvalds/linux/blob/v6.8/net/ipv4/route.c).
pub fn icmp(fcx: &fictionet::Cx) -> fictionet::stdlib::network::icmp::Options {
    use fictionet::Entropy;
    use fictionet::stdlib::network::{icmp, ip};
    use fictionet::sync::Mutex;
    use std::sync::Arc;

    let mut key = [0; 16];
    fcx.fill_random(&mut key);
    let counters = Mutex::new(
        (0..32768)
            .map(|_| (fcx.random_u64() as u32, 0u32))
            .collect::<Vec<_>>(),
    );
    let fcx = fcx.clone();
    icmp::Options {
        echo_nonzero_code: true,
        ipv4_fields: Some(Arc::new(move |source, destination, tos, error| {
            let mut hash = SipHasher24::new_with_key(&key);
            hash.write(&destination.octets());
            hash.write(&source.octets());
            hash.write(&u32::from(ip::protocol::ICMP).to_le_bytes());
            let mut counters = counters.lock();
            let counter = &mut counters[hash.finish() as usize & 32767];
            let tick = fcx.now().since_start().as_millis() as u32;
            if counter.1 != tick {
                counter.0 = counter
                    .0
                    .wrapping_add(fcx.random_below(u64::from(tick.wrapping_sub(counter.1))) as u32);
                counter.1 = tick;
            }
            let id = counter.0 as u16;
            counter.0 = counter.0.wrapping_add(1);
            ip::Fields {
                ttl: 64,
                tos: if error { (tos & 0x1e) | 0xc0 } else { tos },
                id,
                dont_fragment: false,
            }
        })),
    }
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
        challenge_ack_interval: Duration::from_millis(500).into(),
        keep_alive_payload: tcp::KeepAlivePayload::Empty,
    };
    tcp::Settings {
        socket,
        cookies: Some(&Cookies),
        backlog_per_peer: None,
        ecn_syn: |ecn, reserved| ecn == 0 || reserved != 0,
        ipv4_id: Some(|cx| {
            let mut bytes = [0; 2];
            cx.fill_random(&mut bytes);
            u16::from_le_bytes(bytes)
        }),
        timestamp_offset: Some(offset),
        timestamp_clock: Some(|now| (now.total_micros() / 1000) as u32),
        timeout: None,
        keep_alive: None,
        handshake_timeout: Duration::from_secs(63),
        orphan_timeout: Duration::from_secs(60),
        reset_full_queue: false,
        ignore_malformed_options: true,
    }
}

fn offset(key: &[u8; 32], local: IpAddr, remote: IpAddr) -> u32 {
    let mut hash = SipHasher24::new_with_key(key[..16].try_into().unwrap());
    for address in [local, remote] {
        match address {
            IpAddr::V4(a) => hash.write(&a.octets()),
            IpAddr::V6(a) => hash.write(&a.octets()),
        }
    }
    hash.finish() as u32
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
                tsval: stamp.wrapping_add(offset(input.key, input.local.ip(), input.remote.ip())),
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
            let offset = offset(input.key, input.local.ip(), input.remote.ip());
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
