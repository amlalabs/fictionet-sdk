//! Bounded passive transport observations. These describe wire behavior, not identity.
use crate::observe::{Direction, Hex, Observation};
use fictionet::stdlib::{
    network::ip::{self, protocol},
    protocols::dns,
};
use serde::Serialize;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

/// Facts retained independently of successful application requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fact {
    /// Every valid TCP segment, including pure ACKs during held requests.
    Tcp {
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload_bytes: usize,
    },
    /// A decoded DNS question. Responses and malformed messages stay in capture.
    Dns {
        id: u16,
        name: String,
        query_type: u16,
        query_class: u16,
        tcp: bool,
    },
    /// Exact ClientHello handshake bytes, including ordered extensions and GREASE.
    /// Includes the four byte handshake header; may span TLS records and TCP packets.
    TlsClientHello { handshake: Hex },
    /// A bounded stream could no longer be decoded without guessing.
    StreamIncomplete { reason: Incomplete },
}

/// Why stream interpretation stopped; raw packets are still retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Incomplete {
    Gap,
    Limit,
    Closed,
    Expired,
}

type Key = (Arc<str>, SocketAddr, SocketAddr);
const STREAM_LIMIT: usize = 128;
const BYTE_LIMIT: usize = 65536;
const LIFETIME_US: u64 = 180_000_000;

struct Stream {
    next: u32,
    bytes: Vec<u8>,
    handshake: Vec<u8>,
    started: u64,
    dns: bool,
    done: bool,
}

/// A bounded first-flight reader. Out-of-order gaps are explicitly reported;
/// retransmitted prefixes are trimmed and never interpreted twice.
#[derive(Default)]
pub(crate) struct Observer {
    streams: HashMap<Key, Stream>,
}

impl Observer {
    pub(crate) fn packet(
        &mut self,
        attachment: &Arc<str>,
        direction: Direction,
        packet: &[u8],
        at_us: u64,
    ) -> Vec<Observation> {
        let mut out = Vec::new();
        self.streams.retain(|(name, src, dst), stream| {
            if at_us.saturating_sub(stream.started) < LIFETIME_US {
                return true;
            }
            if !stream.done && (!stream.bytes.is_empty() || !stream.handshake.is_empty()) {
                out.push(Observation::Network {
                    at_us,
                    attachment: name.clone(),
                    direction: Direction::In,
                    src: *src,
                    dst: *dst,
                    fact: Fact::StreamIncomplete {
                        reason: Incomplete::Expired,
                    },
                });
            }
            false
        });
        let Some(header) = ip::Header::parse_whole(packet) else {
            return out;
        };
        if header.fragment.is_some_and(|f| !f.is_atomic()) {
            return out;
        }
        let t = header.payload(packet);
        if header.src.is_ipv4() && ip::checksum(&packet[..header.payload.start]) != 0 {
            return out;
        }
        if !matches!(header.protocol, protocol::TCP | protocol::UDP) || t.len() < 8 {
            return out;
        }
        let src = SocketAddr::new(header.src, u16::from_be_bytes([t[0], t[1]]));
        let dst = SocketAddr::new(header.dst, u16::from_be_bytes([t[2], t[3]]));
        let mut facts = Vec::new();
        if header.protocol == protocol::UDP {
            let len = usize::from(u16::from_be_bytes([t[4], t[5]]));
            let checksum = u16::from_be_bytes([t[6], t[7]]);
            if len != t.len()
                || len < 8
                || (checksum == 0 && header.src.is_ipv6())
                || (checksum != 0
                    && ip::transport_checksum(header.src, header.dst, protocol::UDP, t) != 0)
            {
                return out;
            }
            if direction == Direction::In && dst.port() == 53 {
                questions(&t[8..], false, &mut facts);
            }
        } else {
            if t.len() < 20 || ip::transport_checksum(header.src, header.dst, protocol::TCP, t) != 0
            {
                return out;
            }
            let offset = usize::from(t[12] >> 4) * 4;
            if !(20..=t.len()).contains(&offset) {
                return out;
            }
            let seq = u32::from_be_bytes(t[4..8].try_into().unwrap());
            let flags = t[13];
            let payload = &t[offset..];
            facts.push(Fact::Tcp {
                seq,
                ack: u32::from_be_bytes(t[8..12].try_into().unwrap()),
                flags,
                window: u16::from_be_bytes([t[14], t[15]]),
                payload_bytes: payload.len(),
            });
            if direction == Direction::In {
                let key = (attachment.clone(), src, dst);
                if flags & 2 != 0 {
                    self.streams.remove(&key);
                }
                let seq = seq.wrapping_add(u32::from(flags & 2 != 0));
                // A TLS record starts with content type 22. Detect even a one-byte
                // first segment, on every port (including accidental HTTPS upgrades).
                if !payload.is_empty()
                    && !self.streams.contains_key(&key)
                    && (payload[0] == 22 || dst.port() == 53)
                {
                    if self.streams.len() < STREAM_LIMIT {
                        self.streams.insert(
                            key.clone(),
                            Stream {
                                next: seq,
                                bytes: Vec::new(),
                                handshake: Vec::new(),
                                started: at_us,
                                dns: dst.port() == 53,
                                done: false,
                            },
                        );
                    } else {
                        facts.push(Fact::StreamIncomplete {
                            reason: Incomplete::Limit,
                        });
                    }
                }
                let mut remove = false;
                if let Some(stream) = self.streams.get_mut(&key) {
                    if !payload.is_empty() && !stream.done {
                        let delta = seq.wrapping_sub(stream.next) as i32;
                        if delta > 0 {
                            facts.push(Fact::StreamIncomplete {
                                reason: Incomplete::Gap,
                            });
                            remove = true;
                        } else {
                            let skip = (-(i64::from(delta))) as usize;
                            if skip < payload.len() {
                                let fresh = &payload[skip..];
                                if stream.bytes.len() + stream.handshake.len() + fresh.len()
                                    > BYTE_LIMIT
                                {
                                    facts.push(Fact::StreamIncomplete {
                                        reason: Incomplete::Limit,
                                    });
                                    remove = true;
                                } else {
                                    stream.bytes.extend_from_slice(fresh);
                                    stream.next = stream.next.wrapping_add(fresh.len() as u32);
                                    remove = stream.decode(&mut facts);
                                }
                            }
                        }
                    }
                    if flags & 5 != 0 {
                        if !remove && (!stream.bytes.is_empty() || !stream.handshake.is_empty()) {
                            facts.push(Fact::StreamIncomplete {
                                reason: Incomplete::Closed,
                            });
                        }
                        remove = true;
                    }
                }
                if remove {
                    if flags & 5 != 0 {
                        self.streams.remove(&key);
                    } else if let Some(stream) = self.streams.get_mut(&key) {
                        stream.done = true;
                        stream.bytes.clear();
                        stream.handshake.clear();
                    }
                }
            }
        }
        out.extend(facts.into_iter().map(|fact| Observation::Network {
            at_us,
            attachment: attachment.clone(),
            direction,
            src,
            dst,
            fact,
        }));
        out
    }
}

fn questions(bytes: &[u8], tcp: bool, out: &mut Vec<Fact>) {
    if let Ok(message) = dns::read_message(bytes) {
        if message.message_type != dns::op::MessageType::Query {
            return;
        }
        for q in &message.queries {
            out.push(Fact::Dns {
                id: message.id,
                name: q.name().to_string(),
                query_type: q.query_type().into(),
                query_class: q.query_class().into(),
                tcp,
            });
        }
    }
}

impl Stream {
    fn decode(&mut self, out: &mut Vec<Fact>) -> bool {
        if self.dns {
            while self.bytes.len() >= 2 {
                let n = usize::from(u16::from_be_bytes([self.bytes[0], self.bytes[1]]));
                if self.bytes.len() < n + 2 {
                    break;
                }
                questions(&self.bytes[2..n + 2], true, out);
                self.bytes.drain(..n + 2);
            }
            return false;
        }
        while self.bytes.len() >= 5 {
            if self.bytes[0] != 22 || self.bytes[1] != 3 {
                return true;
            }
            let n = usize::from(u16::from_be_bytes([self.bytes[3], self.bytes[4]]));
            if self.bytes.len() < n + 5 {
                break;
            }
            self.handshake.extend_from_slice(&self.bytes[5..n + 5]);
            self.bytes.drain(..n + 5);
            if self.handshake.len() >= 4 {
                if self.handshake[0] != 1 {
                    return true;
                }
                let n = (usize::from(self.handshake[1]) << 16)
                    | (usize::from(self.handshake[2]) << 8)
                    | usize::from(self.handshake[3]);
                if n + 4 > BYTE_LIMIT {
                    out.push(Fact::StreamIncomplete {
                        reason: Incomplete::Limit,
                    });
                    return true;
                }
                if self.handshake.len() >= n + 4 {
                    out.push(Fact::TlsClientHello {
                        handshake: Hex(self.handshake[..n + 4].to_vec()),
                    });
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(seq: u32, flags: u8, payload: &[u8], dns: bool) -> Vec<u8> {
        let from = "192.0.2.1".parse().unwrap();
        let to = "192.0.2.2".parse().unwrap();
        let mut t = vec![0; 20];
        t[..2].copy_from_slice(&12345u16.to_be_bytes());
        t[2..4].copy_from_slice(&(if dns { 53u16 } else { 80u16 }).to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t[14..16].copy_from_slice(&8192u16.to_be_bytes());
        t.extend_from_slice(payload);
        let sum = ip::transport_checksum(from, to, protocol::TCP, &t);
        t[16..18].copy_from_slice(&sum.to_be_bytes());
        ip::packet(from, to, protocol::TCP, &t).into_vec()
    }
    fn facts(observer: &mut Observer, seq: u32, payload: &[u8]) -> Vec<Fact> {
        observer
            .packet(
                &Arc::from("internet"),
                Direction::In,
                &packet(seq, 16, payload, false),
                0,
            )
            .into_iter()
            .filter_map(|o| match o {
                Observation::Network { fact, .. } => Some(fact),
                _ => None,
            })
            .collect()
    }
    #[test]
    fn hello_spans_records_segments_and_retransmitted_prefixes() {
        let hello = [1, 0, 0, 6, 3, 3, 1, 2, 3, 4];
        let mut bytes = vec![22, 3, 1, 0, 3];
        bytes.extend_from_slice(&hello[..3]);
        bytes.extend_from_slice(&[22, 3, 1, 0, 7]);
        bytes.extend_from_slice(&hello[3..]);
        let mut observer = Observer::default();
        assert_eq!(facts(&mut observer, 100, &bytes[..1]).len(), 1);
        assert_eq!(facts(&mut observer, 100, &bytes[..9]).len(), 1);
        let out = facts(&mut observer, 109, &bytes[9..]);
        assert!(out.contains(&Fact::TlsClientHello {
            handshake: Hex(hello.to_vec())
        }));
        assert_eq!(facts(&mut observer, 100, &bytes).len(), 1);
    }
    #[test]
    fn gaps_are_not_silently_spliced_into_hellos() {
        let mut observer = Observer::default();
        facts(&mut observer, 10, &[22]);
        assert!(
            facts(&mut observer, 12, &[3, 1, 0, 0]).contains(&Fact::StreamIncomplete {
                reason: Incomplete::Gap
            })
        );
        assert_eq!(
            facts(&mut observer, 11, &[22, 3, 1, 0, 4, 1, 0, 0, 0]).len(),
            1
        );
    }
    #[test]
    fn ack_and_peer_close_are_visible_without_application_bytes() {
        let mut observer = Observer::default();
        let packet = packet(200, 17, &[], false);
        let out = observer.packet(&Arc::from("internet"), Direction::In, &packet, 123);
        assert!(matches!(
            &out[0],
            Observation::Network {
                at_us: 123,
                fact: Fact::Tcp {
                    seq: 200,
                    flags: 17,
                    window: 8192,
                    payload_bytes: 0,
                    ..
                },
                ..
            }
        ));
    }
    #[test]
    fn dns_queries_are_decoded_after_tcp_framing() {
        let query = [
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 1, 0, 1,
        ];
        let mut observer = Observer::default();
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend(query);
        let out = observer.packet(
            &Arc::from("internet"),
            Direction::In,
            &packet(1, 16, &framed, true),
            0,
        );
        assert!(out.iter().any(|o|matches!(o,Observation::Network {fact:Fact::Dns {id:0x1234,query_type:1,tcp:true,name,..},..} if name=="www.")));
    }

    #[test]
    fn truncated_or_corrupt_packets_do_not_create_transport_facts() {
        let mut observer = Observer::default();
        let mut bytes = packet(1, 16, &[22, 3, 1], false);
        for n in 0..bytes.len() {
            assert!(
                observer
                    .packet(&Arc::from("internet"), Direction::In, &bytes[..n], 0)
                    .is_empty()
            );
        }
        bytes[40] ^= 1;
        assert!(
            observer
                .packet(&Arc::from("internet"), Direction::In, &bytes, 0)
                .is_empty()
        );
        assert!(observer.streams.is_empty());
    }

    #[test]
    fn first_flight_population_is_bounded_and_expires() {
        let mut observer = Observer::default();
        let bytes = packet(1, 16, &[22], false);
        for n in 0..STREAM_LIMIT {
            observer.packet(&Arc::from(format!("client-{n}")), Direction::In, &bytes, 0);
        }
        let out = observer.packet(&Arc::from("overflow"), Direction::In, &bytes, 0);
        assert!(out.iter().any(|o| matches!(
            o,
            Observation::Network {
                fact: Fact::StreamIncomplete {
                    reason: Incomplete::Limit
                },
                ..
            }
        )));
        assert_eq!(observer.streams.len(), STREAM_LIMIT);
        let out = observer.packet(&Arc::from("next"), Direction::In, &bytes, LIFETIME_US);
        assert_eq!(
            out.iter()
                .filter(|o| matches!(
                    o,
                    Observation::Network {
                        fact: Fact::StreamIncomplete {
                            reason: Incomplete::Expired
                        },
                        ..
                    }
                ))
                .count(),
            STREAM_LIMIT
        );
        assert_eq!(observer.streams.len(), 1);
    }
}
