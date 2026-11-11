//! The typed records the honeypot emits.
//!
//! The world hands each [`Record`] to an [`EventSink`](crate::evidence::EventSink)
//! as an owned value. Nothing on the world thread turns it into JSON. The
//! evidence writer serializes it into the event log and passes the same
//! value to its [`RecordConsumer`](crate::evidence::RecordConsumer)s. Every
//! record serializes to one JSON object with an `event` field, and reads
//! back from it, so a stored log replays as the same values.
//!
//! Captured IP packets are not records. They go to the IP pcapng file as
//! [`Packet`]s, and a record names one by its ordinal.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use fictionet::stdlib::network::ethernet::host::Ipv6Gateway;
use fictionet::stdlib::network::route::Prefix;
use serde::{Deserialize, Serialize};

use crate::config::{HttpProfile, Service};
use crate::observe::{Direction, Observation};

/// One record of the event log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // boxing would allocate for every observation
pub enum Record {
    /// Something the world observed.
    Observation(Observed),
    /// An Ethernet frame that crossed the card.
    Frame(Frame),
    /// The executable starting, attaching and stopping.
    Lifecycle(Lifecycle),
}

impl Record {
    /// The ordinal of the captured IP packet this record describes, if any.
    pub fn capture_packet(&self) -> Option<u64> {
        match self {
            Record::Observation(Observed {
                observation: Observation::PortZero { capture_packet, .. },
                ..
            }) => Some(*capture_packet),
            Record::Observation(Observed {
                packet: Some(source),
                ..
            }) => source.capture_packet,
            Record::Observation(_) | Record::Frame(_) | Record::Lifecycle(_) => None,
        }
    }
}

/// An observation, with the packet it was made from when it came from one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    /// What was observed.
    #[serde(flatten)]
    pub observation: Observation,
    /// The whole packet it was read from.
    #[serde(flatten)]
    pub packet: Option<PacketSource>,
}

/// The whole IP packet an observation was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketSource {
    /// The packet's ordinal in the IP capture. None for a packet put
    /// together from fragments, which were captured one by one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_packet: Option<u64>,
    /// How the packet reached the observer.
    pub packet_provenance: Provenance,
}

/// How a whole IP packet reached the observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// As it crossed the attachment.
    AttachmentIp,
    /// Put together from fragments that crossed the attachment.
    ReassembledIp,
}

/// An IP packet as it crossed an attachment, as one pcapng Enhanced Packet
/// Block. Records name it by `ordinal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    /// The packet's number in this run, from 1.
    pub ordinal: u64,
    /// Which way it crossed.
    pub direction: Direction,
    /// The pcapng block.
    pub block: Vec<u8>,
}

/// An Ethernet frame that crossed the card, both ways, before any parsing:
/// malformed headers, VLAN tags, unknown EtherTypes and padding included.
/// The frame goes to the Ethernet pcapng file. The log keeps its length.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename = "ethernet_capture")]
pub struct Frame {
    /// World processing time.
    pub at_us: u64,
    /// When the host received it, by the host system clock, if known.
    pub received_at_us: Option<u64>,
    /// Which clock `received_at_us` or, without it, `at_us` is from.
    pub timestamp_source: TimestampSource,
    /// Which way it crossed.
    pub direction: Direction,
    /// Frame records the queue refused since the last one it took.
    pub lost: u64,
    /// Frames the full receive queue discarded since the last record taken.
    pub rx_queue_dropped: u64,
    /// Frames the full transmit queue discarded since the last record taken.
    pub tx_queue_dropped: u64,
    /// Frames the card dropped. Unknown: no backend reports it.
    pub nic_rx_dropped: Option<u64>,
    /// The frame's length.
    pub length: usize,
    /// The frame. It goes to the Ethernet capture, not the log.
    #[serde(skip)]
    pub bytes: Vec<u8>,
}

/// Which clock a frame's time is from. Neither is a hardware timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampSource {
    /// The host system clock, read when the backend received the frame.
    HostSystemTime,
    /// The world's clock, when the world sent the frame.
    WorldClock,
}

/// The executable's lifecycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Lifecycle {
    /// The configuration of this run.
    Configuration(Box<Configuration>),
    /// The packet backend is attached.
    BackendAttached {
        /// Never tested from inside.
        public_reachability: Reachability,
    },
    /// The world is serving.
    LocalReady {
        /// The writer's run identity.
        run_id: String,
        /// Never tested from inside.
        public_reachability: Reachability,
    },
    /// The world stopped.
    Shutdown {
        /// Whether it stopped cleanly.
        status: Stopped,
        /// Why it failed.
        error: Option<String>,
    },
}

/// Whether the sensor is reachable from the internet. The executable never
/// tests it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// Not tested.
    NotTested,
}

/// How the world stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stopped {
    /// On a signal.
    Stopped,
    /// On an error.
    Failed,
}

/// The configuration of one run, without the SSH password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Configuration {
    /// The executable's version.
    pub build: String,
    /// The server's IPv4 address.
    pub address: Ipv4Addr,
    /// The server's IPv6 address.
    pub address_v6: Option<Ipv6Addr>,
    /// The operating system the server presents.
    pub persona: String,
    /// The HTTP server persona.
    pub http_profile: HttpProfile,
    /// The open ports.
    pub listeners: Vec<Listener>,
    /// The company's application hosts.
    pub company_hosts: Vec<CompanyHost>,
    /// The SSH authentication policy.
    pub ssh_auth: SshAuthPolicy,
    /// The IPv4 prefix the internet comes from.
    #[serde(with = "text")]
    pub internet_ipv4: Prefix,
    /// The IPv6 prefix the internet comes from.
    #[serde(with = "text")]
    pub internet_ipv6: Prefix,
    /// How close together SYNs of a burst are.
    pub burst_window_ms: u64,
    /// How many SYNs make a burst.
    pub burst_syns: usize,
    /// The IPv4 gateway.
    pub gateway: Ipv4Addr,
    /// Where the IPv6 gateway comes from.
    pub gateway_v6: GatewayV6,
    /// The kinds of observation the log holds.
    pub observations: Vec<String>,
    /// The state directory.
    pub state_dir: PathBuf,
    /// Whether exact application bytes are kept.
    pub restricted_evidence: bool,
    /// The evidence queue's byte limit.
    pub queue_bytes: usize,
    /// The largest record the log takes.
    pub max_record_bytes: usize,
    /// The size at which files rotate.
    pub rotate_bytes: u64,
    /// Files kept per stream.
    pub retain_files_per_stream: usize,
    /// Entries kept in each of the observer's maps.
    pub observation_state_limit_per_map: usize,
    /// Connections open at once.
    pub connection_limit: usize,
    /// Never tested from inside.
    pub public_reachability: Reachability,
}

/// One open port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    /// The TCP port.
    pub port: u16,
    /// What it serves.
    pub service: Service,
}

/// A company application host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanyHost {
    /// Its DNS name.
    pub name: String,
    /// Its private address.
    pub address: Ipv4Addr,
    /// Its HTTP port.
    pub http: u16,
    /// Its HTTPS port.
    pub https: u16,
}

/// The SSH authentication policy, without the password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthPolicy {
    /// Every attempt refused.
    Reject,
    /// Any password or signed public key.
    Accept,
    /// The configured password, or any signed public key.
    ConfiguredPasswordOrSignedPublicKey,
}

/// Where the IPv6 gateway comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayV6 {
    /// This address.
    Configured(Ipv6Addr),
    /// The first router that advertises itself as a default router.
    FromRouterAdvertisements,
}

impl From<Ipv6Gateway> for GatewayV6 {
    fn from(gateway: Ipv6Gateway) -> GatewayV6 {
        match gateway {
            Ipv6Gateway::Configured(address) => GatewayV6::Configured(address),
            Ipv6Gateway::FromRouterAdvertisements => GatewayV6::FromRouterAdvertisements,
        }
    }
}

/// A value written as its text form, such as a prefix as `10.0.0.0/8`.
mod text {
    use std::fmt::Display;
    use std::str::FromStr;

    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<T: Display, S: Serializer>(value: &T, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(value)
    }

    pub fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
    where
        T: FromStr<Err: Display>,
        D: Deserializer<'de>,
    {
        String::deserialize(d)?.parse().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use fictionet::stdlib::network::ConnInfo;
    use fictionet::stdlib::services::ssh::{Context, Event};
    use fictionet::time::Instant;
    use fictionet_extras::ssh::honeypot::Record as SshRecord;

    use super::*;
    use crate::network_observe::{Fact, Incomplete};
    use crate::observe::{
        BurstKind, Collection, DssMapping, Flags, Hex, Ipv4Opt, Key, Mptcp, MptcpFault, Opt,
        OptionsFault, Payload, ProbeEnd, RequestPhase, Seq, Timestamp, Token,
    };
    use crate::traps::{ProbeEnd as TrapProbeEnd, ProbeKind, TrapEvent};

    fn round_trip(record: Record) {
        let value = serde_json::to_value(&record).unwrap();
        assert!(value["event"].is_string(), "{value}");
        assert_eq!(
            serde_json::from_value::<Record>(value.clone()).unwrap(),
            record,
            "{value}"
        );
    }

    fn observed(observation: Observation) -> Record {
        Record::Observation(Observed {
            observation,
            packet: Some(PacketSource {
                capture_packet: Some(9),
                packet_provenance: Provenance::AttachmentIp,
            }),
        })
    }

    fn alone(observation: Observation) -> Record {
        Record::Observation(Observed {
            observation,
            packet: None,
        })
    }

    #[test]
    fn every_record_kind_round_trips_through_json() {
        let attachment: Arc<str> = Arc::from("internet");
        let src: SocketAddr = "192.0.2.1:40000".parse().unwrap();
        let dst: SocketAddr = "203.0.113.10:80".parse().unwrap();
        let mptcp = vec![
            Mptcp::MpCapable {
                version: 1,
                checksum_required: false,
                extensibility: false,
                no_new_subflows: false,
                algorithms: 1,
                sender_key: Some(Key(7)),
                receiver_key: None,
                data_level_length: None,
                checksum: None,
            },
            Mptcp::MpJoinSyn {
                backup: false,
                address_id: 1,
                token: Token(0xdead_beef),
                token_known: false,
                random: 5,
            },
            Mptcp::Dss {
                data_ack: Some(Seq::Long(1 << 40)),
                mapping: Some(DssMapping {
                    data_sequence_number: Seq::Short(3),
                    subflow_sequence_number: 1,
                    data_level_length: 10,
                    checksum: None,
                }),
                data_fin: false,
            },
            Mptcp::AddAddr {
                address_id: 2,
                address: "198.51.100.1".parse().unwrap(),
                port: Some(443),
                hmac: Some(Hex(vec![1; 8])),
            },
            Mptcp::Malformed {
                fault: MptcpFault::Length {
                    subtype: 0,
                    length: 3,
                },
                data: Hex(vec![0]),
            },
        ];
        let options = vec![
            Opt::Mss { value: 1460 },
            Opt::Nop,
            Opt::Sack {
                blocks: vec![(1, 2)],
            },
            Opt::Other {
                number: 30,
                data: Hex(vec![0x00, 0x81]),
            },
        ];
        let connection = ConnInfo::new(1, dst, src);
        let context = Context {
            connection: &connection,
            now: Instant::ZERO,
        };
        let ssh = SshRecord::redacted(
            &context,
            &Event::Input {
                channel: 0,
                data: b"ls".to_vec(),
            },
            Instant::ZERO,
        )
        .unwrap();
        let records = [
            observed(Observation::Syn {
                at_us: 1,
                attachment: attachment.clone(),
                src,
                dst,
                flags: Flags(0x02),
                seq: 100,
                ipv4_options: vec![
                    Ipv4Opt::NoOperation,
                    Ipv4Opt::Timestamp {
                        pointer: 5,
                        overflow: 0,
                        timestamps: Timestamp::Addresses(vec![("192.0.2.9".parse().unwrap(), 4)]),
                    },
                    Ipv4Opt::Malformed {
                        number: 9,
                        data: Hex(vec![1, 2]),
                    },
                ],
                ipv4_options_raw: Hex(vec![1, 0x44, 12, 5]),
                options: options.clone(),
                options_fault: Some(OptionsFault::Malformed),
                mptcp: mptcp.clone(),
                payload: Some(Payload::Kept(Hex(b"early".to_vec()))),
                gap_us: Some(40),
            }),
            observed(Observation::Syn {
                at_us: 1,
                attachment: attachment.clone(),
                src,
                dst,
                flags: Flags(0x02),
                seq: 100,
                ipv4_options: Vec::new(),
                ipv4_options_raw: Hex::default(),
                options: Vec::new(),
                options_fault: None,
                mptcp: Vec::new(),
                payload: None,
                gap_us: None,
            }),
            observed(Observation::Segment {
                at_us: 2,
                attachment: attachment.clone(),
                src,
                dst,
                flags: Flags(0x18),
                seq: 101,
                options: options.clone(),
                options_fault: None,
                mptcp: mptcp.clone(),
                payload: Payload::Counted(12),
            }),
            observed(Observation::Answer {
                at_us: 3,
                attachment: attachment.clone(),
                src: dst,
                dst: src,
                flags: Flags(0x12),
                options,
                mptcp,
            }),
            observed(Observation::IpOptionsRetransmit {
                at_us: 4,
                attachment: attachment.clone(),
                src,
                dst,
                seq: 100,
                first_syn_us: 1,
                previous_syn_us: 2,
                gap_us: 2,
                phase: RequestPhase::Completed,
                answered_us: Some(2),
                completed_us: Some(3),
                since_completed_us: Some(1),
            }),
            Record::Observation(Observed {
                observation: Observation::Network {
                    at_us: 5,
                    attachment: attachment.clone(),
                    direction: Direction::In,
                    src,
                    dst,
                    fact: Fact::Dns {
                        id: 1,
                        name: "example.internal".into(),
                        query_type: 1,
                        query_class: 1,
                        tcp: false,
                    },
                },
                packet: Some(PacketSource {
                    capture_packet: None,
                    packet_provenance: Provenance::ReassembledIp,
                }),
            }),
            observed(Observation::Network {
                at_us: 5,
                attachment: attachment.clone(),
                direction: Direction::Out,
                src,
                dst,
                fact: Fact::StreamIncomplete {
                    reason: Incomplete::Gap,
                },
            }),
            alone(Observation::PortZero {
                at_us: 6,
                attachment: attachment.clone(),
                protocol: 17,
                src: "192.0.2.1:0".parse().unwrap(),
                dst,
                capture_packet: 4,
                capture_queued: true,
                fragmented: false,
                checksum_valid: None,
            }),
            alone(Observation::StateLimit {
                at_us: 7,
                collection: Collection::Probes,
                limit: 4096,
            }),
            alone(Observation::MptcpNoData {
                at_us: 8,
                attachment: attachment.clone(),
                src,
                dst,
                seq: 100,
                completed: true,
                end: ProbeEnd::Expired,
                capture_queue_complete: Some(true),
            }),
            observed(Observation::Burst {
                at_us: 9,
                src: src.ip(),
                kind: BurstKind::Joins,
                syns: 8,
                window_us: 100_000,
            }),
            alone(Observation::Lost {
                at_us: 10,
                packets: 1,
                observations: 2,
            }),
            alone(Observation::Trap {
                at_us: 11,
                src,
                dst,
                session: "session".into(),
                trap: TrapEvent::Probe {
                    probe: ProbeKind::Hold,
                    elapsed_ms: 150_000,
                    end: TrapProbeEnd::Answered,
                },
            }),
            alone(Observation::Ssh { at_us: 12, ssh }),
            Record::Frame(Frame {
                at_us: 13,
                received_at_us: None,
                timestamp_source: TimestampSource::WorldClock,
                direction: Direction::Out,
                lost: 0,
                rx_queue_dropped: 0,
                tx_queue_dropped: 1,
                nic_rx_dropped: None,
                length: 60,
                bytes: Vec::new(),
            }),
            Record::Lifecycle(Lifecycle::BackendAttached {
                public_reachability: Reachability::NotTested,
            }),
            Record::Lifecycle(Lifecycle::LocalReady {
                run_id: "run".into(),
                public_reachability: Reachability::NotTested,
            }),
            Record::Lifecycle(Lifecycle::Shutdown {
                status: Stopped::Failed,
                error: Some("stopped".into()),
            }),
            Record::Lifecycle(Lifecycle::Configuration(Box::new(Configuration {
                build: "0.0.0".into(),
                address: "203.0.113.10".parse().unwrap(),
                address_v6: Some("2001:db8::10".parse().unwrap()),
                persona: "Ubuntu 24.04 / Linux 6.8".into(),
                http_profile: HttpProfile::Caddy,
                listeners: vec![Listener {
                    port: 8081,
                    service: Service::Mcp,
                }],
                company_hosts: vec![CompanyHost {
                    name: "deploy.northbank.internal".into(),
                    address: "10.44.0.11".parse().unwrap(),
                    http: 80,
                    https: 443,
                }],
                ssh_auth: SshAuthPolicy::Accept,
                internet_ipv4: "0.0.0.0/0".parse().unwrap(),
                internet_ipv6: "::/0".parse().unwrap(),
                burst_window_ms: 100,
                burst_syns: 8,
                gateway: "203.0.113.1".parse().unwrap(),
                gateway_v6: GatewayV6::Configured("fe80::1".parse().unwrap()),
                observations: vec!["mptcp".into()],
                state_dir: "honeypot-state".into(),
                restricted_evidence: false,
                queue_bytes: 1,
                max_record_bytes: 1,
                rotate_bytes: 1,
                retain_files_per_stream: 3,
                observation_state_limit_per_map: 4096,
                connection_limit: 256,
                public_reachability: Reachability::NotTested,
            }))),
        ];
        for record in records {
            round_trip(record);
        }
    }

    #[test]
    fn the_capture_packet_comes_from_the_packet_or_the_port_zero_fact() {
        let attachment: Arc<str> = Arc::from("internet");
        let port_zero = alone(Observation::PortZero {
            at_us: 0,
            attachment: attachment.clone(),
            protocol: 6,
            src: "192.0.2.1:0".parse().unwrap(),
            dst: "203.0.113.10:22".parse().unwrap(),
            capture_packet: 4,
            capture_queued: true,
            fragmented: false,
            checksum_valid: Some(true),
        });
        assert_eq!(port_zero.capture_packet(), Some(4));
        let lost = Observation::Lost {
            at_us: 0,
            packets: 0,
            observations: 0,
        };
        assert_eq!(observed(lost.clone()).capture_packet(), Some(9));
        assert_eq!(alone(lost).capture_packet(), None);
    }
}
