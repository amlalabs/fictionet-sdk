//! Differential checks against the executable Lean reference.
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::mptcp::{Error, MptcpOption};
use serde_json::Value;

fn cases(kind: &str, mut check: impl FnMut(&Value)) {
    let dir = std::env::var_os("MPTCP_VECTORS").expect("run cargo xtask mptcp-verify diff");
    let path = std::path::Path::new(&dir).join(format!("{kind}.json"));
    let data: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let cases = data.as_array().unwrap();
    assert!(!cases.is_empty(), "empty {kind} vectors");
    for case in cases {
        check(case);
    }
    println!("{kind}: {} cases, 0 disagree", cases.len());
}

fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
        .collect()
}

#[test]
fn codec() {
    cases("codec", |case| {
        let input = bytes(&case["input"]);
        match MptcpOption::parse(&input) {
            Ok(option) => {
                assert_eq!(option.to_bytes().unwrap(), bytes(&case["output"]), "{case}");
                assert_eq!(
                    semantic_fields(&option),
                    case["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_u64().unwrap())
                        .collect::<Vec<_>>(),
                    "{case}"
                );
            }
            Err(error) => {
                let error = match error {
                    Error::NoSubtype => "empty".to_owned(),
                    Error::TooLong(n) => format!("long:{n}"),
                    Error::Subtype(n) => format!("subtype:{n}"),
                    Error::Length { subtype, length } => format!("length:{subtype}:{length}"),
                    Error::NoAlgorithm => "algorithm".to_owned(),
                    Error::Unwritable => "unwritable".to_owned(),
                };
                assert_eq!(error, case["error"].as_str().unwrap(), "{case}");
            }
        }
    });
}

fn n(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap()
}

#[test]
fn crypto() {
    use fictionet::stdlib::protocols::mptcp::{dss_checksum, idsn, join_hmac, token};
    cases("crypto", |v| {
        assert_eq!(u64::from(token(n(v, "key"))), n(v, "token"), "{v}");
        assert_eq!(idsn(n(v, "key")), n(v, "idsn"), "{v}");
        assert_eq!(
            join_hmac(
                n(v, "key"),
                n(v, "peer"),
                n(v, "a") as u32,
                n(v, "b") as u32
            )
            .as_slice(),
            bytes(&v["hmac"]),
            "{v}"
        );
        assert_eq!(
            u64::from(dss_checksum(
                n(v, "key"),
                n(v, "a") as u32,
                n(v, "length") as u16,
                &bytes(&v["data"])
            )),
            n(v, "checksum"),
            "{v}"
        );
    });
}

#[test]
fn sequence() {
    use fictionet::stdlib::protocols::mptcp::Sequence;
    cases("sequence", |v| {
        assert_eq!(
            Sequence::Short(n(v, "low") as u32).expand(n(v, "near")),
            n(v, "expanded"),
            "{v}"
        );
        assert_eq!(
            Sequence::Long(n(v, "expanded")).expand(n(v, "near")),
            n(v, "expanded"),
            "{v}"
        );
    });
}

fn semantic_fields(option: &MptcpOption) -> Vec<u64> {
    use fictionet::stdlib::protocols::mptcp::{Join, Keys, Sequence};
    fn seq(s: Sequence) -> Vec<u64> {
        match s {
            Sequence::Short(v) => vec![4, u64::from(v)],
            Sequence::Long(v) => vec![8, v],
        }
    }
    fn optional(n: Option<u16>) -> Vec<u64> {
        n.map_or_else(|| vec![0], |n| vec![1, u64::from(n)])
    }
    match option {
        MptcpOption::Capable(c) => {
            let mut out = vec![
                0,
                c.version.into(),
                c.checksum_required.into(),
                c.extensibility.into(),
                c.no_new_subflows.into(),
                c.algorithms.into(),
            ];
            out.extend(match c.keys {
                Keys::Absent => vec![0],
                Keys::Sender(k) => vec![1, k],
                Keys::Both { sender, receiver } => vec![2, sender, receiver],
                Keys::Data {
                    sender,
                    receiver,
                    data_level_length,
                    checksum,
                } => {
                    let mut v = vec![3, sender, receiver, data_level_length.into()];
                    v.extend(optional(checksum));
                    v
                }
            });
            out
        }
        MptcpOption::Join(j) => match j {
            Join::Syn {
                backup,
                address_id,
                token,
                random,
            } => vec![
                1,
                0,
                (*backup).into(),
                (*address_id).into(),
                (*token).into(),
                (*random).into(),
            ],
            Join::SynAck {
                backup,
                address_id,
                hmac,
                random,
            } => {
                let mut v = vec![1, 1, (*backup).into(), (*address_id).into()];
                v.extend(hmac.iter().map(|&b| u64::from(b)));
                v.push((*random).into());
                v
            }
            Join::Ack { hmac } => {
                let mut v = vec![1, 2];
                v.extend(hmac.iter().map(|&b| u64::from(b)));
                v
            }
        },
        MptcpOption::Dss(d) => {
            let mut v = vec![2, d.data_fin.into()];
            v.extend(d.data_ack.map_or_else(|| vec![0], seq));
            if let Some(m) = d.mapping {
                v.extend(seq(m.data_sequence_number));
                v.extend([
                    u64::from(m.subflow_sequence_number),
                    u64::from(m.data_level_length),
                ]);
                v.extend(optional(m.checksum));
            } else {
                v.push(0);
            }
            v
        }
        MptcpOption::AddAddr(a) => {
            let mut v = vec![3, a.address_id.into()];
            let bytes = match a.address {
                std::net::IpAddr::V4(a) => a.octets().to_vec(),
                std::net::IpAddr::V6(a) => a.octets().to_vec(),
            };
            v.push(bytes.len() as u64);
            v.extend(bytes.into_iter().map(u64::from));
            v.extend(optional(a.port));
            if let Some(h) = a.hmac {
                v.push(1);
                v.extend(h.into_iter().map(u64::from));
            } else {
                v.push(0);
            }
            v
        }
        MptcpOption::RemoveAddr { address_ids } => {
            let mut v = vec![4];
            v.extend(address_ids.iter().map(|&b| u64::from(b)));
            v
        }
        MptcpOption::Prio { backup } => vec![5, (*backup).into()],
        MptcpOption::Fail {
            data_sequence_number,
        } => vec![6, *data_sequence_number],
        MptcpOption::FastClose { receiver_key } => vec![7, *receiver_key],
        MptcpOption::TcpRst { transient, reason } => vec![8, (*transient).into(), (*reason).into()],
    }
}

#[test]
fn layout() {
    use fictionet::stdlib::network::{ip, tcp};
    use fictionet::{Interface, InterfaceExt};
    cases("layout", |v| {
        let v = v.clone();
        let result = fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            move |fcx| async move {
                let linux = v["linux"].as_bool().unwrap();
                let settings = if linux {
                    fictionet_extras::linux::settings()
                } else {
                    tcp::Settings::default()
                };
                assert_eq!(
                    u64::from(settings.socket.ack_segments),
                    n(&v, "ackSegments")
                );
                assert_eq!(
                    settings.socket.ack_inclusive,
                    v["ackInclusive"].as_bool().unwrap()
                );
                assert_eq!(tcp::SYN_OPTIONS_ROOM as u64, n(&v, "synBudget"));
                assert_eq!(tcp::SEGMENT_OPTIONS_ROOM as u64, n(&v, "segmentBudget"));
                let src = "192.0.2.1".parse().unwrap();
                let dst = "192.0.2.2".parse().unwrap();
                let (mut peer, side) = fictionet::pair();
                let server =
                    tcp::endpoint_with(&fcx, side, dst, tcp::Options::default().settings(settings));
                let mut listener = server.listen(80)?;
                let extra = n(&v, "extra") as usize;
                listener.answer(Box::new(move |_: &tcp::Syn<'_>| {
                    tcp::SynAnswer::Accept(if extra == 0 {
                        Vec::new()
                    } else {
                        vec![tcp::TcpOption::Unknown {
                            kind: 30,
                            data: vec![0; extra - 2],
                        }]
                    })
                }));
                let mut options = vec![2, 4, 5, 180];
                if v["scale"].as_bool().unwrap() {
                    options.extend([3, 3, 7]);
                }
                if v["sack"].as_bool().unwrap() {
                    options.extend([4, 2]);
                }
                if v["timestamp"].as_bool().unwrap() {
                    options.extend([8, 10, 0, 0, 0, 1, 0, 0, 0, 0]);
                }
                options.resize(options.len().next_multiple_of(4), 0);
                let mut t = vec![0; 20];
                t[..2].copy_from_slice(&4000u16.to_be_bytes());
                t[2..4].copy_from_slice(&80u16.to_be_bytes());
                t[4..8].copy_from_slice(&1000u32.to_be_bytes());
                t[12] = ((20 + options.len()) / 4) as u8 * 16;
                t[13] = 2;
                t[14..16].copy_from_slice(&65535u16.to_be_bytes());
                t.extend(options);
                let sum = ip::transport_checksum(src, dst, 6, &t);
                t[16..18].copy_from_slice(&sum.to_be_bytes());
                peer.send(ip::packet(src, dst, 6, &t));
                let packet = peer.recv(&fcx).await.expect("SYN-ACK");
                let tcp = ip::Header::parse_whole(&packet.0)
                    .unwrap()
                    .payload(&packet.0);
                assert_eq!(tcp[13] & 0x12, 0x12, "{v}");
                assert_eq!(u64::from(tcp[12] >> 4) * 4 - 20, n(&v, "length"), "{v}");
                let mut kinds = Vec::new();
                let mut at = 20;
                while at < usize::from(tcp[12] >> 4) * 4 {
                    let kind = tcp[at];
                    if kind == 0 {
                        break;
                    }
                    kinds.push(u64::from(kind));
                    at += if kind == 1 {
                        1
                    } else {
                        usize::from(tcp[at + 1])
                    };
                }
                assert_eq!(
                    kinds,
                    v["kinds"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|n| n.as_u64().unwrap())
                        .collect::<Vec<_>>(),
                    "{v}"
                );
                assert!(extra as u64 <= n(&v, "room"));
                Err(fictionet::Error::msg("complete"))
            },
        ));
        assert_eq!(result.unwrap_err().to_string(), "complete");
    });
}

#[test]
fn data() {
    use fictionet::stdlib::protocols::mptcp::{
        DataLevel, Dss, Mapping, Sequence, dss_checksum, idsn,
    };
    cases("data", |v| {
        let key = n(v, "key");
        let base = idsn(key).wrapping_add(1);
        let checksums = v["checksums"].as_bool().unwrap();
        let mut level = DataLevel::new(7, key, 0, 0, checksums, None);
        let mut seq = 1u32;
        let mut out = Vec::new();
        for event in v["steps"].as_array().unwrap() {
            let kind = n(event, "kind");
            let index = n(event, "index");
            if kind == 2 {
                level.received(seq, 1, false, []);
            } else {
                let fin = kind == 1;
                let payload = if fin { vec![] } else { vec![65 + index as u8] };
                let dsn = base.wrapping_add(index);
                let ssn = if fin { 0 } else { seq };
                let sum =
                    checksums.then(|| dss_checksum(dsn, ssn, 1, &payload) ^ u16::from(kind == 3));
                level.received(
                    seq,
                    payload.len(),
                    false,
                    [MptcpOption::Dss(Dss {
                        data_ack: None,
                        data_fin: fin,
                        mapping: Some(Mapping {
                            data_sequence_number: Sequence::Long(dsn),
                            subflow_sequence_number: ssn,
                            data_level_length: 1,
                            checksum: sum,
                        }),
                    })],
                );
                level.arrived(seq, &payload, &mut out);
                seq += payload.len() as u32;
            }
            assert_eq!(out, bytes(&event["output"]), "{v} at {event}");
            assert_eq!(
                level.error().is_some(),
                event["error"].as_bool().unwrap(),
                "{v} at {event}"
            );
            assert_eq!(
                level.fallen_back(),
                event["fallback"].as_bool().unwrap(),
                "{v} at {event}"
            );
            if !level.fallen_back() {
                assert_eq!(
                    level.sent(1, &[], false, Some(seq)).unwrap().data_ack,
                    Some(Sequence::Long(base.wrapping_add(n(event, "ack")))),
                    "{v} at {event}"
                );
            }
        }
    });
}

#[test]
fn transmit() {
    use fictionet::stdlib::protocols::mptcp::{DataLevel, Sequence};
    let mut level = None;
    let payload = vec![0; 65535];
    let iss = u32::MAX - 10;
    cases("transmit", |v| {
        let level =
            level.get_or_insert_with(|| DataLevel::new(n(v, "key"), 7, iss, 0, false, None));
        let seq = iss.wrapping_add(n(v, "offset") as u32);
        let mapping = level
            .sent(seq, &payload, false, None)
            .unwrap()
            .mapping
            .unwrap();
        assert_eq!(
            mapping.data_sequence_number,
            Sequence::Long(n(v, "dsn")),
            "{v}"
        );
        assert_eq!(
            mapping.subflow_sequence_number,
            n(v, "offset") as u32,
            "{v}"
        );
    });
}
