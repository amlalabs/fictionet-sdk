//! The server's MPTCP listener: how it answers MP_CAPABLE and MP_JOIN, and
//! the keys of its open connections.
//!
//! A SYN with MP_CAPABLE that offers HMAC-SHA256 gets a SYN-ACK with
//! MP_CAPABLE version 1 and a fresh random key (RFC 8684 section 3.1). A
//! version above 1 gets version 1 back, as section 3.1 has a host answer
//! with the highest version it speaks, and as Linux answers it. The
//! SYN-ACK asks for checksums when the SYN did, as Linux does with
//! checksums off by default. Linux ignores MP_CAPABLE of version 0, with a
//! key, with the extensibility flag B, or with no HMAC-SHA256, and so does
//! this listener: the connection goes on as plain TCP. So does a SYN that
//! carries both MP_CAPABLE and MP_JOIN.
//!
//! The connection uses MPTCP once its third ACK echoes the keys, and its
//! token then names it. When that ACK carries no MP_CAPABLE, the
//! connection falls back to plain TCP and has no token, as on Linux. A
//! handshake answered with a SYN cookie keeps nothing, so the server takes
//! its own key from the third ACK's echo, as Linux does.
//!
//! After its handshake the server speaks plain TCP on every connection, as
//! an MPTCP host does once a connection has fallen back (section 3.7). It
//! never takes a second subflow, but it answers MP_JOIN as Linux does
//! (section 3.2). An MP_JOIN SYN whose token names one of its open
//! connections gets a SYN-ACK with MP_JOIN, its truncated HMAC and a random
//! number, and the join is refused at its third ACK, which carries the
//! client's HMAC, with a RST that has MP_TCPRST "administratively
//! prohibited" (section 3.6). An MP_JOIN SYN whose token names none is
//! refused at once with MP_TCPRST "MPTCP-specific error".
//!
//! [`Tokens`] holds the token and keys of each open connection that
//! negotiated MPTCP, from when it is accepted until it is gone.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::tcp::{AckAnswer, Answer, Handshake, SynAnswer, TcpOption};
use fictionet::stdlib::protocols::mptcp::{
    self, Capable, Join, Keys, MptcpOption, algorithm, join_hmac, reason, token,
};
use fictionet::stdlib::world::net::{Arrival, PortServer};
use fictionet::sync::Mutex;

/// The keys of one connection that uses MPTCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPair {
    /// The server's key, whose token names the connection.
    pub local: u64,
    /// The client's key.
    pub remote: u64,
}

/// The tokens of the server's open MPTCP connections, each with its keys.
#[derive(Default)]
pub struct Tokens(Mutex<HashMap<u32, KeyPair>>);

impl Tokens {
    /// The keys of the open connection with `token`.
    pub fn keys(&self, token: u32) -> Option<KeyPair> {
        self.0.lock().get(&token).copied()
    }

    /// Whether an open connection has `token`.
    pub fn knows(&self, token: u32) -> bool {
        self.0.lock().contains_key(&token)
    }

    /// How many open connections use MPTCP.
    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    /// Whether none does.
    pub fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }

    /// Notes the connection with `keys` until the guard drops.
    fn open(self: &Arc<Self>, keys: KeyPair) -> Open {
        self.0.lock().insert(token(keys.local), keys);
        Open {
            tokens: self.clone(),
            keys,
        }
    }
}

/// One open connection's entry in [`Tokens`], removed when it drops.
struct Open {
    tokens: Arc<Tokens>,
    keys: KeyPair,
}

impl Drop for Open {
    fn drop(&mut self) {
        let mut open = self.tokens.0.lock();
        let token = token(self.keys.local);
        if open.get(&token) == Some(&self.keys) {
            open.remove(&token);
        }
    }
}

/// The MPTCP options in a list of TCP options, read with the stdlib
/// codec. Options it cannot read are left out, as a host ignores them.
pub fn mptcp_options(options: &[TcpOption]) -> impl Iterator<Item = MptcpOption> + '_ {
    options.iter().filter_map(|o| match o {
        TcpOption::Unknown { kind, data } if *kind == mptcp::KIND => MptcpOption::parse(data).ok(),
        _ => None,
    })
}

/// How the listener answers a SYN with `options`. `random` gives the key of
/// a new MPTCP connection and the random number of a join's SYN-ACK.
pub fn answer_syn(
    options: &[TcpOption],
    tokens: &Tokens,
    mut random: impl FnMut() -> u64,
) -> SynAnswer {
    let mut capable = None;
    let mut join = None;
    for option in mptcp_options(options) {
        match option {
            MptcpOption::Capable(offer) => {
                capable.get_or_insert(offer);
            }
            MptcpOption::Join(Join::Syn { token, random, .. }) => {
                join.get_or_insert((token, random));
            }
            _ => {}
        }
    }
    match (capable, join) {
        (Some(_), Some(_)) => SynAnswer::Accept(Vec::new()),
        (Some(offer), None) if takes(&offer) => {
            let key = loop {
                let key = random();
                if !tokens.knows(token(key)) {
                    break key;
                }
            };
            SynAnswer::Accept(vec![option(MptcpOption::Capable(Capable {
                version: mptcp::VERSION,
                checksum_required: offer.checksum_required,
                extensibility: false,
                no_new_subflows: false,
                algorithms: algorithm::HMAC_SHA256,
                keys: Keys::Sender(key),
            }))])
        }
        (None, Some((token, their_random))) => match tokens.keys(token) {
            Some(keys) => {
                let our_random = random() as u32;
                let hmac = join_hmac(keys.local, keys.remote, our_random, their_random);
                let mut truncated = [0; 8];
                truncated.copy_from_slice(&hmac[..8]);
                // The initial subflow's address, with no backup flag, as
                // a Linux listener with no endpoints configured answers.
                SynAnswer::Accept(vec![option(MptcpOption::Join(Join::SynAck {
                    backup: false,
                    address_id: 0,
                    hmac: truncated,
                    random: our_random,
                }))])
            }
            None => SynAnswer::Refuse(vec![tcprst(reason::MPTCP_SPECIFIC)]),
        },
        _ => SynAnswer::Accept(Vec::new()),
    }
}

/// How the listener answers the ACK that completes a handshake: a join is
/// refused, whatever its HMAC, since the server takes no second subflow.
/// Without a SYN cookie the SYN-ACK says it was a join; with one, the
/// MP_JOIN on the ACK does.
pub fn answer_ack(handshake: &Handshake) -> AckAnswer {
    let join = match &handshake.syn_ack {
        Some(syn_ack) => mptcp_options(syn_ack).any(|o| matches!(o, MptcpOption::Join(_))),
        None => mptcp_options(&handshake.ack).any(|o| matches!(o, MptcpOption::Join(_))),
    };
    if join {
        AckAnswer::Refuse(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)])
    } else {
        AckAnswer::Accept
    }
}

/// Whether the listener takes an MP_CAPABLE offer.
fn takes(offer: &Capable) -> bool {
    offer.version >= mptcp::VERSION
        && offer.keys == Keys::Absent
        && !offer.extensibility
        && offer.algorithms & algorithm::HMAC_SHA256 != 0
}

/// An MPTCP option as a TCP option.
fn option(option: MptcpOption) -> TcpOption {
    TcpOption::Unknown {
        kind: mptcp::KIND,
        data: option
            .to_bytes()
            .expect("the listener writes only options the codec reads"),
    }
}

/// MP_TCPRST, not transient, with `reason`.
fn tcprst(reason: u8) -> TcpOption {
    option(MptcpOption::TcpRst {
        transient: false,
        reason,
    })
}

/// The keys of a connection whose handshake this was, if it uses MPTCP:
/// its third ACK echoed the keys in MP_CAPABLE. The server's key is the
/// one its SYN-ACK sent or, after a SYN cookie, the one the ACK echoes.
pub fn negotiated(handshake: &Handshake) -> Option<KeyPair> {
    let (remote, echoed) = mptcp_options(&handshake.ack).find_map(|o| match o {
        MptcpOption::Capable(Capable {
            keys:
                Keys::Both { sender, receiver }
                | Keys::Data {
                    sender, receiver, ..
                },
            ..
        }) => Some((sender, receiver)),
        _ => None,
    })?;
    let local = match &handshake.syn_ack {
        Some(syn_ack) => mptcp_options(syn_ack).find_map(|o| match o {
            MptcpOption::Capable(Capable {
                keys: Keys::Sender(key),
                ..
            }) => Some(key),
            _ => None,
        })?,
        None => echoed,
    };
    Some(KeyPair { local, remote })
}

/// A port server with an MPTCP listener in front: it answers handshakes as
/// the [module docs](self) say, notes each MPTCP connection's token while
/// the connection is open, and hands the connection to `inner`.
pub struct Listener<S> {
    inner: S,
    tokens: Arc<Tokens>,
    fcx: Cx,
}

impl<S> Listener<S> {
    /// `inner` behind an MPTCP listener whose keys come from `fcx`.
    pub fn new(fcx: &Cx, tokens: Arc<Tokens>, inner: S) -> Listener<S> {
        Listener {
            inner,
            tokens,
            fcx: fcx.clone(),
        }
    }
}

/// The listener's answers, as the endpoint asks for them.
struct Answers {
    tokens: Arc<Tokens>,
    fcx: Cx,
}

impl Answer for Answers {
    fn syn(&self, syn: &[TcpOption]) -> SynAnswer {
        answer_syn(syn, &self.tokens, || self.fcx.random_u64())
    }

    fn ack(&self, handshake: &Handshake) -> AckAnswer {
        answer_ack(handshake)
    }
}

impl<S: PortServer> PortServer for Listener<S> {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        if let Some(keys) = negotiated(&arrival.info.handshake) {
            arrival
                .socket
                .hold_until_gone(Box::new(self.tokens.open(keys)));
        }
        self.inner.serve(fcx, arrival)
    }

    fn alpn(&self) -> Vec<Vec<u8>> {
        self.inner.alpn()
    }

    fn answer(&self) -> Option<Box<dyn Answer>> {
        Some(Box::new(Answers {
            tokens: self.tokens.clone(),
            fcx: self.fcx.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn(options: &[MptcpOption]) -> Vec<TcpOption> {
        let mut syn = vec![TcpOption::MaxSegmentSize(1460), TcpOption::SackPermitted];
        syn.extend(options.iter().cloned().map(option));
        syn
    }

    fn linux_capable() -> Capable {
        Capable {
            version: 1,
            checksum_required: false,
            extensibility: false,
            no_new_subflows: false,
            algorithms: algorithm::HMAC_SHA256,
            keys: Keys::Absent,
        }
    }

    fn join(token: u32) -> MptcpOption {
        MptcpOption::Join(Join::Syn {
            backup: false,
            address_id: 0,
            token,
            random: 1,
        })
    }

    /// The answer's key, with this `random`.
    fn answer(options: &[TcpOption], tokens: &Tokens, random: u64) -> SynAnswer {
        answer_syn(options, tokens, || random)
    }

    #[test]
    fn mp_capable_gets_a_key() {
        let tokens = Tokens::default();
        for checksums in [false, true] {
            let offer = Capable {
                checksum_required: checksums,
                ..linux_capable()
            };
            let answer = answer(&syn(&[MptcpOption::Capable(offer)]), &tokens, 7);
            assert_eq!(
                answer,
                SynAnswer::Accept(vec![option(MptcpOption::Capable(Capable {
                    keys: Keys::Sender(7),
                    ..offer
                }))])
            );
        }
    }

    /// A version above 1 gets version 1 back, as Linux answers it: a SYN
    /// with Length 4 and a higher version is taken (mptcp_parse_option).
    #[test]
    fn a_higher_version_gets_version_1() {
        let tokens = Tokens::default();
        for version in 2..=15 {
            let offer = Capable {
                version,
                ..linux_capable()
            };
            assert_eq!(
                answer(&syn(&[MptcpOption::Capable(offer)]), &tokens, 7),
                SynAnswer::Accept(vec![option(MptcpOption::Capable(Capable {
                    keys: Keys::Sender(7),
                    ..linux_capable()
                }))]),
                "version {version}"
            );
        }
    }

    #[test]
    fn offers_linux_ignores_are_plain_tcp() {
        let tokens = Tokens::default();
        let plain = SynAnswer::Accept(Vec::new());
        for offer in [
            Capable {
                version: 0,
                keys: Keys::Sender(1),
                ..linux_capable()
            },
            Capable {
                keys: Keys::Sender(1),
                ..linux_capable()
            },
            Capable {
                extensibility: true,
                ..linux_capable()
            },
            Capable {
                algorithms: 0x02,
                ..linux_capable()
            },
        ] {
            let options = syn(&[MptcpOption::Capable(offer)]);
            assert_eq!(answer(&options, &tokens, 7), plain, "{offer:?}");
        }
        let both = syn(&[MptcpOption::Capable(linux_capable()), join(1)]);
        assert_eq!(answer(&both, &tokens, 7), plain);
        assert_eq!(answer(&syn(&[]), &tokens, 7), plain);
        let malformed = vec![TcpOption::Unknown {
            kind: mptcp::KIND,
            data: vec![0x00],
        }];
        assert_eq!(answer(&malformed, &tokens, 7), plain);
    }

    /// A join to an open connection gets a SYN-ACK with MP_JOIN, whose
    /// HMAC is the listener's (RFC 8684 section 3.2); one to no connection
    /// gets a RST at once.
    #[test]
    fn joins_get_a_syn_ack_when_their_token_is_known() {
        let tokens = Arc::new(Tokens::default());
        let keys = KeyPair {
            local: 42,
            remote: 0x1111,
        };
        let open = tokens.open(keys);
        assert!(tokens.knows(token(42)));
        let SynAnswer::Accept(sent) = answer(&syn(&[join(token(42))]), &tokens, 0x7777) else {
            panic!("a SYN-ACK")
        };
        let hmac = join_hmac(42, 0x1111, 0x7777, 1);
        assert_eq!(
            sent,
            [option(MptcpOption::Join(Join::SynAck {
                backup: false,
                address_id: 0,
                hmac: hmac[..8].try_into().unwrap(),
                random: 0x7777,
            }))]
        );
        assert_eq!(
            answer(&syn(&[join(token(43))]), &tokens, 7),
            SynAnswer::Refuse(vec![tcprst(reason::MPTCP_SPECIFIC)])
        );
        drop(open);
        assert!(tokens.is_empty());
        assert_eq!(
            answer(&syn(&[join(token(42))]), &tokens, 7),
            SynAnswer::Refuse(vec![tcprst(reason::MPTCP_SPECIFIC)])
        );
    }

    #[test]
    fn joins_are_refused_at_their_ack() {
        let join_syn_ack = option(MptcpOption::Join(Join::SynAck {
            backup: false,
            address_id: 0,
            hmac: [0; 8],
            random: 1,
        }));
        let join_ack = option(MptcpOption::Join(Join::Ack { hmac: [0; 20] }));
        let refused = AckAnswer::Refuse(vec![tcprst(reason::ADMINISTRATIVELY_PROHIBITED)]);
        let kept = Handshake {
            syn: Some(Arc::default()),
            syn_ack: Some(vec![join_syn_ack].into()),
            ack: Arc::default(),
        };
        assert_eq!(answer_ack(&kept), refused);
        let cookie = Handshake {
            syn: None,
            syn_ack: None,
            ack: vec![join_ack].into(),
        };
        assert_eq!(answer_ack(&cookie), refused);
        assert_eq!(answer_ack(&Handshake::default()), AckAnswer::Accept);
    }

    /// A connection uses MPTCP once its third ACK echoes the keys; the
    /// server's key is the one it sent, or after a SYN cookie the echo.
    #[test]
    fn the_third_ack_decides_mptcp() {
        let issued = option(MptcpOption::Capable(Capable {
            keys: Keys::Sender(7),
            ..linux_capable()
        }));
        let echo = |receiver| {
            option(MptcpOption::Capable(Capable {
                keys: Keys::Both {
                    sender: 9,
                    receiver,
                },
                ..linux_capable()
            }))
        };
        let handshake = |syn_ack: Option<Vec<TcpOption>>, ack: Vec<TcpOption>| Handshake {
            syn: syn_ack.as_ref().map(|_| Arc::default()),
            syn_ack: syn_ack.map(Arc::from),
            ack: ack.into(),
        };
        let keys = KeyPair {
            local: 7,
            remote: 9,
        };
        assert_eq!(
            negotiated(&handshake(Some(vec![issued.clone()]), vec![echo(7)])),
            Some(keys)
        );
        // The key sent stands whatever the echo says.
        assert_eq!(
            negotiated(&handshake(Some(vec![issued.clone()]), vec![echo(8)])),
            Some(keys)
        );
        assert_eq!(negotiated(&handshake(Some(vec![issued]), vec![])), None);
        assert_eq!(negotiated(&handshake(Some(vec![]), vec![echo(7)])), None);
        assert_eq!(negotiated(&handshake(None, vec![echo(7)])), Some(keys));
    }

    /// Any port server, with ALPN.
    struct H2;

    impl PortServer for H2 {
        fn serve(&self, _: Cx, _: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(async {})
        }

        fn alpn(&self) -> Vec<Vec<u8>> {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
    }

    #[test]
    fn the_listener_keeps_the_inner_server_s_alpn() {
        fictionet::block_on(fictionet::lab(
            fictionet::Seed::from_u64(1),
            |fcx| async move {
                let listener = Listener::new(&fcx, Arc::default(), H2);
                assert_eq!(listener.alpn(), H2.alpn());
                assert!(listener.answer().is_some());
                Ok(())
            },
        ))
        .unwrap();
    }
}
