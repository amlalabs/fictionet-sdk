//! The server's MPTCP listener: how it answers MP_CAPABLE and MP_JOIN in
//! a SYN, and the keys of its open connections.
//!
//! A SYN with MP_CAPABLE version 1 that offers HMAC-SHA256 gets a SYN-ACK
//! with MP_CAPABLE and a fresh random key (RFC 8684 section 3.1). The
//! SYN-ACK asks for checksums when the SYN did, as Linux does with
//! checksums off by default. Linux ignores MP_CAPABLE that has another
//! version, a key, the extensibility flag B, or no HMAC-SHA256, and so does
//! this listener: the connection goes on as plain TCP. So does a SYN that
//! carries both MP_CAPABLE and MP_JOIN.
//!
//! After its handshake the server speaks plain TCP on every connection, as
//! an MPTCP host does once a connection has fallen back (section 3.7). It
//! never takes a second subflow. An MP_JOIN SYN gets a RST with MP_TCPRST
//! (sections 3.2 and 3.6): reason "administratively prohibited" when its
//! token names one of the server's open connections, as Linux answers a
//! join to a connection that has fallen back, and "MPTCP-specific error"
//! when it names none.
//!
//! [`Tokens`] holds the token and key of each open connection that
//! negotiated MPTCP, from when it is accepted until it is gone.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::network::tcp::{AnswerSyn, SynAnswer, TcpOption};
use fictionet::stdlib::protocols::mptcp::{
    self, Capable, Join, Keys, MptcpOption, algorithm, reason, token,
};
use fictionet::stdlib::world::net::{Arrival, PortServer};
use fictionet::sync::Mutex;

/// The tokens of the server's open MPTCP connections, each with its key.
#[derive(Default)]
pub struct Tokens(Mutex<HashMap<u32, u64>>);

impl Tokens {
    /// Whether an open connection has `token`.
    pub fn knows(&self, token: u32) -> bool {
        self.0.lock().contains_key(&token)
    }

    /// How many open connections negotiated MPTCP.
    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    /// Whether none did.
    pub fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }

    /// A key whose token no open connection has.
    fn fresh_key(&self, fcx: &Cx) -> u64 {
        let open = self.0.lock();
        loop {
            let key = fcx.random_u64();
            if !open.contains_key(&token(key)) {
                return key;
            }
        }
    }

    /// Notes the connection with `key` until the guard drops.
    fn open(self: &Arc<Self>, key: u64) -> Open {
        self.0.lock().insert(token(key), key);
        Open {
            tokens: self.clone(),
            key,
        }
    }
}

/// One open connection's entry in [`Tokens`], removed when it drops.
struct Open {
    tokens: Arc<Tokens>,
    key: u64,
}

impl Drop for Open {
    fn drop(&mut self) {
        let mut open = self.tokens.0.lock();
        if open.get(&token(self.key)) == Some(&self.key) {
            open.remove(&token(self.key));
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

/// How the listener answers a SYN with `options`. `key` makes the key of
/// a new MPTCP connection.
pub fn answer(options: &[TcpOption], tokens: &Tokens, key: impl FnOnce() -> u64) -> SynAnswer {
    let mut capable = None;
    let mut join = None;
    for option in mptcp_options(options) {
        match option {
            MptcpOption::Capable(offer) => {
                capable.get_or_insert(offer);
            }
            MptcpOption::Join(Join::Syn { token, .. }) => {
                join.get_or_insert(token);
            }
            _ => {}
        }
    }
    match (capable, join) {
        (Some(_), Some(_)) => SynAnswer::Accept(Vec::new()),
        (Some(offer), None) if takes(&offer) => {
            SynAnswer::Accept(vec![option(MptcpOption::Capable(Capable {
                version: mptcp::VERSION,
                checksum_required: offer.checksum_required,
                extensibility: false,
                no_new_subflows: false,
                algorithms: algorithm::HMAC_SHA256,
                keys: Keys::Sender(key()),
            }))])
        }
        (None, Some(token)) => SynAnswer::Refuse(vec![option(MptcpOption::TcpRst {
            transient: false,
            reason: if tokens.knows(token) {
                reason::ADMINISTRATIVELY_PROHIBITED
            } else {
                reason::MPTCP_SPECIFIC
            },
        })]),
        _ => SynAnswer::Accept(Vec::new()),
    }
}

/// Whether the listener takes an MP_CAPABLE offer.
fn takes(offer: &Capable) -> bool {
    offer.version == mptcp::VERSION
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

/// The key the server sent in its SYN-ACK's MP_CAPABLE, if it sent one.
pub fn issued_key(syn_ack: &[TcpOption]) -> Option<u64> {
    mptcp_options(syn_ack).find_map(|o| match o {
        MptcpOption::Capable(Capable {
            keys: Keys::Sender(key),
            ..
        }) => Some(key),
        _ => None,
    })
}

/// A port server with an MPTCP listener in front: it answers SYNs as the
/// [module docs](self) say, notes each MPTCP connection's token while the
/// connection is open, and hands the connection to `inner`.
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

impl<S: PortServer> PortServer for Listener<S> {
    fn serve(&self, fcx: Cx, arrival: Arrival) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        if let Some(key) = issued_key(&arrival.info.syn_ack_options) {
            arrival
                .socket
                .hold_until_gone(Box::new(self.tokens.open(key)));
        }
        self.inner.serve(fcx, arrival)
    }

    fn answer_syn(&self) -> Option<AnswerSyn> {
        let (tokens, fcx) = (self.tokens.clone(), self.fcx.clone());
        Some(Box::new(move |options| {
            answer(options, &tokens, || tokens.fresh_key(&fcx))
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

    #[test]
    fn mp_capable_gets_a_key() {
        let tokens = Tokens::default();
        for checksums in [false, true] {
            let offer = Capable {
                checksum_required: checksums,
                ..linux_capable()
            };
            let answer = answer(&syn(&[MptcpOption::Capable(offer)]), &tokens, || 7);
            assert_eq!(
                answer,
                SynAnswer::Accept(vec![option(MptcpOption::Capable(Capable {
                    keys: Keys::Sender(7),
                    ..offer
                }))])
            );
            let SynAnswer::Accept(sent) = answer else {
                unreachable!()
            };
            assert_eq!(issued_key(&sent), Some(7));
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
                version: 2,
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
            assert_eq!(answer(&options, &tokens, || 7), plain, "{offer:?}");
        }
        let both = syn(&[MptcpOption::Capable(linux_capable()), join(1)]);
        assert_eq!(answer(&both, &tokens, || 7), plain);
        assert_eq!(answer(&syn(&[]), &tokens, || 7), plain);
        let malformed = vec![TcpOption::Unknown {
            kind: mptcp::KIND,
            data: vec![0x00],
        }];
        assert_eq!(answer(&malformed, &tokens, || 7), plain);
    }

    #[test]
    fn joins_are_refused_with_the_reason_their_token_gives() {
        let tokens = Arc::new(Tokens::default());
        let refusal = |reason| {
            SynAnswer::Refuse(vec![option(MptcpOption::TcpRst {
                transient: false,
                reason,
            })])
        };
        let open = tokens.open(42);
        assert!(tokens.knows(token(42)));
        assert_eq!(
            answer(&syn(&[join(token(42))]), &tokens, || unreachable!()),
            refusal(reason::ADMINISTRATIVELY_PROHIBITED)
        );
        assert_eq!(
            answer(&syn(&[join(token(43))]), &tokens, || unreachable!()),
            refusal(reason::MPTCP_SPECIFIC)
        );
        drop(open);
        assert!(tokens.is_empty());
        assert_eq!(
            answer(&syn(&[join(token(42))]), &tokens, || unreachable!()),
            refusal(reason::MPTCP_SPECIFIC)
        );
    }
}
