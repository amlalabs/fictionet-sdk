//! A value's [`Heap`] measure is what the allocator holds for it, and a
//! value parsed with [`parse_paid`] is charged exactly that. An SSH key
//! exchange allocates no more than the scratch its transport states.

use std::collections::VecDeque;

use crate::common::alloc::{left_allocated, measuring};
use fictionet::heap_of;
use fictionet::stdlib::codec::{Heap, HeapBound, most_list_places, parse_paid};
use fictionet::stdlib::layer::Budget;
use fictionet::{Entropy, Seed, SeededEntropy};

struct Record {
    name: String,
    lines: Vec<Vec<u8>>,
    queue: VecDeque<u32>,
    note: Option<Box<str>>,
    code: u16,
}

heap_of! { Record { name, lines, queue, note, code } }

/// A record grown the ways code grows values: pushed, collected,
/// reserved, boxed, and sometimes left empty.
fn record(rng: &SeededEntropy) -> Record {
    let mut name = String::new();
    for _ in 0..rng.random_below(40) {
        name.push('n');
    }
    let lines = (0..rng.random_below(6))
        .map(|_| {
            let mut line = Vec::with_capacity(rng.random_below(16) as usize);
            line.extend((0..rng.random_below(24)).map(|b| b as u8));
            line
        })
        .collect();
    let mut queue = VecDeque::new();
    for value in 0..rng.random_below(20) {
        queue.push_back(value as u32);
    }
    let note = (rng.random_below(2) == 0)
        .then(|| "note".repeat(rng.random_below(5) as usize).into_boxed_str());
    Record {
        name,
        lines,
        queue,
        note,
        code: rng.random_below(9) as u16,
    }
}

#[test]
fn a_measure_is_what_the_allocator_holds() {
    let rng = SeededEntropy::new(Seed::from_u64(3));
    for _ in 0..256 {
        let (record, live) = left_allocated(|| record(&rng));
        assert_eq!(i128::try_from(record.heap()).unwrap(), live);
        assert!(record.code < 9);
    }
}

/// Comma-separated names, each parsed into its own string.
struct Names {
    names: Vec<String>,
}

heap_of! { Names { names } }

/// Each name takes at least its comma; the strings hold at most the bytes
/// of the input.
impl HeapBound for Names {
    fn most_heap(len: usize) -> usize {
        most_list_places::<String>(len + 1, 1) + len
    }
}

fn names(bytes: &[u8]) -> Result<Names, std::str::Utf8Error> {
    let text = std::str::from_utf8(bytes)?;
    Ok(Names {
        names: text.split(',').map(str::to_owned).collect(),
    })
}

#[test]
fn a_paid_parse_is_charged_what_the_allocator_holds() {
    let rng = SeededEntropy::new(Seed::from_u64(5));
    for _ in 0..256 {
        let mut input = Vec::new();
        for name in 0..rng.random_below(48) {
            if name > 0 {
                input.push(b',');
            }
            input.extend((0..rng.random_below(3)).map(|_| b'a'));
        }
        let budget = Budget::new(Names::most_heap(input.len()));
        let (paid, live) = left_allocated(|| parse_paid(&budget, &input, names));
        let paid = paid.expect("the bound fits").expect("the input parses");
        assert_eq!(i128::try_from(paid.charged()).unwrap(), live);
        assert_eq!(budget.used(), paid.charged());
        assert!(paid.charged() <= Names::most_heap(input.len()));
    }
}

/// Answering an ECDH_INIT allocates at most the transport's stated
/// scratch for it, besides what the transport keeps (the session
/// identifier and the next incoming keys, which its state's charge
/// covers): for each key exchange method, and for each kind of cipher.
/// An Ed25519 host key signs without allocating, so everything counted
/// is the transport's own; an RSA signer's working memory is the `rsa`
/// crate's and would be counted here too.
#[test]
fn an_ssh_key_exchange_allocates_at_most_its_scratch() {
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::protocols::ssh::transport::{HostKey, Transport, TransportEvent};
    use fictionet::stdlib::protocols::ssh::{Identification, Message};
    use p256::elliptic_curve::sec1::ToSec1Point;
    use std::sync::Arc;

    let shares: [(&str, Vec<u8>); 4] = [
        (
            "curve25519-sha256",
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([9; 32]))
                .as_bytes()
                .to_vec(),
        ),
        (
            "curve25519-sha256@libssh.org",
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([5; 32]))
                .as_bytes()
                .to_vec(),
        ),
        (
            "ecdh-sha2-nistp256",
            p256::SecretKey::from_slice(&[3; 32])
                .unwrap()
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        ),
        (
            "ecdh-sha2-nistp384",
            p384::SecretKey::from_slice(&[3; 48])
                .unwrap()
                .public_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec(),
        ),
    ];
    for (kex, share) in shares {
        for cipher in ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"] {
            let host = Arc::new(HostKey::ed25519_from_seed([7; 32]).unwrap());
            let mut transport =
                Transport::new(host, Identification::new("2.0", "server", None).unwrap());
            transport.seed([1; 32]).unwrap();
            let mut out = Vec::with_capacity(1 << 16);
            transport.start(&mut out).unwrap();
            let peer = Identification::new("2.0", "client", None).unwrap();
            transport
                .handle(TransportEvent::Version(peer), &mut out)
                .unwrap();
            let ours = Message::KexInit(transport.proposal().clone())
                .to_bytes()
                .unwrap();
            let mut proposal = transport.proposal().clone();
            proposal.kex_algorithms = vec![kex.to_owned()];
            proposal.encryption_client_to_server = vec![cipher.to_owned()];
            proposal.encryption_server_to_client = vec![cipher.to_owned()];
            let theirs = Message::KexInit(proposal).to_bytes().unwrap();
            let event = TransportEvent::Packet {
                sequence: 0,
                payload: theirs.clone(),
            };
            transport.handle(event, &mut out).unwrap();

            let mut ecdh = vec![30];
            ecdh.extend_from_slice(&(share.len() as u32).to_be_bytes());
            ecdh.extend_from_slice(&share);
            let scratch = transport.scratch(&ecdh);
            let held = fictionet::stdlib::codec::Decode::held(&transport);
            out.clear();
            let room = out.capacity();
            let event = TransportEvent::Packet {
                sequence: 1,
                payload: ecdh,
            };
            let (answered, stats) = measuring(|| transport.handle(event, &mut out));
            assert!(answered.unwrap().is_none());
            assert_eq!(out.capacity(), room, "the reply fit the room given");
            // What the transport keeps: its state now, less its state
            // before, whose two proposals it frees only on returning.
            let kept =
                fictionet::stdlib::codec::Decode::held(&transport) + ours.len() + theirs.len()
                    - held;
            assert!(
                stats.peak_live_bytes <= scratch + kept,
                "{kex} with {cipher}: {} bytes live at the peak, more than the scratch {scratch} \
                 and the {kept} bytes kept",
                stats.peak_live_bytes
            );
            // The scratch follows from what the exchange works with, not
            // from an allowance: it is within twice what it allocates.
            assert!(
                scratch <= 2 * stats.peak_live_bytes,
                "{kex} with {cipher}: the scratch {scratch} is more than twice the {} bytes \
                 the exchange allocates",
                stats.peak_live_bytes
            );
        }
    }
}

/// Checking a signed SSH request allocates at most what
/// `Request::most_verify_heap` states, for users and keys of every
/// length the generator reaches. Ed25519 checks allocate nothing in
/// `ring`, so everything counted is the request's own.
#[test]
fn checking_an_ssh_signature_allocates_at_most_its_bound() {
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::protocols::ssh::auth::{Method, Request};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let rng = SeededEntropy::new(Seed::from_u64(23));
    for _ in 0..64 {
        let mut seed = [0; 32];
        rng.fill_random(&mut seed);
        let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let mut key = Vec::new();
        string(&mut key, b"ssh-ed25519");
        string(&mut key, pair.public_key().as_ref());
        let session_id: Vec<u8> = (0..rng.random_below(65)).map(|b| b as u8).collect();
        let mut request = Request {
            user: "u".repeat(rng.random_below(2000) as usize),
            service: "ssh-connection".into(),
            method: Method::PublicKey {
                algorithm: "ssh-ed25519".into(),
                key,
                signature: Some(Vec::new()),
            },
        };
        let prefix = request.to_bytes().unwrap();
        let mut signed = Vec::new();
        string(&mut signed, &session_id);
        signed.extend_from_slice(&prefix[..prefix.len() - 4]);
        let signature = pair.sign(&signed);
        let mut blob = Vec::new();
        string(&mut blob, b"ssh-ed25519");
        string(&mut blob, signature.as_ref());
        if let Method::PublicKey { signature, .. } = &mut request.method {
            *signature = Some(blob);
        }
        let raw = request.to_bytes().unwrap();
        let (verified, stats) = measuring(|| request.verify_public_key(&session_id, &raw));
        assert!(verified.unwrap());
        let bound = Request::most_verify_heap(raw.len(), session_id.len());
        assert!(
            stats.peak_live_bytes <= bound,
            "checking {} bytes allocated {}, more than the bound {bound}",
            raw.len(),
            stats.peak_live_bytes
        );
    }
}
