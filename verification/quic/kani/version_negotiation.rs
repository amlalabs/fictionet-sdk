//! Version negotiation decisions of RFC 9368 and RFC 9369
//!
//! Compiled into `connection/negotiation.rs` under `cfg(kani)`, so the
//! harnesses call the production `Negotiation::{client, admit, decodable,
//! react, check_server}` and `version::{select_compatible,
//! negotiation_was_genuine}` without stubs. Versions are arbitrary 32-bit
//! values and lists the known versions of three arbitrary values, which
//! covers every list of up to three known versions in every order. The
//! downgrade check is proved over two-entry lists of each kind of version
//! (`any_kinds`). The admission harnesses leave their boxed test keys
//! undropped and need `-Z restrict-vtable`.

use super::*;
use crate::crypto::{HeaderKey, KeyPair, PacketKey};
use crate::version::{is_known, negotiation_was_genuine, select_compatible};

fn any_list() -> VersionList {
    VersionList::known([kani::any(), kani::any(), kani::any()])
}

/// The decisions tell versions apart only by equality, `is_known` and
/// `compatible`. Versions 1 and 2, two distinct drafts (each compatible
/// only with itself) and a version the engine does not run therefore cover
/// every list of up to two entries.
fn any_kind_of_version() -> u32 {
    const KINDS: [u32; 5] = [
        crate::version::QUIC_V1,
        crate::version::QUIC_V2,
        0xff00_001d,
        0xff00_0020,
        0x1a2a_3a4a,
    ];
    let index: usize = kani::any();
    kani::assume(index < KINDS.len());
    KINDS[index]
}

/// Two versions of any kinds. Three entries ran CBMC out of 10 GiB in
/// symbolic execution of the nested list scans.
fn any_kinds() -> [u32; 2] {
    [any_kind_of_version(), any_kind_of_version()]
}

/// The position of `version` in `list`, if listed
fn rank(list: &VersionList, version: u32) -> Option<usize> {
    list.as_slice().iter().position(|&v| v == version)
}

/// RFC 9368 section 2.3: a server answers a first flight in `original` in
/// a version it supports, that the client listed, and that `original`
/// converts to, taking its own most preferred such version; with none it
/// keeps `original`.
#[kani::proof]
#[kani::unwind(10)]
fn the_server_chooses_only_from_the_clients_offer() {
    let original: u32 = kani::any();
    let server: [u32; 3] = kani::any();
    let client = any_list();
    let chosen = select_compatible(original, &server, &client);
    let acceptable = |v: u32| {
        is_known(v) && compatible(original, v) && client.contains(v) && server.contains(&v)
    };
    assert!(compatible(original, chosen));
    if chosen != original {
        assert!(acceptable(chosen));
    }
    match server.iter().position(|&v| acceptable(v)) {
        Some(first) => assert_eq!(chosen, server[first]),
        None => assert_eq!(chosen, original),
    }
}

/// RFC 9368 sections 2.1 and 4: a client ignores a Version Negotiation
/// packet that lists its Original Version, and any after it already
/// reacted once. Otherwise it restarts in its most preferred version that
/// the packet lists and it supports, and fails when there is none.
#[kani::proof]
#[kani::unwind(10)]
fn a_client_reacts_once_never_to_its_own_version_and_by_preference() {
    let original: u32 = kani::any();
    let preference = any_list();
    let reacted: bool = kani::any();
    let listed: [u32; 3] = kani::any();
    let supported: [u32; 3] = kani::any();
    let client = Negotiation::client(
        original,
        preference,
        reacted,
        TransportParameters::default(),
    );
    let usable = |v: u32| listed.contains(&v) && supported.contains(&v);
    let reaction = client.react(|v| listed.contains(&v), &supported);
    if reacted || listed.contains(&original) {
        assert_eq!(reaction, Reaction::Ignore);
        return;
    }
    match reaction {
        Reaction::Ignore => panic!("a fresh list without the original version is answered"),
        Reaction::Restart(version) => {
            assert!(usable(version) && preference.contains(version));
            let at = rank(&preference, version).unwrap();
            assert!(!preference.as_slice()[..at].iter().any(|&v| usable(v)));
        }
        Reaction::Fail => assert!(!preference.as_slice().iter().any(|&v| usable(v))),
    }
}

fn with_information(info: VersionInformation) -> TransportParameters {
    let mut params = TransportParameters::default();
    params.version_information = Some(info);
    params
}

/// RFC 9368 section 4, downgrade prevention, on
/// `version::negotiation_was_genuine`, which `Negotiation::check_server`
/// applies to a client that reacted to Version Negotiation. The client
/// restarted in `attempt`, from its preferences; an honest server that
/// accepted the attempt reports its Available Versions and negotiated
/// either the attempt or a compatible version that both offered (what
/// `the_server_chooses_only_from_the_clients_offer` proves of
/// `select_compatible`).
///
/// Sound: the check passes only when no version the server reports comes
/// before the attempt in the client's preferences, so a forged packet that
/// moved the client to a less preferred version is caught. Complete: when
/// the attempt is the client's most preferred version the server reports,
/// which is what the server's own Version Negotiation packet makes it
/// attempt, the check passes, also when the server then upgraded the
/// attempt (RFC 9368 Figure 1). With
/// `a_client_reacts_once_never_to_its_own_version_and_by_preference`, a
/// forged Version Negotiation packet can only end the attempt.
#[kani::proof]
#[kani::unwind(10)]
fn the_downgrade_check_is_sound_and_complete() {
    let preference = VersionList::known(any_kinds());
    let attempt = any_kind_of_version();
    kani::assume(preference.contains(attempt));
    let server = VersionList::known(any_kinds());
    kani::assume(server.contains(attempt));
    let offered = preference.compatible_with(attempt);
    let negotiated = any_kind_of_version();
    kani::assume(
        negotiated == attempt
            || (compatible(attempt, negotiated)
                && offered.contains(negotiated)
                && server.contains(negotiated)),
    );
    let info = VersionInformation {
        chosen: negotiated,
        available: server,
        unknown_available: kani::any(),
    };
    let genuine = negotiation_was_genuine(&preference, &info, attempt, negotiated);
    let at = rank(&preference, attempt).unwrap();
    let skipped = preference.as_slice()[..at]
        .iter()
        .any(|&v| server.contains(v));
    if genuine {
        assert!(!skipped);
    } else {
        assert!(skipped);
    }
}

/// Without Version Negotiation, an honest server's compatible choice is
/// accepted, and a Chosen Version the client did not offer never is.
#[kani::proof]
#[kani::unwind(10)]
fn a_client_accepts_only_a_chosen_version_it_offered() {
    let original: u32 = kani::any();
    let preference = any_list();
    kani::assume(preference.contains(original));
    let client = Negotiation::client(original, preference, false, TransportParameters::default());
    let server: [u32; 3] = kani::any();
    let honest = select_compatible(original, &server, &client.offered);
    let info = |chosen| {
        with_information(VersionInformation {
            chosen,
            available: VersionList::known(server),
            unknown_available: false,
        })
    };
    assert!(client.check_server(&info(honest), honest).is_ok());
    let chosen: u32 = kani::any();
    let result = client.check_server(&info(chosen), chosen);
    assert_eq!(result.is_ok(), client.offered.contains(chosen));
    // What a client offers converts from its first flight and is preferred.
    assert!(client.offered.contains(original));
    for &v in client.offered.as_slice() {
        assert!(compatible(original, v) && preference.contains(v));
    }
}

struct NoKey;

impl PacketKey for NoKey {
    fn encrypt(&self, _: u64, _: &mut [u8], _: usize) {}
    fn decrypt(
        &self,
        _: u64,
        _: &[u8],
        _: &mut bytes::BytesMut,
    ) -> Result<(), crate::crypto::CryptoError> {
        Ok(())
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn confidentiality_limit(&self) -> u64 {
        0
    }
    fn integrity_limit(&self) -> u64 {
        0
    }
    fn heap_size(&self) -> usize {
        0
    }
}

impl HeaderKey for NoKey {
    fn decrypt(&self, _: usize, _: &mut [u8]) {}
    fn encrypt(&self, _: usize, _: &mut [u8]) {}
    fn sample_size(&self) -> usize {
        16
    }
    fn heap_size(&self) -> usize {
        0
    }
}

fn keys() -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(NoKey),
            remote: Box::new(NoKey),
        },
        packet: KeyPair {
            local: Box::new(NoKey),
            remote: Box::new(NoKey),
        },
    }
}

/// RFC 9369 section 4.1 and RFC 9368 section 2.3, for every state a
/// connection can be in: Handshake packets are taken only in the current
/// version; 0-RTT only by a server and only in the Original Version; an
/// Initial in another version only with the retained keys of that version
/// (server) or as a trial of an offered compatible version before the
/// client settles; a Retry only in the Original Version before settling.
/// Every packet admitted carries a version the header decoder accepts.
fn admitted_only_in_its_version(kind: LongKind) {
    let server: bool = kani::any();
    let side = if server { Side::Server } else { Side::Client };
    let original: u32 = kani::any();
    let current: u32 = kani::any();
    // A connection only ever runs versions the engine implements.
    kani::assume(is_known(original) && is_known(current));
    let settled: bool = kani::any();
    let offered = any_list();
    // A server retains only the original version's keys; a client tries
    // only an offered version's.
    let other_version = if server { original } else { kani::any() };
    kani::assume(server || offered.contains(other_version));
    let other = kani::any::<bool>().then(|| OtherInitial {
        version: other_version,
        keys: keys(),
        charge: KeyCharge { _charge: None },
    });
    let negotiation = Negotiation {
        original,
        preference: offered,
        offered,
        settled: server || settled,
        reacted: kani::any(),
        other,
        params: None,
    };
    let version: u32 = kani::any();
    let admission = negotiation.admit(side, current, kind, version);
    let retained = negotiation.other.as_ref().map(|other| other.version);
    match (kind, admission) {
        (_, Admission::Drop) => {}
        (LongKind::Handshake, admitted) => {
            assert_eq!(admitted, Admission::Current);
            assert_eq!(version, current);
        }
        (LongKind::ZeroRtt, admitted) => {
            assert_eq!(admitted, Admission::Current);
            assert!(server && version == original);
        }
        (LongKind::Initial, Admission::Current) => assert_eq!(version, current),
        (LongKind::Initial, Admission::Other) => {
            assert!(server && retained == Some(version) && version != current);
        }
        (LongKind::Initial, Admission::Try) => {
            assert!(!server && !negotiation.settled && version != current);
            assert!(offered.contains(version) && compatible(original, version));
        }
        (LongKind::Retry, admitted) => {
            assert_eq!(admitted, Admission::Current);
            assert!(server || (version == original && !negotiation.settled));
        }
    }
    let decodable = negotiation.decodable(side, current);
    let client_retry = !server && kind == LongKind::Retry;
    if admission != Admission::Drop && (kind != LongKind::Retry || client_retry) {
        // A client's offer holds its Original Version (`Negotiation::client`).
        kani::assume(server || offered.contains(original));
        assert!(decodable.contains(version));
    }
    // Leave the boxed keys undropped: their drop glue is not under test.
    std::mem::forget(negotiation);
}

#[kani::proof]
#[kani::unwind(10)]
fn initial_packets_are_admitted_only_in_their_version() {
    admitted_only_in_its_version(LongKind::Initial);
}

#[kani::proof]
#[kani::unwind(10)]
fn zero_rtt_packets_are_admitted_only_in_their_version() {
    admitted_only_in_its_version(LongKind::ZeroRtt);
}

#[kani::proof]
#[kani::unwind(10)]
fn handshake_packets_are_admitted_only_in_their_version() {
    admitted_only_in_its_version(LongKind::Handshake);
}

#[kani::proof]
#[kani::unwind(10)]
fn retry_packets_are_admitted_only_in_their_version() {
    admitted_only_in_its_version(LongKind::Retry);
}
