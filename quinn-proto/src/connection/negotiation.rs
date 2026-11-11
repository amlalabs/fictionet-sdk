//! Version negotiation state of one connection (RFC 9368, RFC 9369)
//!
//! A client starts in its Original Version and lists the versions its first
//! flight converts to. The server may answer in one of them: compatible
//! negotiation. The client learns the negotiated version from the first
//! long header of another offered version, or settles on the original when
//! the server's CRYPTO data arrives in it. A server that cannot parse the
//! first flight sends Version Negotiation; the client then starts again in
//! a version of the server's list, once, and later checks that the server's
//! Version Information shows the choice was genuine.
//!
//! The decisions are plain functions of this state so they can be proved
//! apart from packet processing.

use fictionet_buf::Charge;

use crate::{
    crypto::Keys,
    packet::{LongHeaderType, LongType},
    transport_parameters::TransportParameters,
    version::{compatible, negotiation_was_genuine, VersionInformation, VersionList},
    Side, TransportError,
};

/// Long header packet kinds whose version matters
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LongKind {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
}

impl LongKind {
    pub(super) fn of(ty: LongHeaderType) -> Self {
        match ty {
            LongHeaderType::Initial => Self::Initial,
            LongHeaderType::Retry => Self::Retry,
            LongHeaderType::Standard(LongType::ZeroRtt) => Self::ZeroRtt,
            LongHeaderType::Standard(LongType::Handshake) => Self::Handshake,
        }
    }
}

/// How to treat a received long header packet of some version
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Admission {
    /// Process with the connection's keys for its packet space
    Current,
    /// Process an Initial with the retained keys of the other version
    Other,
    /// A client tries the Initial keys of an offered version; the switch
    /// happens only if the packet authenticates
    Try,
    /// Drop: the version is wrong for this packet kind (RFC 9369 section 4.1)
    Drop,
}

/// What a client does with a Version Negotiation packet
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Reaction {
    /// Ignore it (RFC 9368 section 4)
    Ignore,
    /// Start a new first flight in this version (RFC 9368 section 2.1)
    Restart(u32),
    /// No version in common: abandon the attempt
    Fail,
}

/// Initial keys of the version other than the connection's current one
pub(crate) struct OtherInitial {
    pub(super) version: u32,
    pub(super) keys: Keys,
    /// Pays for the keys' storage while they are retained
    _charge: Option<Charge>,
}

impl OtherInitial {
    pub(crate) fn new(version: u32, keys: Keys, charge: Option<Charge>) -> Self {
        Self {
            version,
            keys,
            _charge: charge,
        }
    }
}

pub(crate) struct Negotiation {
    /// The version of the client's first flight on this connection
    pub(super) original: u32,
    /// Client: every version it accepts, most preferred first
    pub(super) preference: VersionList,
    /// Client: the Available Versions it sent, which it may be switched to
    pub(super) offered: VersionList,
    /// Client: whether the negotiated version is known
    pub(super) settled: bool,
    /// Client: whether this first flight answers a Version Negotiation packet
    pub(super) reacted: bool,
    /// Server: the original version's Initial receive keys, kept until a
    /// Handshake packet arrives in the negotiated version. Client: the keys
    /// of an offered version a server Initial may use.
    pub(super) other: Option<OtherInitial>,
    /// Client: its transport parameters, carrying this first flight's
    /// Version Information, sent again after Version Negotiation. Server:
    /// its transport parameters until it has chosen the version, which its
    /// Version Information then names.
    params: Option<TransportParameters>,
}

impl Negotiation {
    /// A client sending its first flight in `original` with `params`, to
    /// which this adds the matching Version Information
    pub(crate) fn client(
        original: u32,
        preference: VersionList,
        reacted: bool,
        mut params: TransportParameters,
    ) -> Self {
        let offered = preference.compatible_with(original);
        params.version_information = Some(VersionInformation {
            chosen: original,
            available: offered,
            unknown_available: false,
        });
        Self {
            original,
            preference,
            offered,
            settled: false,
            reacted,
            other: None,
            params: Some(params),
        }
    }

    /// A client's transport parameters for its first flight
    pub(crate) fn client_params(&self) -> &TransportParameters {
        self.params
            .as_ref()
            .expect("only clients send their first flight")
    }

    /// A server answering a first flight in `original` with `params`. It
    /// chooses the version once the client's offer has arrived (RFC 9368
    /// section 2.3), before its TLS session reads the ClientHello.
    pub(crate) fn server(original: u32, params: TransportParameters) -> Self {
        Self {
            original,
            preference: VersionList::EMPTY,
            offered: VersionList::EMPTY,
            settled: true,
            reacted: false,
            other: None,
            params: Some(params),
        }
    }

    /// Server: whether it still waits for the client's offer
    pub(super) fn choosing(&self, side: Side) -> bool {
        side.is_server() && self.params.is_some()
    }

    /// Server: stop waiting, taking the transport parameters to send
    pub(super) fn chose(&mut self) -> TransportParameters {
        self.params
            .take()
            .expect("a server chooses its version once")
    }

    /// The versions packet headers may carry right now
    pub(super) fn decodable(&self, side: Side, current: u32) -> VersionList {
        let mut versions = VersionList::EMPTY;
        versions.push(current);
        match side {
            Side::Server => {
                versions.push(self.original);
            }
            Side::Client if !self.settled => {
                for &version in self.offered.as_slice() {
                    versions.push(version);
                }
            }
            Side::Client => {}
        }
        versions
    }

    /// How to treat a long header packet of `kind` in `version` while the
    /// connection runs `current` (RFC 9369 section 4.1)
    pub(super) fn admit(
        &self,
        side: Side,
        current: u32,
        kind: LongKind,
        version: u32,
    ) -> Admission {
        let other = self.other.as_ref().map(|other| other.version);
        match (side, kind) {
            (_, LongKind::Handshake) if version == current => Admission::Current,
            (_, LongKind::Handshake) => Admission::Drop,
            // 0-RTT is only ever sent in the original version.
            (Side::Server, LongKind::ZeroRtt) if version == self.original => Admission::Current,
            (_, LongKind::ZeroRtt) => Admission::Drop,
            (_, LongKind::Initial) if version == current => Admission::Current,
            (Side::Server, LongKind::Initial) if other == Some(version) => Admission::Other,
            (Side::Server, LongKind::Initial) => Admission::Drop,
            (Side::Client, LongKind::Initial)
                if !self.settled
                    && self.offered.contains(version)
                    && compatible(self.original, version) =>
            {
                Admission::Try
            }
            (Side::Client, LongKind::Initial) => Admission::Drop,
            // A Retry uses the original version, before anything settled.
            (Side::Client, LongKind::Retry) if version == self.original && !self.settled => {
                Admission::Current
            }
            (Side::Client, LongKind::Retry) => Admission::Drop,
            // Clients never send Retry; processing reports the violation.
            (Side::Server, LongKind::Retry) => Admission::Current,
        }
    }

    /// A client's answer to a Version Negotiation packet listing versions
    /// for which `listed` holds, given the versions its endpoint can decode
    pub(super) fn react(&self, listed: impl Fn(u32) -> bool, supported: &[u32]) -> Reaction {
        if self.reacted || listed(self.original) {
            return Reaction::Ignore;
        }
        match self
            .preference
            .first_offered(|version| listed(version) && supported.contains(&version))
        {
            Some(version) => Reaction::Restart(version),
            None => Reaction::Fail,
        }
    }

    /// A client's check of the server's transport parameters once the
    /// connection runs `negotiated` (RFC 9368 section 4). The decoder has
    /// already compared the server's Chosen Version with `negotiated`.
    pub(super) fn check_server(
        &self,
        params: &TransportParameters,
        negotiated: u32,
    ) -> Result<(), TransportError> {
        match params.version_information {
            None if self.reacted => Err(TransportError::VERSION_NEGOTIATION_ERROR(
                "Version Information missing after Version Negotiation",
            )),
            None => Ok(()),
            Some(info) if !self.offered.contains(info.chosen) => Err(
                TransportError::VERSION_NEGOTIATION_ERROR("server chose a version not offered"),
            ),
            Some(info)
                if self.reacted
                    && !negotiation_was_genuine(&self.preference, &info, negotiated) =>
            {
                Err(TransportError::VERSION_NEGOTIATION_ERROR(
                    "Version Negotiation contradicts the server's versions",
                ))
            }
            Some(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{QUIC_V1, QUIC_V2};

    const DRAFT: u32 = 0xff00_001d;

    fn both() -> VersionList {
        VersionList::new(&[QUIC_V2, QUIC_V1]).unwrap()
    }

    #[test]
    fn a_client_offers_only_versions_its_first_flight_converts_to() {
        let preference = VersionList::new(&[QUIC_V2, DRAFT, QUIC_V1]).unwrap();
        let client =
            Negotiation::client(QUIC_V1, preference, false, TransportParameters::default());
        assert_eq!(
            client
                .client_params()
                .version_information
                .unwrap()
                .available
                .as_slice(),
            &[QUIC_V2, QUIC_V1]
        );
        let draft = Negotiation::client(DRAFT, preference, false, TransportParameters::default());
        assert_eq!(
            draft
                .client_params()
                .version_information
                .unwrap()
                .available
                .as_slice(),
            &[DRAFT]
        );
    }

    #[test]
    fn a_client_tries_offered_initials_until_it_settles() {
        let mut client =
            Negotiation::client(QUIC_V1, both(), false, TransportParameters::default());
        let admit = |n: &Negotiation, kind, version| n.admit(Side::Client, QUIC_V1, kind, version);
        assert_eq!(
            admit(&client, LongKind::Initial, QUIC_V1),
            Admission::Current
        );
        assert_eq!(admit(&client, LongKind::Initial, QUIC_V2), Admission::Try);
        assert_eq!(admit(&client, LongKind::Initial, DRAFT), Admission::Drop);
        assert_eq!(
            admit(&client, LongKind::Handshake, QUIC_V2),
            Admission::Drop
        );
        assert_eq!(admit(&client, LongKind::Retry, QUIC_V1), Admission::Current);
        assert_eq!(admit(&client, LongKind::Retry, QUIC_V2), Admission::Drop);
        client.settled = true;
        assert_eq!(admit(&client, LongKind::Initial, QUIC_V2), Admission::Drop);
        assert_eq!(admit(&client, LongKind::Retry, QUIC_V1), Admission::Drop);
        assert_eq!(
            client.decodable(Side::Client, QUIC_V1).as_slice(),
            &[QUIC_V1]
        );
    }

    #[test]
    fn a_client_offering_only_its_version_never_switches() {
        let client = Negotiation::client(
            QUIC_V1,
            VersionList::new(&[QUIC_V1]).unwrap(),
            false,
            TransportParameters::default(),
        );
        assert_eq!(
            client.admit(Side::Client, QUIC_V1, LongKind::Initial, QUIC_V2),
            Admission::Drop
        );
    }

    #[test]
    fn a_server_keeps_original_initials_and_zero_rtt_and_negotiated_handshakes() {
        let server = Negotiation::server(QUIC_V1, TransportParameters::default());
        let admit = |kind, version| server.admit(Side::Server, QUIC_V2, kind, version);
        assert_eq!(admit(LongKind::Initial, QUIC_V2), Admission::Current);
        // Without retained keys an original Initial cannot be read.
        assert_eq!(admit(LongKind::Initial, QUIC_V1), Admission::Drop);
        assert_eq!(admit(LongKind::ZeroRtt, QUIC_V1), Admission::Current);
        assert_eq!(admit(LongKind::ZeroRtt, QUIC_V2), Admission::Drop);
        assert_eq!(admit(LongKind::Handshake, QUIC_V2), Admission::Current);
        assert_eq!(admit(LongKind::Handshake, QUIC_V1), Admission::Drop);
    }

    #[test]
    fn version_negotiation_restarts_once_in_the_preferred_listed_version() {
        let client = Negotiation::client(QUIC_V1, both(), false, TransportParameters::default());
        let supported = [QUIC_V1, QUIC_V2];
        let lists = |versions: &'static [u32]| move |v: u32| versions.contains(&v);
        assert_eq!(
            client.react(lists(&[QUIC_V2, DRAFT]), &supported),
            Reaction::Restart(QUIC_V2)
        );
        assert_eq!(
            client.react(lists(&[QUIC_V1, QUIC_V2]), &supported),
            Reaction::Ignore
        );
        assert_eq!(client.react(lists(&[DRAFT]), &supported), Reaction::Fail);
        assert_eq!(client.react(lists(&[QUIC_V2]), &[QUIC_V1]), Reaction::Fail);
        let again = Negotiation::client(QUIC_V2, both(), true, TransportParameters::default());
        assert_eq!(again.react(lists(&[QUIC_V1]), &supported), Reaction::Ignore);
    }

    #[test]
    fn after_version_negotiation_the_server_must_confirm_the_choice() {
        let info = |chosen, available: &[u32]| {
            let mut params = TransportParameters::default();
            params.version_information = Some(VersionInformation {
                chosen,
                available: VersionList::new(available).unwrap(),
                unknown_available: false,
            });
            params
        };
        // The client preferred version 2 but a forged packet sent it to 1.
        let preference = VersionList::new(&[QUIC_V2, QUIC_V1]).unwrap();
        let reacted =
            Negotiation::client(QUIC_V1, preference, true, TransportParameters::default());
        assert!(reacted
            .check_server(&info(QUIC_V1, &[QUIC_V1, QUIC_V2]), QUIC_V1)
            .is_err());
        assert!(reacted
            .check_server(&info(QUIC_V1, &[QUIC_V1]), QUIC_V1)
            .is_ok());
        assert!(reacted
            .check_server(&TransportParameters::default(), QUIC_V1)
            .is_err());
        let plain = Negotiation::client(QUIC_V1, preference, false, TransportParameters::default());
        assert!(plain
            .check_server(&TransportParameters::default(), QUIC_V1)
            .is_ok());
        assert!(plain
            .check_server(&info(QUIC_V1, &[QUIC_V1, QUIC_V2]), QUIC_V1)
            .is_ok());
        let only = Negotiation::client(
            QUIC_V1,
            VersionList::new(&[QUIC_V1]).unwrap(),
            false,
            TransportParameters::default(),
        );
        assert!(only
            .check_server(&info(QUIC_V2, &[QUIC_V2]), QUIC_V2)
            .is_err());
    }
}
