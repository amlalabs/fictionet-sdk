//! An Ubuntu OpenSSH appearance and opt-in application helpers.
//!
//! [`Profile::ubuntu_24_04`] describes the original Noble package,
//! `1:9.6p1-3ubuntu13`, rather than following later security package revisions.
//! Its reference preferences are data, not a claim that Fictionet implements
//! every algorithm. [`Profile::proposal`] intersects those preferences with the
//! transport's supported proposal before anything is advertised.
//!
//! Sources: Ubuntu's [release announcement] and [source package], especially
//! `debian/patches/package-versioning.patch`, `debian/patches/debian-config.patch`
//! and `debian/openssh-server.sshd.pam.in`; OpenSSH's [algorithm preferences],
//! [server host-key proposals], [server defaults], [authentication implementation]
//! and [session implementation].
//!
//! [release announcement]: https://lists.ubuntu.com/archives/noble-changes/2024-April/035926.html
//! [source package]: https://archive.ubuntu.com/ubuntu/pool/main/o/openssh/openssh_9.6p1-3ubuntu13.debian.tar.xz
//! [algorithm preferences]: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/myproposal.h
//! [server host-key proposals]: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/sshd.c
//! [server defaults]: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c
//! [authentication implementation]: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth2.c
//! [session implementation]: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/session.c

use std::time::Duration;

use fictionet::stdlib::protocols::ssh::{Identification, KexInit};
use fictionet::stdlib::services::ssh::AuthMethod;

pub mod honeypot;
pub mod terminal;

/// Presentation and authentication defaults for a particular SSH installation.
///
/// Credentials, acceptance and multiple-factor policy belong to the application.
/// A rejected credential has partial success false; only a successful factor
/// followed by a required additional factor warrants partial success true.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Version exchange, distinct from an authentication banner.
    pub identification: Identification,
    /// Ordered methods advertised on an ordinary authentication failure.
    pub authentication_methods: Vec<AuthMethod>,
    /// Time allowed for authentication.
    pub login_grace: Duration,
    /// Failed authentication attempts allowed before disconnecting.
    pub max_attempts: u32,
    /// Optional authentication banner, sent before the first authentication result.
    pub banner: Option<String>,
    /// Caller-supplied login text, normally rendered by Ubuntu's PAM session.
    /// No host file or program is read or executed to populate it.
    pub motd: Vec<u8>,
}

impl Profile {
    /// Ubuntu 24.04's release package with the stock server configuration.
    ///
    /// Public-key and password authentication are enabled; keyboard-interactive
    /// and GSSAPI server authentication are disabled. There is no default
    /// authentication banner. Ubuntu disables sshd's `PrintMotd` and uses PAM
    /// to display dynamic and static login text instead. This profile leaves
    /// that text empty for the world to supply, without inventing host details.
    pub fn ubuntu_24_04() -> Self {
        Self {
            identification: Identification::new("2.0", "OpenSSH_9.6p1", Some("Ubuntu-3ubuntu13"))
                .expect("fixed OpenSSH identification"),
            authentication_methods: vec![AuthMethod::PublicKey, AuthMethod::Password],
            login_grace: Duration::from_secs(120),
            max_attempts: 6,
            banner: None,
            motd: Vec::new(),
        }
    }

    /// The stock Ubuntu server's ordered algorithm offer with its default keys.
    ///
    /// OpenSSH 9.6's `fill_default_server_options` in
    /// [`servconf.c`](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/servconf.c)
    /// loads RSA, ECDSA and Ed25519 host keys in that order. Its
    /// `list_hostkey_types` in
    /// [`sshd.c`](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/sshd.c)
    /// preserves file order, offering RSA SHA-512 before SHA-256 and filtering
    /// out the disabled RSA SHA-1 signature. The stock ECDSA key is P-256;
    /// certificates and security keys require separate provisioning.
    /// Extension and strict-key-exchange markers follow the algorithm names in
    /// [`kex.c`](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/kex.c).
    /// This reference must not be sent directly by a subset implementation.
    pub fn reference_preferences(&self) -> KexInit {
        let ciphers = names(
            "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
        );
        let macs = names(
            "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        );
        let compression = names("none,zlib@openssh.com");
        KexInit {
            kex_algorithms: names(
                "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
            ),
            server_host_key_algorithms: names(
                "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
            ),
            encryption_client_to_server: ciphers.clone(),
            encryption_server_to_client: ciphers,
            mac_client_to_server: macs.clone(),
            mac_server_to_client: macs,
            compression_client_to_server: compression.clone(),
            compression_server_to_client: compression,
            ..KexInit::default()
        }
    }

    /// Order only the transport's implemented algorithms by this profile.
    /// Host-key support must also reflect the keys the caller has provisioned.
    /// The transport remains responsible for rejecting unusable empty lists.
    pub fn proposal(&self, supported: &KexInit, cookie: [u8; 16]) -> KexInit {
        let mut proposal = self.reference_preferences();
        proposal.cookie = cookie;
        for (preferred, available) in [
            (&mut proposal.kex_algorithms, &supported.kex_algorithms),
            (
                &mut proposal.server_host_key_algorithms,
                &supported.server_host_key_algorithms,
            ),
            (
                &mut proposal.encryption_client_to_server,
                &supported.encryption_client_to_server,
            ),
            (
                &mut proposal.encryption_server_to_client,
                &supported.encryption_server_to_client,
            ),
            (
                &mut proposal.mac_client_to_server,
                &supported.mac_client_to_server,
            ),
            (
                &mut proposal.mac_server_to_client,
                &supported.mac_server_to_client,
            ),
            (
                &mut proposal.compression_client_to_server,
                &supported.compression_client_to_server,
            ),
            (
                &mut proposal.compression_server_to_client,
                &supported.compression_server_to_client,
            ),
        ] {
            preferred.retain(|name| available.contains(name));
        }
        proposal
    }

    /// Login text for a shell request, suppressed by a quiet login or a command.
    /// PAM's login text can appear even without a PTY; exec and subsystem
    /// requests must pass `shell = false`. The application supplies hush-login
    /// policy through `quiet` and sends these bytes after authentication.
    pub fn login_text(&self, shell: bool, quiet: bool) -> &[u8] {
        if shell && !quiet { &self.motd } else { &[] }
    }
}

/// Remaining OpenSSH authentication timing delay for a username and secret.
///
/// Reproduces the bounded username input and SHA-512 prefix used by OpenSSH
/// 9.6's `user_specific_delay`, then its doubling rule for elapsed processing
/// time. The base is five milliseconds plus up to about 4.295 milliseconds.
/// Pass the time already spent authenticating. The initial `none` probe does
/// not use this delay. For stock Ubuntu password failures that reach PAM,
/// [`password_failure_delay`] also models PAM's preceding delay.
/// The caller schedules the result on the world's clock; this function never
/// sleeps and does not generate a secret or consult the host clock.
#[cfg(not(target_arch = "wasm32"))]
pub fn authentication_delay(secret: u64, username: &[u8], elapsed: Duration) -> Duration {
    let secret = secret.to_string();
    let mut input = [0u8; 511];
    input[..secret.len()].copy_from_slice(secret.as_bytes());
    let user_len = username
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(username.len())
        .min(input.len() - secret.len());
    input[secret.len()..secret.len() + user_len].copy_from_slice(&username[..user_len]);
    let hash = ring::digest::digest(&ring::digest::SHA512, &input[..secret.len() + user_len]);
    let prefix = u32::from_be_bytes(hash.as_ref()[..4].try_into().expect("SHA-512 prefix"));
    if elapsed > Duration::from_secs(5) {
        return Duration::ZERO;
    }
    let mut target = Duration::from_millis(5) + Duration::from_nanos(u64::from(prefix) / 1000);
    while target < elapsed {
        target *= 2;
    }
    target - elapsed
}

/// Remaining delay for a password failure through Ubuntu 24.04's stock PAM stack.
///
/// Ubuntu's [PAM package] enables `pam_unix` without `nodelay` in
/// `debian/pam-configs/unix`. Its [password verification] requests two seconds;
/// Linux-PAM's [delay implementation] varies this using three pseudo-random
/// draws, producing a delay between one and three seconds. OpenSSH then applies
/// [`authentication_delay`] to elapsed time including that PAM delay, so the
/// combined delay can be longer than three seconds.
///
/// Supply PAM's seconds-based seed as `pam_seed`: real PAM uses the low 32 bits
/// of Unix time when authentication starts. A world may supply its own clock or
/// a seeded epoch offset. `elapsed` is time already spent before PAM's wait.
/// Linux-PAM 1.5.3 sleeps for the full sampled delay, without subtracting elapsed
/// authentication time; its recorded start time only seeds the sampler.
/// No clock is read and no sleeping occurs here. OpenSSH's [password path]
/// rejects empty or overlong passwords before PAM, and its [request handler]
/// rejects password changes; these should use [`authentication_delay`] alone.
/// Customized PAM stacks have different timing.
///
/// [PAM package]: https://archive.ubuntu.com/ubuntu/pool/main/p/pam/pam_1.5.3-5ubuntu5.debian.tar.xz
/// [password verification]: https://github.com/linux-pam/linux-pam/blob/v1.5.3/modules/pam_unix/support.c
/// [delay implementation]: https://github.com/linux-pam/linux-pam/blob/v1.5.3/libpam/pam_delay.c
/// [password path]: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth-passwd.c
/// [request handler]: https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth2-passwd.c
#[cfg(not(target_arch = "wasm32"))]
pub fn password_failure_delay(
    secret: u64,
    username: &[u8],
    mut pam_seed: u32,
    elapsed: Duration,
) -> Duration {
    let mut sum = 0.0;
    for _ in 0..3 {
        pam_seed = pam_seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        sum += f64::from((pam_seed / 10) % 1_000_000);
    }
    let variation = (sum / 3.0) / 1_000_000.0 - 0.5;
    let pam = Duration::from_micros((2_000_000.0 * (1.0 + variation)) as u64);
    pam + authentication_delay(secret, username, elapsed.saturating_add(pam))
}

fn names(list: &str) -> Vec<String> {
    list.split(',').map(str::to_owned).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::Wire;
    use fictionet::stdlib::protocols::ssh::Message;

    #[test]
    fn proposals_and_identification_round_trip() {
        let profile = Profile::ubuntu_24_04();
        let reference = profile.reference_preferences();
        for stride in 1..8 {
            let mut supported = reference.clone();
            supported.kex_algorithms = supported
                .kex_algorithms
                .into_iter()
                .step_by(stride)
                .collect();
            supported.server_host_key_algorithms = supported
                .server_host_key_algorithms
                .into_iter()
                .rev()
                .step_by(stride)
                .collect();
            let proposal = profile.proposal(&supported, [stride as u8; 16]);
            let message = Message::KexInit(proposal);
            assert_eq!(
                Message::parse(&message.to_bytes().unwrap()).unwrap(),
                message
            );
        }
        let version = profile.identification;
        assert_eq!(
            Identification::parse(&version.to_bytes().unwrap()).unwrap(),
            version
        );
    }
}
