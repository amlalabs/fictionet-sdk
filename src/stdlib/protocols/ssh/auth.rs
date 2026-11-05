//! Authentication payloads. The caller chooses credentials, methods and policy.
//!
//! Passwords and keyboard responses are bytes and are never logged by this
//! module. Parsing is bounded by the transport payload limit. Message sixty
//! depends on the active method; use [`Message::parse_with_method`] to decode it.

use super::{Error, MAX_NAME, MAX_PAYLOAD, Reader};
use fictionet::stdlib::codec::Wire;

/// SHA256 fingerprint of an SSH encoded public key, before display encoding.
pub fn public_key_fingerprint(key: &[u8]) -> [u8; 32] {
    ring::digest::digest(&ring::digest::SHA256, key)
        .as_ref()
        .try_into()
        .expect("SHA256 digest length")
}

/// An authentication request, including the service the user wants to enter.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// Account name.
    pub user: String,
    /// Requested service, normally `ssh-connection`.
    pub service: String,
    /// Credentials or a method probe.
    pub method: Method,
}

/// Authentication credentials. Debug output deliberately omits secrets.
#[derive(Clone, PartialEq, Eq)]
pub enum Method {
    /// Ask whether authentication is required.
    None,
    /// Password authentication or password change.
    Password {
        /// Current password.
        password: Vec<u8>,
        /// Replacement password, if a change is requested.
        new_password: Option<Vec<u8>>,
    },
    /// Probe a key or prove possession of it.
    PublicKey {
        /// Signature algorithm.
        algorithm: String,
        /// SSH encoded public key.
        key: Vec<u8>,
        /// SSH encoded signature; absent for a probe.
        signature: Option<Vec<u8>>,
    },
    /// Begin a keyboard interactive exchange.
    KeyboardInteractive {
        /// Language preference.
        language: String,
        /// Comma separated submethod preferences.
        submethods: String,
    },
    /// A method interpreted by the caller.
    Other {
        /// Method name.
        name: String,
        /// Method specific fields.
        data: Vec<u8>,
    },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("user", &self.user)
            .field("service", &self.service)
            .field("method", &self.method.name())
            .finish_non_exhaustive()
    }
}

impl Method {
    /// Wire method name.
    pub fn name(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Password { .. } => "password",
            Self::PublicKey { .. } => "publickey",
            Self::KeyboardInteractive { .. } => "keyboard-interactive",
            Self::Other { name, .. } => name,
        }
    }
}

impl Wire for Request {
    type ParseError = Error;
    type WriteError = Error;

    fn parse(payload: &[u8]) -> Result<Self, Error> {
        let mut r = reader(payload)?;
        if r.byte()? != 50 {
            return Err(Error::Unwritable);
        }
        let user = r.text(MAX_PAYLOAD)?;
        let service = name(&mut r)?;
        let method_name = name(&mut r)?;
        let method = match method_name.as_str() {
            "none" => Method::None,
            "password" => {
                let change = r.boolean()?;
                Method::Password {
                    password: r.string()?.to_vec(),
                    new_password: if change {
                        Some(r.string()?.to_vec())
                    } else {
                        None
                    },
                }
            }
            "publickey" => {
                let signed = r.boolean()?;
                Method::PublicKey {
                    algorithm: name(&mut r)?,
                    key: r.string()?.to_vec(),
                    signature: if signed {
                        Some(r.string()?.to_vec())
                    } else {
                        None
                    },
                }
            }
            "keyboard-interactive" => Method::KeyboardInteractive {
                language: r.text(MAX_PAYLOAD)?,
                submethods: r.text(MAX_PAYLOAD)?,
            },
            _ => Method::Other {
                name: method_name,
                data: rest(&mut r),
            },
        };
        r.finish()?;
        Ok(Self {
            user,
            service,
            method,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = Payload::new(50);
        w.string(self.user.as_bytes())?;
        w.name(&self.service)?;
        w.name(self.method.name())?;
        match &self.method {
            Method::None => (),
            Method::Password {
                password,
                new_password,
            } => {
                w.byte(u8::from(new_password.is_some()))?;
                w.string(password)?;
                if let Some(password) = new_password {
                    w.string(password)?;
                }
            }
            Method::PublicKey {
                algorithm,
                key,
                signature,
            } => {
                w.byte(u8::from(signature.is_some()))?;
                w.name(algorithm)?;
                w.string(key)?;
                if let Some(signature) = signature {
                    w.string(signature)?;
                }
            }
            Method::KeyboardInteractive {
                language,
                submethods,
            } => {
                w.string(language.as_bytes())?;
                w.string(submethods.as_bytes())?;
            }
            Method::Other { name, data } => {
                if matches!(
                    name.as_str(),
                    "none" | "password" | "publickey" | "keyboard-interactive"
                ) {
                    return Err(Error::Unwritable);
                }
                w.raw(data)?;
            }
        }
        w.finish(out)
    }
}

impl Request {
    /// Verify an Ed25519 or RSA SHA256 or SHA512 proof over the session
    /// identifier and exact received request prefix. A probe, unsupported algorithm, mismatched
    /// request or invalid signature returns false. Malformed key or signature
    /// encodings return an error. Authorization remains the caller's decision.
    pub fn verify_public_key(&self, session_id: &[u8], raw_request: &[u8]) -> Result<bool, Error> {
        let Method::PublicKey {
            algorithm,
            key,
            signature: Some(signature),
        } = &self.method
        else {
            return Ok(false);
        };
        if Self::parse(raw_request)? != *self {
            return Ok(false);
        }
        if !matches!(
            algorithm.as_str(),
            "ssh-ed25519" | "rsa-sha2-256" | "rsa-sha2-512"
        ) {
            return Ok(false);
        }
        let mut signature_reader = Reader::new(signature);
        if signature_reader.string()? != algorithm.as_bytes() {
            return Ok(false);
        }
        let signature_bytes = signature_reader.string()?;
        signature_reader.finish()?;
        if session_id.len() > MAX_PAYLOAD {
            return Err(Error::FieldTooLong);
        }
        let prefix_len = raw_request.len() - 4 - signature.len();
        let mut signed = Vec::with_capacity(4 + session_id.len() + prefix_len);
        signed.extend_from_slice(&(session_id.len() as u32).to_be_bytes());
        signed.extend_from_slice(session_id);
        signed.extend_from_slice(&raw_request[..prefix_len]);
        let mut key_reader = Reader::new(key);
        let key_algorithm = key_reader.string()?;
        if algorithm == "ssh-ed25519" {
            if key_algorithm != b"ssh-ed25519" {
                return Ok(false);
            }
            let public_key = key_reader.string()?;
            key_reader.finish()?;
            return Ok(ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                public_key,
            )
            .verify(&signed, signature_bytes)
            .is_ok());
        }
        if key_algorithm != b"ssh-rsa" {
            return Ok(false);
        }
        let exponent = key_reader.mpint()?;
        let modulus = key_reader.mpint()?;
        key_reader.finish()?;
        if exponent.is_negative()
            || modulus.is_negative()
            || exponent.as_bytes().is_empty()
            || modulus.as_bytes().is_empty()
        {
            return Ok(false);
        }
        let exponent = exponent
            .as_bytes()
            .strip_prefix(&[0])
            .unwrap_or(exponent.as_bytes());
        let modulus = modulus
            .as_bytes()
            .strip_prefix(&[0])
            .unwrap_or(modulus.as_bytes());
        let parameters = if algorithm == "rsa-sha2-256" {
            &ring::signature::RSA_PKCS1_2048_8192_SHA256
        } else {
            &ring::signature::RSA_PKCS1_2048_8192_SHA512
        };
        if signature_bytes.len() > modulus.len() {
            return Ok(false);
        }
        let mut padded_signature = vec![0; modulus.len()];
        padded_signature[modulus.len() - signature_bytes.len()..].copy_from_slice(signature_bytes);
        Ok(ring::signature::RsaPublicKeyComponents {
            n: modulus,
            e: exponent,
        }
        .verify(parameters, &signed, &padded_signature)
        .is_ok())
    }
}

/// One keyboard interactive prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    /// Text shown to the user.
    pub text: String,
    /// Whether input may be shown while typed.
    pub echo: bool,
}

/// Authentication messages. Response values intentionally have no Debug
/// implementation because keyboard responses can contain secrets.
#[derive(Clone, PartialEq, Eq)]
pub enum Message {
    /// Client credentials.
    Request(Request),
    /// Remaining methods and whether an earlier factor succeeded.
    Failure {
        /// Methods still available.
        methods: Vec<String>,
        /// Whether a factor has succeeded but more are required.
        partial_success: bool,
    },
    /// Authentication completed.
    Success,
    /// Text displayed before authentication completes.
    Banner {
        /// Banner text.
        message: String,
        /// Language tag.
        language: String,
    },
    /// The server will accept a signed proof for this key.
    PublicKeyOk {
        /// Signature algorithm.
        algorithm: String,
        /// Public key blob.
        key: Vec<u8>,
    },
    /// The current password must be changed.
    PasswordChange {
        /// Instruction shown to the user.
        prompt: String,
        /// Language tag.
        language: String,
    },
    /// A keyboard interactive challenge.
    InfoRequest {
        /// Challenge title.
        name: String,
        /// Instructions shown before the prompts.
        instruction: String,
        /// Language tag.
        language: String,
        /// Ordered prompts.
        prompts: Vec<Prompt>,
    },
    /// Ordered keyboard interactive answers.
    InfoResponse(Vec<Vec<u8>>),
}

impl Message {
    /// Decode with the active authentication method, resolving message sixty.
    pub fn parse_with_method(payload: &[u8], method: &str) -> Result<Self, Error> {
        let mut r = reader(payload)?;
        let message = match r.byte()? {
            50 => return Request::parse(payload).map(Self::Request),
            51 => Self::Failure {
                methods: r.name_list(MAX_PAYLOAD)?,
                partial_success: r.boolean()?,
            },
            52 => Self::Success,
            53 => Self::Banner {
                message: r.text(MAX_PAYLOAD)?,
                language: r.text(MAX_PAYLOAD)?,
            },
            60 => match method {
                "publickey" => Self::PublicKeyOk {
                    algorithm: name(&mut r)?,
                    key: r.string()?.to_vec(),
                },
                "password" => Self::PasswordChange {
                    prompt: r.text(MAX_PAYLOAD)?,
                    language: r.text(MAX_PAYLOAD)?,
                },
                "keyboard-interactive" => {
                    let name = r.text(MAX_PAYLOAD)?;
                    let instruction = r.text(MAX_PAYLOAD)?;
                    let language = r.text(MAX_PAYLOAD)?;
                    let count = r.uint32()? as usize;
                    if count > r.remaining().len() / 5 {
                        return Err(Error::Truncated);
                    }
                    let mut prompts = Vec::with_capacity(count);
                    for _ in 0..count {
                        prompts.push(Prompt {
                            text: r.text(MAX_PAYLOAD)?,
                            echo: r.boolean()?,
                        });
                    }
                    Self::InfoRequest {
                        name,
                        instruction,
                        language,
                        prompts,
                    }
                }
                _ => return Err(Error::Unwritable),
            },
            61 => {
                let count = r.uint32()? as usize;
                if count > r.remaining().len() / 4 {
                    return Err(Error::Truncated);
                }
                let mut responses = Vec::with_capacity(count);
                for _ in 0..count {
                    responses.push(r.string()?.to_vec());
                }
                Self::InfoResponse(responses)
            }
            _ => return Err(Error::Unwritable),
        };
        r.finish()?;
        Ok(message)
    }
}

impl Wire for Message {
    type ParseError = Error;
    type WriteError = Error;

    /// Decode with keyboard interactive as the context for message sixty.
    fn parse(payload: &[u8]) -> Result<Self, Error> {
        Self::parse_with_method(payload, "keyboard-interactive")
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let mut w = Payload::new(match self {
            Self::Request(request) => return request.write(out),
            Self::Failure { .. } => 51,
            Self::Success => 52,
            Self::Banner { .. } => 53,
            Self::PublicKeyOk { .. } | Self::PasswordChange { .. } | Self::InfoRequest { .. } => 60,
            Self::InfoResponse(_) => 61,
        });
        match self {
            Self::Request(_) => unreachable!(),
            Self::Failure {
                methods,
                partial_success,
            } => {
                let mut size = 0usize;
                for method in methods {
                    if !super::is_name(method.as_bytes()) {
                        return Err(Error::Unwritable);
                    }
                    size = size
                        .checked_add(method.len() + 1)
                        .ok_or(Error::Unwritable)?;
                    if size > MAX_PAYLOAD {
                        return Err(Error::Unwritable);
                    }
                }
                w.string(methods.join(",").as_bytes())?;
                w.byte(u8::from(*partial_success))?;
            }
            Self::Success => (),
            Self::Banner { message, language } => {
                w.string(message.as_bytes())?;
                w.string(language.as_bytes())?;
            }
            Self::PublicKeyOk { algorithm, key } => {
                w.name(algorithm)?;
                w.string(key)?;
            }
            Self::PasswordChange { prompt, language } => {
                w.string(prompt.as_bytes())?;
                w.string(language.as_bytes())?;
            }
            Self::InfoRequest {
                name,
                instruction,
                language,
                prompts,
            } => {
                w.string(name.as_bytes())?;
                w.string(instruction.as_bytes())?;
                w.string(language.as_bytes())?;
                w.count(prompts.len(), 5)?;
                for prompt in prompts {
                    w.string(prompt.text.as_bytes())?;
                    w.byte(u8::from(prompt.echo))?;
                }
            }
            Self::InfoResponse(responses) => {
                w.count(responses.len(), 4)?;
                for response in responses {
                    w.string(response)?;
                }
            }
        }
        w.finish(out)
    }
}

pub(super) fn reader(payload: &[u8]) -> Result<Reader<'_>, Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::FieldTooLong);
    }
    if payload.is_empty() {
        return Err(Error::Empty);
    }
    Ok(Reader::new(payload))
}

pub(super) fn name(r: &mut Reader<'_>) -> Result<String, Error> {
    let name = r.text(MAX_NAME)?;
    if !super::is_name(name.as_bytes()) {
        return Err(Error::Name);
    }
    Ok(name)
}

pub(super) fn rest(r: &mut Reader<'_>) -> Vec<u8> {
    let data = r.remaining().to_vec();
    *r = Reader::new(&[]);
    data
}

pub(super) struct Payload(Vec<u8>);

impl Payload {
    pub(super) fn new(number: u8) -> Self {
        Self(vec![number])
    }
    pub(super) fn raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > MAX_PAYLOAD - self.0.len() {
            return Err(Error::Unwritable);
        }
        self.0
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Unwritable)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    pub(super) fn byte(&mut self, byte: u8) -> Result<(), Error> {
        self.raw(&[byte])
    }
    pub(super) fn uint32(&mut self, value: u32) -> Result<(), Error> {
        self.raw(&value.to_be_bytes())
    }
    pub(super) fn string(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > MAX_PAYLOAD {
            return Err(Error::Unwritable);
        }
        self.uint32(bytes.len() as u32)?;
        self.raw(bytes)
    }
    pub(super) fn name(&mut self, name: &str) -> Result<(), Error> {
        if !super::is_name(name.as_bytes()) {
            return Err(Error::Unwritable);
        }
        self.string(name.as_bytes())
    }
    pub(super) fn count(&mut self, count: usize, minimum_size: usize) -> Result<(), Error> {
        if count > MAX_PAYLOAD / minimum_size {
            return Err(Error::Unwritable);
        }
        self.uint32(count as u32)
    }
    pub(super) fn finish(self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.try_reserve_exact(self.0.len())
            .map_err(|_| Error::Unwritable)?;
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::{
        codec::Lcg,
        test_support::{mutate, rounds},
    };

    #[test]
    fn randomized_authentication_roundtrips() {
        let mut g = Lcg::new(0x61757468);
        for _ in 0..rounds(1000) {
            let methods = [
                Method::None,
                Method::Password {
                    password: g.bytes(200),
                    new_password: g.coin().then(|| g.bytes(200)),
                },
                Method::PublicKey {
                    algorithm: "ssh-ed25519".into(),
                    key: g.bytes(200),
                    signature: g.coin().then(|| g.bytes(200)),
                },
                Method::KeyboardInteractive {
                    language: g.text(20),
                    submethods: g.text(60),
                },
                Method::Other {
                    name: "extension@example.com".into(),
                    data: g.bytes(200),
                },
            ];
            for method in methods {
                let request = Request {
                    user: g.text(200),
                    service: "ssh-connection".into(),
                    method,
                };
                let mut bytes = request.to_bytes().unwrap();
                assert_eq!(Request::parse(&bytes).unwrap(), request);
                mutate(&mut g, &mut bytes);
                if let Ok(parsed) = Request::parse(&bytes) {
                    assert_eq!(Request::parse(&parsed.to_bytes().unwrap()).unwrap(), parsed);
                }
            }
            let responses = [
                Message::Failure {
                    methods: vec!["publickey".into(), "password".into()],
                    partial_success: g.coin(),
                },
                Message::Success,
                Message::Banner {
                    message: g.text(200),
                    language: g.text(20),
                },
                Message::PublicKeyOk {
                    algorithm: "ssh-ed25519".into(),
                    key: g.bytes(200),
                },
                Message::PasswordChange {
                    prompt: g.text(200),
                    language: g.text(20),
                },
                Message::InfoRequest {
                    name: g.text(50),
                    instruction: g.text(200),
                    language: g.text(20),
                    prompts: (0..g.index(10))
                        .map(|_| Prompt {
                            text: g.text(200),
                            echo: g.coin(),
                        })
                        .collect(),
                },
                Message::InfoResponse((0..g.index(10)).map(|_| g.bytes(200)).collect()),
            ];
            for response in responses {
                let context = match response {
                    Message::PublicKeyOk { .. } => "publickey",
                    Message::PasswordChange { .. } => "password",
                    _ => "keyboard-interactive",
                };
                let mut bytes = response.to_bytes().unwrap();
                assert!(Message::parse_with_method(&bytes, context).unwrap() == response);
                mutate(&mut g, &mut bytes);
                if let Ok(parsed) = Message::parse_with_method(&bytes, context) {
                    assert!(
                        Message::parse_with_method(&parsed.to_bytes().unwrap(), context).unwrap()
                            == parsed
                    );
                }
            }
        }
    }

    #[test]
    fn randomized_signed_request_roundtrips() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let mut g = Lcg::new(0x7369676e);
        for _ in 0..rounds(100) {
            let mut seed = [0; 32];
            g.fill(&mut seed);
            let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
            let mut key = Payload::new(0);
            key.name("ssh-ed25519").unwrap();
            key.string(pair.public_key().as_ref()).unwrap();
            let session_id = g.bytes(64);
            let mut request = Request {
                user: g.text(100),
                service: "ssh-connection".into(),
                method: Method::PublicKey {
                    algorithm: "ssh-ed25519".into(),
                    key: key.0[1..].to_vec(),
                    signature: Some(Vec::new()),
                },
            };
            let mut signed = Payload::new(0);
            signed.string(&session_id).unwrap();
            let prefix = request.to_bytes().unwrap();
            signed.raw(&prefix[..prefix.len() - 4]).unwrap();
            let signature = pair.sign(&signed.0[1..]);
            let mut signature_blob = Payload::new(0);
            signature_blob.name("ssh-ed25519").unwrap();
            signature_blob.string(signature.as_ref()).unwrap();
            if let Method::PublicKey { signature, .. } = &mut request.method {
                *signature = Some(signature_blob.0[1..].to_vec());
            }
            let bytes = request.to_bytes().unwrap();
            let parsed = Request::parse(&bytes).unwrap();
            assert_eq!(parsed, request);
            assert!(parsed.verify_public_key(&session_id, &bytes).unwrap());
        }
    }
}
