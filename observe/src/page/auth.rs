use std::io;

use super::http::Request;

pub(super) struct Auth {
    pub token: String,
}

impl Auth {
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            token: super::random_hex()?,
        })
    }

    pub fn allows(&self, req: &Request) -> bool {
        req.authorization.as_deref().is_some_and(|value| {
            value.split_once(' ').is_some_and(|(scheme, token)| {
                scheme.eq_ignore_ascii_case("Bearer")
                    && token.len() == self.token.len()
                    && token
                        .bytes()
                        .zip(self.token.bytes())
                        .fold(0, |diff, (a, b)| diff | (a ^ b))
                        == 0
            })
        })
    }

    pub fn bootstrap(&self, req: &Request) -> bool {
        req.query.is_empty() && self.allows(req)
    }
}
