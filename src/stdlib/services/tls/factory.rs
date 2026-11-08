use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::layer::{Budget, ByteStream, Layer, Side};
use fictionet::stdlib::network::ConnInfo;
use fictionet::stdlib::services::stack::{BoxError, Boxed, Job};
use fictionet::time::Instant;

use super::{HandshakeError, Picking, Secure, TlsLayer};

/// Authoritative negotiation state. Failure must remain failure even after
/// an implementation has handed its error to the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handshake<'a> {
    /// No application may be constructed yet.
    Pending,
    /// The authenticated stream is ready for its application.
    Established {
        /// The name requested by the peer, if present.
        server_name: Option<&'a str>,
        /// The application protocol agreed with the peer, if present.
        alpn: Option<&'a [u8]>,
    },
    /// Negotiation failed; no application may be constructed.
    Failed,
}

/// A replaceable TLS stream layer. Metadata is authoritative only once
/// established. Implementations retain plaintext until the upper layer
/// accepts it, and enforce the opening handshake deadline.
pub trait Negotiation: Layer<Lower = ByteStream, Upper = ByteStream> {
    /// Current handshake state and negotiated metadata.
    fn handshake(&self) -> Handshake<'_>;
}

/// Asynchronous certificate selection by the name in the client's hello.
/// `None` refuses the name. Dropping the future cancels selection.
pub type Selection = Arc<dyn Fn(Cx, Option<String>) -> Picking + Send + Sync>;

/// What a TLS factory receives for one accepted connection, before
/// negotiation.
pub struct Opening {
    /// Runtime context, including deterministic entropy.
    pub cx: Cx,
    /// Connection identity before negotiation.
    pub info: ConnInfo,
    /// The connection's allocation budget.
    pub budget: Budget,
    /// Absolute deadline, including asynchronous certificate selection.
    pub deadline: Instant,
    /// The listener's per-name certificate selection. Invoke this with the
    /// client's requested name to use the world's certificates; application
    /// routing follows the name reported in `Handshake::Established`.
    pub select: Selection,
}

type Application = Box<dyn FnOnce(Handshake<'_>) -> Boxed + Send>;
type Make = dyn Fn(Opening, Application) -> Boxed + Send + Sync;

/// A listener's TLS implementation. The default composition is
/// `Chain<TlsLayer, Later<Boxed>>`, through [`Secure`]. Applications are
/// constructed only after successful negotiation, before plaintext delivery.
#[derive(Clone)]
pub struct Factory {
    make: Arc<Make>,
    error: fn(BoxError) -> HandshakeError,
}

impl Factory {
    /// Uses `make` to construct a fresh replacement layer per connection.
    pub fn new<T>(make: impl Fn(Opening) -> T + Send + Sync + 'static) -> Self
    where
        T: Negotiation + Send + 'static,
        T::Report: core::fmt::Debug + Send + 'static,
        T::Work: Job<Done = T::Done>,
        T::Done: Send + 'static,
        T::Error: Into<BoxError> + core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    {
        Self {
            make: Arc::new(move |opening, application| {
                Boxed::new(Secure::new(make(opening), move |tls: &T| {
                    application(tls.handshake())
                }))
            }),
            error: |error| {
                let error = match error.downcast::<Side<T::Error, BoxError>>() {
                    Ok(error) => match *error {
                        Side::Lower(error) => error.into(),
                        Side::Upper(error) => error,
                    },
                    Err(error) => error,
                };
                match error.downcast::<HandshakeError>() {
                    Ok(error) => *error,
                    Err(error) => HandshakeError::Failed(error.to_string()),
                }
            },
        }
    }

    /// Converts an error from this factory's boxed stack for TLS observers.
    /// Standard handshake errors retain their classification; replacement
    /// errors of another type are reported as `HandshakeError::Failed`.
    pub fn handshake_error(&self, error: BoxError) -> HandshakeError {
        (self.error)(error)
    }

    /// Composes this listener's TLS with the negotiated application.
    pub fn build(
        &self,
        opening: Opening,
        application: impl FnOnce(Handshake<'_>) -> Boxed + Send + 'static,
    ) -> Boxed {
        (self.make)(opening, Box::new(application))
    }
}

impl Default for Factory {
    fn default() -> Self {
        Self::new(|opening| {
            TlsLayer::selecting(move |cx, hello| {
                (opening.select)(cx, hello.server_name().map(str::to_owned))
            })
            .handshake_by(opening.deadline)
        })
    }
}
