use std::net::IpAddr;
use std::sync::Arc;

use fictionet::Cx;
use fictionet::stdlib::layer::{Budget, Chunk, Layer, Packets};
use fictionet::stdlib::services::stack::{BoxError, Boxed, Job};

use super::{CheckedIpPacket, IpLayer};

/// An IP implementation between a machine's interface and its transports.
pub type Stack = Boxed<Packets<Chunk, Chunk>, Packets<CheckedIpPacket, Chunk>>;

/// Construction context for one machine's IP layer, before its route or
/// services are published. A factory must not start protocol progress.
pub struct Opening {
    /// Clock and entropy of the world that owns this machine.
    pub cx: Cx,
    /// The machine's address.
    pub addr: IpAddr,
    /// The budget for retained packet and composition state.
    pub budget: Budget,
}

/// Builds a replaceable IP layer for a world host. The default is `IpLayer`;
/// TCP, UDP and the applications above them keep their existing boundaries.
#[derive(Clone)]
pub struct Factory(Arc<dyn Fn(Opening) -> Stack + Send + Sync>);

impl Factory {
    /// Uses `make` to construct each machine's layer. Packets emitted upward
    /// must satisfy the checked `CheckedIpPacket` contract. Egress packets also pass
    /// through this layer, so a replacement can encapsulate both directions.
    pub fn new<L>(make: impl Fn(Opening) -> L + Send + Sync + 'static) -> Self
    where
        L: Layer<Lower = Packets<Chunk, Chunk>, Upper = Packets<CheckedIpPacket, Chunk>>
            + Send
            + 'static,
        L::Report: core::fmt::Debug + Send + 'static,
        L::Work: Job<Done = L::Done>,
        L::Done: Send + 'static,
        L::Error: Into<BoxError> + Send + Sync + 'static,
    {
        Self(Arc::new(move |opening| Boxed::new(make(opening))))
    }

    /// Constructs a layer without starting a task or publishing a route.
    pub fn build(&self, opening: Opening) -> Stack {
        (self.0)(opening)
    }
}

impl Default for Factory {
    fn default() -> Self {
        Self::new(|_| IpLayer::host())
    }
}
