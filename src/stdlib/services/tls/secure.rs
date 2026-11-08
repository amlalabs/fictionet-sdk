use std::sync::Arc;

use rustls::ServerConfig;

use super::{HandshakeError, Pick, TlsLayer};
use fictionet::stdlib::layer::{
    Admit, ByteStream, Chain, CommandOf, Env, EventOf, Later, Layer, Side, StreamEvent,
};
use fictionet::time::Instant;

/// [`TlsLayer`] with the layer above it made once the handshake is done,
/// from what the handshake settled: the name in the client's hello and the
/// protocol both sides agreed on with ALPN.
///
/// It is [`Chain`]`<TlsLayer, `[`Later`]`<U>>`: the plaintext the client sends
/// right after its handshake waits in order until `make` has made the layer
/// above, then reaches it first. A handshake that fails never makes it.
pub struct Secure<U: Layer<Lower = ByteStream>, F> {
    chain: Chain<TlsLayer, Later<U>>,
    make: Option<F>,
}

impl<U, F> Secure<U, F>
where
    U: Layer<Lower = ByteStream>,
    F: FnOnce(&TlsLayer) -> U,
{
    /// `tls`, with what `make` makes from it above, once its handshake is
    /// done.
    pub fn new(tls: TlsLayer, make: F) -> Secure<U, F> {
        Secure {
            chain: Chain::new(tls, Later::new()),
            make: Some(make),
        }
    }

    /// The TLS layer.
    pub fn tls(&self) -> &TlsLayer {
        self.chain.lower()
    }

    /// The layer above, once it is made.
    pub fn upper(&self) -> Option<&U> {
        self.chain.upper().get()
    }
}

impl<U, F> Layer for Secure<U, F>
where
    U: Layer<Lower = ByteStream>,
    F: FnOnce(&TlsLayer) -> U,
{
    type Lower = ByteStream;
    type Upper = U::Upper;
    type Report = Side<(), U::Report>;
    type Timer = Side<(), U::Timer>;
    type Work = Side<Pick, U::Work>;
    type Done = Side<Option<Arc<ServerConfig>>, U::Done>;
    type Error = Side<HandshakeError, U::Error>;

    fn report_bytes(report: &Self::Report) -> Option<usize> {
        match report {
            Side::Lower(()) => Some(0),
            Side::Upper(report) => U::report_bytes(report),
        }
    }

    fn depth(&self) -> usize {
        self.chain.depth()
    }

    fn is_terminal(&self) -> bool {
        self.chain.is_terminal()
    }

    fn on_event(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        event: StreamEvent,
    ) -> Result<Admit<StreamEvent>, Self::Error> {
        self.chain.on_event(env, event)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        command: CommandOf<U::Upper>,
    ) -> Result<Admit<CommandOf<U::Upper>>, Self::Error> {
        self.chain.on_command(env, command)
    }

    fn on_timer(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        timer: Self::Timer,
    ) -> Result<(), Self::Error> {
        self.chain.on_timer(env, timer)
    }

    fn on_done(
        &mut self,
        env: &mut Env<'_, Self::Report>,
        done: Self::Done,
    ) -> Result<(), Self::Error> {
        self.chain.on_done(env, done)
    }

    fn advance(&mut self, env: &mut Env<'_, Self::Report>) -> Result<bool, Self::Error> {
        let tls = self.chain.lower();
        let settled = !tls.is_handshaking() && tls.failure().is_none();
        let mut moved = false;
        if settled && let Some(make) = self.make.take() {
            let upper = make(self.chain.lower());
            self.chain.upper_mut().set(upper);
            moved = true;
        }
        Ok(self.chain.advance(env)? || moved)
    }

    fn take_command(&mut self) -> Option<CommandOf<ByteStream>> {
        self.chain.take_command()
    }

    fn take_event(&mut self) -> Option<EventOf<U::Upper>> {
        self.chain.take_event()
    }

    fn take_urgent(&mut self) -> Option<EventOf<U::Upper>> {
        self.chain.take_urgent()
    }

    fn take_work(&mut self) -> Option<Self::Work> {
        self.chain.take_work()
    }

    fn deadline(&self) -> Option<(Instant, Self::Timer)> {
        self.chain.deadline()
    }
}
