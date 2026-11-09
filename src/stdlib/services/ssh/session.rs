//! Handler policy on one typed SSH channel.

use super::channel::{ChannelCommand, ChannelEvent, ChannelPort, Opening};
use super::{
    Chunk, ConnInfo, Context, Handler, OUTPUT_LIMIT, Output, Program, Pty, Session, SessionEvent,
    SessionRequest, TransportError, wire,
};
use crate::stdlib::layer::{
    Admit, Budget, Charge, Env, Layer, Owned, StreamCommand, StreamEvent, Top,
};
use core::convert::Infallible;
use std::sync::Arc;

/// Adapts the synchronous session policy to one channel. Configuration and
/// callback-owned memory remain application allocations; retained session bytes
/// reported by `Session::held` are charged after each callback.
pub struct SessionLayer<H: Handler> {
    handler: Arc<H>,
    pub(super) policy_close: Option<Arc<super::AtomicU8>>,
    connection: Arc<ConnInfo>,
    opening: Owned<Opening>,
    session: Option<H::Session>,
    pty: Option<Pty>,
    environment: Vec<(Vec<u8>, Vec<u8>)>,
    output: Output,
    pending: Option<ChannelCommand>,
    started: bool,
    draining: bool,
    eof: bool,
    closed: bool,
    exit: Option<u32>,
    exit_stage: u8,
    now: crate::time::Instant,
    state: Option<Charge>,
}
impl<H: Handler> SessionLayer<H> {
    /// One application instance, made by `Children` from the authenticated opening.
    pub fn new(
        handler: Arc<H>,
        connection: Arc<ConnInfo>,
        opening: Owned<Opening>,
        budget: &Budget,
    ) -> Self {
        Self {
            handler,
            policy_close: None,
            connection,
            opening,
            session: None,
            pty: None,
            environment: Vec::new(),
            output: Output::with_budget(budget.clone()),
            pending: None,
            started: false,
            draining: false,
            eof: false,
            closed: false,
            exit: None,
            exit_stage: 0,
            now: crate::time::Instant::ZERO,
            state: None,
        }
    }
    fn account(&mut self, budget: &Budget) -> Result<(), TransportError> {
        if let Some(signal) = &self.policy_close {
            let policy = u8::from(self.output.hangup) | (u8::from(self.output.disconnect) << 1);
            signal.fetch_or(policy, super::Ordering::Relaxed);
        }
        let bytes = 4 * super::ssh::MAX_PAYLOAD + self.session.as_ref().map_or(0, Session::held);
        let fits = match &mut self.state {
            Some(charge) => charge.set(bytes),
            None => {
                self.state = budget.charge(bytes);
                self.state.is_some()
            }
        };
        if fits {
            Ok(())
        } else {
            Err(TransportError::State)
        }
    }
    fn request(&mut self, request: wire::SessionRequest, want_reply: bool) {
        let context = Context {
            connection: &self.connection,
            now: self.now,
        };
        if !matches!(self.opening.kind, wire::OpenKind::Session) {
            if want_reply {
                self.pending = Some(ChannelCommand::Reply(false));
            }
            return;
        }
        let accepted = match request {
            wire::SessionRequest::Pty {
                ref terminal,
                ref dimensions,
                ref modes,
            } if self.session.is_none() && self.pty.is_none() => {
                let accepted = self
                    .handler
                    .configure(&context, self.opening.channel, &request);
                if accepted {
                    self.pty = Some(Pty {
                        terminal: terminal.clone(),
                        columns: dimensions.columns,
                        rows: dimensions.rows,
                        pixel_width: dimensions.pixel_width,
                        pixel_height: dimensions.pixel_height,
                        modes: modes.clone(),
                    });
                }
                accepted
            }
            wire::SessionRequest::Env {
                ref name,
                ref value,
            } if self.session.is_none() && self.environment.len() < 32 => {
                let held: usize = self
                    .environment
                    .iter()
                    .map(|(n, v)| n.len() + v.len())
                    .sum();
                let accepted = held + name.len() + value.len() <= 8192
                    && self
                        .handler
                        .configure(&context, self.opening.channel, &request);
                if accepted {
                    self.environment.push((name.clone(), value.clone()));
                }
                accepted
            }
            wire::SessionRequest::Shell
            | wire::SessionRequest::Exec(_)
            | wire::SessionRequest::Subsystem(_)
                if self.session.is_none() =>
            {
                let program = match request {
                    wire::SessionRequest::Shell => Program::Shell,
                    wire::SessionRequest::Exec(c) => Program::Exec(c),
                    wire::SessionRequest::Subsystem(n) => Program::Subsystem(n),
                    _ => unreachable!(),
                };
                let request = SessionRequest {
                    user: self.opening.user.clone(),
                    channel: self.opening.channel,
                    program,
                    pty: self.pty.clone(),
                    environment: self.environment.clone(),
                };
                self.session = self.handler.open(&context, &request, &mut self.output);
                if let Some(session) = &mut self.session {
                    if self.eof {
                        session.event(&context, &SessionEvent::Eof, &mut self.output);
                    }
                } else {
                    self.output.clear();
                }
                self.session.is_some()
            }
            wire::SessionRequest::WindowChange(dimensions) if self.pty.is_some() => {
                if let Some(pty) = &mut self.pty {
                    pty.columns = dimensions.columns;
                    pty.rows = dimensions.rows;
                    pty.pixel_width = dimensions.pixel_width;
                    pty.pixel_height = dimensions.pixel_height;
                }
                if let Some(session) = &mut self.session {
                    session.event(
                        &context,
                        &SessionEvent::WindowChange {
                            columns: dimensions.columns,
                            rows: dimensions.rows,
                            pixel_width: dimensions.pixel_width,
                            pixel_height: dimensions.pixel_height,
                        },
                        &mut self.output,
                    );
                }
                true
            }
            wire::SessionRequest::Signal(signal) if self.session.is_some() => {
                self.session.as_mut().unwrap().event(
                    &context,
                    &SessionEvent::Signal(signal),
                    &mut self.output,
                );
                true
            }
            _ => false,
        };

        if want_reply {
            self.pending = Some(ChannelCommand::Reply(accepted));
        }
    }
}
impl<H: Handler> Layer for SessionLayer<H> {
    type Lower = ChannelPort;
    type Upper = Top;
    type Report = Infallible;
    type Timer = ();
    type Work = ();
    type Done = ();
    type Error = TransportError;
    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, TransportError> {
        self.now = env.now();
        if self.started {
            return Ok(false);
        }
        self.account(env.budget())?;
        self.started = true;
        let accepted = match &self.opening.kind {
            wire::OpenKind::Session => true,
            wire::OpenKind::DirectTcpIp(endpoint) => {
                let context = Context {
                    connection: &self.connection,
                    now: self.now,
                };
                self.session = self.handler.direct_tcpip(
                    &context,
                    self.opening.channel,
                    endpoint,
                    &mut self.output,
                );
                self.session.is_some()
            }
            _ => false,
        };
        self.pending = Some(ChannelCommand::Accept(accepted));
        self.account(env.budget())?;
        Ok(true)
    }
    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: ChannelEvent,
    ) -> Result<Admit<ChannelEvent>, TransportError> {
        self.now = env.now();
        if matches!(event, ChannelEvent::Stream(StreamEvent::Written(_))) {
            return Ok(Admit::Taken);
        }
        if matches!(event, ChannelEvent::Stream(StreamEvent::Reset)) {
            if !self.closed {
                self.closed = true;
                if let Some(session) = &mut self.session {
                    session.event(
                        &Context {
                            connection: &self.connection,
                            now: self.now,
                        },
                        &SessionEvent::Closed,
                        &mut self.output,
                    );
                }
            }
            return Ok(Admit::Taken);
        }
        if self.closed || self.draining || self.output.hangup || self.output.disconnect {
            return Ok(Admit::Closed(event));
        }
        if self.pending.is_some() || self.output.bytes > OUTPUT_LIMIT - super::PACKET as usize {
            return Ok(Admit::Blocked(event));
        }
        self.account(env.budget())?;
        match event {
            ChannelEvent::Stream(StreamEvent::Data(data)) => {
                let session = self.session.as_mut().ok_or(TransportError::State)?;
                session.input(
                    &Context {
                        connection: &self.connection,
                        now: self.now,
                    },
                    &data,
                    &mut self.output,
                );
            }
            ChannelEvent::Stream(StreamEvent::Ended) => {
                self.eof = true;
                if let Some(session) = &mut self.session {
                    session.event(
                        &Context {
                            connection: &self.connection,
                            now: self.now,
                        },
                        &SessionEvent::Eof,
                        &mut self.output,
                    );
                }
            }
            ChannelEvent::Request {
                want_reply,
                request,
            } => {
                let (request, _charge) = request.into_parts();
                self.request(request, want_reply);
            }
            ChannelEvent::Extended { kind, data } => {
                if let Some(session) = &mut self.session {
                    session.extended(
                        &Context {
                            connection: &self.connection,
                            now: self.now,
                        },
                        kind,
                        &data,
                        &mut self.output,
                    );
                }
            }
            ChannelEvent::Reply(accepted) => {
                if let Some(session) = &mut self.session {
                    session.reply(
                        &Context {
                            connection: &self.connection,
                            now: self.now,
                        },
                        accepted,
                        &mut self.output,
                    );
                }
            }
            ChannelEvent::Stream(StreamEvent::Written(_) | StreamEvent::Reset) => unreachable!(),
        }
        self.account(env.budget())?;
        Ok(Admit::Taken)
    }
    fn on_command(
        &mut self,
        _: &mut Env<'_, Infallible>,
        command: Infallible,
    ) -> Result<Admit<Infallible>, TransportError> {
        match command {}
    }
    fn take_event(&mut self) -> Option<Infallible> {
        None
    }
    fn take_command(&mut self, _env: &mut Env<'_, Self::Report>) -> Option<ChannelCommand> {
        if self.output.disconnect {
            self.output.disconnect = false;
            return Some(ChannelCommand::Disconnect);
        }
        if let Some(command) = self.pending.take() {
            return Some(command);
        }
        if self.output.hangup && !self.draining {
            self.draining = true;
            return Some(ChannelCommand::Draining);
        }
        if let Some(status) = self.exit {
            self.exit_stage += 1;
            return Some(match self.exit_stage {
                1 if matches!(self.opening.kind, wire::OpenKind::Session) => {
                    let charge = self.output.budget.as_ref()?.charge(0)?;
                    ChannelCommand::Request {
                        want_reply: false,
                        request: Owned::new(wire::SessionRequest::ExitStatus(status), charge),
                    }
                }
                1 | 2 => {
                    if self.exit_stage == 1 {
                        self.exit_stage = 2;
                    }
                    ChannelCommand::Stream(StreamCommand::End)
                }
                _ => {
                    self.exit = None;
                    ChannelCommand::Close
                }
            });
        }
        match self.output.chunks.pop_front() {
            Some(Chunk::Data { stderr, data, .. }) => {
                self.output.bytes -= data.len();
                Some(if stderr {
                    ChannelCommand::Extended { kind: 1, data }
                } else {
                    ChannelCommand::Stream(StreamCommand::Write(data))
                })
            }
            Some(Chunk::Exit(status)) => {
                self.exit = Some(status);
                self.take_command(_env)
            }
            None if self.output.hangup => {
                self.output.hangup = false;
                Some(ChannelCommand::Hangup)
            }
            None => None,
        }
    }
}
impl<H: Handler> Drop for SessionLayer<H> {
    fn drop(&mut self) {
        if !self.closed
            && let Some(session) = &mut self.session
        {
            session.event(
                &Context {
                    connection: &self.connection,
                    now: self.now,
                },
                &SessionEvent::Closed,
                &mut self.output,
            );
        }
    }
}
