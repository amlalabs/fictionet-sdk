//! gRPC calls on one HTTP/2 exchange.

use std::collections::VecDeque;
use std::convert::Infallible;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::layer::{
    Admit, Charge, ChargedBytes, Chunk, Env, Layer, MessageCommand, MessageEvent, Messages,
};
use fictionet::stdlib::protocols::grpc::{self, Code, ContentType, Rejection, Status};
use fictionet::stdlib::protocols::http2::ErrorCode;

use super::{ExchangeCommand, ExchangeEvent, Http2, HttpExchange, Opening, ResponseHead};

/// How many messages wait for the application before the call stops
/// taking body bytes.
const WAITING: usize = 16;

/// What comes up from a gRPC call.
#[derive(Debug)]
pub enum GrpcEvent {
    /// The call, with its checked headers. It comes first, once.
    Call(Box<grpc::Request>),
    /// The client's next message.
    Message(grpc::Message),
}

/// What an application answers a gRPC call with.
#[derive(Debug)]
pub enum GrpcCommand {
    /// A message to the client.
    Message(grpc::Message),
    /// The call's status, which ends it. Ending the port without one ends
    /// the call with `OK`.
    Status(Status),
}

/// gRPC on one [`HttpExchange`]: the call's headers checked with
/// [`grpc::Request::parse`], its DATA read as length-prefixed messages,
/// however the frames split them, and the application's messages and
/// status written back as DATA and trailers.
///
/// It sits under an application with a [`Messages`] port: the call
/// ([`GrpcEvent::Call`]), each message ([`GrpcEvent::Message`]), then
/// [`MessageEvent::Ended`] when the client half-closes. The application
/// sends [`GrpcCommand`]s and ends with a status. Each call is its own
/// child, so calls on one connection interleave without mixing:
/// `Chain<Http2, Children<Chain<Grpc, App>, Top, Opening>>`. The connection
/// dates the heads when it has the world's date ([`Http2::date`]).
///
/// A request that is not a gRPC call is answered without the application:
/// the HTTP status or the trailers-only status [`grpc::Request::parse`]
/// names. A message stream that breaks the framing ends the call with
/// `INTERNAL`; a body the connection cannot hold, with
/// `RESOURCE_EXHAUSTED`. A partial message is charged to the budget while
/// it waits for the rest.
pub struct Grpc {
    content_type: ContentType,
    up: VecDeque<MessageEvent<GrpcEvent>>,
    /// The bytes of a message not yet whole, after whole messages that
    /// wait for the application to have room.
    partial: Vec<u8>,
    /// Where the whole messages at the start of `partial`, their prefixes
    /// checked, end.
    checked: usize,
    charge: Option<Charge>,
    next: Option<ExchangeCommand>,
    /// A message that waits for the head to go first.
    message: Option<grpc::Message>,
    head_sent: bool,
    /// The status went out, or the call was answered without the
    /// application: nothing more is sent.
    finished: bool,
    /// The client's side of the call ended, or broke.
    read_over: bool,
    /// The client's end came, and goes up once the messages before it do.
    client_ended: bool,
}

impl Grpc {
    /// The call `opening` starts.
    pub fn new(opening: Opening) -> Grpc {
        let mut grpc = Grpc {
            content_type: ContentType::plain(),
            up: VecDeque::new(),
            partial: Vec::new(),
            checked: 0,
            charge: opening.charge,
            next: None,
            message: None,
            head_sent: false,
            finished: false,
            read_over: false,
            client_ended: false,
        };
        let request = &opening.request;
        let pseudo = [
            (":method", request.method().as_str().to_owned()),
            (
                ":scheme",
                request.uri().scheme_str().unwrap_or("http").to_owned(),
            ),
            (
                ":path",
                request
                    .uri()
                    .path_and_query()
                    .map_or(String::new(), |p| p.as_str().to_owned()),
            ),
        ];
        let authority = request
            .uri()
            .authority()
            .map(|a| (":authority", a.as_str().to_owned()));
        let fields = pseudo
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .chain(authority.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())))
            .chain(
                request
                    .headers()
                    .iter()
                    .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes())),
            );
        match grpc::Request::parse(fields) {
            Ok(call) => {
                grpc.content_type = call.content_type.clone();
                grpc.up
                    .push_back(MessageEvent::Message(GrpcEvent::Call(Box::new(call))));
                if opening.ended {
                    grpc.read_over = true;
                    grpc.up.push_back(MessageEvent::Ended);
                }
            }
            Err(rejection) => grpc.reject(rejection),
        }
        grpc
    }

    /// Answers a request that is not a call, without the application.
    fn reject(&mut self, rejection: Rejection) {
        self.read_over = true;
        self.finished = true;
        self.next = Some(match rejection {
            Rejection::Http(status) => ExchangeCommand::Head(Box::new(ResponseHead {
                status: StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
                headers: HeaderMap::new(),
                end: true,
            })),
            Rejection::Status(status) => self.trailers_only(&status),
        });
    }

    fn trailers_only(&self, status: &Status) -> ExchangeCommand {
        let fields = status
            .trailers_only(&self.content_type)
            .or_else(|_| Status::new(status.code, "").trailers_only(&self.content_type))
            .unwrap_or_default();
        ExchangeCommand::Head(Box::new(ResponseHead {
            status: StatusCode::OK,
            headers: map(fields),
            end: true,
        }))
    }

    /// Ends the call with `status`, from the server's side.
    fn fail(&mut self, status: Status) {
        self.read_over = true;
        self.partial = Vec::new();
        self.checked = 0;
        if !self.finished {
            self.finish(status);
        }
    }

    fn finish(&mut self, status: Status) {
        self.finished = true;
        self.next = Some(if self.head_sent {
            let fields = status.to_trailers().unwrap_or_default();
            ExchangeCommand::Trailers(Box::new(map(fields)))
        } else {
            self.trailers_only(&status)
        });
    }

    /// Frames `message` as the next body bytes, charged before they are
    /// allocated.
    fn send(&mut self, env: &Env<'_, Infallible>, message: grpc::Message) {
        let len = message.data.len() + 5;
        let Some(mut bytes) = ChargedBytes::with_capacity(env.budget(), len) else {
            self.next = Some(ExchangeCommand::Reset(ErrorCode::InternalError));
            self.finished = true;
            return;
        };
        if bytes.fill(|bytes| message.write(bytes)).is_err() {
            drop(bytes);
            self.finish(Status::new(Code::ResourceExhausted, "message too large"));
            return;
        }
        self.next = Some(ExchangeCommand::Data(Chunk::from(bytes)));
    }

    /// Reads the whole messages at the start of the partial bytes, while
    /// the application has room for them, then the client's end once every
    /// message before it is read. Returns whether anything moved.
    fn messages(&mut self) -> bool {
        if self.finished && self.read_over && self.partial.is_empty() {
            return false;
        }
        let mut at = 0;
        let mut moved = false;
        while self.up.len() < WAITING {
            match grpc::Message::parse_prefix(&self.partial[at..]) {
                Ok(Some((message, used))) => {
                    at += used;
                    moved = true;
                    self.up
                        .push_back(MessageEvent::Message(GrpcEvent::Message(message)));
                }
                Ok(None) => break,
                Err(error) => {
                    self.fail(error.to_status());
                    return true;
                }
            }
        }
        self.partial.drain(..at);
        self.checked = self.checked.saturating_sub(at);
        // The messages still waiting for the application are checked as
        // their prefixes come, so a call that breaks the framing or declares
        // too much ends then, not once the application has read the rest.
        loop {
            match grpc::prefix_len(&self.partial[self.checked..]) {
                Ok(Some(len)) if len <= self.partial.len() - self.checked => self.checked += len,
                Ok(_) => break,
                Err(error) => {
                    self.fail(error.to_status());
                    return true;
                }
            }
        }
        // With room left, every whole message is read: what remains is a
        // part of one.
        if self.client_ended && self.up.len() < WAITING {
            self.client_ended = false;
            moved = true;
            if self.partial.is_empty() {
                self.up.push_back(MessageEvent::Ended);
            } else {
                self.fail(Status::new(
                    Code::Internal,
                    "the call ended inside a message",
                ));
            }
        }
        moved
    }
}

/// Fields as a header map, without the status pseudo-header.
fn map(fields: Vec<(String, String)>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        if name.starts_with(':') {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.append(name, value);
        }
    }
    headers
}

impl Layer for Grpc {
    type Lower = HttpExchange;
    type Upper = Messages<GrpcEvent, GrpcCommand>;
    type Report = Infallible;
    type Timer = ();
    type Work = Infallible;
    type Done = Infallible;
    type Error = Infallible;

    fn on_event(
        &mut self,
        env: &mut Env<'_, Infallible>,
        event: ExchangeEvent,
    ) -> Result<Admit<ExchangeEvent>, Infallible> {
        match event {
            ExchangeEvent::Data(chunk) if !self.read_over => {
                // Bytes are taken as they come, so this call never holds up
                // its siblings; an application that falls behind leaves
                // them unread here, up to a message and a window past it.
                let need = self.partial.len() + chunk.len();
                if need > grpc::MAX_MESSAGE + 5 + Http2::WINDOW as usize {
                    self.fail(Status::new(Code::ResourceExhausted, "message too large"));
                    return Ok(Admit::Taken);
                }
                let held = self.charge.as_ref().map_or(0, Charge::bytes);
                let grown = held + need.saturating_sub(self.partial.capacity());
                let fits = match &mut self.charge {
                    Some(charge) => charge.grow_to(grown),
                    None => {
                        self.charge = env.budget().charge(grown);
                        self.charge.is_some()
                    }
                };
                if !fits {
                    self.fail(Status::new(Code::ResourceExhausted, "the server is full"));
                    return Ok(Admit::Taken);
                }
                self.partial.reserve_exact(chunk.len());
                self.partial.extend_from_slice(&chunk);
                self.messages();
            }
            ExchangeEvent::Data(_) => {}
            ExchangeEvent::Trailers(_) | ExchangeEvent::End if !self.read_over => {
                self.read_over = true;
                self.client_ended = true;
                self.messages();
            }
            ExchangeEvent::Trailers(_) | ExchangeEvent::End => {}
            ExchangeEvent::Overflow(_) => {
                self.fail(Status::new(Code::ResourceExhausted, "the server is full"));
            }
            ExchangeEvent::Written(_) => {}
            ExchangeEvent::Closed { .. } => {
                self.read_over = true;
                self.finished = true;
                self.next = None;
                self.up.clear();
            }
        }
        Ok(Admit::Taken)
    }

    fn on_command(
        &mut self,
        env: &mut Env<'_, Infallible>,
        command: MessageCommand<GrpcCommand>,
    ) -> Result<Admit<MessageCommand<GrpcCommand>>, Infallible> {
        if self.finished {
            return Ok(Admit::Closed(command));
        }
        if self.next.is_some() || self.message.is_some() {
            return Ok(Admit::Blocked(command));
        }
        match command {
            MessageCommand::Send(GrpcCommand::Message(message)) => {
                if !self.head_sent {
                    // The head goes first; the message follows it.
                    self.head_sent = true;
                    let fields = grpc::response_headers(&self.content_type);
                    self.next = Some(ExchangeCommand::Head(Box::new(ResponseHead {
                        status: StatusCode::OK,
                        headers: map(fields),
                        end: false,
                    })));
                    self.message = Some(message);
                } else {
                    self.send(env, message);
                }
            }
            MessageCommand::Send(GrpcCommand::Status(status)) => self.finish(status),
            MessageCommand::End => self.finish(Status::ok()),
        }
        Ok(Admit::Taken)
    }

    fn advance(&mut self, env: &mut Env<'_, Infallible>) -> Result<bool, Infallible> {
        let mut moved = self.messages();
        if self.next.is_none()
            && let Some(message) = self.message.take()
        {
            self.send(env, message);
            moved = true;
        }
        Ok(moved)
    }

    fn take_command(&mut self, _: &mut Env<'_, Self::Report>) -> Option<ExchangeCommand> {
        self.next.take()
    }

    fn take_event(&mut self) -> Option<MessageEvent<GrpcEvent>> {
        self.up.pop_front()
    }
}
