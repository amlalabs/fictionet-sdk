// The ngtcp2 peer in `peer.c`, driven with virtual time.

use std::ffi::CString;
use std::ptr::NonNull;
use std::time::Duration;

use crate::network::Endpoint;

#[repr(C)]
struct Raw {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn fn_client_new(
        chosen: u32,
        versions: *const u32,
        nversions: usize,
        app: i32,
        ca: *const u8,
        ca_len: usize,
        seed: u64,
        now: u64,
    ) -> *mut Raw;
    fn fn_server_new(
        versions: *const u32,
        nversions: usize,
        cert: *const u8,
        cert_len: usize,
        key: *const u8,
        key_len: usize,
        retry: i32,
        seed: u64,
    ) -> *mut Raw;
    fn fn_serve(peer: *mut Raw, path: *const i8, data: *const u8, len: usize) -> i32;
    fn fn_request(peer: *mut Raw, path: *const i8) -> i32;
    fn fn_recv(peer: *mut Raw, pkt: *const u8, len: usize, now: u64) -> i32;
    fn fn_owns(peer: *mut Raw, pkt: *const u8, len: usize) -> i32;
    fn fn_send(peer: *mut Raw, out: *mut u8, cap: usize, now: u64) -> i64;
    fn fn_expiry(peer: *mut Raw) -> u64;
    fn fn_expire(peer: *mut Raw, now: u64) -> i32;
    fn fn_close(peer: *mut Raw, out: *mut u8, cap: usize, now: u64) -> i64;
    fn fn_peer_close(peer: *mut Raw, code: *mut u64, application: *mut i32) -> i32;
    fn fn_failure(peer: *mut Raw) -> i32;
    fn fn_version(peer: *mut Raw) -> u32;
    fn fn_response(
        peer: *mut Raw,
        index: usize,
        body: *mut *const u8,
        len: *mut usize,
        status: *mut i32,
    ) -> i32;
    fn fn_free(peer: *mut Raw);
}

pub const CERTIFICATE: &[u8] = include_bytes!("../it/fixtures/tls/p256.cert.der");
pub const KEY: &[u8] = include_bytes!("../it/fixtures/tls/p256.key.der");

/// The application protocol a client speaks
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum App {
    /// "GET /path\r\n" on a bidirectional stream, answered with the file
    Hq = 0,
    /// HTTP/3 through nghttp3
    H3 = 1,
}

/// An ngtcp2 error code (`NGTCP2_ERR_*`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure(pub i32);

/// How the remote endpoint closed the connection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    Transport(u64),
    Application(u64),
}

/// A completed request
#[derive(Debug)]
pub struct Response {
    pub body: Vec<u8>,
    /// The HTTP status; `None` for hq-interop
    pub status: Option<u16>,
}

pub struct Ngtcp2 {
    raw: NonNull<Raw>,
    requests: usize,
    closing: Option<Vec<u8>>,
}

fn nanos(at: Duration) -> u64 {
    u64::try_from(at.as_nanos()).unwrap()
}

impl Ngtcp2 {
    /// A client whose first flight is in `first`, preferring `versions`
    pub fn client(first: u32, versions: &[u32], app: App, seed: u64, now: Duration) -> Self {
        let raw = unsafe {
            fn_client_new(
                first,
                versions.as_ptr(),
                versions.len(),
                app as i32,
                CERTIFICATE.as_ptr(),
                CERTIFICATE.len(),
                seed,
                nanos(now),
            )
        };
        Self::new(raw)
    }

    /// An hq-interop server preferring `versions`, sending a Retry first
    /// when `retry` is set
    pub fn server(versions: &[u32], retry: bool, seed: u64) -> Self {
        let raw = unsafe {
            fn_server_new(
                versions.as_ptr(),
                versions.len(),
                CERTIFICATE.as_ptr(),
                CERTIFICATE.len(),
                KEY.as_ptr(),
                KEY.len(),
                i32::from(retry),
                seed,
            )
        };
        Self::new(raw)
    }

    fn new(raw: *mut Raw) -> Self {
        Self {
            raw: NonNull::new(raw).expect("ngtcp2 peer"),
            requests: 0,
            closing: None,
        }
    }

    pub fn serve(&mut self, path: &str, data: &[u8]) {
        let path = CString::new(path).unwrap();
        let rv = unsafe { fn_serve(self.raw.as_ptr(), path.as_ptr(), data.as_ptr(), data.len()) };
        assert_eq!(rv, 0);
    }

    pub fn request(&mut self, path: &str) {
        let path = CString::new(path).unwrap();
        let rv = unsafe { fn_request(self.raw.as_ptr(), path.as_ptr()) };
        assert_eq!(rv, 0);
        self.requests += 1;
    }

    /// Request `index`, once its response is complete
    pub fn response(&self, index: usize) -> Option<Response> {
        let mut body = std::ptr::null();
        let mut len = 0;
        let mut status = 0;
        let done =
            unsafe { fn_response(self.raw.as_ptr(), index, &mut body, &mut len, &mut status) };
        assert!(done >= 0);
        (done == 1).then(|| Response {
            body: if len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(body, len) }.to_vec()
            },
            status: (status != 0).then(|| u16::try_from(status).unwrap()),
        })
    }

    /// Every response, once all requests are complete
    pub fn responses(&self) -> Option<Vec<Response>> {
        (0..self.requests).map(|i| self.response(i)).collect()
    }

    /// Whether `datagram` is for this client, by its destination
    /// connection ID
    pub fn owns(&self, datagram: &[u8]) -> bool {
        unsafe { fn_owns(self.raw.as_ptr(), datagram.as_ptr(), datagram.len()) == 1 }
    }

    /// Close with no error; the CONNECTION_CLOSE leaves on the next transmit
    pub fn close(&mut self, now: Duration) {
        let mut out = vec![0; 1500];
        let n = unsafe { fn_close(self.raw.as_ptr(), out.as_mut_ptr(), out.len(), nanos(now)) };
        assert!(n >= 0, "close: {n}");
        out.truncate(n as usize);
        self.closing = (n > 0).then_some(out);
    }

    pub fn failure(&self) -> Option<Failure> {
        let code = unsafe { fn_failure(self.raw.as_ptr()) };
        (code != 0).then_some(Failure(code))
    }

    /// The close the remote endpoint sent, if it did
    pub fn peer_close(&self) -> Option<Closed> {
        let mut code = 0;
        let mut application = 0;
        let closed = unsafe { fn_peer_close(self.raw.as_ptr(), &mut code, &mut application) };
        (closed == 1).then_some(if application == 1 {
            Closed::Application(code)
        } else {
            Closed::Transport(code)
        })
    }
}

impl Endpoint for Ngtcp2 {
    fn receive(&mut self, datagram: &[u8], now: Duration) {
        let rv = unsafe {
            fn_recv(
                self.raw.as_ptr(),
                datagram.as_ptr(),
                datagram.len(),
                nanos(now),
            )
        };
        assert_eq!(rv, 0, "ngtcp2 receive failed: {rv}");
    }

    fn transmit(&mut self, now: Duration) -> Option<Vec<u8>> {
        if let Some(close) = self.closing.take() {
            return Some(close);
        }
        if self.timer().is_some_and(|at| at <= now) {
            let rv = unsafe { fn_expire(self.raw.as_ptr(), nanos(now)) };
            assert_eq!(rv, 0, "ngtcp2 timer failed: {rv}");
        }
        let mut out = vec![0; 1500];
        let n = unsafe { fn_send(self.raw.as_ptr(), out.as_mut_ptr(), out.len(), nanos(now)) };
        assert!(n >= 0, "ngtcp2 send failed: {n}");
        out.truncate(n as usize);
        (n > 0).then_some(out)
    }

    fn timer(&self) -> Option<Duration> {
        let at = unsafe { fn_expiry(self.raw.as_ptr()) };
        (at != u64::MAX).then(|| Duration::from_nanos(at))
    }

    fn version(&self) -> Option<u32> {
        let version = unsafe { fn_version(self.raw.as_ptr()) };
        (version != 0).then_some(version)
    }
}

/// Several clients at one address on the client's side of the link. Each
/// datagram goes to the client whose connection ID it names.
pub struct Clients(pub Vec<Ngtcp2>);

impl Endpoint for Clients {
    fn receive(&mut self, datagram: &[u8], now: Duration) {
        if let Some(client) = self.0.iter_mut().find(|client| client.owns(datagram)) {
            client.receive(datagram, now);
        }
    }

    fn transmit(&mut self, now: Duration) -> Option<Vec<u8>> {
        self.0.iter_mut().find_map(|client| client.transmit(now))
    }

    fn timer(&self) -> Option<Duration> {
        self.0.iter().filter_map(Endpoint::timer).min()
    }

    fn version(&self) -> Option<u32> {
        self.0.first().and_then(Endpoint::version)
    }
}

impl Drop for Ngtcp2 {
    fn drop(&mut self) {
        unsafe { fn_free(self.raw.as_ptr()) }
    }
}
