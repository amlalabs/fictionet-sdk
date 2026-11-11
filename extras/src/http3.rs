//! HTTP/3 server profiles that look like real servers.
//!
//! Each preset implements [`Http3Profile`] and [`Policy`] with what one
//! server sends: its SETTINGS in order, the unidirectional streams it opens,
//! its reserved frames, and how its QPACK encoder writes fields. A world
//! gives one to [`Responder::http3_profile`](fictionet::stdlib::web::httpd::Responder::http3_profile).
//!
//! ```
//! use fictionet::stdlib::web::httpd::Responder;
//! # fn build(responder: Responder) {
//! let responder = responder.http3_profile(fictionet_extras::http3::Nginx);
//! let _server = responder.http3();
//! # }
//! ```
//!
//! The values come from each server's source, read on 2026-11-11. They are
//! not yet checked against live captures: UDP port 443 was closed on the
//! network the presets were written from.

use fictionet::stdlib::protocols::qpack::{Field, Huffman, Policy, Style, Table};
use fictionet::stdlib::web::httpd::{Http3Profile, Http3Setting, Http3Stream};

/// Cloudflare's HTTP/3, as its open-source stack, quiche, sends it with
/// default settings.
///
/// SETTINGS carry the field section size, 32768, and one reserved entry.
/// They leave out both QPACK limits, so the dynamic table and blocked
/// streams are zero. The server opens its control, encoder and decoder
/// streams, then a reserved stream carrying `GREASE is the word`. Before the
/// first response HEADERS it sends two reserved frames, one empty and one
/// carrying the same text. Its encoder never uses the dynamic table, writes
/// Huffman code whenever it is no longer than the string, and never sets the
/// never-indexed bit.
///
/// Sources, quiche master on 2026-11-11 and the same code in quiche 0.30.1:
/// [`Config::new` and `with_transport`](https://github.com/cloudflare/quiche/blob/master/quiche/src/h3/mod.rs)
/// (defaults, SETTINGS, stream order and reserved frames),
/// [`Frame::to_bytes`](https://github.com/cloudflare/quiche/blob/master/quiche/src/h3/frame.rs)
/// (SETTINGS order), the [QPACK encoder](https://github.com/cloudflare/quiche/blob/master/quiche/src/h3/qpack/encoder.rs),
/// and [`huffman_encoding_len`](https://github.com/cloudflare/quiche/blob/master/octets/src/lib.rs).
/// Cloudflare's [h3i post](https://blog.cloudflare.com/h3i/) shows its edge,
/// cloudflare-quic.com, sending the two reserved frames before a response's
/// HEADERS. Whether the edge keeps quiche's default SETTINGS is not in any
/// public source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cloudflare;

/// What quiche's reserved stream and second reserved frame carry.
const GREASE: &[u8] = b"GREASE is the word";

impl Policy for Cloudflare {
    fn capacity(&self, _peer_max: u64) -> u64 {
        0
    }
    fn insert(&self, _: &Field, _: &Table) -> bool {
        false
    }
    fn style(&self) -> Style {
        Style {
            huffman: Huffman::NotLonger,
            never_index: false,
        }
    }
}

impl Http3Profile for Cloudflare {
    fn settings(&self) -> &[Http3Setting] {
        &[
            Http3Setting::FieldSectionSize(32_768),
            Http3Setting::Reserved,
        ]
    }
    fn streams(&self) -> &[Http3Stream] {
        &[
            Http3Stream::Control,
            Http3Stream::Encoder,
            Http3Stream::Decoder,
            Http3Stream::Reserved(GREASE),
        ]
    }
    fn reserved_frames(&self) -> &[&'static [u8]] {
        &[b"", GREASE]
    }
}

/// nginx's HTTP/3 with its default configuration.
///
/// SETTINGS carry only the QPACK limits: a 4096-byte table and 128 blocked
/// streams, which follows `http3_max_concurrent_streams` (default 128).
/// There is no field section size and no reserved entry. The server opens
/// its control stream, then its decoder stream; it never opens an encoder
/// stream. Its encoder writes every field from the static table or as a
/// literal, with Huffman code only when shorter, and never sets the
/// never-indexed bit. It sends no reserved frames.
///
/// Sources, nginx master on 2026-11-11:
/// [`ngx_http_v3_send_settings`](https://github.com/nginx/nginx/blob/master/src/http/v3/ngx_http_v3_uni.c),
/// [the defaults](https://github.com/nginx/nginx/blob/master/src/http/v3/ngx_http_v3_module.c)
/// and [`NGX_HTTP_V3_MAX_TABLE_CAPACITY`](https://github.com/nginx/nginx/blob/master/src/http/v3/ngx_http_v3.h),
/// [`ngx_http_v3_init`](https://github.com/nginx/nginx/blob/master/src/http/v3/ngx_http_v3_request.c)
/// (stream order), the [field encoders](https://github.com/nginx/nginx/blob/master/src/http/v3/ngx_http_v3_encode.c)
/// and their callers in [the header filter](https://github.com/nginx/nginx/blob/master/src/http/v3/ngx_http_v3_filter_module.c),
/// which always pass a zero insert count and static references, and
/// [`ngx_http_huff_encode`](https://github.com/nginx/nginx/blob/master/src/http/ngx_http_huff_encode.c).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Nginx;

impl Policy for Nginx {
    fn capacity(&self, _peer_max: u64) -> u64 {
        0
    }
    fn insert(&self, _: &Field, _: &Table) -> bool {
        false
    }
    fn style(&self) -> Style {
        Style {
            huffman: Huffman::Shorter,
            never_index: false,
        }
    }
}

impl Http3Profile for Nginx {
    fn settings(&self) -> &[Http3Setting] {
        &[
            Http3Setting::QpackTableCapacity(4096),
            Http3Setting::QpackBlockedStreams(128),
        ]
    }
    fn streams(&self) -> &[Http3Stream] {
        &[Http3Stream::Control, Http3Stream::Decoder]
    }
    fn reserved_frames(&self) -> &[&'static [u8]] {
        &[]
    }
}
