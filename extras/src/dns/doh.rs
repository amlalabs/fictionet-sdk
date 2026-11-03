//! What the public resolvers' DNS over HTTPS servers answer past RFC 8484,
//! as seen on 2026-11-02, for a world's
//! [`Fronts::fallback`](fictionet::stdlib::world::net::dns::encrypted::Fronts::fallback):
//! the JSON APIs of Google and Cloudflare, and each operator's own errors.
//!
//! - [`google`]: `GET /resolve?name=...&type=...`, Google's JSON API,
//!   which answers `application/json` unless `ct=application/dns-message`
//!   asks for the message itself, and Google's HTML error pages.
//! - [`cloudflare`]: `GET /dns-query?name=...&type=...` with
//!   `Accept: application/dns-json` or `ct=application/dns-json`,
//!   Cloudflare's form of the same JSON; an empty `400` for a GET with no
//!   question; and a redirect from `cloudflare-dns.com` to the same path
//!   on `one.one.one.one`, whose website the world does not serve.
//! - [`quad9`] and [`opendns`]: RFC 8484 alone, with each operator's
//!   plain text or HTML errors.
//!
//! [`resolve`] and [`dns_json`] answer the two JSON forms for any
//! [`Fronts`], so a world can serve them on a resolver of its own. A JSON
//! question reaches the resolver as the fronts' own queries do, from the
//! same cache.

use std::str::FromStr;
use std::sync::Arc;

use http::header::{ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use http::{HeaderValue, Method, Request, Response, StatusCode};

use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::codec::base64;
use fictionet::stdlib::protocols::dns::dnssec::rdata::DNSSECRData;
use fictionet::stdlib::protocols::dns::op::{Edns, Message, MessageType, OpCode, Query};
use fictionet::stdlib::protocols::dns::read_message;
use fictionet::stdlib::protocols::dns::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, Mandatory, SVCB, SvcParamKey, SvcParamValue, Unknown,
};
use fictionet::stdlib::protocols::dns::rr::rdata::{CNAME, HTTPS, NS, PTR};
use fictionet::stdlib::protocols::dns::rr::{Name, RData, Record, RecordType};
use fictionet::stdlib::protocols::dns::serialize::binary::BinEncodable;
use fictionet::stdlib::protocols::json::Value;
use fictionet::stdlib::protocols::urlencoded_form::{self, Form};
use fictionet::stdlib::services::dns::zone::dname_target;
use fictionet::stdlib::web::httpd::{self, Body, Exchange, Handler, Reply, request_host};
use fictionet::stdlib::world::net::dns::encrypted::{Fronts, freshness, message_response};

/// The path of RFC 8484, where Cloudflare also serves its JSON.
const DNS_QUERY: &str = "/dns-query";

/// The path of Google's JSON API.
const RESOLVE: &str = "/resolve";

/// The media type of a DNS message over HTTPS (RFC 8484 §6).
const DNS_MESSAGE: &str = "application/dns-message";

/// Cloudflare's media type for the JSON form.
const DNS_JSON: &str = "application/dns-json";

/// The media type of Google's JSON answers.
const JSON: &str = "application/json; charset=UTF-8";

/// How the answer to a JSON API question goes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// The resolver's DNS message (RFC 8484 §4.2).
    Message,
    /// The JSON form, as this media type.
    Json(&'static str),
}

/// Google's JSON API at `/resolve` for `request`, whatever its path:
/// `GET` only, answered as `application/json` unless
/// `ct=application/dns-message` asks for the message itself.
pub fn resolve(fronts: &Fronts, request: &Request<Body>, ex: &mut Exchange<'_>) -> Reply {
    if *request.method() != Method::GET {
        let mut response = httpd::text(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed.\n");
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("GET"));
        return Reply::Now(response);
    }
    let Some(form) = form(request) else {
        return Reply::Now(bad_query_string());
    };
    let answer = match urlencoded_form::first(&form.pairs, "ct") {
        Some(DNS_MESSAGE) => Answer::Message,
        _ => Answer::Json(JSON),
    };
    json_reply(fronts, &form.pairs, answer, ex)
}

/// Whether `request` asks for Cloudflare's JSON form: it accepts
/// `application/dns-json`, or asks for it with `ct`.
pub fn asks_dns_json(request: &Request<Body>) -> bool {
    let accepts = request
        .headers()
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.to_ascii_lowercase().contains(DNS_JSON));
    accepts
        || form(request)
            .is_some_and(|form| urlencoded_form::first(&form.pairs, "ct") == Some(DNS_JSON))
}

/// Cloudflare's JSON form for `request`, a GET with the question in its
/// parameters, answered as `application/dns-json`.
pub fn dns_json(fronts: &Fronts, request: &Request<Body>, ex: &mut Exchange<'_>) -> Reply {
    let Some(form) = form(request) else {
        return Reply::Now(bad_query_string());
    };
    json_reply(fronts, &form.pairs, Answer::Json(DNS_JSON), ex)
}

/// The parameters of `request`'s query string, when it parses.
fn form(request: &Request<Body>) -> Option<Form> {
    Form::parse(request.uri().query().unwrap_or("").as_bytes()).ok()
}

fn bad_query_string() -> Response<Body> {
    httpd::text(StatusCode::BAD_REQUEST, "Bad query string.\n")
}

/// The reply to the JSON API question in `pairs`, put to the resolver
/// of `fronts` as the connection's client and answered as `answer`. A
/// bad parameter is refused with `400 Bad Request` and the reason in
/// JSON, as Cloudflare refuses one.
fn json_reply(
    fronts: &Fronts,
    pairs: &[(String, String)],
    answer: Answer,
    ex: &mut Exchange<'_>,
) -> Reply {
    let Some(client) = fronts.client(ex.conn()) else {
        return Reply::Now(httpd::text(
            StatusCode::MISDIRECTED_REQUEST,
            "This server does not serve that host.\n",
        ));
    };
    let query = match json_query(pairs, ex) {
        Ok(query) => query,
        Err(error) => return Reply::Now(json_error(error)),
    };
    let resolver = fronts.resolver().clone();
    Reply::Later(Box::new(move |fcx| {
        Box::pin(async move {
            let Some(reply) = resolver.query(&fcx, client, query).await else {
                return Ok(httpd::text(
                    StatusCode::BAD_REQUEST,
                    "The query is not a DNS query.\n",
                ));
            };
            Ok(answered(reply, answer))
        })
    }))
}

/// `400 Bad Request` with `error` in JSON.
fn json_error(error: String) -> Response<Body> {
    let body = Value::Object(vec![("error".to_owned(), Value::from(error))]);
    let mut response = Response::new(Body::from(body.to_bytes().unwrap_or_default()));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(JSON));
    response
}

/// The response carrying the resolver's `reply` as `answer` says. A reply
/// that does not parse goes back as the message itself. Every DNS answer,
/// SERVFAIL and NXDOMAIN included, is `200 OK`.
fn answered(reply: Vec<u8>, answer: Answer) -> Response<Body> {
    let (Answer::Json(media), Ok(message)) = (answer, read_message(&reply)) else {
        return message_response(reply);
    };
    let mut response = Response::new(Body::from(to_json(&message)));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(media));
    if let Some(seconds) = freshness(&message)
        && let Ok(value) = HeaderValue::from_str(&format!("max-age={seconds}"))
    {
        headers.insert(CACHE_CONTROL, value);
    }
    response
}

/// The query the JSON API's parameters ask: `name` (required, RFC 4343
/// escapes allowed), `type` (a number from 1 to 65535 or a mnemonic,
/// default A), `cd`, and `do`. Other parameters, such as
/// `edns_client_subnet` and `random_padding`, are ignored. The first of
/// duplicate parameters counts. `Err` holds why the question is refused.
fn json_query(pairs: &[(String, String)], ex: &mut Exchange<'_>) -> Result<Vec<u8>, String> {
    let param = |name: &str| urlencoded_form::first(pairs, name);
    let text = param("name").ok_or_else(|| "Missing name parameter.".to_owned())?;
    let name = Name::from_ascii(text)
        .ok()
        .filter(|name| !name.is_root())
        .ok_or_else(|| format!("Invalid name `{text}`."))?;
    let kind = match param("type") {
        None | Some("") => RecordType::A,
        Some(kind) => record_type(kind).ok_or_else(|| format!("Invalid type `{kind}`."))?,
    };
    let flag = |param_name: &str, label: &str| match param(param_name) {
        None | Some("" | "0" | "false") => Ok(false),
        Some("1" | "true") => Ok(true),
        Some(other) => Err(format!(
            "Invalid {label} flag `{other}`. Expected to be empty or one of `0`, `false`, `1`, or `true`."
        )),
    };
    let cd = flag("cd", "CD")?;
    let dnssec_ok = flag("do", "DO")?;

    // RD and AD set, the second asking for the AD bit (RFC 6840 §5.7); an
    // OPT record carries DO (RFC 3225).
    let mut message = Message::new(ex.random_u64() as u16, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.authentic_data = true;
    message.metadata.checking_disabled = cd;
    message.add_query(Query::query(name, kind));
    let mut edns = Edns::new();
    edns.set_dnssec_ok(dnssec_ok);
    message.set_edns(edns);
    message
        .to_vec()
        .map_err(|error| format!("Cannot ask that: {error}."))
}

/// A record type as the JSON API takes it: a number from 1 to 65535, or a
/// mnemonic in any case.
fn record_type(text: &str) -> Option<RecordType> {
    match text.parse::<u16>() {
        Ok(0) => None,
        Ok(number) => Some(RecordType::from(number)),
        Err(_) => RecordType::from_str(&text.to_ascii_uppercase()).ok(),
    }
}

/// `message` in the JSON both Google's and Cloudflare's APIs use: the
/// header bits, the question, and each section's records with their data
/// in presentation format.
fn to_json(message: &Message) -> Vec<u8> {
    let flags = &message.metadata;
    let mut fields = vec![
        (
            "Status".to_owned(),
            Value::from(u32::from(u16::from(flags.response_code))),
        ),
        ("TC".to_owned(), Value::from(flags.truncation)),
        ("RD".to_owned(), Value::from(flags.recursion_desired)),
        ("RA".to_owned(), Value::from(flags.recursion_available)),
        ("AD".to_owned(), Value::from(flags.authentic_data)),
        ("CD".to_owned(), Value::from(flags.checking_disabled)),
    ];
    let questions = message
        .queries
        .iter()
        .map(|query| {
            Value::Object(vec![
                ("name".to_owned(), Value::from(name_text(query.name()))),
                (
                    "type".to_owned(),
                    Value::from(u32::from(u16::from(query.query_type()))),
                ),
            ])
        })
        .collect::<Vec<_>>();
    fields.push(("Question".to_owned(), Value::from(questions)));
    for (section, records) in [
        ("Answer", &message.answers),
        ("Authority", &message.authorities),
        ("Additional", &message.additionals),
    ] {
        if !records.is_empty() {
            let records = records.iter().map(record_json).collect::<Vec<_>>();
            fields.push((section.to_owned(), Value::from(records)));
        }
    }
    Value::Object(fields).to_bytes().unwrap_or_default()
}

/// One record of a JSON answer.
fn record_json(record: &Record) -> Value {
    let data = presentation(&record.data);
    Value::Object(vec![
        ("name".to_owned(), Value::from(name_text(&record.name))),
        (
            "type".to_owned(),
            Value::from(u32::from(u16::from(record.record_type()))),
        ),
        ("TTL".to_owned(), Value::from(record.ttl)),
        ("data".to_owned(), Value::from(data)),
    ])
}

/// RDATA in presentation format, as a master file holds it and BIND reads
/// it back.
///
/// TXT data is every character-string quoted, with no space between them,
/// as Google gives TXT and SPF data. HINFO, CAA, and NAPTR strings are
/// quoted and escaped (RFC 1035 §5.1), SVCB and HTTPS parameters are
/// written as RFC 9460 §2.1 and Appendix A give them, and a DNAME gives
/// its target. Every name is written by [`name_text`], in ASCII as
/// Google's and Cloudflare's APIs give names. Types without names whose
/// own text hickory writes in presentation format use it. Any other type,
/// NULL and types hickory does not know among them, takes the generic
/// `\# <length> <hex>` form (RFC 3597 §5).
fn presentation(data: &RData) -> String {
    match data {
        RData::TXT(txt) => txt.txt_data.iter().map(|part| quoted(part)).collect(),
        RData::HINFO(hinfo) => format!("{} {}", quoted(&hinfo.cpu), quoted(&hinfo.os)),
        RData::CAA(caa) => format!("{} {} {}", caa.flags(), caa.tag, quoted(&caa.value)),
        RData::NAPTR(naptr) => format!(
            "{} {} {} {} {} {}",
            naptr.order,
            naptr.preference,
            quoted(&naptr.flags),
            quoted(&naptr.services),
            quoted(&naptr.regexp),
            name_text(&naptr.replacement)
        ),
        RData::SVCB(svcb) | RData::HTTPS(HTTPS(svcb)) => service_binding(svcb),
        RData::NS(NS(target)) | RData::CNAME(CNAME(target)) | RData::PTR(PTR(target)) => {
            name_text(target)
        }
        RData::MX(mx) => format!("{} {}", mx.preference, name_text(&mx.exchange)),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            name_text(&srv.target)
        ),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            name_text(&soa.mname),
            name_text(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
            let input = rrsig.input();
            format!(
                "{} {} {} {} {} {} {} {} {}",
                input.type_covered,
                input.algorithm,
                input.num_labels,
                input.original_ttl,
                input.sig_expiration.get(),
                input.sig_inception.get(),
                input.key_tag,
                name_text(&input.signer_name),
                base64::encode(rrsig.sig())
            )
        }
        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => {
            let mut out = name_text(nsec.next_domain_name());
            for rtype in nsec.type_bit_maps() {
                out.push_str(&format!(" {rtype}"));
            }
            out
        }
        RData::A(_)
        | RData::AAAA(_)
        | RData::SSHFP(_)
        | RData::TLSA(_)
        | RData::OPENPGPKEY(_)
        | RData::DNSSEC(_) => data.to_string(),
        _ => match dname_target(data) {
            Some(target) => name_text(&target),
            None => generic(data),
        },
    }
}

/// A name in presentation format, as a master file holds it (RFC 1035
/// §5.1): each label as its octets, with A-labels as they are, a
/// character a master file reads otherwise escaped with a backslash, and
/// any other octet outside printable ASCII as `\DDD` in decimal.
fn name_text(name: &Name) -> String {
    if name.is_root() {
        return ".".to_owned();
    }
    let mut out = String::new();
    for label in name.iter() {
        for &byte in label {
            match byte {
                b'.' | b'\\' | b'"' | b';' | b'(' | b')' | b'@' | b'$' => {
                    out.push('\\');
                    out.push(char::from(byte));
                }
                0x21..=0x7e => out.push(char::from(byte)),
                _ => out.push_str(&format!("\\{byte:03}")),
            }
        }
        out.push('.');
    }
    out
}

/// SVCB or HTTPS RDATA in presentation format (RFC 9460 §2.1): the
/// priority, the target, and each parameter as `key=value`, a key without
/// a value for `no-default-alpn` and empty values.
fn service_binding(svcb: &SVCB) -> String {
    let mut out = format!("{} {}", svcb.svc_priority, name_text(&svcb.target_name));
    for (key, value) in &svcb.svc_params {
        let key = param_key(*key);
        let value: Vec<u8> = match value {
            SvcParamValue::Mandatory(Mandatory(keys)) => keys
                .iter()
                .map(|key| param_key(*key))
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            // A comma or a backslash inside one ALPN ID is escaped, so the
            // list splits where it should (RFC 9460 Appendix A.1).
            SvcParamValue::Alpn(Alpn(ids)) => ids
                .iter()
                .map(|id| id.replace('\\', "\\\\").replace(',', "\\,"))
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            SvcParamValue::NoDefaultAlpn => Vec::new(),
            SvcParamValue::Port(port) => port.to_string().into_bytes(),
            SvcParamValue::Ipv4Hint(IpHint(addresses)) => addresses
                .iter()
                .map(|address| address.0.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            SvcParamValue::Ipv6Hint(IpHint(addresses)) => addresses
                .iter()
                .map(|address| address.0.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .into_bytes(),
            SvcParamValue::EchConfigList(EchConfigList(list)) => base64::encode(list).into_bytes(),
            SvcParamValue::Unknown(Unknown(bytes)) => bytes.clone(),
        };
        out.push(' ');
        out.push_str(&key);
        if !value.is_empty() {
            out.push('=');
            // A value with nothing a master file would read otherwise
            // goes out as it is; any other is a quoted character-string.
            let plain = value.iter().all(|byte| {
                byte.is_ascii_graphic() && !matches!(byte, b'"' | b'\\' | b';' | b'(' | b')')
            });
            if plain {
                out.push_str(&String::from_utf8_lossy(&value));
            } else {
                out.push_str(&quoted(&value));
            }
        }
    }
    out
}

/// A SvcParamKey in presentation format (RFC 9460 §14.3.2): its name, or
/// `keyN` for a key without one.
fn param_key(key: SvcParamKey) -> String {
    match key {
        SvcParamKey::Mandatory => "mandatory".to_string(),
        SvcParamKey::Alpn => "alpn".to_string(),
        SvcParamKey::NoDefaultAlpn => "no-default-alpn".to_string(),
        SvcParamKey::Port => "port".to_string(),
        SvcParamKey::Ipv4Hint => "ipv4hint".to_string(),
        SvcParamKey::EchConfigList => "ech".to_string(),
        SvcParamKey::Ipv6Hint => "ipv6hint".to_string(),
        other => format!("key{}", u16::from(other)),
    }
}

/// RDATA in the generic form of RFC 3597 §5: `\#`, the length, and the
/// octets in hexadecimal.
fn generic(data: &RData) -> String {
    let octets = data.to_bytes().unwrap_or_default();
    let mut out = format!("\\# {}", octets.len());
    if !octets.is_empty() {
        out.push(' ');
        for byte in octets {
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// A character-string in presentation format (RFC 1035 §5.1): in quotes,
/// with `"` and `\` escaped and bytes outside printable ASCII as `\DDD`.
fn quoted(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7e => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\{byte:03}")),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// The operators

/// Whether `request` is a GET of `/dns-query` with no `dns` parameter,
/// the one request of RFC 8484's path the fronts leave to their fallback.
fn no_query(request: &Request<Body>) -> bool {
    request.uri().path() == DNS_QUERY
}

/// A response with `status`, `body`, and its media type when it has one.
fn http_reply(status: StatusCode, media: Option<&'static str>, body: String) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    if let Some(media) = media {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(media));
    }
    response
}

/// `dns.google`'s fallback for `fronts`: Google's JSON API at `/resolve`
/// ([`resolve`]), and Google's HTML error pages.
pub fn google(fronts: Fronts) -> Arc<dyn Handler> {
    Arc::new(Google { fronts })
}

struct Google {
    fronts: Fronts,
}

impl Google {
    /// Google's error page for `status`, saying `message`.
    fn error(status: StatusCode, message: &str) -> Response<Body> {
        let code = status.as_u16();
        let reason = status.canonical_reason().unwrap_or_default();
        let body = format!(
            "<!DOCTYPE html>\n<html lang=en>\n  <meta charset=utf-8>\n  \
             <meta name=viewport content=\"initial-scale=1, minimum-scale=1, width=device-width\">\n  \
             <title>Error {code} ({reason})!!1</title>\n  <style>\n    {GOOGLE_ERROR_STYLE}\n  </style>\n  \
             <a href=//www.google.com/><span id=logo aria-label=Google></span></a>\n  \
             <p><b>{code}.</b> <ins>That\u{2019}s an error.</ins>\n  \
             <p>{message} <ins>That\u{2019}s all we know.</ins>\n"
        );
        http_reply(status, Some("text/html; charset=UTF-8"), body)
    }
}

/// The style of Google's error pages.
const GOOGLE_ERROR_STYLE: &str = "*{margin:0;padding:0}html,code{font:15px/22px arial,sans-serif}html{background:#fff;color:#222;padding:15px}body{margin:7% auto 0;max-width:390px;min-height:180px;padding:30px 0 15px}* > body{background:url(//www.google.com/images/errors/robot.png) 100% 5px no-repeat;padding-right:205px}p{margin:11px 0 22px;overflow:hidden}ins{color:#777;text-decoration:none}a img{border:0}@media screen and (max-width:772px){body{background:none;margin-top:0;max-width:none;padding-right:0}}#logo{background:url(//www.google.com/images/branding/googlelogo/1x/googlelogo_color_150x54dp.png) no-repeat;margin-left:-5px}@media only screen and (min-resolution:192dpi){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat 0% 0%/100% 100%;-moz-border-image:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) 0}}@media only screen and (-webkit-min-device-pixel-ratio:2){#logo{background:url(//www.google.com/images/branding/googlelogo/2x/googlelogo_color_150x54dp.png) no-repeat;-webkit-background-size:100% 100%}}#logo{display:inline-block;height:54px;width:150px}";

impl Handler for Google {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        if request.uri().path() == RESOLVE {
            return resolve(&self.fronts, &request, ex);
        }
        if no_query(&request) {
            let named = form(&request)
                .is_some_and(|form| urlencoded_form::first(&form.pairs, "name").is_some());
            let detail = if named {
                "RFC8484 handler at /dns-query received parameter &#39;name&#39;, which it does \
                 not accept.  Did you intend to pass the &#39;dns&#39; parameter, or call the JSON \
                 handler at /resolve?  See https://developers.google.com/speed/public-dns/docs/doh"
            } else {
                "Query must have a valid \u{2018}dns\u{2019} parameter.."
            };
            let message =
                format!("Your client has issued a malformed or illegal request. {detail}");
            return Reply::Now(Google::error(StatusCode::BAD_REQUEST, &message));
        }
        let path = request
            .uri()
            .path()
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let message =
            format!("The requested URL <code>{path}</code> was not found on this server. ");
        Reply::Now(Google::error(StatusCode::NOT_FOUND, &message))
    }
}

/// `cloudflare-dns.com` and `one.one.one.one`'s fallback for `fronts`:
/// Cloudflare's JSON at `/dns-query` ([`dns_json`]), an empty `400` to a
/// GET with no question, and a redirect from `cloudflare-dns.com` to the
/// same path on `one.one.one.one`, whose website the world does not
/// serve.
pub fn cloudflare(fronts: Fronts) -> Arc<dyn Handler> {
    Arc::new(Cloudflare { fronts })
}

struct Cloudflare {
    fronts: Fronts,
}

impl Handler for Cloudflare {
    fn call(&self, request: Request<Body>, ex: &mut Exchange<'_>) -> Reply {
        if no_query(&request) {
            if asks_dns_json(&request) {
                return dns_json(&self.fronts, &request, ex);
            }
            return Reply::Now(http_reply(StatusCode::BAD_REQUEST, None, String::new()));
        }
        let redirects = request_host(&request).is_some_and(|host| {
            host.trim_end_matches('.')
                .eq_ignore_ascii_case("cloudflare-dns.com")
        });
        if !redirects {
            return Reply::Now(http_reply(
                StatusCode::NOT_FOUND,
                Some("text/html; charset=utf-8"),
                String::new(),
            ));
        }
        let target = match request.uri().path_and_query().map(|p| p.as_str()) {
            None | Some("/") => "/dns/",
            Some(target) => target,
        };
        let body = "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n\
                    <center><h1>301 Moved Permanently</h1></center>\r\n\
                    <hr><center>cloudflare</center>\r\n</body>\r\n</html>\r\n";
        let mut response = http_reply(
            StatusCode::MOVED_PERMANENTLY,
            Some("text/html; charset=UTF-8"),
            body.to_owned(),
        );
        if let Ok(location) = HeaderValue::from_str(&format!("https://one.one.one.one{target}")) {
            response.headers_mut().insert(LOCATION, location);
        }
        Reply::Now(response)
    }
}

/// `dns.quad9.net`'s fallback: RFC 8484 alone, with Quad9's plain text
/// errors.
pub fn quad9(_fronts: Fronts) -> Arc<dyn Handler> {
    Arc::new(Quad9)
}

struct Quad9;

impl Handler for Quad9 {
    fn call(&self, request: Request<Body>, _ex: &mut Exchange<'_>) -> Reply {
        if !no_query(&request) {
            return Reply::Now(httpd::text(
                StatusCode::NOT_FOUND,
                "there is no endpoint configured for this path",
            ));
        }
        let text = match request.uri().query() {
            None | Some("") => "DoH non-compliant query",
            Some(_) => "DoH unable to decode BASE64-URL",
        };
        Reply::Now(httpd::text(StatusCode::BAD_REQUEST, text))
    }
}

/// `doh.opendns.com`'s fallback: RFC 8484 alone, with OpenDNS's HTML
/// errors.
pub fn opendns(_fronts: Fronts) -> Arc<dyn Handler> {
    Arc::new(OpenDns)
}

struct OpenDns;

impl OpenDns {
    /// OpenDNS's error page for `status`, saying `message`.
    fn error(status: StatusCode, message: &str) -> Response<Body> {
        let code = status.as_u16();
        let reason = status.canonical_reason().unwrap_or_default();
        let body = format!(
            "<html>\r\n<head><title>{code} {reason}</title></head>\r\n<body>\r\n\
             <center><h1>{message}</h1></center>\r\n</body>\r\n</html>\r\n"
        );
        http_reply(status, Some("text/html"), body)
    }
}

impl Handler for OpenDns {
    fn call(&self, request: Request<Body>, _ex: &mut Exchange<'_>) -> Reply {
        if no_query(&request) {
            return Reply::Now(OpenDns::error(
                StatusCode::BAD_REQUEST,
                "No valid query received",
            ));
        }
        Reply::Now(OpenDns::error(
            StatusCode::NOT_FOUND,
            "The request was directed to a path other than the configured endpoint",
        ))
    }
}
