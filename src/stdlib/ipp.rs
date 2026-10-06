//! IPP, the Internet Printing Protocol: reading and writing requests and
//! responses, with no I/O.
//!
//! IPP is how computers talk to printers. A client sends a request in the
//! body of an HTTP POST, usually to TCP port 631, with the media type
//! `application/ipp`. The printer answers in the body of the HTTP
//! response. Both messages share one binary layout: a version, an
//! operation ID (in a request) or a status code (in a response), a request
//! ID, groups of attributes, an end tag, and then any document data, such
//! as the pages of a print job. This module follows RFC 8010 (the
//! encoding) and RFC 8011 (the model, with its operation and status
//! codes).
//!
//! Nothing here reads a socket or parses HTTP. A world that plays a
//! printer takes the body of each POST, reads its attributes with
//! [`Stream<Head>`](super::codec::Stream) (or parses the whole [`Message`]),
//! and writes the bytes of its reply as the HTTP response body. Which
//! operations the printer supports, which attributes it has, and what it
//! does with a document are up to world code.
//!
//! Every reader checks lengths, because the agent can send any bytes it
//! likes. Each length field is checked before it is used, the attribute
//! section may be at most [`MAX_HEAD`] bytes, and collections may nest at
//! most [`MAX_DEPTH`] deep. A group that names one attribute twice is
//! refused, as RFC 8011 recommends. Names, and values with a fixed size,
//! must have the form [`Attribute::name`] and [`Value`] describe. Writers
//! refuse values that cannot be written unchanged. After the head item,
//! the document remains unread for `Stream::swap` into a bounded collector.
//!
//! ```
//! use fictionet::stdlib::codec::{Stream, Wire};
//! use fictionet::stdlib::ipp::{operation, status, tag, Attribute, Head, Header, Message, Value};
//!
//! // An HTTP request body asking for the printer's attributes.
//! let request = Message::request(operation::GET_PRINTER_ATTRIBUTES, 7);
//! let body = Wire::to_bytes(&Header::from(request)).unwrap();
//! let mut stream = Stream::new(Head::new());
//! assert_eq!(stream.push(&body), body.len());
//! let request = stream.next().unwrap().unwrap().unwrap();
//! assert_eq!(request.code, operation::GET_PRINTER_ATTRIBUTES);
//! assert_eq!(stream.next(), None);
//!
//! // The reply echoes the version and request ID.
//! let mut reply = Message::request(status::SUCCESSFUL_OK, request.request_id);
//! reply.version = request.version;
//! reply.add(tag::PRINTER_ATTRIBUTES, Attribute::new("printer-name", Value::Name("lobby".into())));
//! reply.add(tag::PRINTER_ATTRIBUTES, Attribute::new("printer-state", Value::Enum(3)));
//! let reply = Header::from(reply);
//! let bytes = Wire::to_bytes(&reply).unwrap();
//! assert_eq!(&bytes[..8], [1, 1, 0, 0, 0, 0, 0, 7]);
//! assert_eq!(<Header as Wire>::parse(&bytes).unwrap(), reply);
//! ```

use std::collections::BTreeSet;

use super::codec::{Decode, Step, Wire};

/// The TCP port IPP printers listen on.
pub const PORT: u16 = 631;
/// The HTTP media type of an IPP request or response body.
pub const MEDIA_TYPE: &str = "application/ipp";
/// The length of the fixed start of a message: the version, the operation
/// ID or status code, and the request ID.
pub const HEADER_LEN: usize = 8;
/// The longest name or value one attribute field may hold. Lengths are
/// signed 16-bit numbers on the wire, so a length above this is negative
/// and refused.
pub const MAX_FIELD: usize = 0x7fff;
/// The longest attribute or member name: RFC 8011 section 5.1.4 limits
/// keywords to 255 bytes.
pub const MAX_NAME: usize = 255;
/// The longest attribute section a reader takes: the header, every
/// attribute, and the end tag. The document data after it is not counted.
pub const MAX_HEAD: usize = 1 << 20;
/// How deep collections may nest. A collection inside an attribute is at
/// depth 1, a collection inside that one at depth 2, and so on.
pub const MAX_DEPTH: usize = 16;

/// Tags: the byte before each group (delimiter tags) and before each value
/// (value tags). Delimiter tags are below 0x10.
pub mod tag {
    #![allow(missing_docs)]
    // Delimiter tags.
    pub const OPERATION_ATTRIBUTES: u8 = 0x01;
    pub const JOB_ATTRIBUTES: u8 = 0x02;
    /// Ends the attribute section. Document data follows.
    pub const END_OF_ATTRIBUTES: u8 = 0x03;
    pub const PRINTER_ATTRIBUTES: u8 = 0x04;
    pub const UNSUPPORTED_ATTRIBUTES: u8 = 0x05;
    pub const SUBSCRIPTION_ATTRIBUTES: u8 = 0x06;
    pub const EVENT_NOTIFICATION_ATTRIBUTES: u8 = 0x07;
    pub const RESOURCE_ATTRIBUTES: u8 = 0x08;
    pub const DOCUMENT_ATTRIBUTES: u8 = 0x09;
    pub const SYSTEM_ATTRIBUTES: u8 = 0x0a;
    // Out-of-band value tags, 0x10 to 0x1f.
    pub const UNSUPPORTED: u8 = 0x10;
    pub const UNKNOWN: u8 = 0x12;
    pub const NO_VALUE: u8 = 0x13;
    pub const NOT_SETTABLE: u8 = 0x15;
    pub const DELETE_ATTRIBUTE: u8 = 0x16;
    pub const ADMIN_DEFINE: u8 = 0x17;
    // Integer value tags.
    pub const INTEGER: u8 = 0x21;
    pub const BOOLEAN: u8 = 0x22;
    pub const ENUM: u8 = 0x23;
    // Octet-string value tags.
    pub const OCTET_STRING: u8 = 0x30;
    pub const DATE_TIME: u8 = 0x31;
    pub const RESOLUTION: u8 = 0x32;
    pub const RANGE_OF_INTEGER: u8 = 0x33;
    /// Begins a collection.
    pub const BEG_COLLECTION: u8 = 0x34;
    pub const TEXT_WITH_LANGUAGE: u8 = 0x35;
    pub const NAME_WITH_LANGUAGE: u8 = 0x36;
    /// Ends a collection.
    pub const END_COLLECTION: u8 = 0x37;
    // Character-string value tags.
    pub const TEXT_WITHOUT_LANGUAGE: u8 = 0x41;
    pub const NAME_WITHOUT_LANGUAGE: u8 = 0x42;
    pub const KEYWORD: u8 = 0x44;
    pub const URI: u8 = 0x45;
    pub const URI_SCHEME: u8 = 0x46;
    pub const CHARSET: u8 = 0x47;
    pub const NATURAL_LANGUAGE: u8 = 0x48;
    pub const MIME_MEDIA_TYPE: u8 = 0x49;
    /// A collection member name.
    pub const MEMBER_ATTR_NAME: u8 = 0x4a;
    /// The first four bytes of the value hold the real tag.
    pub const EXTENSION: u8 = 0x7f;
}

/// Operation IDs, from RFC 8011 and the IANA IPP registry.
pub mod operation {
    #![allow(missing_docs)]
    pub const PRINT_JOB: u16 = 0x0002;
    pub const PRINT_URI: u16 = 0x0003;
    pub const VALIDATE_JOB: u16 = 0x0004;
    pub const CREATE_JOB: u16 = 0x0005;
    pub const SEND_DOCUMENT: u16 = 0x0006;
    pub const SEND_URI: u16 = 0x0007;
    pub const CANCEL_JOB: u16 = 0x0008;
    pub const GET_JOB_ATTRIBUTES: u16 = 0x0009;
    pub const GET_JOBS: u16 = 0x000a;
    pub const GET_PRINTER_ATTRIBUTES: u16 = 0x000b;
    pub const HOLD_JOB: u16 = 0x000c;
    pub const RELEASE_JOB: u16 = 0x000d;
    pub const RESTART_JOB: u16 = 0x000e;
    pub const PAUSE_PRINTER: u16 = 0x0010;
    pub const RESUME_PRINTER: u16 = 0x0011;
    pub const PURGE_JOBS: u16 = 0x0012;
    pub const SET_PRINTER_ATTRIBUTES: u16 = 0x0013;
    pub const SET_JOB_ATTRIBUTES: u16 = 0x0014;
    pub const GET_PRINTER_SUPPORTED_VALUES: u16 = 0x0015;
    pub const CREATE_PRINTER_SUBSCRIPTIONS: u16 = 0x0016;
    pub const CREATE_JOB_SUBSCRIPTIONS: u16 = 0x0017;
    pub const GET_SUBSCRIPTION_ATTRIBUTES: u16 = 0x0018;
    pub const GET_SUBSCRIPTIONS: u16 = 0x0019;
    pub const RENEW_SUBSCRIPTION: u16 = 0x001a;
    pub const CANCEL_SUBSCRIPTION: u16 = 0x001b;
    pub const GET_NOTIFICATIONS: u16 = 0x001c;
    pub const GET_RESOURCE_ATTRIBUTES: u16 = 0x001e;
    pub const GET_RESOURCES: u16 = 0x0020;
    pub const ENABLE_PRINTER: u16 = 0x0022;
    pub const DISABLE_PRINTER: u16 = 0x0023;
    pub const PAUSE_PRINTER_AFTER_CURRENT_JOB: u16 = 0x0024;
    pub const HOLD_NEW_JOBS: u16 = 0x0025;
    pub const RELEASE_HELD_NEW_JOBS: u16 = 0x0026;
    pub const DEACTIVATE_PRINTER: u16 = 0x0027;
    pub const ACTIVATE_PRINTER: u16 = 0x0028;
    pub const RESTART_PRINTER: u16 = 0x0029;
    pub const SHUTDOWN_PRINTER: u16 = 0x002a;
    pub const STARTUP_PRINTER: u16 = 0x002b;
    pub const REPROCESS_JOB: u16 = 0x002c;
    pub const CANCEL_CURRENT_JOB: u16 = 0x002d;
    pub const SUSPEND_CURRENT_JOB: u16 = 0x002e;
    pub const RESUME_JOB: u16 = 0x002f;
    pub const PROMOTE_JOB: u16 = 0x0030;
    pub const SCHEDULE_JOB_AFTER: u16 = 0x0031;
    pub const CANCEL_DOCUMENT: u16 = 0x0033;
    pub const GET_DOCUMENT_ATTRIBUTES: u16 = 0x0034;
    pub const GET_DOCUMENTS: u16 = 0x0035;
    pub const DELETE_DOCUMENT: u16 = 0x0036;
    pub const SET_DOCUMENT_ATTRIBUTES: u16 = 0x0037;
    pub const CANCEL_JOBS: u16 = 0x0038;
    pub const CANCEL_MY_JOBS: u16 = 0x0039;
    pub const RESUBMIT_JOB: u16 = 0x003a;
    pub const CLOSE_JOB: u16 = 0x003b;
    pub const IDENTIFY_PRINTER: u16 = 0x003c;
    pub const VALIDATE_DOCUMENT: u16 = 0x003d;
}

/// Status codes, from RFC 8011 and the IANA IPP registry.
pub mod status {
    #![allow(missing_docs)]
    pub const SUCCESSFUL_OK: u16 = 0x0000;
    pub const SUCCESSFUL_OK_IGNORED_OR_SUBSTITUTED_ATTRIBUTES: u16 = 0x0001;
    pub const SUCCESSFUL_OK_CONFLICTING_ATTRIBUTES: u16 = 0x0002;
    pub const SUCCESSFUL_OK_IGNORED_SUBSCRIPTIONS: u16 = 0x0003;
    pub const SUCCESSFUL_OK_TOO_MANY_EVENTS: u16 = 0x0005;
    pub const SUCCESSFUL_OK_EVENTS_COMPLETE: u16 = 0x0007;
    pub const CLIENT_ERROR_BAD_REQUEST: u16 = 0x0400;
    pub const CLIENT_ERROR_FORBIDDEN: u16 = 0x0401;
    pub const CLIENT_ERROR_NOT_AUTHENTICATED: u16 = 0x0402;
    pub const CLIENT_ERROR_NOT_AUTHORIZED: u16 = 0x0403;
    pub const CLIENT_ERROR_NOT_POSSIBLE: u16 = 0x0404;
    pub const CLIENT_ERROR_TIMEOUT: u16 = 0x0405;
    pub const CLIENT_ERROR_NOT_FOUND: u16 = 0x0406;
    pub const CLIENT_ERROR_GONE: u16 = 0x0407;
    pub const CLIENT_ERROR_REQUEST_ENTITY_TOO_LARGE: u16 = 0x0408;
    pub const CLIENT_ERROR_REQUEST_VALUE_TOO_LONG: u16 = 0x0409;
    pub const CLIENT_ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED: u16 = 0x040a;
    pub const CLIENT_ERROR_ATTRIBUTES_OR_VALUES_NOT_SUPPORTED: u16 = 0x040b;
    pub const CLIENT_ERROR_URI_SCHEME_NOT_SUPPORTED: u16 = 0x040c;
    pub const CLIENT_ERROR_CHARSET_NOT_SUPPORTED: u16 = 0x040d;
    pub const CLIENT_ERROR_CONFLICTING_ATTRIBUTES: u16 = 0x040e;
    pub const CLIENT_ERROR_COMPRESSION_NOT_SUPPORTED: u16 = 0x040f;
    pub const CLIENT_ERROR_COMPRESSION_ERROR: u16 = 0x0410;
    pub const CLIENT_ERROR_DOCUMENT_FORMAT_ERROR: u16 = 0x0411;
    pub const CLIENT_ERROR_DOCUMENT_ACCESS_ERROR: u16 = 0x0412;
    pub const CLIENT_ERROR_ATTRIBUTES_NOT_SETTABLE: u16 = 0x0413;
    pub const CLIENT_ERROR_IGNORED_ALL_SUBSCRIPTIONS: u16 = 0x0414;
    pub const CLIENT_ERROR_TOO_MANY_SUBSCRIPTIONS: u16 = 0x0415;
    pub const CLIENT_ERROR_DOCUMENT_PASSWORD_ERROR: u16 = 0x0418;
    pub const CLIENT_ERROR_DOCUMENT_PERMISSION_ERROR: u16 = 0x0419;
    pub const CLIENT_ERROR_DOCUMENT_SECURITY_ERROR: u16 = 0x041a;
    pub const CLIENT_ERROR_DOCUMENT_UNPRINTABLE_ERROR: u16 = 0x041b;
    pub const CLIENT_ERROR_ACCOUNT_INFO_NEEDED: u16 = 0x041c;
    pub const CLIENT_ERROR_ACCOUNT_CLOSED: u16 = 0x041d;
    pub const CLIENT_ERROR_ACCOUNT_LIMIT_REACHED: u16 = 0x041e;
    pub const CLIENT_ERROR_ACCOUNT_AUTHORIZATION_FAILED: u16 = 0x041f;
    pub const CLIENT_ERROR_NOT_FETCHABLE: u16 = 0x0420;
    pub const SERVER_ERROR_INTERNAL_ERROR: u16 = 0x0500;
    pub const SERVER_ERROR_OPERATION_NOT_SUPPORTED: u16 = 0x0501;
    pub const SERVER_ERROR_SERVICE_UNAVAILABLE: u16 = 0x0502;
    pub const SERVER_ERROR_VERSION_NOT_SUPPORTED: u16 = 0x0503;
    pub const SERVER_ERROR_DEVICE_ERROR: u16 = 0x0504;
    pub const SERVER_ERROR_TEMPORARY_ERROR: u16 = 0x0505;
    pub const SERVER_ERROR_NOT_ACCEPTING_JOBS: u16 = 0x0506;
    pub const SERVER_ERROR_BUSY: u16 = 0x0507;
    pub const SERVER_ERROR_JOB_CANCELED: u16 = 0x0508;
    pub const SERVER_ERROR_MULTIPLE_DOCUMENT_JOBS_NOT_SUPPORTED: u16 = 0x0509;
    pub const SERVER_ERROR_PRINTER_IS_DEACTIVATED: u16 = 0x050a;
    pub const SERVER_ERROR_TOO_MANY_JOBS: u16 = 0x050b;
    pub const SERVER_ERROR_TOO_MANY_DOCUMENTS: u16 = 0x050c;

    /// Whether `code` is in the successful class, 0x0000 to 0x00ff.
    pub fn is_successful(code: u16) -> bool {
        code <= 0x00ff
    }
}

const OPERATION_NAMES: &[(u16, &str)] = &[
    (operation::PRINT_JOB, "Print-Job"),
    (operation::PRINT_URI, "Print-URI"),
    (operation::VALIDATE_JOB, "Validate-Job"),
    (operation::CREATE_JOB, "Create-Job"),
    (operation::SEND_DOCUMENT, "Send-Document"),
    (operation::SEND_URI, "Send-URI"),
    (operation::CANCEL_JOB, "Cancel-Job"),
    (operation::GET_JOB_ATTRIBUTES, "Get-Job-Attributes"),
    (operation::GET_JOBS, "Get-Jobs"),
    (operation::GET_PRINTER_ATTRIBUTES, "Get-Printer-Attributes"),
    (operation::HOLD_JOB, "Hold-Job"),
    (operation::RELEASE_JOB, "Release-Job"),
    (operation::RESTART_JOB, "Restart-Job"),
    (operation::PAUSE_PRINTER, "Pause-Printer"),
    (operation::RESUME_PRINTER, "Resume-Printer"),
    (operation::PURGE_JOBS, "Purge-Jobs"),
    (operation::SET_PRINTER_ATTRIBUTES, "Set-Printer-Attributes"),
    (operation::SET_JOB_ATTRIBUTES, "Set-Job-Attributes"),
    (operation::GET_PRINTER_SUPPORTED_VALUES, "Get-Printer-Supported-Values"),
    (operation::CREATE_PRINTER_SUBSCRIPTIONS, "Create-Printer-Subscriptions"),
    (operation::CREATE_JOB_SUBSCRIPTIONS, "Create-Job-Subscriptions"),
    (operation::GET_SUBSCRIPTION_ATTRIBUTES, "Get-Subscription-Attributes"),
    (operation::GET_SUBSCRIPTIONS, "Get-Subscriptions"),
    (operation::RENEW_SUBSCRIPTION, "Renew-Subscription"),
    (operation::CANCEL_SUBSCRIPTION, "Cancel-Subscription"),
    (operation::GET_NOTIFICATIONS, "Get-Notifications"),
    (operation::GET_RESOURCE_ATTRIBUTES, "Get-Resource-Attributes"),
    (operation::GET_RESOURCES, "Get-Resources"),
    (operation::ENABLE_PRINTER, "Enable-Printer"),
    (operation::DISABLE_PRINTER, "Disable-Printer"),
    (operation::PAUSE_PRINTER_AFTER_CURRENT_JOB, "Pause-Printer-After-Current-Job"),
    (operation::HOLD_NEW_JOBS, "Hold-New-Jobs"),
    (operation::RELEASE_HELD_NEW_JOBS, "Release-Held-New-Jobs"),
    (operation::DEACTIVATE_PRINTER, "Deactivate-Printer"),
    (operation::ACTIVATE_PRINTER, "Activate-Printer"),
    (operation::RESTART_PRINTER, "Restart-Printer"),
    (operation::SHUTDOWN_PRINTER, "Shutdown-Printer"),
    (operation::STARTUP_PRINTER, "Startup-Printer"),
    (operation::REPROCESS_JOB, "Reprocess-Job"),
    (operation::CANCEL_CURRENT_JOB, "Cancel-Current-Job"),
    (operation::SUSPEND_CURRENT_JOB, "Suspend-Current-Job"),
    (operation::RESUME_JOB, "Resume-Job"),
    (operation::PROMOTE_JOB, "Promote-Job"),
    (operation::SCHEDULE_JOB_AFTER, "Schedule-Job-After"),
    (operation::CANCEL_DOCUMENT, "Cancel-Document"),
    (operation::GET_DOCUMENT_ATTRIBUTES, "Get-Document-Attributes"),
    (operation::GET_DOCUMENTS, "Get-Documents"),
    (operation::DELETE_DOCUMENT, "Delete-Document"),
    (operation::SET_DOCUMENT_ATTRIBUTES, "Set-Document-Attributes"),
    (operation::CANCEL_JOBS, "Cancel-Jobs"),
    (operation::CANCEL_MY_JOBS, "Cancel-My-Jobs"),
    (operation::RESUBMIT_JOB, "Resubmit-Job"),
    (operation::CLOSE_JOB, "Close-Job"),
    (operation::IDENTIFY_PRINTER, "Identify-Printer"),
    (operation::VALIDATE_DOCUMENT, "Validate-Document"),
];

const STATUS_NAMES: &[(u16, &str)] = &[
    (status::SUCCESSFUL_OK, "successful-ok"),
    (status::SUCCESSFUL_OK_IGNORED_OR_SUBSTITUTED_ATTRIBUTES, "successful-ok-ignored-or-substituted-attributes"),
    (status::SUCCESSFUL_OK_CONFLICTING_ATTRIBUTES, "successful-ok-conflicting-attributes"),
    (status::SUCCESSFUL_OK_IGNORED_SUBSCRIPTIONS, "successful-ok-ignored-subscriptions"),
    (status::SUCCESSFUL_OK_TOO_MANY_EVENTS, "successful-ok-too-many-events"),
    (status::SUCCESSFUL_OK_EVENTS_COMPLETE, "successful-ok-events-complete"),
    (status::CLIENT_ERROR_BAD_REQUEST, "client-error-bad-request"),
    (status::CLIENT_ERROR_FORBIDDEN, "client-error-forbidden"),
    (status::CLIENT_ERROR_NOT_AUTHENTICATED, "client-error-not-authenticated"),
    (status::CLIENT_ERROR_NOT_AUTHORIZED, "client-error-not-authorized"),
    (status::CLIENT_ERROR_NOT_POSSIBLE, "client-error-not-possible"),
    (status::CLIENT_ERROR_TIMEOUT, "client-error-timeout"),
    (status::CLIENT_ERROR_NOT_FOUND, "client-error-not-found"),
    (status::CLIENT_ERROR_GONE, "client-error-gone"),
    (status::CLIENT_ERROR_REQUEST_ENTITY_TOO_LARGE, "client-error-request-entity-too-large"),
    (status::CLIENT_ERROR_REQUEST_VALUE_TOO_LONG, "client-error-request-value-too-long"),
    (status::CLIENT_ERROR_DOCUMENT_FORMAT_NOT_SUPPORTED, "client-error-document-format-not-supported"),
    (status::CLIENT_ERROR_ATTRIBUTES_OR_VALUES_NOT_SUPPORTED, "client-error-attributes-or-values-not-supported"),
    (status::CLIENT_ERROR_URI_SCHEME_NOT_SUPPORTED, "client-error-uri-scheme-not-supported"),
    (status::CLIENT_ERROR_CHARSET_NOT_SUPPORTED, "client-error-charset-not-supported"),
    (status::CLIENT_ERROR_CONFLICTING_ATTRIBUTES, "client-error-conflicting-attributes"),
    (status::CLIENT_ERROR_COMPRESSION_NOT_SUPPORTED, "client-error-compression-not-supported"),
    (status::CLIENT_ERROR_COMPRESSION_ERROR, "client-error-compression-error"),
    (status::CLIENT_ERROR_DOCUMENT_FORMAT_ERROR, "client-error-document-format-error"),
    (status::CLIENT_ERROR_DOCUMENT_ACCESS_ERROR, "client-error-document-access-error"),
    (status::CLIENT_ERROR_ATTRIBUTES_NOT_SETTABLE, "client-error-attributes-not-settable"),
    (status::CLIENT_ERROR_IGNORED_ALL_SUBSCRIPTIONS, "client-error-ignored-all-subscriptions"),
    (status::CLIENT_ERROR_TOO_MANY_SUBSCRIPTIONS, "client-error-too-many-subscriptions"),
    (status::CLIENT_ERROR_DOCUMENT_PASSWORD_ERROR, "client-error-document-password-error"),
    (status::CLIENT_ERROR_DOCUMENT_PERMISSION_ERROR, "client-error-document-permission-error"),
    (status::CLIENT_ERROR_DOCUMENT_SECURITY_ERROR, "client-error-document-security-error"),
    (status::CLIENT_ERROR_DOCUMENT_UNPRINTABLE_ERROR, "client-error-document-unprintable-error"),
    (status::CLIENT_ERROR_ACCOUNT_INFO_NEEDED, "client-error-account-info-needed"),
    (status::CLIENT_ERROR_ACCOUNT_CLOSED, "client-error-account-closed"),
    (status::CLIENT_ERROR_ACCOUNT_LIMIT_REACHED, "client-error-account-limit-reached"),
    (status::CLIENT_ERROR_ACCOUNT_AUTHORIZATION_FAILED, "client-error-account-authorization-failed"),
    (status::CLIENT_ERROR_NOT_FETCHABLE, "client-error-not-fetchable"),
    (status::SERVER_ERROR_INTERNAL_ERROR, "server-error-internal-error"),
    (status::SERVER_ERROR_OPERATION_NOT_SUPPORTED, "server-error-operation-not-supported"),
    (status::SERVER_ERROR_SERVICE_UNAVAILABLE, "server-error-service-unavailable"),
    (status::SERVER_ERROR_VERSION_NOT_SUPPORTED, "server-error-version-not-supported"),
    (status::SERVER_ERROR_DEVICE_ERROR, "server-error-device-error"),
    (status::SERVER_ERROR_TEMPORARY_ERROR, "server-error-temporary-error"),
    (status::SERVER_ERROR_NOT_ACCEPTING_JOBS, "server-error-not-accepting-jobs"),
    (status::SERVER_ERROR_BUSY, "server-error-busy"),
    (status::SERVER_ERROR_JOB_CANCELED, "server-error-job-canceled"),
    (status::SERVER_ERROR_MULTIPLE_DOCUMENT_JOBS_NOT_SUPPORTED, "server-error-multiple-document-jobs-not-supported"),
    (status::SERVER_ERROR_PRINTER_IS_DEACTIVATED, "server-error-printer-is-deactivated"),
    (status::SERVER_ERROR_TOO_MANY_JOBS, "server-error-too-many-jobs"),
    (status::SERVER_ERROR_TOO_MANY_DOCUMENTS, "server-error-too-many-documents"),
];

/// The registered name of an operation ID, such as `"Print-Job"` for 2.
pub fn operation_name(id: u16) -> Option<&'static str> {
    OPERATION_NAMES.iter().find(|(c, _)| *c == id).map(|(_, n)| *n)
}

/// The operation ID with a registered name, such as 2 for `"Print-Job"`.
/// Case matters, as in the registry.
pub fn operation_by_name(name: &str) -> Option<u16> {
    OPERATION_NAMES.iter().find(|(_, n)| *n == name).map(|(c, _)| *c)
}

/// The registered name of a status code, such as `"successful-ok"` for 0.
pub fn status_name(code: u16) -> Option<&'static str> {
    STATUS_NAMES.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

/// The status code with a registered name, such as 0x0406 for
/// `"client-error-not-found"`.
pub fn status_by_name(name: &str) -> Option<u16> {
    STATUS_NAMES.iter().find(|(_, n)| *n == name).map(|(c, _)| *c)
}

/// The name of a delimiter or value tag, such as `"keyword"` for 0x44.
pub fn tag_name(t: u8) -> Option<&'static str> {
    Some(match t {
        tag::OPERATION_ATTRIBUTES => "operation-attributes-tag",
        tag::JOB_ATTRIBUTES => "job-attributes-tag",
        tag::END_OF_ATTRIBUTES => "end-of-attributes-tag",
        tag::PRINTER_ATTRIBUTES => "printer-attributes-tag",
        tag::UNSUPPORTED_ATTRIBUTES => "unsupported-attributes-tag",
        tag::SUBSCRIPTION_ATTRIBUTES => "subscription-attributes-tag",
        tag::EVENT_NOTIFICATION_ATTRIBUTES => "event-notification-attributes-tag",
        tag::RESOURCE_ATTRIBUTES => "resource-attributes-tag",
        tag::DOCUMENT_ATTRIBUTES => "document-attributes-tag",
        tag::SYSTEM_ATTRIBUTES => "system-attributes-tag",
        tag::UNSUPPORTED => "unsupported",
        tag::UNKNOWN => "unknown",
        tag::NO_VALUE => "no-value",
        tag::NOT_SETTABLE => "not-settable",
        tag::DELETE_ATTRIBUTE => "delete-attribute",
        tag::ADMIN_DEFINE => "admin-define",
        tag::INTEGER => "integer",
        tag::BOOLEAN => "boolean",
        tag::ENUM => "enum",
        tag::OCTET_STRING => "octetString",
        tag::DATE_TIME => "dateTime",
        tag::RESOLUTION => "resolution",
        tag::RANGE_OF_INTEGER => "rangeOfInteger",
        tag::BEG_COLLECTION => "begCollection",
        tag::TEXT_WITH_LANGUAGE => "textWithLanguage",
        tag::NAME_WITH_LANGUAGE => "nameWithLanguage",
        tag::END_COLLECTION => "endCollection",
        tag::TEXT_WITHOUT_LANGUAGE => "textWithoutLanguage",
        tag::NAME_WITHOUT_LANGUAGE => "nameWithoutLanguage",
        tag::KEYWORD => "keyword",
        tag::URI => "uri",
        tag::URI_SCHEME => "uriScheme",
        tag::CHARSET => "charset",
        tag::NATURAL_LANGUAGE => "naturalLanguage",
        tag::MIME_MEDIA_TYPE => "mimeMediaType",
        tag::MEMBER_ATTR_NAME => "memberAttrName",
        tag::EXTENSION => "extension",
        _ => return None,
    })
}

/// Whether `t` is a value tag this module does not give a meaning to, so
/// its value is kept as [`Value::Unknown`].
fn is_unknown_tag(t: u8) -> bool {
    matches!(t, 0x20 | 0x24..=0x2f | 0x38..=0x3f | 0x40 | 0x43 | 0x4b..=0x7e | 0x80..=0xff)
}

/// One IPP message: a request or a response.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Message {
    /// The IPP version, major then minor, such as `(1, 1)` or `(2, 0)`.
    /// Whether a version is supported is up to world code.
    pub version: (u8, u8),
    /// The operation ID in a request, or the status code in a response.
    /// The bytes do not say which, so the reader cannot either.
    pub code: u16,
    /// Chosen by the client and copied into the response. RFC 8011 asks for
    /// 1 to 2^31 - 1, but any value is read and written.
    pub request_id: u32,
    /// The attribute groups, in order.
    pub groups: Vec<Group>,
    /// The bytes after the end tag: the document, if any.
    pub data: Vec<u8>,
}

/// An attribute group: a delimiter tag and the attributes after it. A group
/// may be empty. No two of its attributes may share a name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Group {
    /// The delimiter tag, such as [`tag::OPERATION_ATTRIBUTES`]. It is
    /// below 0x10 and is never [`tag::END_OF_ATTRIBUTES`].
    pub tag: u8,
    /// The group's attributes, in order.
    pub attributes: Vec<Attribute>,
}

impl Group {
    /// The attribute called `name` in this group.
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// The attribute called `name` in this group, to change.
    pub fn attribute_mut(&mut self, name: &str) -> Option<&mut Attribute> {
        self.attributes.iter_mut().find(|a| a.name == name)
    }
}

/// One attribute: a name and one or more values. A collection's members
/// have the same shape.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attribute {
    /// The attribute's name, such as `"printer-uri"`. RFC 8010 section 3.2
    /// makes a name a keyword. The reader takes 1 to [`MAX_NAME`] bytes of
    /// printable US-ASCII (0x21 to 0x7e), as CUPS does, so a name with a
    /// NUL, a space or a non-ASCII byte is refused by readers and writers.
    pub name: String,
    /// Its values. A read attribute has at least one. More than one is a
    /// "1setOf" attribute, sent as additional values.
    pub values: Vec<Value>,
}

impl Attribute {
    /// An attribute with one value.
    pub fn new(name: impl Into<String>, value: Value) -> Attribute {
        Attribute { name: name.into(), values: vec![value] }
    }
}

/// A dateTime value, laid out as in RFC 2579. Readers and writers refuse
/// a value with a field outside the range its doc gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DateTime {
    /// The year, such as 2026.
    pub year: u16,
    /// The month, 1 to 12.
    pub month: u8,
    /// The day of the month, 1 to 31.
    pub day: u8,
    /// The hour, 0 to 23.
    pub hour: u8,
    /// The minutes, 0 to 59.
    pub minutes: u8,
    /// The seconds, 0 to 60.
    pub seconds: u8,
    /// Tenths of a second, 0 to 9.
    pub deci_seconds: u8,
    /// `b'+'` or `b'-'`: which side of UTC the time zone is on.
    pub direction: u8,
    /// Hours from UTC, 0 to 14. RFC 2579 says 0 to 13, but UTC+14 is in
    /// use, so 14 is taken too.
    pub utc_hours: u8,
    /// Minutes from UTC, 0 to 59.
    pub utc_minutes: u8,
}

/// One attribute value. Each variant is one value tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    /// An out-of-band value, tags 0x10 to 0x1f, such as
    /// [`tag::UNSUPPORTED`] or [`tag::NO_VALUE`]. It carries no data; any
    /// bytes sent with it are ignored.
    OutOfBand(u8),
    /// Tag 0x21: a signed 32-bit integer.
    Integer(i32),
    /// Tag 0x22: a boolean, one byte, 0 or 1.
    Boolean(bool),
    /// Tag 0x23: an enum value, such as a printer state. RFC 8011
    /// section 5.1.5 allows 1 to 2^31 - 1; 0 and below are refused by the
    /// reader and writer.
    Enum(i32),
    /// Tag 0x30: bytes with no set format.
    OctetString(Vec<u8>),
    /// Tag 0x31: a date and time.
    DateTime(DateTime),
    /// Tag 0x32: a resolution across and along the feed direction, in
    /// `units` (3 is dots per inch, 4 is dots per centimeter). RFC 8011
    /// section 5.1.16 makes both resolutions positive and the units 3 or 4;
    /// any other is refused by the reader and writer.
    Resolution {
        /// Resolution across the paper path. Must be positive.
        cross_feed: i32,
        /// Resolution along the paper path. Must be positive.
        feed: i32,
        /// 3 for dots per inch or 4 for dots per centimeter.
        units: i8,
    },
    /// Tag 0x33: a range of integers, both ends included.
    Range {
        /// Inclusive lower bound.
        lower: i32,
        /// Inclusive upper bound.
        upper: i32,
    },
    /// Tag 0x35: text with the natural language it is in.
    TextWithLanguage {
        /// Natural language.
        language: String,
        /// Text in that language.
        text: String,
    },
    /// Tag 0x36: a name with the natural language it is in.
    NameWithLanguage {
        /// Natural language.
        language: String,
        /// Name in that language.
        name: String,
    },
    /// Tag 0x41: text in the message's charset.
    Text(String),
    /// Tag 0x42: a name in the message's charset.
    Name(String),
    /// Tag 0x44: a keyword, such as `"one-sided"`.
    Keyword(String),
    /// Tag 0x45: a URI.
    Uri(String),
    /// Tag 0x46: a URI scheme, such as `"ipp"`.
    UriScheme(String),
    /// Tag 0x47: a charset name, such as `"utf-8"`.
    Charset(String),
    /// Tag 0x48: a natural language, such as `"en-us"`.
    NaturalLanguage(String),
    /// Tag 0x49: a media type, such as `"application/pdf"`.
    MimeMediaType(String),
    /// Tag 0x34 to tag 0x37: a collection of member attributes, each with
    /// one or more values.
    Collection(Vec<Attribute>),
    /// Tag 0x7f: an extended type, whose 32-bit tag is the first four bytes
    /// of the value, then its data.
    Extension {
        /// Extended type tag.
        tag: u32,
        /// Uninterpreted value bytes.
        data: Vec<u8>,
    },
    /// Any other value tag, with its bytes unread.
    Unknown {
        /// Unrecognized value tag.
        tag: u8,
        /// Uninterpreted value bytes.
        data: Vec<u8>,
    },
}

impl Value {
    /// The value tag this value is written with.
    pub fn tag(&self) -> u8 {
        match self {
            Value::OutOfBand(t) => *t,
            Value::Integer(_) => tag::INTEGER,
            Value::Boolean(_) => tag::BOOLEAN,
            Value::Enum(_) => tag::ENUM,
            Value::OctetString(_) => tag::OCTET_STRING,
            Value::DateTime(_) => tag::DATE_TIME,
            Value::Resolution { .. } => tag::RESOLUTION,
            Value::Range { .. } => tag::RANGE_OF_INTEGER,
            Value::TextWithLanguage { .. } => tag::TEXT_WITH_LANGUAGE,
            Value::NameWithLanguage { .. } => tag::NAME_WITH_LANGUAGE,
            Value::Text(_) => tag::TEXT_WITHOUT_LANGUAGE,
            Value::Name(_) => tag::NAME_WITHOUT_LANGUAGE,
            Value::Keyword(_) => tag::KEYWORD,
            Value::Uri(_) => tag::URI,
            Value::UriScheme(_) => tag::URI_SCHEME,
            Value::Charset(_) => tag::CHARSET,
            Value::NaturalLanguage(_) => tag::NATURAL_LANGUAGE,
            Value::MimeMediaType(_) => tag::MIME_MEDIA_TYPE,
            Value::Collection(_) => tag::BEG_COLLECTION,
            Value::Extension { .. } => tag::EXTENSION,
            Value::Unknown { tag, .. } => *tag,
        }
    }

    /// The string a text, name or character-string value holds.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::TextWithLanguage { text: s, .. }
            | Value::NameWithLanguage { name: s, .. }
            | Value::Text(s)
            | Value::Name(s)
            | Value::Keyword(s)
            | Value::Uri(s)
            | Value::UriScheme(s)
            | Value::Charset(s)
            | Value::NaturalLanguage(s)
            | Value::MimeMediaType(s) => Some(s),
            _ => None,
        }
    }

    /// The number an integer or enum value holds.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Value::Integer(n) | Value::Enum(n) => Some(*n),
            _ => None,
        }
    }
}

/// Why IPP bytes or a value are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The value cannot be written without changing it.
    Unwritable,
    /// The attribute section runs past [`MAX_HEAD`] bytes.
    TooLong,
    /// A name or value length field is above [`MAX_FIELD`], so it is
    /// negative.
    Length(u16),
    /// An attribute came before any group's delimiter tag.
    NoGroup,
    /// An additional value (a name length of 0) came with no attribute
    /// before it in its group.
    NoAttribute,
    /// The value for this tag has the wrong length or content, such as an
    /// integer that is not 4 bytes, a string that is not UTF-8, an enum of
    /// 0, or a month of 13.
    BadValue(u8),
    /// An attribute or member name is empty where one is needed, longer
    /// than [`MAX_NAME`], or not printable US-ASCII.
    BadName,
    /// A group starts with delimiter tag 0x00, which RFC 8010 section 3.5.1
    /// reserves.
    ReservedGroup,
    /// A collection is malformed: a member with no value, a value with no
    /// member name, a name where none belongs, a member name or end tag
    /// outside a collection, an empty member name with no value before or
    /// after it, or a collection with no end.
    Collection,
    /// Collections nest deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Two attributes in one group have the same name. RFC 8011 calls
    /// such a group malformed and recommends refusing it.
    Duplicate,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unwritable => f.write_str("value cannot be written without changing it"),
            Error::TooLong => write!(f, "the attribute section is longer than {MAX_HEAD} bytes"),
            Error::Length(n) => write!(f, "length field {n:#06x} is negative"),
            Error::NoGroup => f.write_str("an attribute comes before any group tag"),
            Error::NoAttribute => f.write_str("an additional value has no attribute before it"),
            Error::BadValue(t) => write!(f, "a value with tag {t:#04x} is malformed"),
            Error::BadName => f.write_str("a name is not 1 to 255 bytes of printable US-ASCII"),
            Error::ReservedGroup => f.write_str("a group has the reserved tag 0x00"),
            Error::Collection => f.write_str("a collection is malformed"),
            Error::TooDeep => write!(f, "collections nest deeper than {MAX_DEPTH}"),
            Error::Duplicate => f.write_str("two attributes in one group have the same name"),
        }
    }
}

impl std::error::Error for Error {}

impl Message {
    /// A request for `operation`, IPP 1.1, with the two operation
    /// attributes every request starts with: `attributes-charset`
    /// (`utf-8`) and `attributes-natural-language` (`en`).
    pub fn request(operation: u16, request_id: u32) -> Message {
        Message {
            version: (1, 1),
            code: operation,
            request_id,
            groups: vec![standard_operation_group()],
            data: Vec::new(),
        }
    }

    /// A response to this request with `status`, the same version and
    /// request ID, and the two operation attributes every response starts
    /// with. When the request's version is not supported, RFC 8011 section
    /// 4.1.8 asks for the supported version closest to it: set
    /// [`Message::version`] on the response, as in
    /// `reply.version = (2, 0)`.
    pub fn response(&self, status: u16) -> Message {
        Message {
            version: self.version,
            code: status,
            request_id: self.request_id,
            groups: vec![standard_operation_group()],
            data: Vec::new(),
        }
    }

    /// Adds `attribute` to the last group if it has tag `group`, and
    /// otherwise to a new group with that tag at the end. Operation
    /// attributes are the exception: RFC 8011 section 4.1.4 has one
    /// operation group, first, so they go to the first group with
    /// [`tag::OPERATION_ATTRIBUTES`], or to a new one at the start.
    pub fn add(&mut self, group: u8, attribute: Attribute) {
        if group == tag::OPERATION_ATTRIBUTES {
            match self.group_mut(group) {
                Some(g) => g.attributes.push(attribute),
                None => self.groups.insert(0, Group { tag: group, attributes: vec![attribute] }),
            }
            return;
        }
        match self.groups.last_mut() {
            Some(g) if g.tag == group => g.attributes.push(attribute),
            _ => self.groups.push(Group { tag: group, attributes: vec![attribute] }),
        }
    }

    /// The first group with tag `group`.
    pub fn group(&self, group: u8) -> Option<&Group> {
        self.groups.iter().find(|g| g.tag == group)
    }

    /// The first group with tag `group`, to change.
    pub fn group_mut(&mut self, group: u8) -> Option<&mut Group> {
        self.groups.iter_mut().find(|g| g.tag == group)
    }

    /// The first attribute called `name` in a group with tag `group`.
    pub fn attribute(&self, group: u8, name: &str) -> Option<&Attribute> {
        self.groups.iter().filter(|g| g.tag == group).flat_map(|g| &g.attributes).find(|a| a.name == name)
    }
}

fn standard_operation_group() -> Group {
    Group {
        tag: tag::OPERATION_ATTRIBUTES,
        attributes: vec![
            Attribute::new("attributes-charset", Value::Charset("utf-8".into())),
            Attribute::new("attributes-natural-language", Value::NaturalLanguage("en".into())),
        ],
    }
}

/// The largest document [`Message`] reads or writes: 64 MiB. This is a
/// world policy, not a wire length field. After [`Head`], streaming worlds
/// choose their own document budget with [`super::codec::Collect`].
pub const MAX_DOCUMENT: usize = 64 * 1024 * 1024;

/// An IPP message through its end-of-attributes tag, without document data.
///
/// [`Wire`] reads and writes exactly this head.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    /// The major and minor IPP version.
    pub version: (u8, u8),
    /// The operation ID or status code.
    pub code: u16,
    /// The client's request ID, also used in its response.
    pub request_id: u32,
    /// Attribute groups in wire order.
    pub groups: Vec<Group>,
}

impl From<Message> for Header {
    /// Takes the fixed header and attributes, discarding document data.
    fn from(message: Message) -> Self {
        Self {
            version: message.version,
            code: message.code,
            request_id: message.request_id,
            groups: message.groups,
        }
    }
}

/// Why bytes do not contain one complete IPP head or message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The head was refused.
    Head(Error),
    /// The input ends before the end-of-attributes tag.
    Truncated,
    /// Bytes follow the end-of-attributes tag when reading a [`Header`].
    Trailing,
    /// A [`Message`] document is longer than [`MAX_DOCUMENT`].
    DocumentTooLong,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Head(e) => e.fmt(f),
            Self::Truncated => f.write_str("IPP head ended early"),
            Self::Trailing => f.write_str("bytes follow the IPP head"),
            Self::DocumentTooLong => write!(f, "document exceeds {MAX_DOCUMENT} bytes"),
        }
    }
}
impl core::error::Error for ParseError {}

impl Header {
    /// Attaches document bytes to this head. Writing the returned message
    /// checks the document against [`MAX_DOCUMENT`].
    pub fn with_document(self, data: Vec<u8>) -> Message {
        Message {
            version: self.version,
            code: self.code,
            request_id: self.request_id,
            groups: self.groups,
            data,
        }
    }
}

impl Wire for Message {
    type ParseError = ParseError;
    type WriteError = Error;

    /// Reads a complete HTTP body: the head and all following document
    /// bytes. Refuses incomplete or invalid heads, heads over [`MAX_HEAD`],
    /// and documents over [`MAX_DOCUMENT`].
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let end = scan_head(bytes, &mut 0, MAX_HEAD)
            .map_err(ParseError::Head)?
            .ok_or(ParseError::Truncated)?;
        let (bytes, data) = bytes.split_at_checked(end).ok_or(ParseError::Truncated)?;
        let (fixed, body) = bytes.split_first_chunk().ok_or(ParseError::Truncated)?;
        let header = head(fixed, body).map_err(ParseError::Head)?;
        if data.len() > MAX_DOCUMENT {
            return Err(ParseError::DocumentTooLong);
        }
        Ok(header.with_document(data.to_vec()))
    }

    /// Appends a complete body. Refuses the heads listed by
    /// [`Header::write`] and documents over [`MAX_DOCUMENT`].
    /// Refusal leaves `out` unchanged.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.data.len() > MAX_DOCUMENT {
            return Err(Error::Unwritable);
        }
        write_head(self.version, self.code, self.request_id, &self.groups, out)?;
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

impl Wire for Header {
    type ParseError = ParseError;
    type WriteError = Error;

    /// Reads one head through its end tag. Refuses trailing document bytes,
    /// incomplete records, negative lengths, invalid attributes, duplicate
    /// names, oversized heads, and collections deeper than [`MAX_DEPTH`].
    fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let end = scan_head(bytes, &mut 0, MAX_HEAD)
            .map_err(ParseError::Head)?
            .ok_or(ParseError::Truncated)?;
        if end != bytes.len() {
            return Err(ParseError::Trailing);
        }
        let (fixed, body) = bytes.split_first_chunk().ok_or(ParseError::Truncated)?;
        head(fixed, body).map_err(ParseError::Head)
    }

    /// Appends a complete head. Refuses invalid tags, names, empty value
    /// lists, duplicate attributes, out-of-range scalars, oversized fields
    /// or heads, and collections deeper than [`MAX_DEPTH`]. Stages at most
    /// [`MAX_HEAD`] bytes and one scalar of at most [`MAX_FIELD`] bytes.
    /// Returns [`Error::Unwritable`] without changing `out` on refusal.
    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        write_head(self.version, self.code, self.request_id, &self.groups, out)
    }
}

fn write_head(
    version: (u8, u8),
    code: u16,
    request_id: u32,
    groups: &[Group],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[version.0, version.1]);
    bytes.extend_from_slice(&code.to_be_bytes());
    bytes.extend_from_slice(&request_id.to_be_bytes());
    for group in groups {
        if group.tag == 0 || group.tag >= 0x10 || group.tag == tag::END_OF_ATTRIBUTES {
            return Err(Error::Unwritable);
        }
        head_room(&bytes, 1)?;
        bytes.push(group.tag);
        let mut names = BTreeSet::new();
        for attribute in &group.attributes {
            if !is_name(attribute.name.as_bytes())
                || attribute.values.is_empty()
                || !names.insert(&attribute.name)
            {
                return Err(Error::Unwritable);
            }
            for (i, value) in attribute.values.iter().enumerate() {
                let name = if i == 0 {
                    attribute.name.as_bytes()
                } else {
                    b""
                };
                write_value(&mut bytes, name, value, 0)?;
            }
        }
    }
    bytes.push(tag::END_OF_ATTRIBUTES);
    out.extend_from_slice(&bytes);
    Ok(())
}

// Leave room for the final end-of-attributes tag throughout encoding.
fn head_room(out: &[u8], n: usize) -> Result<(), Error> {
    if out.len().checked_add(n).is_none_or(|end| end >= MAX_HEAD) {
        return Err(Error::Unwritable);
    }
    Ok(())
}

fn put(out: &mut Vec<u8>, tag: u8, name: &[u8], value: &[u8]) -> Result<(), Error> {
    if name.len() > MAX_NAME || value.len() > MAX_FIELD {
        return Err(Error::Unwritable);
    }
    let size = 5usize
        .checked_add(name.len())
        .and_then(|n| n.checked_add(value.len()))
        .ok_or(Error::Unwritable)?;
    head_room(out, size)?;
    out.push(tag);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn write_value(out: &mut Vec<u8>, name: &[u8], v: &Value, depth: usize) -> Result<(), Error> {
    if !in_range(v) {
        return Err(Error::Unwritable);
    }
    match v {
        Value::Collection(members) => {
            if depth >= MAX_DEPTH {
                return Err(Error::Unwritable);
            }
            put(out, tag::BEG_COLLECTION, name, &[])?;
            for member in members {
                if !is_name(member.name.as_bytes()) || member.values.is_empty() {
                    return Err(Error::Unwritable);
                }
                put(out, tag::MEMBER_ATTR_NAME, &[], member.name.as_bytes())?;
                for value in &member.values {
                    write_value(out, &[], value, depth + 1)?;
                }
            }
            put(out, tag::END_COLLECTION, &[], &[])
        }
        Value::OutOfBand(t) => {
            if !(0x10..=0x1f).contains(t) {
                return Err(Error::Unwritable);
            }
            put(out, *t, name, &[])
        }
        Value::Integer(n) | Value::Enum(n) => put(out, v.tag(), name, &n.to_be_bytes()),
        Value::Boolean(b) => put(out, v.tag(), name, &[u8::from(*b)]),
        Value::OctetString(b) => put(out, v.tag(), name, b),
        Value::DateTime(d) => {
            let y = d.year.to_be_bytes();
            put(
                out,
                v.tag(),
                name,
                &[
                    y[0],
                    y[1],
                    d.month,
                    d.day,
                    d.hour,
                    d.minutes,
                    d.seconds,
                    d.deci_seconds,
                    d.direction,
                    d.utc_hours,
                    d.utc_minutes,
                ],
            )
        }
        Value::Resolution {
            cross_feed,
            feed,
            units,
        } => {
            let mut b = cross_feed.to_be_bytes().to_vec();
            b.extend_from_slice(&feed.to_be_bytes());
            b.push(*units as u8);
            put(out, v.tag(), name, &b)
        }
        Value::Range { lower, upper } => {
            let mut b = lower.to_be_bytes().to_vec();
            b.extend_from_slice(&upper.to_be_bytes());
            put(out, v.tag(), name, &b)
        }
        Value::TextWithLanguage { language, text: s }
        | Value::NameWithLanguage { language, name: s } => {
            let size = language.len().saturating_add(s.len()).saturating_add(4);
            if size > MAX_FIELD {
                return Err(Error::Unwritable);
            }
            let mut b = Vec::with_capacity(size);
            b.extend_from_slice(&(language.len() as u16).to_be_bytes());
            b.extend_from_slice(language.as_bytes());
            b.extend_from_slice(&(s.len() as u16).to_be_bytes());
            b.extend_from_slice(s.as_bytes());
            put(out, v.tag(), name, &b)
        }
        Value::Text(s)
        | Value::Name(s)
        | Value::Keyword(s)
        | Value::Uri(s)
        | Value::UriScheme(s)
        | Value::Charset(s)
        | Value::NaturalLanguage(s)
        | Value::MimeMediaType(s) => put(out, v.tag(), name, s.as_bytes()),
        Value::Extension { tag: t, data } => {
            if data.len() > MAX_FIELD - 4 {
                return Err(Error::Unwritable);
            }
            let mut b = t.to_be_bytes().to_vec();
            b.extend_from_slice(data);
            put(out, v.tag(), name, &b)
        }
        Value::Unknown { tag: t, data } => {
            if !is_unknown_tag(*t) {
                return Err(Error::Unwritable);
            }
            put(out, *t, name, data)
        }
    }
}

/// A refused complete head, with the request ID needed for an error reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadError {
    /// Echo this ID in a client-error-bad-request response.
    pub request_id: u32,
    /// Why the attributes were refused.
    pub error: Error,
}

impl core::fmt::Display for HeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IPP request {}: {}", self.request_id, self.error)
    }
}
impl core::error::Error for HeadError {}

/// Reads one IPP head item, then returns [`Step::End`] unconditionally.
///
/// All document bytes remain unread for [`super::codec::Stream::swap`]
/// into a [`super::codec::Collect`] with [`MAX_DOCUMENT`] or a world's
/// smaller named limit. The enclosing HTTP body supplies EOF.
///
/// Capacity is the head limit, including the fixed header and end tag.
/// Incomplete heads return [`Step::Need`], so the stream reports truncation
/// at EOF. Empty input at EOF is a clean end with no item. Invalid length
/// fields and over-limit heads end the stream. Attribute errors, including
/// over-long names, are [`HeadError`] items carrying the request ID; the
/// document boundary remains known. No input bytes are retained.
///
/// After a framing failure or truncation, no head bytes have been consumed.
/// Once eight bytes have arrived, bytes `4..8` of
/// [`super::codec::Stream::unread`] hold the request ID in big-endian order.
/// Echo that ID in a [`status::CLIENT_ERROR_BAD_REQUEST`] response, as
/// RFC 8011 section 4.1.2 requires. For a complete head, use the request ID
/// in the [`Header`] or [`HeadError`] item instead.
///
/// ```
/// use fictionet::stdlib::{codec::{Collect, Stream, Wire, finish, pump}, ipp::{Head, MAX_DOCUMENT}};
/// use core::convert::Infallible;
///
/// struct Document(Vec<u8>);
/// impl Wire for Document {
///     type ParseError = Infallible;
///     type WriteError = Infallible;
///     /// Copies bytes unchanged. The collector bounds their length. Refuses no bytes.
///     fn parse(bytes: &[u8]) -> Result<Self, Infallible> { Ok(Self(bytes.to_vec())) }
///     /// Appends bytes unchanged. Refuses no values.
///     fn write(&self, out: &mut Vec<u8>) -> Result<(), Infallible> {
///         out.extend_from_slice(&self.0);
///         Ok(())
///     }
/// }
/// let input = b"\x01\x01\0\x02\0\0\0\x07\x03document";
/// let mut stream = Stream::new(Head::new());
/// let accepted = pump(&mut stream, input, |head| {
///     assert_eq!(head.unwrap().request_id, 7);
/// }).unwrap();
/// assert!(stream.is_done());
/// let mut document = stream.swap(Collect::<Document>::new(MAX_DOCUMENT));
/// pump(&mut document, &input[accepted..], |_| unreachable!()).unwrap();
/// // HTTP signals the end of its body.
/// finish(&mut document, |Document(bytes)| assert_eq!(bytes, b"document")).unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct Head {
    head_limit: usize,
    scanned: usize,
    done: bool,
}

impl Head {
    /// Reads heads up to [`MAX_HEAD`].
    pub fn new() -> Self {
        Self::with_limit(MAX_HEAD)
    }

    /// Sets the head limit, including the end tag, clamped from
    /// `HEADER_LEN + 1` through [`MAX_HEAD`].
    pub fn with_limit(head_limit: usize) -> Self {
        Self {
            head_limit: head_limit.clamp(HEADER_LEN + 1, MAX_HEAD),
            scanned: 0,
            done: false,
        }
    }

    /// The largest head, including the fixed header and end tag.
    pub fn head_limit(&self) -> usize {
        self.head_limit
    }
}

impl Default for Head {
    fn default() -> Self {
        Self::new()
    }
}

impl Decode for Head {
    type Item = Result<Header, HeadError>;
    type Error = Error;
    const NAME: &'static str = "IPP";

    fn capacity(&self) -> usize {
        self.head_limit
    }

    fn decode(&mut self, input: &[u8], _eof: bool) -> Result<Step<Self::Item>, Error> {
        if self.done {
            return Ok(Step::End);
        }
        let Some(end) = scan_head(input, &mut self.scanned, self.head_limit)? else {
            return Ok(Step::Need);
        };
        let Some(bytes) = input.get(..end) else {
            return Ok(Step::Need);
        };
        let Some((fixed, body)) = bytes.split_first_chunk::<HEADER_LEN>() else {
            return Ok(Step::Need);
        };
        let request_id = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        self.done = true;
        let item = head(fixed, body).map_err(|error| HeadError { request_id, error });
        Ok(Step::Item(item, end))
    }
}

// Only the scan cursor survives Need. Every complete record is visited once.
// Reserve space for the end tag. Name validity is checked by head() once
// the complete attribute section and its document boundary are known.
fn scan_head(bytes: &[u8], pos: &mut usize, limit: usize) -> Result<Option<usize>, Error> {
    if bytes.len() < HEADER_LEN {
        return Ok(None);
    }
    *pos = (*pos).max(HEADER_LEN);
    loop {
        let p = *pos;
        let Some(&tag) = bytes.get(p) else {
            return Ok(None);
        };
        let next = p.checked_add(1).ok_or(Error::TooLong)?;
        if next > limit {
            return Err(Error::TooLong);
        }
        if tag == tag::END_OF_ATTRIBUTES {
            return Ok(Some(next));
        }
        if tag < 0x10 {
            if next >= limit {
                return Err(Error::TooLong);
            }
            *pos = next;
            continue;
        }
        let name_start = p.checked_add(3).ok_or(Error::TooLong)?;
        if name_start >= limit {
            return Err(Error::TooLong);
        }
        let Some(n) = len_at(bytes, next)? else {
            return Ok(None);
        };
        let at = name_start.checked_add(n).ok_or(Error::TooLong)?;
        let value_start = at.checked_add(2).ok_or(Error::TooLong)?;
        if value_start >= limit {
            return Err(Error::TooLong);
        }
        let Some(v) = len_at(bytes, at)? else {
            return Ok(None);
        };
        let end = value_start.checked_add(v).ok_or(Error::TooLong)?;
        if end >= limit {
            return Err(Error::TooLong);
        }
        if bytes.len() < end {
            return Ok(None);
        }
        *pos = end;
    }
}

/// Reads a length field at `i`: `None` if its bytes have not come.
fn len_at(b: &[u8], i: usize) -> Result<Option<usize>, Error> {
    match b.get(i..i.saturating_add(2)) {
        Some(&[hi, lo]) => {
            let n = u16::from_be_bytes([hi, lo]);
            if usize::from(n) > MAX_FIELD { Err(Error::Length(n)) } else { Ok(Some(usize::from(n))) }
        }
        _ => Ok(None),
    }
}

/// One record of the attribute section.
enum Record<'a> {
    Delimiter(u8),
    Value { tag: u8, name: &'a [u8], value: &'a [u8] },
}

/// The records of an attribute section whose lengths [`scan_head`] has checked.
struct Records<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>> {
        let b = self.b;
        let p = self.pos;
        let &t = b.get(p)?;
        if t < 0x10 {
            self.pos = p + 1;
            return Some(Record::Delimiter(t));
        }
        let n = usize::from(u16::from_be_bytes([*b.get(p + 1)?, *b.get(p + 2)?]));
        let name = b.get(p + 3..p + 3 + n)?;
        let at = p + 3 + n;
        let v = usize::from(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]));
        let value = b.get(at + 2..at + 2 + v)?;
        self.pos = at + 2 + v;
        Some(Record::Value { tag: t, name, value })
    }
}

/// Reads a fixed header and an attribute section through its end tag,
/// whose lengths [`scan_head`] has checked.
fn head(fixed: &[u8; HEADER_LEN], body: &[u8]) -> Result<Header, Error> {
    let mut records = Records { b: body, pos: 0 };
    let mut groups: Vec<Group> = Vec::new();
    // The names in the current group, to find one used twice. A BTreeSet
    // keeps the check free of the random keys a HashSet would draw.
    let mut names: BTreeSet<&[u8]> = BTreeSet::new();
    while let Some(r) = records.next() {
        match r {
            Record::Delimiter(tag::END_OF_ATTRIBUTES) => break,
            Record::Delimiter(0) => return Err(Error::ReservedGroup),
            Record::Delimiter(t) => {
                groups.push(Group { tag: t, attributes: Vec::new() });
                names.clear();
            }
            Record::Value { tag, name, value } => {
                let group = groups.last_mut().ok_or(Error::NoGroup)?;
                if name.is_empty() {
                    let attribute = group.attributes.last_mut().ok_or(Error::NoAttribute)?;
                    attribute.values.push(read_value(tag, value, &mut records, 0)?);
                } else {
                    if !names.insert(name) {
                        return Err(Error::Duplicate);
                    }
                    let name = utf8_name(name)?;
                    let v = read_value(tag, value, &mut records, 0)?;
                    group.attributes.push(Attribute { name, values: vec![v] });
                }
            }
        }
    }
    Ok(Header {
        version: (fixed[0], fixed[1]),
        code: u16::from_be_bytes([fixed[2], fixed[3]]),
        request_id: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
        groups,
    })
}

/// Whether `b` is an attribute or member name this module reads and writes:
/// 1 to [`MAX_NAME`] bytes of printable US-ASCII.
fn is_name(b: &[u8]) -> bool {
    (1..=MAX_NAME).contains(&b.len()) && b.iter().all(|c| (0x21..=0x7e).contains(c))
}

fn utf8_name(b: &[u8]) -> Result<String, Error> {
    if !is_name(b) {
        return Err(Error::BadName);
    }
    String::from_utf8(b.to_vec()).map_err(|_| Error::BadName)
}

/// Whether a value with a fixed layout is in the ranges RFC 8011 and
/// RFC 2579 give. Every other value is.
fn in_range(v: &Value) -> bool {
    match v {
        Value::Enum(n) => *n >= 1,
        Value::Resolution { cross_feed, feed, units } => *cross_feed > 0 && *feed > 0 && matches!(units, 3 | 4),
        Value::DateTime(d) => {
            (1..=12).contains(&d.month)
                && (1..=31).contains(&d.day)
                && d.hour <= 23
                && d.minutes <= 59
                && d.seconds <= 60
                && d.deci_seconds <= 9
                && matches!(d.direction, b'+' | b'-')
                && d.utc_hours <= 14
                && d.utc_minutes <= 59
        }
        _ => true,
    }
}

/// Reads one value. A collection takes its members from `records`; `depth`
/// is how many collections hold this value, so recursion stops at
/// [`MAX_DEPTH`].
fn read_value(t: u8, v: &[u8], records: &mut Records<'_>, depth: usize) -> Result<Value, Error> {
    let value = read_one(t, v, records, depth)?;
    if in_range(&value) { Ok(value) } else { Err(Error::BadValue(t)) }
}

fn read_one(t: u8, v: &[u8], records: &mut Records<'_>, depth: usize) -> Result<Value, Error> {
    let bad = Error::BadValue(t);
    let s = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|_| bad);
    let i32_at = |i: usize| i32::from_be_bytes([v[i], v[i + 1], v[i + 2], v[i + 3]]);
    Ok(match t {
        tag::MEMBER_ATTR_NAME | tag::END_COLLECTION => return Err(Error::Collection),
        tag::BEG_COLLECTION => {
            if depth >= MAX_DEPTH {
                return Err(Error::TooDeep);
            }
            Value::Collection(read_members(records, depth + 1)?)
        }
        0x10..=0x1f => Value::OutOfBand(t),
        tag::INTEGER | tag::ENUM => {
            if v.len() != 4 {
                return Err(bad);
            }
            if t == tag::INTEGER { Value::Integer(i32_at(0)) } else { Value::Enum(i32_at(0)) }
        }
        tag::BOOLEAN => match v {
            [0] => Value::Boolean(false),
            [1] => Value::Boolean(true),
            _ => return Err(bad),
        },
        tag::OCTET_STRING => Value::OctetString(v.to_vec()),
        tag::DATE_TIME => {
            let &[y0, y1, month, day, hour, minutes, seconds, deci_seconds, direction, utc_hours, utc_minutes] = v
            else {
                return Err(bad);
            };
            Value::DateTime(DateTime {
                year: u16::from_be_bytes([y0, y1]),
                month,
                day,
                hour,
                minutes,
                seconds,
                deci_seconds,
                direction,
                utc_hours,
                utc_minutes,
            })
        }
        tag::RESOLUTION => {
            if v.len() != 9 {
                return Err(bad);
            }
            Value::Resolution { cross_feed: i32_at(0), feed: i32_at(4), units: v[8] as i8 }
        }
        tag::RANGE_OF_INTEGER => {
            if v.len() != 8 {
                return Err(bad);
            }
            Value::Range { lower: i32_at(0), upper: i32_at(4) }
        }
        tag::TEXT_WITH_LANGUAGE | tag::NAME_WITH_LANGUAGE => {
            let (language, rest) = counted(v).ok_or(bad)?;
            let (text, rest) = counted(rest).ok_or(bad)?;
            if !rest.is_empty() {
                return Err(bad);
            }
            let (language, text) = (s(language)?, s(text)?);
            if t == tag::TEXT_WITH_LANGUAGE {
                Value::TextWithLanguage { language, text }
            } else {
                Value::NameWithLanguage { language, name: text }
            }
        }
        tag::TEXT_WITHOUT_LANGUAGE => Value::Text(s(v)?),
        tag::NAME_WITHOUT_LANGUAGE => Value::Name(s(v)?),
        tag::KEYWORD => Value::Keyword(s(v)?),
        tag::URI => Value::Uri(s(v)?),
        tag::URI_SCHEME => Value::UriScheme(s(v)?),
        tag::CHARSET => Value::Charset(s(v)?),
        tag::NATURAL_LANGUAGE => Value::NaturalLanguage(s(v)?),
        tag::MIME_MEDIA_TYPE => Value::MimeMediaType(s(v)?),
        tag::EXTENSION => {
            let (&[a, b, c, d], data) = (v.first_chunk::<4>().ok_or(bad)?, &v[4..]);
            Value::Extension { tag: u32::from_be_bytes([a, b, c, d]), data: data.to_vec() }
        }
        _ => Value::Unknown { tag: t, data: v.to_vec() },
    })
}

/// A 2-byte length and that many bytes, then the rest.
fn counted(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&[hi, lo], rest) = (b.first_chunk::<2>()?, &b[2..]);
    let n = usize::from(u16::from_be_bytes([hi, lo]));
    if rest.len() < n { None } else { Some(rest.split_at(n)) }
}

/// Reads a collection's members, after its begCollection, up to and
/// including its endCollection. A member's later values come either with
/// no memberAttrName before them, as CUPS writes them, or after a
/// memberAttrName with an empty value, as RFC 8010 section 3.1.7 says.
fn read_members(records: &mut Records<'_>, depth: usize) -> Result<Vec<Attribute>, Error> {
    let mut members: Vec<Attribute> = Vec::new();
    // Whether an empty memberAttrName has said another value comes next.
    let mut more = false;
    loop {
        let Some(Record::Value { tag: t, name, value }) = records.next() else {
            return Err(Error::Collection);
        };
        if !name.is_empty() {
            return Err(Error::Collection);
        }
        if (t == tag::END_COLLECTION || t == tag::MEMBER_ATTR_NAME)
            && (more || members.last().is_some_and(|m| m.values.is_empty()))
        {
            return Err(Error::Collection);
        }
        match t {
            tag::END_COLLECTION => return Ok(members),
            tag::MEMBER_ATTR_NAME if value.is_empty() => {
                if members.is_empty() {
                    return Err(Error::Collection);
                }
                more = true;
            }
            tag::MEMBER_ATTR_NAME => members.push(Attribute { name: utf8_name(value)?, values: Vec::new() }),
            _ => {
                let member = members.last_mut().ok_or(Error::Collection)?;
                member.values.push(read_value(t, value, records, depth)?);
                more = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::codec::{
        Fail, Stream, contract,
        test_support::{Lcg, decode_all, mutate},
    };

    /// One record's bytes.
    fn rec(t: u8, name: &str, value: &[u8]) -> Vec<u8> {
        let mut out = vec![t];
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    /// The Print-Job request of RFC 8010 appendix A.1.
    fn print_job() -> Vec<u8> {
        [
            vec![0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01],
            rec(0x47, "attributes-charset", b"utf-8"),
            rec(0x48, "attributes-natural-language", b"en-us"),
            rec(0x45, "printer-uri", b"ipp://printer.example.com/ipp/print/pinetree"),
            rec(0x42, "job-name", b"foobar"),
            rec(0x22, "ipp-attribute-fidelity", &[0x01]),
            vec![0x02],
            rec(0x21, "copies", &[0, 0, 0, 0x14]),
            rec(0x44, "sides", b"two-sided-long-edge"),
            vec![0x03],
            b"%!PDF...".to_vec(),
        ]
        .concat()
    }

    #[test]
    fn print_job_example() {
        let bytes = print_job();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.version, (1, 1));
        assert_eq!(m.code, operation::PRINT_JOB);
        assert_eq!(operation_name(m.code), Some("Print-Job"));
        assert_eq!(m.request_id, 1);
        assert_eq!(m.groups.len(), 2);
        assert_eq!(m.groups[0].tag, tag::OPERATION_ATTRIBUTES);
        assert_eq!(m.attribute(tag::JOB_ATTRIBUTES, "copies").unwrap().values, [Value::Integer(20)]);
        assert_eq!(
            m.attribute(tag::JOB_ATTRIBUTES, "sides").unwrap().values,
            [Value::Keyword("two-sided-long-edge".into())]
        );
        let op = |n| m.attribute(tag::OPERATION_ATTRIBUTES, n).unwrap().values.clone();
        assert_eq!(op("attributes-charset"), [Value::Charset("utf-8".into())]);
        assert_eq!(op("attributes-natural-language"), [Value::NaturalLanguage("en-us".into())]);
        assert_eq!(op("printer-uri")[0].as_str(), Some("ipp://printer.example.com/ipp/print/pinetree"));
        assert_eq!(op("job-name"), [Value::Name("foobar".into())]);
        assert_eq!(op("ipp-attribute-fidelity"), [Value::Boolean(true)]);
        assert_eq!(m.data, b"%!PDF...");
        assert_eq!(m.to_bytes().unwrap(), bytes);
    }

    /// The successful Print-Job response of RFC 8010 appendix A.2.
    #[test]
    fn print_job_response_example() {
        let bytes = [
            vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01],
            rec(0x47, "attributes-charset", b"utf-8"),
            rec(0x48, "attributes-natural-language", b"en-us"),
            rec(0x41, "status-message", b"successful-ok"),
            vec![0x02],
            rec(0x21, "job-id", &147i32.to_be_bytes()),
            rec(0x45, "job-uri", b"ipp://printer.example.com/ipp/print/pinetree/147"),
            rec(0x23, "job-state", &3i32.to_be_bytes()),
            vec![0x03],
        ]
        .concat();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(status_name(m.code), Some("successful-ok"));
        assert!(status::is_successful(m.code));
        assert_eq!(m.attribute(tag::JOB_ATTRIBUTES, "job-id").unwrap().values[0].as_i32(), Some(147));
        assert_eq!(m.attribute(tag::JOB_ATTRIBUTES, "job-state").unwrap().values, [Value::Enum(3)]);
        assert!(m.data.is_empty());
        assert_eq!(m.to_bytes().unwrap(), bytes);
    }

    /// The Create-Job request with a "media-col" collection of RFC 8010
    /// appendix A.7.
    fn media_col() -> Vec<u8> {
        [
            vec![0x01, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x01],
            rec(0x47, "attributes-charset", b"utf-8"),
            rec(0x48, "attributes-natural-language", b"en-us"),
            rec(0x45, "printer-uri", b"ipp://printer.example.com/ipp/print/pinetree"),
            rec(0x34, "media-col", b""),
            rec(0x4a, "", b"media-size"),
            rec(0x34, "", b""),
            rec(0x4a, "", b"x-dimension"),
            rec(0x21, "", &21000i32.to_be_bytes()),
            rec(0x4a, "", b"y-dimension"),
            rec(0x21, "", &29700i32.to_be_bytes()),
            rec(0x37, "", b""),
            rec(0x4a, "", b"media-type"),
            rec(0x44, "", b"stationery"),
            rec(0x37, "", b""),
            vec![0x03],
        ]
        .concat()
    }

    #[test]
    fn collection_example() {
        let bytes = media_col();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(operation_name(m.code), Some("Create-Job"));
        let col = &m.attribute(tag::OPERATION_ATTRIBUTES, "media-col").unwrap().values;
        let expected = Value::Collection(vec![
            Attribute::new(
                "media-size",
                Value::Collection(vec![
                    Attribute::new("x-dimension", Value::Integer(21000)),
                    Attribute::new("y-dimension", Value::Integer(29700)),
                ]),
            ),
            Attribute::new("media-type", Value::Keyword("stationery".into())),
        ]);
        assert_eq!(col, &[expected]);
        assert_eq!(m.to_bytes().unwrap(), bytes);
        // A member with two values: the second follows with no member name.
        let mut m = Message::request(operation::CREATE_JOB, 2);
        let member =
            Attribute { name: "k".into(), values: vec![Value::Keyword("a".into()), Value::Keyword("b".into())] };
        m.add(tag::JOB_ATTRIBUTES, Attribute::new("c", Value::Collection(vec![member])));
        let bytes = m.to_bytes().unwrap();
        let tail = [
            rec(0x34, "c", b""),
            rec(0x4a, "", b"k"),
            rec(0x44, "", b"a"),
            rec(0x44, "", b"b"),
            rec(0x37, "", b""),
            vec![3],
        ];
        assert!(bytes.ends_with(&tail.concat()));
        assert_eq!(Message::parse(&bytes).unwrap(), m);
    }

    #[test]
    fn additional_values_and_empty_groups() {
        let bytes = [
            vec![0x02, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x02, 0x01, 0x04],
            rec(0x44, "sides-supported", b"one-sided"),
            rec(0x44, "", b"two-sided-long-edge"),
            rec(0x44, "", b"two-sided-short-edge"),
            vec![0x05, 0x03],
        ]
        .concat();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.groups.iter().map(|g| g.tag).collect::<Vec<_>>(), [1, 4, 5]);
        assert!(m.groups[0].attributes.is_empty());
        assert_eq!(m.groups[1].attributes[0].values.len(), 3);
        assert_eq!(m.to_bytes().unwrap(), bytes);
    }

    fn every_value() -> Vec<Value> {
        vec![
            Value::OutOfBand(tag::UNSUPPORTED),
            Value::OutOfBand(tag::UNKNOWN),
            Value::OutOfBand(tag::NO_VALUE),
            Value::OutOfBand(tag::NOT_SETTABLE),
            Value::OutOfBand(tag::DELETE_ATTRIBUTE),
            Value::OutOfBand(tag::ADMIN_DEFINE),
            Value::OutOfBand(0x1f),
            Value::Integer(-7),
            Value::Integer(i32::MAX),
            Value::Boolean(false),
            Value::Enum(9),
            Value::OctetString(vec![0, 1, 0xff]),
            Value::DateTime(DateTime {
                year: 2026,
                month: 10,
                day: 5,
                hour: 13,
                minutes: 30,
                seconds: 2,
                deci_seconds: 4,
                direction: b'-',
                utc_hours: 4,
                utc_minutes: 0,
            }),
            Value::Resolution { cross_feed: 600, feed: 300, units: 3 },
            Value::Range { lower: 1, upper: 100 },
            Value::TextWithLanguage { language: "fr".into(), text: "bonjour é".into() },
            Value::NameWithLanguage { language: "de".into(), name: "Drucker".into() },
            Value::Text("hello".into()),
            Value::Name("".into()),
            Value::Keyword("one-sided".into()),
            Value::Uri("ipp://p/".into()),
            Value::UriScheme("ipps".into()),
            Value::Charset("utf-8".into()),
            Value::NaturalLanguage("en".into()),
            Value::MimeMediaType("application/pdf".into()),
            Value::Collection(vec![]),
            Value::Collection(vec![Attribute::new("a", Value::Integer(1))]),
            Value::Extension { tag: 0x4000_0001, data: vec![9, 9] },
            Value::Unknown { tag: 0x20, data: vec![] },
            Value::Unknown { tag: 0x43, data: b"x".to_vec() },
            Value::Unknown { tag: 0x99, data: vec![1, 2, 3] },
        ]
    }

    #[test]
    fn strict_head_covers_all_values_and_bounds_collection_depth() {
        use crate::stdlib::codec::contract;
        let mut message = Message::request(operation::PRINT_JOB, 3);
        message.add(
            tag::JOB_ATTRIBUTES,
            Attribute {
                name: "all".into(),
                values: every_value(),
            },
        );
        message.add(
            tag::JOB_ATTRIBUTES,
            Attribute::new(
                "c",
                Value::Collection(vec![Attribute {
                    name: "m".into(),
                    values: every_value(),
                }]),
            ),
        );
        let head = Header::from(message);
        contract::check_wire_value(&head);
        let bytes = Wire::to_bytes(&head).unwrap();
        contract::check_wire::<Header>(&bytes);
        contract::check_decode_with_alloc_limit(Head::new, &bytes, 2 * MAX_HEAD);
        for (depth, accepted) in [(MAX_DEPTH, true), (MAX_DEPTH + 1, false)] {
            let mut message = Message::request(operation::PRINT_JOB, 3);
            message.add(tag::JOB_ATTRIBUTES, Attribute::new("nested", nested(depth)));
            let head = Header::from(message);
            contract::check_wire_value(&head);
            let mut out = b"prefix".to_vec();
            assert_eq!(head.write(&mut out).is_ok(), accepted);
            if !accepted {
                assert_eq!(out, b"prefix");
            }
        }
    }

    #[test]
    fn every_value_tag_round_trips() {
        for v in every_value() {
            let mut m = Message::request(operation::PRINT_JOB, 3);
            m.add(tag::JOB_ATTRIBUTES, Attribute::new("x", v.clone()));
            let back = Message::parse(&m.to_bytes().unwrap()).unwrap();
            assert_eq!(back, m, "{v:?}");
            assert!(tag_name(v.tag()).is_some() || is_unknown_tag(v.tag()) || (0x10..=0x1f).contains(&v.tag()));
        }
        // All of them as one attribute, and inside a collection.
        let mut m = Message::request(operation::PRINT_JOB, 3);
        m.add(tag::JOB_ATTRIBUTES, Attribute { name: "all".into(), values: every_value() });
        m.add(
            tag::JOB_ATTRIBUTES,
            Attribute::new("c", Value::Collection(vec![Attribute { name: "m".into(), values: every_value() }])),
        );
        m.data = vec![1, 2, 3];
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m);
    }

    #[test]
    fn exact_value_bytes() {
        for (name, value, record) in [
            (
                "r",
                Value::Resolution {
                    cross_feed: 600,
                    feed: 600,
                    units: 3,
                },
                vec![0x32, 0, 1, b'r', 0, 9, 0, 0, 2, 0x58, 0, 0, 2, 0x58, 3],
            ),
            (
                "t",
                Value::TextWithLanguage {
                    language: "en".into(),
                    text: "hi".into(),
                },
                vec![0x35, 0, 1, b't', 0, 8, 0, 2, b'e', b'n', 0, 2, b'h', b'i'],
            ),
            (
                "n",
                Value::OutOfBand(tag::NO_VALUE),
                vec![0x13, 0, 1, b'n', 0, 0],
            ),
        ] {
            let head = Header {
                version: (1, 1),
                code: 2,
                request_id: 1,
                groups: vec![Group {
                    tag: 1,
                    attributes: vec![Attribute::new(name, value)],
                }],
            };
            assert_eq!(
                head.to_bytes().unwrap(),
                [vec![1, 1, 0, 2, 0, 0, 0, 1, 1], record, vec![3]].concat()
            );
        }
    }

    #[test]
    fn out_of_band_and_collection_bytes_are_ignored() {
        // Out-of-band and collection delimiters with bytes the spec says
        // must be empty are read, and the bytes dropped.
        let bytes = [
            vec![1, 1, 0, 2, 0, 0, 0, 1, 1],
            rec(0x10, "a", b"junk"),
            rec(0x34, "c", b"junk"),
            rec(0x37, "", b"junk"),
            vec![3],
        ]
        .concat();
        let m = Message::parse(&bytes).unwrap();
        assert_eq!(m.groups[0].attributes[0].values, [Value::OutOfBand(0x10)]);
        assert_eq!(m.groups[0].attributes[1].values, [Value::Collection(vec![])]);
    }

    #[test]
    fn errors() {
        let hdr = vec![1, 1, 0, 2, 0, 0, 0, 1];
        let with = |parts: Vec<Vec<u8>>| Message::parse(&[vec![hdr.clone()], parts, vec![vec![3]]].concat().concat());
        assert_eq!(Message::parse(&hdr), Err(ParseError::Truncated));
        assert_eq!(Message::parse(&[1, 1]), Err(ParseError::Truncated));
        assert_eq!(
            with(vec![rec(0x44, "a", b"b")]),
            Err(ParseError::Head(Error::NoGroup))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x44, "", b"b")]),
            Err(ParseError::Head(Error::NoAttribute))
        );
        // A new group forgets the last attribute.
        assert_eq!(
            with(vec![
                vec![1],
                rec(0x44, "a", b"b"),
                vec![2],
                rec(0x44, "", b"b")
            ]),
            Err(ParseError::Head(Error::NoAttribute))
        );
        assert_eq!(
            with(vec![vec![1, 0x44, 0x80, 0x00]]),
            Err(ParseError::Head(Error::Length(0x8000)))
        );
        assert_eq!(
            with(vec![vec![1, 0x44, 0, 1, b'a', 0xff, 0xff]]),
            Err(ParseError::Head(Error::Length(0xffff)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x21, "a", &[0, 0, 1])]),
            Err(ParseError::Head(Error::BadValue(0x21)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x23, "a", &[0, 0, 0, 0, 1])]),
            Err(ParseError::Head(Error::BadValue(0x23)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x22, "a", &[2])]),
            Err(ParseError::Head(Error::BadValue(0x22)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x22, "a", &[])]),
            Err(ParseError::Head(Error::BadValue(0x22)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x31, "a", &[0; 10])]),
            Err(ParseError::Head(Error::BadValue(0x31)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x32, "a", &[0; 8])]),
            Err(ParseError::Head(Error::BadValue(0x32)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x33, "a", &[0; 9])]),
            Err(ParseError::Head(Error::BadValue(0x33)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x35, "a", &[0, 2, b'e'])]),
            Err(ParseError::Head(Error::BadValue(0x35)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x35, "a", &[0, 0, 0, 0, 9])]),
            Err(ParseError::Head(Error::BadValue(0x35)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x36, "a", &[0, 0])]),
            Err(ParseError::Head(Error::BadValue(0x36)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x41, "a", &[0xff])]),
            Err(ParseError::Head(Error::BadValue(0x41)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x7f, "a", &[0, 0, 1])]),
            Err(ParseError::Head(Error::BadValue(0x7f)))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x44, "a!~", b"")]).map(|_| ()),
            Ok(())
        );
        assert_eq!(
            with(vec![vec![1, 0x44, 0, 1, 0xc3, 0, 0]]),
            Err(ParseError::Head(Error::BadName))
        );
        // Collection errors.
        assert_eq!(
            with(vec![vec![1], rec(0x37, "a", b"")]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x4a, "a", b"m")]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x34, "a", b"")]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x34, "a", b""), vec![2]]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x34, "a", b""), rec(0x21, "", &[0; 4])]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![
                vec![1],
                rec(0x34, "a", b""),
                rec(0x4a, "", b"m"),
                rec(0x37, "", b"")
            ]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![
                vec![1],
                rec(0x34, "a", b""),
                rec(0x4a, "", b"m"),
                rec(0x4a, "", b"n")
            ]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x34, "a", b""), rec(0x4a, "x", b"m")]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![vec![1], rec(0x34, "a", b""), rec(0x4a, "", &[0xff])]),
            Err(ParseError::Head(Error::BadName))
        );
        // The head may not run past MAX_HEAD.
        let mut long = hdr.clone();
        long.push(1);
        while long.len() < MAX_HEAD {
            long.extend(rec(0x30, "a", &[0; 30000]));
        }
        assert_eq!(Message::parse(&long), Err(ParseError::Head(Error::TooLong)));
        assert_eq!(
            decode_all(Head::new, &long).1,
            Some(Fail::Protocol(Error::TooLong))
        );
        contract::check_decode_with_alloc_limit(Head::new, &long, 2 * MAX_HEAD);
        // Every message shows its error.
        for e in [
            Error::TooLong,
            Error::Length(0x8000),
            Error::NoGroup,
            Error::NoAttribute,
        ] {
            assert!(!e.to_string().is_empty());
        }
        for e in [Error::BadValue(0x21), Error::BadName, Error::Collection, Error::TooDeep, Error::ReservedGroup] {
            assert!(!e.to_string().is_empty());
        }
    }

    /// RFC 8010 section 3.1.7: a memberAttrName with an empty value says
    /// the next value is another value of the member before it.
    #[test]
    fn empty_member_name_adds_a_value() {
        let hdr = vec![1, 1, 0, 5, 0, 0, 0, 1, 2];
        let with = |parts: Vec<Vec<u8>>| Message::parse(&[vec![hdr.clone()], parts, vec![vec![3]]].concat().concat());
        let m = with(vec![
            rec(0x34, "c", b""),
            rec(0x4a, "", b"k"),
            rec(0x44, "", b"a"),
            rec(0x4a, "", b""),
            rec(0x44, "", b"b"),
            rec(0x37, "", b""),
        ])
        .unwrap();
        let member =
            Attribute { name: "k".into(), values: vec![Value::Keyword("a".into()), Value::Keyword("b".into())] };
        assert_eq!(m.groups[0].attributes, [Attribute::new("c", Value::Collection(vec![member]))]);
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m);
        // It needs a member with a value before it, and a value after it.
        assert_eq!(
            with(vec![rec(0x34, "c", b""), rec(0x4a, "", b""), rec(0x44, "", b"a"), rec(0x37, "", b"")]),
            Err(ParseError::Head(Error::Collection))
        );
        assert_eq!(
            with(vec![rec(0x34, "c", b""), rec(0x4a, "", b"k"), rec(0x4a, "", b""), rec(0x44, "", b"a")]),
            Err(ParseError::Head(Error::Collection))
        );
        for after in [rec(0x37, "", b""), rec(0x4a, "", b"n"), rec(0x4a, "", b"")] {
            assert_eq!(
                with(vec![rec(0x34, "c", b""), rec(0x4a, "", b"k"), rec(0x44, "", b"a"), rec(0x4a, "", b""), after]),
                Err(ParseError::Head(Error::Collection))
            );
        }
    }

    /// RFC 8011 section 4.1: a group with two attributes of one name is
    /// malformed. Readers and writers refuse it.
    #[test]
    fn duplicate_names() {
        let bytes = [
            vec![1, 1, 0, 2, 0, 0, 0, 1, 1],
            rec(0x44, "a", b"x"),
            rec(0x44, "a", b"y"),
            vec![3],
        ]
        .concat();
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::Head(Error::Duplicate))
        );
        assert_eq!(
            decode_all(Head::new, &bytes),
            (
                vec![Err(HeadError {
                    request_id: 1,
                    error: Error::Duplicate
                })],
                None
            )
        );
        assert!(!Error::Duplicate.to_string().is_empty());
        // The same name in two groups is fine.
        let bytes =
            [vec![1, 1, 0, 2, 0, 0, 0, 1, 2], rec(0x44, "a", b"x"), vec![2], rec(0x44, "a", b"y"), vec![3]].concat();
        assert_eq!(Message::parse(&bytes).unwrap().groups.len(), 2);
        let mut message = Message::request(operation::PRINT_JOB, 1);
        message.add(tag::JOB_ATTRIBUTES, Attribute::new("a", Value::Integer(1)));
        message.add(tag::JOB_ATTRIBUTES, Attribute::new("a", Value::Integer(2)));
        assert_unwritable(&message);
        message.groups[1].attributes[0].values.clear();
        assert_unwritable(&message);
    }

    #[test]
    fn accessors_and_derives() {
        let mut m = Message::parse(&print_job()).unwrap();
        let g = m.group(tag::JOB_ATTRIBUTES).unwrap();
        assert_eq!(g.attribute("copies").unwrap().values, [Value::Integer(20)]);
        assert!(g.attribute("nope").is_none());
        let g = m.group_mut(tag::JOB_ATTRIBUTES).unwrap();
        g.attribute_mut("copies").unwrap().values = vec![Value::Integer(2)];
        assert_eq!(m.attribute(tag::JOB_ATTRIBUTES, "copies").unwrap().values, [Value::Integer(2)]);
        // Messages, values and errors can be kept in sets and maps.
        let set: std::collections::HashSet<Message> = [m.clone(), m.clone()].into_iter().collect();
        assert_eq!(set.len(), 1);
        let errors: std::collections::HashSet<Error> = [Error::Duplicate, Error::Duplicate].into_iter().collect();
        assert_eq!(errors.len(), 1);
        // A scan cursor can be copied without copying input.
        let bytes = print_job();
        let mut decoder = Head::new();
        assert_eq!(decoder.decode(&bytes[..20], false), Ok(Step::Need));
        let mut copy = decoder.clone();
        assert!(matches!(
            copy.decode(&bytes, false),
            Ok(Step::Item(Ok(_), _))
        ));
        assert_eq!(decoder.decode(&bytes[..20], false), Ok(Step::Need));
    }

    /// A value nested in `n` collections.
    fn nested(n: usize) -> Value {
        let mut v = Value::Integer(1);
        for _ in 0..n {
            v = Value::Collection(vec![Attribute::new("m", v)]);
        }
        v
    }

    #[test]
    fn depth_limit() {
        let mut m = Message::request(operation::PRINT_JOB, 1);
        m.add(tag::JOB_ATTRIBUTES, Attribute::new("deep", nested(MAX_DEPTH)));
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m);
        // One deeper is refused by both reader and writer.
        let mut bytes = vec![1, 1, 0, 2, 0, 0, 0, 1, 2];
        bytes.extend(rec(0x34, "deep", b""));
        for _ in 0..MAX_DEPTH {
            bytes.extend(rec(0x4a, "", b"m"));
            bytes.extend(rec(0x34, "", b""));
        }
        bytes.extend(rec(0x4a, "", b"m"));
        bytes.extend(rec(0x21, "", &[0, 0, 0, 1]));
        for _ in 0..=MAX_DEPTH {
            bytes.extend(rec(0x37, "", b""));
        }
        bytes.push(3);
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::Head(Error::TooDeep))
        );
        let mut m = Message::request(operation::PRINT_JOB, 1);
        m.add(tag::JOB_ATTRIBUTES, Attribute::new("deep", nested(MAX_DEPTH + 1)));
        m.add(
            tag::JOB_ATTRIBUTES,
            Attribute { name: "x".into(), values: vec![nested(MAX_DEPTH + 5), Value::Integer(2)] },
        );
        assert_unwritable(&m);
        // Very deep input is cut off without deep recursion.
        let mut bytes = vec![1, 1, 0, 2, 0, 0, 0, 1, 2];
        bytes.extend(rec(0x34, "deep", b""));
        for _ in 0..50_000 {
            bytes.extend(rec(0x4a, "", b"m"));
            bytes.extend(rec(0x34, "", b""));
        }
        bytes.push(3);
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::Head(Error::TooDeep))
        );
    }

    #[test]
    fn every_truncated_prefix() {
        for bytes in [print_job(), media_col()] {
            let message = Message::parse(&bytes).unwrap();
            let used = bytes.len() - message.data.len();
            for n in 0..used {
                assert_eq!(
                    Message::parse(&bytes[..n]).unwrap_err().to_string(),
                    Header::parse(&bytes[..n]).unwrap_err().to_string()
                );
                assert_eq!(
                    Header::parse(&bytes[..n]),
                    Err(ParseError::Truncated),
                    "{n} bytes"
                );
                assert_eq!(
                    Message::parse(&bytes[..n]),
                    Err(ParseError::Truncated),
                    "{n} bytes"
                );
                assert_eq!(Head::new().decode(&bytes[..n], false), Ok(Step::Need));
            }
            for n in used..=bytes.len() {
                let parsed = Message::parse(&bytes[..n]).unwrap();
                assert_eq!(parsed.groups, message.groups);
                assert_eq!(parsed.data, bytes[used..n]);
            }
            contract::check_decode_with_alloc_limit(Head::new, &bytes, 2 * MAX_HEAD);
        }
    }

    #[test]
    fn head_preserves_document_bytes() {
        let bytes = print_job();
        contract::check_decode_with_alloc_limit(Head::new, &bytes, 2 * MAX_HEAD);
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&bytes), bytes.len());
        let header = stream.next().unwrap().unwrap().unwrap();
        assert_eq!(stream.next(), None);
        assert_eq!(stream.unread(), b"%!PDF...");
        assert_eq!(
            header.with_document(stream.unread().to_vec()),
            Message::parse(&bytes).unwrap()
        );
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&[1, 1, 0, 2, 0, 0, 0, 1, 0x44]), 9);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(&[0, 1, b'a', 0, 0, 3]), 6);
        assert_eq!(
            stream.next(),
            Some(Ok(Err(HeadError {
                request_id: 1,
                error: Error::NoGroup
            })))
        );
        assert_eq!(stream.next(), None);
    }

    #[test]
    fn head_scans_a_large_input_in_linear_time() {
        let mut message = Message::request(operation::PRINT_JOB, 1);
        for i in 0..30_000 {
            message.add(
                tag::JOB_ATTRIBUTES,
                Attribute::new(format!("n{i}"), Value::Integer(i)),
            );
        }
        let bytes = message.to_bytes().unwrap();
        assert!(bytes.len() < MAX_HEAD);
        let started = std::time::Instant::now();
        contract::check_decode_with_alloc_limit(Head::new, &bytes, 2 * MAX_HEAD);
        assert_eq!(
            decode_all(Head::new, &bytes),
            (vec![Ok(Header::from(message))], None)
        );
        assert!(
            started.elapsed().as_secs() < 10,
            "took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn writers_refuse_values_that_would_change() {
        let big = "é".repeat(MAX_FIELD);
        for value in [
            Value::Text(big.clone()),
            Value::OctetString(vec![7; 70_000]),
            Value::TextWithLanguage {
                language: big.clone(),
                text: big.clone(),
            },
            Value::NameWithLanguage {
                language: "en".into(),
                name: big,
            },
            Value::Extension {
                tag: 1,
                data: vec![1; 70_000],
            },
            Value::Unknown {
                tag: 0x99,
                data: vec![1; 70_000],
            },
            Value::OutOfBand(0x21),
            Value::Unknown {
                tag: tag::INTEGER,
                data: vec![],
            },
            Value::Unknown {
                tag: tag::END_COLLECTION,
                data: vec![],
            },
            Value::Collection(vec![Attribute {
                name: "empty".into(),
                values: vec![],
            }]),
            Value::Collection(vec![Attribute::new("", Value::Integer(1))]),
            Value::Collection(vec![Attribute {
                name: "x".into(),
                values: vec![Value::OutOfBand(3), Value::Integer(5)],
            }]),
        ] {
            let mut message = Message::request(operation::PRINT_JOB, 1);
            message.add(tag::JOB_ATTRIBUTES, Attribute::new("x", value));
            assert_unwritable(&message);
        }
        for group in [
            Group {
                tag: 0x10,
                attributes: vec![],
            },
            Group {
                tag: tag::END_OF_ATTRIBUTES,
                attributes: vec![],
            },
            Group {
                tag: tag::JOB_ATTRIBUTES,
                attributes: vec![Attribute::new("", Value::Integer(1))],
            },
            Group {
                tag: tag::JOB_ATTRIBUTES,
                attributes: vec![Attribute {
                    name: "none".into(),
                    values: vec![],
                }],
            },
        ] {
            let mut message = Message::request(operation::PRINT_JOB, 1);
            message.groups.push(group);
            assert_unwritable(&message);
        }
        let mut message = Message::request(operation::PRINT_JOB, 1);
        for i in 0..40 {
            message.add(
                tag::JOB_ATTRIBUTES,
                Attribute::new(format!("o{i}"), Value::OctetString(vec![0; MAX_FIELD])),
            );
        }
        message.data = vec![5; 10];
        assert_unwritable(&message);
        let mut message = Message::request(operation::PRINT_JOB, 1);
        message.data = vec![0; MAX_DOCUMENT + 1];
        assert_unwritable(&message);
        let mut bytes = Message::request(operation::PRINT_JOB, 1)
            .to_bytes()
            .unwrap();
        bytes.extend_from_slice(&message.data);
        assert_eq!(Message::parse(&bytes), Err(ParseError::DocumentTooLong));
        bytes[8] = 0;
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::Head(Error::ReservedGroup))
        );
    }

    #[test]
    fn names() {
        assert_eq!(operation_name(0x000b), Some("Get-Printer-Attributes"));
        assert_eq!(operation_name(0x0001), None);
        assert_eq!(operation_by_name("Cancel-Job"), Some(operation::CANCEL_JOB));
        assert_eq!(status_name(0x0406), Some("client-error-not-found"));
        assert_eq!(status_name(0x0416), None);
        assert_eq!(status_by_name("server-error-busy"), Some(0x0507));
        assert!(!status::is_successful(status::CLIENT_ERROR_BAD_REQUEST));
        for (c, n) in OPERATION_NAMES {
            assert_eq!(operation_by_name(n), Some(*c));
        }
        for (c, n) in STATUS_NAMES {
            assert_eq!(status_by_name(n), Some(*c));
        }
        assert_eq!(tag_name(0x44), Some("keyword"));
        assert_eq!(tag_name(0x43), None);
        for t in 0x10..=0xffu8 {
            // Every value tag is named, out-of-band, or unknown.
            assert!(tag_name(t).is_some() || is_unknown_tag(t) || (0x10..=0x1f).contains(&t), "{t:#x}");
            assert!(!(tag_name(t).is_some() && is_unknown_tag(t)), "{t:#x}");
        }
    }

    /// The module documentation's example, with this file's paths.
    #[test]
    fn module_example() {
        fn answer(request: &Message) -> Message {
            match request.code {
                operation::GET_PRINTER_ATTRIBUTES => {
                    let mut reply = request.response(status::SUCCESSFUL_OK);
                    reply.add(tag::PRINTER_ATTRIBUTES, Attribute::new("printer-name", Value::Name("lobby".into())));
                    reply.add(tag::PRINTER_ATTRIBUTES, Attribute::new("printer-state", Value::Enum(3)));
                    reply
                }
                _ => request.response(status::SERVER_ERROR_OPERATION_NOT_SUPPORTED),
            }
        }
        let body = [
            &[1, 1, 0x00, 0x0b, 0, 0, 0, 7, tag::OPERATION_ATTRIBUTES][..],
            &[tag::CHARSET, 0, 18],
            b"attributes-charset",
            &[0, 5],
            b"utf-8",
            &[tag::NATURAL_LANGUAGE, 0, 27],
            b"attributes-natural-language",
            &[0, 2],
            b"en",
            &[tag::END_OF_ATTRIBUTES],
        ]
        .concat();
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&body), body.len());
        let request = stream
            .next()
            .unwrap()
            .unwrap()
            .unwrap()
            .with_document(Vec::new());
        assert_eq!(request.code, operation::GET_PRINTER_ATTRIBUTES);
        let charset = request.attribute(tag::OPERATION_ATTRIBUTES, "attributes-charset").unwrap();
        assert_eq!(charset.values, [Value::Charset("utf-8".into())]);
        let reply = answer(&request).to_bytes().unwrap();
        assert_eq!(&reply[..8], [1, 1, 0, 0, 0, 0, 0, 7]);
        let back = Message::parse(&reply).unwrap();
        let state = back.attribute(tag::PRINTER_ATTRIBUTES, "printer-state").unwrap();
        assert_eq!(state.values, [Value::Enum(3)]);
        // The request the example builds by hand is the one `request` makes.
        assert_eq!(
            Message::request(operation::GET_PRINTER_ATTRIBUTES, 7)
                .to_bytes()
                .unwrap(),
            body
        );
    }

    /// A head that exceeds the limit is refused with bounded allocation.
    #[test]
    fn stream_holds_a_bounded_head_without_polling() {
        let mut long = vec![1, 1, 0, 2, 0, 0, 0, 1, 1];
        while long.len() < 3 * MAX_HEAD {
            long.extend(rec(0x30, "a", &[0; 30000]));
        }
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&long), MAX_HEAD);
        assert_eq!(stream.push(&long), 0);
        assert_eq!(stream.next(), Some(Err(Fail::Protocol(Error::TooLong))));
        assert_eq!(stream.next(), None);
        contract::check_decode_with_alloc_limit(Head::new, &long, 2 * MAX_HEAD);
        let mut partial = vec![1, 1, 0, 2, 0, 0, 0, 1, 1];
        for _ in 0..30 {
            partial.extend(rec(0x30, "", &[0; 30000]));
        }
        assert_eq!(Head::new().decode(&partial, false), Ok(Step::Need));
        let mut bytes = print_job();
        bytes.extend_from_slice(b"more");
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&bytes), bytes.len());
        let header = stream.next().unwrap().unwrap().unwrap();
        assert_eq!(stream.next(), None);
        assert_eq!(
            header.with_document(stream.unread().to_vec()),
            Message::parse(&bytes).unwrap()
        );
    }

    /// RFC 8011 section 4.1.2: a response copies the request ID, so the
    /// decoder keeps it when the body is broken.
    #[test]
    fn head_errors_carry_the_request_id() {
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&[1, 1, 0, 2, 0, 0]), 6);
        assert_eq!(stream.next(), None);
        let mut bytes = vec![0, 42, 1];
        bytes.extend(rec(0x22, "a", &[2]));
        bytes.push(3);
        assert_eq!(stream.push(&bytes), bytes.len());
        assert_eq!(
            stream.next(),
            Some(Ok(Err(HeadError {
                request_id: 42,
                error: Error::BadValue(0x22)
            })))
        );
        assert_eq!(stream.next(), None);
    }

    /// RFC 8010 section 3.2 and RFC 8011 section 5.1.4: a name is at most
    /// 255 bytes of US-ASCII. CUPS takes any printable byte.
    #[test]
    fn names_are_printable_ascii() {
        let hdr = vec![1, 1, 0, 2, 0, 0, 0, 1, 1];
        let with = |parts: Vec<Vec<u8>>| Message::parse(&[vec![hdr.clone()], parts, vec![vec![3]]].concat().concat());
        for bad in ["x\0y", "a b", "é", &"a".repeat(MAX_NAME + 1)] {
            assert_eq!(
                with(vec![rec(0x44, bad, b"k")]),
                Err(ParseError::Head(Error::BadName)),
                "{bad:?}"
            );
            assert_eq!(
                with(vec![
                    rec(0x34, "c", b""),
                    rec(0x4a, "", bad.as_bytes()),
                    rec(0x21, "", &[0; 4]),
                    rec(0x37, "", b"")
                ]),
                Err(ParseError::Head(Error::BadName)),
                "{bad:?}"
            );
            // The writer refuses the attribute or member.
            let mut m = Message::request(operation::PRINT_JOB, 1);
            m.add(tag::JOB_ATTRIBUTES, Attribute::new(bad, Value::Integer(1)));
            m.add(
                tag::JOB_ATTRIBUTES,
                Attribute::new("c", Value::Collection(vec![Attribute::new(bad, Value::Integer(1))])),
            );
            assert_unwritable(&m);
        }
        let ok = "a".repeat(MAX_NAME);
        assert_eq!(with(vec![rec(0x44, &ok, b"k")]).unwrap().groups[0].attributes[0].name, ok);
    }

    /// RFC 8011 sections 5.1.5 and 5.1.16, and RFC 2579's DateAndTime.
    #[test]
    fn fixed_values_are_in_range() {
        let date = DateTime {
            year: 2026,
            month: 10,
            day: 5,
            hour: 13,
            minutes: 30,
            seconds: 60,
            deci_seconds: 9,
            direction: b'+',
            utc_hours: 14,
            utc_minutes: 59,
        };
        let bad = [
            Value::Enum(0),
            Value::Enum(-1),
            Value::Resolution { cross_feed: 0, feed: 300, units: 3 },
            Value::Resolution { cross_feed: 300, feed: -1, units: 3 },
            Value::Resolution { cross_feed: 300, feed: 300, units: 0 },
            Value::Resolution { cross_feed: 300, feed: 300, units: 5 },
            Value::DateTime(DateTime { month: 0, ..date }),
            Value::DateTime(DateTime { month: 13, ..date }),
            Value::DateTime(DateTime { day: 0, ..date }),
            Value::DateTime(DateTime { day: 32, ..date }),
            Value::DateTime(DateTime { hour: 24, ..date }),
            Value::DateTime(DateTime { minutes: 60, ..date }),
            Value::DateTime(DateTime { seconds: 61, ..date }),
            Value::DateTime(DateTime { deci_seconds: 10, ..date }),
            Value::DateTime(DateTime { direction: 0, ..date }),
            Value::DateTime(DateTime { utc_hours: 15, ..date }),
            Value::DateTime(DateTime { utc_minutes: 60, ..date }),
        ];
        for v in bad {
            // Written by hand, the reader refuses it.
            let mut bytes = vec![1, 1, 0, 2, 0, 0, 0, 1, 1];
            let mut value = Vec::new();
            match &v {
                Value::Enum(n) => value.extend(n.to_be_bytes()),
                Value::Resolution { cross_feed, feed, units } => {
                    value.extend(cross_feed.to_be_bytes());
                    value.extend(feed.to_be_bytes());
                    value.push(*units as u8);
                }
                Value::DateTime(d) => value.extend([
                    7,
                    234,
                    d.month,
                    d.day,
                    d.hour,
                    d.minutes,
                    d.seconds,
                    d.deci_seconds,
                    d.direction,
                    d.utc_hours,
                    d.utc_minutes,
                ]),
                _ => unreachable!(),
            }
            bytes.extend(rec(v.tag(), "x", &value));
            bytes.push(3);
            assert_eq!(
                Message::parse(&bytes),
                Err(ParseError::Head(Error::BadValue(v.tag()))),
                "{v:?}"
            );
            // The writer refuses it.
            let mut m = Message::request(operation::PRINT_JOB, 1);
            m.add(tag::JOB_ATTRIBUTES, Attribute { name: "x".into(), values: vec![v.clone(), Value::Integer(1)] });
            assert_unwritable(&m);
        }
        // The edges are kept.
        let mut m = Message::request(operation::PRINT_JOB, 1);
        let values = vec![
            Value::Enum(1),
            Value::Enum(i32::MAX),
            Value::Resolution { cross_feed: 1, feed: 1, units: 4 },
            Value::DateTime(date),
            Value::DateTime(DateTime {
                month: 1,
                day: 1,
                hour: 0,
                minutes: 0,
                seconds: 0,
                deci_seconds: 0,
                direction: b'-',
                utc_hours: 0,
                utc_minutes: 0,
                ..date
            }),
        ];
        m.add(tag::JOB_ATTRIBUTES, Attribute { name: "x".into(), values });
        assert_eq!(Message::parse(&m.to_bytes().unwrap()).unwrap(), m);
    }

    /// RFC 8010 section 3.5.1 reserves delimiter tag 0x00.
    #[test]
    fn reserved_group_tag() {
        let bytes = [
            vec![1, 1, 0, 2, 0, 0, 0, 1, 1],
            vec![0],
            rec(0x21, "a", &[0; 4]),
            vec![3],
        ]
        .concat();
        assert_eq!(
            Message::parse(&bytes),
            Err(ParseError::Head(Error::ReservedGroup))
        );
        assert_eq!(
            decode_all(Head::new, &bytes),
            (
                vec![Err(HeadError {
                    request_id: 1,
                    error: Error::ReservedGroup
                })],
                None
            )
        );
        let mut m = Message::request(operation::PRINT_JOB, 1);
        m.groups.push(Group { tag: 0, attributes: vec![Attribute::new("a", Value::Integer(1))] });
        assert_unwritable(&m);
        // Unassigned delimiter tags are kept, for groups defined later.
        let bytes = [vec![1, 1, 0, 2, 0, 0, 0, 1, 0x0b], rec(0x21, "a", &[0; 4]), vec![3]].concat();
        assert_eq!(Message::parse(&bytes).unwrap().groups[0].tag, 0x0b);
    }

    /// RFC 8011 section 4.1.4: one operation group, first.
    #[test]
    fn operation_attributes_stay_in_the_first_group() {
        let mut m = Message::request(operation::PRINT_JOB, 1);
        m.add(tag::JOB_ATTRIBUTES, Attribute::new("copies", Value::Integer(2)));
        m.add(tag::OPERATION_ATTRIBUTES, Attribute::new("job-name", Value::Name("a".into())));
        assert_eq!(m.groups.iter().map(|g| g.tag).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(m.groups[0].attributes[2].name, "job-name");
        let mut m = Message { version: (1, 1), code: 2, request_id: 1, groups: vec![], data: vec![] };
        m.add(tag::JOB_ATTRIBUTES, Attribute::new("copies", Value::Integer(2)));
        m.add(tag::OPERATION_ATTRIBUTES, Attribute::new("job-name", Value::Name("a".into())));
        assert_eq!(m.groups.iter().map(|g| g.tag).collect::<Vec<_>>(), [1, 2]);
        // Other groups still follow the order they are added in.
        m.add(tag::JOB_ATTRIBUTES, Attribute::new("sides", Value::Keyword("one-sided".into())));
        m.add(tag::PRINTER_ATTRIBUTES, Attribute::new("p", Value::Integer(1)));
        m.add(tag::JOB_ATTRIBUTES, Attribute::new("q", Value::Integer(1)));
        assert_eq!(m.groups.iter().map(|g| g.tag).collect::<Vec<_>>(), [1, 2, 4, 2]);
    }

    fn assert_unwritable<M: Wire<WriteError = Error> + PartialEq + std::fmt::Debug>(value: &M) {
        contract::check_wire_value(value);
        let mut out = b"prefix".to_vec();
        assert_eq!(value.write(&mut out), Err(Error::Unwritable));
        assert_eq!(out, b"prefix");
    }

    #[test]
    fn framing_failure_keeps_request_id_for_bad_request_reply() {
        let bytes = b"\x01\x01\0\x02\0\0\0\x2a\x01\x41\xff\xff";
        let mut stream = Stream::new(Head::new());
        assert_eq!(stream.push(&bytes[..8]), 8);
        assert_eq!(stream.next(), None);
        assert_eq!(stream.push(&bytes[8..]), bytes.len() - 8);
        assert_eq!(
            stream.next(),
            Some(Err(Fail::Protocol(Error::Length(0xffff))))
        );
        let fixed = stream.unread().first_chunk::<8>().unwrap();
        let request_id = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        assert_eq!(request_id, 42);
        let reply = Message::request(operation::PRINT_JOB, request_id)
            .response(status::CLIENT_ERROR_BAD_REQUEST);
        assert_eq!(Message::parse(&reply.to_bytes().unwrap()), Ok(reply));
        check(bytes);
    }

    /// Checks everything the fuzz target checks, for one buffer.
    fn check(data: &[u8]) {
        contract::check_decode_with_alloc_limit(Head::new, data, 2 * MAX_HEAD);
        contract::check_wire::<Header>(data);
        contract::check_wire::<Message>(data);
        let (items, failure) = decode_all(Head::new, data);
        match Message::parse(data) {
            Ok(message) => {
                assert_eq!((items, failure), (vec![Ok(Header::from(message))], None));
            }
            Err(ParseError::DocumentTooLong) => {
                let end = scan_head(data, &mut 0, MAX_HEAD).unwrap().unwrap();
                assert_eq!(
                    (items, failure),
                    (vec![Ok(Header::parse(&data[..end]).unwrap())], None)
                );
            }
            Err(ParseError::Truncated) => {
                assert!(items.is_empty());
                assert_eq!(
                    failure,
                    (!data.is_empty()).then_some(Fail::Truncated { unread: data.len() })
                );
            }
            Err(ParseError::Head(error @ (Error::Length(_) | Error::TooLong))) => {
                assert!(items.is_empty());
                assert_eq!(failure, Some(Fail::Protocol(error)));
            }
            Err(ParseError::Head(error)) => {
                let fixed = data.first_chunk::<8>().unwrap();
                let request_id = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
                assert_eq!(
                    (items, failure),
                    (vec![Err(HeadError { request_id, error })], None)
                );
            }
            Err(ParseError::Trailing) => panic!("a message includes its document"),
        }
        let mut stream = Stream::new(Head::new());
        let _ = stream.push(data);
        stream.end();
        let item = stream.next();
        if let Some(fixed) = data.first_chunk::<8>() {
            let expected = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
            let request_id = match item {
                Some(Ok(Ok(header))) => header.request_id,
                Some(Ok(Err(error))) => error.request_id,
                _ => {
                    let fixed = stream.unread().first_chunk::<8>().unwrap();
                    u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]])
                }
            };
            assert_eq!(request_id, expected);
        }
    }

    #[test]
    fn lcg_fuzz() {
        let mut rng = Lcg::new(0x1bb_631);
        let seeds = [
            print_job(),
            media_col(),
            Message::request(2, 9).to_bytes().unwrap(),
        ];
        let mut full = Message::request(operation::PRINT_JOB, 3);
        full.add(tag::JOB_ATTRIBUTES, Attribute { name: "all".into(), values: every_value() });
        let seeds = [seeds.to_vec(), vec![full.to_bytes().unwrap()]].concat();
        let mut parsed = 0;
        for i in 0..6000 {
            let mut buf = if i % 4 == 0 {
                rng.bytes(64)
            } else {
                seeds[rng.index(seeds.len())].clone()
            };
            for _ in 0..rng.index(6) {
                mutate(&mut rng, &mut buf);
                let tags = [0, 3, 0x34, 0x37, 0x4a, 0x7f, 0x80];
                let at = rng.index(buf.len() + 1);
                buf.insert(at, tags[rng.index(tags.len())]);
            }
            if Message::parse(&buf).is_ok() {
                parsed += 1;
            }
            check(&buf);
        }
        // Mutations keep enough messages whole to test the round trip.
        assert!(parsed > 500, "{parsed}");
        // Random messages, written and read back.
        for _ in 0..2000 {
            let mut m = Message {
                version: (2, 0),
                code: rng.next() as u16,
                request_id: rng.next() as u32,
                groups: vec![],
                data: vec![],
            };
            for _ in 0..rng.index(4) {
                let mut attributes = Vec::new();
                for j in 0..rng.index(4) {
                    let all = every_value();
                    let values = (0..1 + rng.index(3)).map(|_| all[rng.index(all.len())].clone()).collect();
                    attributes.push(Attribute { name: format!("a{j}"), values });
                }
                m.groups.push(Group {
                    tag: [1, 2, 4, 5, 0x0b, 0x0f][rng.index(6)],
                    attributes,
                });
            }
            m.data = rng.bytes(8);
            let bytes = m.to_bytes().unwrap();
            assert_eq!(Message::parse(&bytes).unwrap(), m);
            check(&bytes);
        }
    }
}
