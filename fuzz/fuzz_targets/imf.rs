//! Internet Message Format headers and structured field values.
#![no_main]

use fictionet::stdlib::codec::{Fail, Stream, Wire, contract, test_support::decode_all};
use fictionet::stdlib::imf::{
    Address, AddressList, DateTime, ENCODED_LINE_LEN, EncodedText, Error, FOLD_AT, Head, Header,
    MAX_FIELDS, MAX_HEADER_BYTES, MAX_LINE_BYTES, MAX_MESSAGE_IDS, MAX_VALUE_BYTES, Mailbox,
    MessageId, MessageIds, decode_text, parse_address_list, parse_message_ids, split_message,
};
use libfuzzer_sys::fuzz_target;

fn is_control(c: char) -> bool {
    c.is_ascii_control() && c != '\t'
}

// Count RFC 2047 wrappers, base64 quartets, and separators at UTF-8 boundaries.
fn encoded_size(text: &str) -> usize {
    let mut size = 0usize;
    let mut chunk = 0usize;
    for c in text.chars() {
        if chunk + c.len_utf8() > 48 {
            size = size.saturating_add(12 + 4 * chunk.div_ceil(3));
            chunk = 0;
        }
        chunk += c.len_utf8();
    }
    size.saturating_add(if chunk == 0 {
        0
    } else {
        11 + 4 * chunk.div_ceil(3)
    })
}

fn atom(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(c) || !c.is_ascii()
}

fn quoted_size(text: &str) -> usize {
    text.len()
        .saturating_add(2)
        .saturating_add(text.matches(['"', '\\']).count())
}

fn phrase_size(text: &str) -> usize {
    if text.contains(is_control) {
        encoded_size(text)
    } else if !text.is_empty()
        && !text.contains("=?")
        && text
            .split(' ')
            .all(|word| !word.is_empty() && word.chars().all(atom))
    {
        text.len()
    } else {
        quoted_size(text)
    }
}

fn mailbox_size(mailbox: &Mailbox) -> usize {
    let local = &mailbox.local;
    let local_size = if !local.is_empty()
        && local
            .split('.')
            .all(|word| !word.is_empty() && word.chars().all(atom))
    {
        local.len()
    } else {
        quoted_size(local)
    };
    local_size
        .saturating_add(1)
        .saturating_add(mailbox.domain.len())
        .saturating_add(
            mailbox
                .name
                .as_ref()
                .map_or(0, |s| phrase_size(s).saturating_add(3)),
        )
}

fn address_list_size(list: &[Address]) -> usize {
    list.iter().fold(
        list.len().saturating_sub(1).saturating_mul(2),
        |n, address| {
            n.saturating_add(match address {
                Address::Mailbox(mailbox) => mailbox_size(mailbox),
                Address::Group { name, members } => members.iter().fold(
                    phrase_size(name)
                        .saturating_add(2)
                        .saturating_add(members.len().saturating_sub(1).saturating_mul(2)),
                    |n, mailbox| n.saturating_add(mailbox_size(mailbox)),
                ),
            })
        },
    )
}

// Count fold positions and line lengths without producing wire bytes.
fn folded_size(name: &str, value: &str) -> (usize, usize) {
    let v = value.as_bytes();
    let whitespace = |c: u8| matches!(c, b' ' | b'\t');
    let limit = if value.contains("=?") {
        ENCODED_LINE_LEN
    } else {
        FOLD_AT
    };
    let first = v.iter().position(|&c| whitespace(c)).unwrap_or(v.len());
    let mut used = name.len() + 2;
    let mut size = used.saturating_add(v.len()).saturating_add(2);
    let mut longest = 0;
    if used + first > limit && first < limit {
        longest = name.len() + 1;
        size = size.saturating_add(2);
        used = 1;
    }
    let last = v.iter().rposition(|&c| !whitespace(c)).unwrap_or(0);
    let mut breaks = Vec::new();
    let (mut text, mut escaped) = (false, false);
    for (i, &c) in v.iter().enumerate().take(last) {
        if whitespace(c) && text && !escaped {
            breaks.push(i);
        }
        text |= !whitespace(c);
        escaped = c == b'\\' && !escaped;
    }
    let mut breaks = breaks.into_iter().peekable();
    let mut start = 0;
    while used + v.len() - start > limit {
        let text_start = start
            + v[start..]
                .iter()
                .position(|&c| !whitespace(c))
                .unwrap_or(v.len() - start);
        while breaks.peek().is_some_and(|&next| next <= text_start) {
            breaks.next();
        }
        let mut chosen = breaks.next();
        while breaks
            .peek()
            .is_some_and(|&next| used + next - start <= limit)
        {
            chosen = breaks.next();
        }
        let Some(next) = chosen else { break };
        longest = longest.max(used + next - start);
        size = size.saturating_add(2);
        start = next;
        used = 0;
    }
    (size, longest.max(used + v.len() - start))
}

fuzz_target!(|data: &[u8]| {
    contract::check_decode_with_alloc_limit(Head::new, data, 2 * MAX_HEADER_BYTES);
    contract::check_decode_with_alloc_limit(|| Head::with_limit(64), data, 128);
    contract::check_wire::<Header>(data);
    let (items, failure) = decode_all(Head::new, data);
    let mut values = vec![String::from_utf8_lossy(data).into_owned()];
    match split_message(data) {
        Err(error) => {
            assert!(items == [Err(error)] || failure == Some(Fail::Protocol(error)));
        }
        Ok((header, body)) => {
            assert_eq!(
                (items, failure),
                (
                    if data.is_empty() {
                        vec![]
                    } else {
                        vec![Ok(header.clone())]
                    },
                    None
                )
            );
            if !data.is_empty() {
                let mut stream = Stream::with_buffer(Head::new(), data.len());
                assert_eq!(stream.push(data), data.len());
                stream.end();
                assert_eq!(stream.next(), Some(Ok(Ok(header.clone()))));
                assert_eq!(stream.unread(), body);
            }
            contract::check_wire_value(&header);
            if let Err(Error::Unwritable) = header.to_bytes() {
                let sizes: Vec<_> = header
                    .fields
                    .iter()
                    .map(|f| folded_size(&f.name, &f.value))
                    .collect();
                assert!(
                    header.fields.iter().any(|f| f.value.contains(is_control))
                        || header.fields.len() > MAX_FIELDS
                        || sizes
                            .iter()
                            .fold(2usize, |n, (size, _)| n.saturating_add(*size))
                            > MAX_HEADER_BYTES
                        || sizes.iter().any(|(_, line)| *line > MAX_LINE_BYTES)
                );
            }
            values.extend(header.fields.into_iter().map(|field| field.value));
        }
    }
    for text in values {
        contract::check_wire::<Mailbox>(text.as_bytes());
        contract::check_wire::<Address>(text.as_bytes());
        contract::check_wire::<AddressList>(text.as_bytes());
        contract::check_wire::<DateTime>(text.as_bytes());
        contract::check_wire::<MessageId>(text.as_bytes());
        contract::check_wire::<MessageIds>(text.as_bytes());
        contract::check_wire::<EncodedText>(text.as_bytes());
        let value = EncodedText(text.clone());
        contract::check_wire_value(&value);
        let result = value.to_bytes();
        if !text.contains(['\0', '\r', '\n']) && encoded_size(&text) <= MAX_VALUE_BYTES {
            assert!(result.is_ok(), "{text:?}");
        }
        if let Ok(bytes) = result {
            let encoded = String::from_utf8(bytes).unwrap();
            assert_eq!(decode_text(&encoded), text);
            let mut header = Header::default();
            header.push("Subject", &encoded);
            contract::check_wire_value(&header);
            if let Ok(bytes) = header.to_bytes() {
                assert!(
                    bytes
                        .split(|&c| c == b'\n')
                        .all(|line| line.len() <= ENCODED_LINE_LEN + 1)
                );
            }
        }
        if let Ok(list) = parse_address_list(&text) {
            let list = AddressList(list);
            contract::check_wire_value(&list);
            if let Err(Error::Unwritable) = list.to_bytes() {
                assert!(
                    text.contains(is_control)
                        || text.contains('\\')
                        || address_list_size(&list.0) > MAX_VALUE_BYTES,
                    "{text:?}"
                );
            }
        }
        if let Ok(ids) = parse_message_ids(&text) {
            let ids = MessageIds(ids);
            contract::check_wire_value(&ids);
            if let Err(Error::Unwritable) = ids.to_bytes() {
                let parts: Result<Vec<_>, _> = ids.0.iter().map(Wire::to_bytes).collect();
                assert!(
                    parts.is_err()
                        || ids.0.len() > MAX_MESSAGE_IDS
                        || parts
                            .unwrap()
                            .iter()
                            .fold(ids.0.len().saturating_sub(1), |n, b| n
                                .saturating_add(b.len()))
                            > MAX_VALUE_BYTES,
                    "{text:?}"
                );
            }
        }
        let mut header = Header::default();
        header.push("Subject", &text);
        contract::check_wire_value(&header);
    }
    let mut body = Header::default().to_bytes().unwrap();
    body.extend_from_slice(data.get(..4096).unwrap_or(data));
    contract::check_decode_with_alloc_limit(|| Head::with_limit(64), &body, 128);
});
