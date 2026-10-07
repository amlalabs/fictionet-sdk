//! RESP (Redis) commands and values through the shared codec driver.

use fictionet::stdlib::codec::{
    Decode, Fail, Lcg, Stream, Wire, contract, finish, pump,
    test_support::{decode_all, mutate},
};
use fictionet::stdlib::resp;

const RESP_LIMIT: usize = 128;

fn resp_limits() -> resp::Limits {
    resp::Limits {
        frame: RESP_LIMIT,
        ..resp::Limits::DEFAULT
    }
}

#[test]
fn resp_requests_and_replies() {
    let command = resp::Command::new(["SET", "key", "value"]);
    let mut input = b"\r\n*0\r\n".to_vec();
    Wire::write(&command, &mut input).unwrap();
    input.extend_from_slice(b"GET key\n");
    let expected = [command, resp::Command::new(["GET", "key"])];
    contract::check_decode_with_alloc_limit(
        || resp::Commands::with_limits(resp_limits()),
        &input,
        2 * RESP_LIMIT,
    );
    let (commands, error) = decode_all(|| resp::Commands::with_limits(resp_limits()), &input);
    assert_eq!(error, None);
    assert_eq!(commands, expected);
    let mut replies = Vec::new();
    for command in commands {
        let request = Wire::to_bytes(&command).unwrap();
        contract::check_wire::<resp::Command>(&request);
        assert_eq!(
            <resp::Command as Wire>::parse(&request),
            Ok(command.clone())
        );
        let reply = if command.is("SET") {
            resp::Value::ok()
        } else {
            resp::Value::bulk("value")
        };
        Wire::write(&reply, &mut replies).unwrap();
    }
    contract::check_decode_with_alloc_limit(
        || resp::Values::with_limits(resp_limits()),
        &replies,
        2 * RESP_LIMIT,
    );
    let (values, error) = decode_all(|| resp::Values::with_limits(resp_limits()), &replies);
    assert_eq!(error, None);
    assert_eq!(values, [resp::Value::ok(), resp::Value::bulk("value")]);
    for value in values {
        let bytes = Wire::to_bytes(&value).unwrap();
        contract::check_wire::<resp::Value>(&bytes);
        assert_eq!(<resp::Value as Wire>::parse(&bytes), Ok(value));
    }
}

#[test]
fn resp_limits_and_terminal_errors() {
    assert_eq!(resp::Values::new().capacity(), resp::MAX_FRAME_LEN);
    assert_eq!(resp::Commands::new().capacity(), resp::MAX_FRAME_LEN);
    let limits = resp::Limits {
        frame: 16,
        ..resp::Limits::DEFAULT
    };
    let bytes = vec![b'+'; limits.frame + 1];
    let mut commands = Stream::new(resp::Commands::with_limits(limits));
    assert_eq!(commands.push(&bytes), limits.frame);
    assert_eq!(
        commands.next(),
        Some(Err(Fail::Protocol(resp::ParseError::FrameTooLarge)))
    );
    assert!(commands.next().is_none());
    let mut values = Stream::new(resp::Values::with_limits(limits));
    assert_eq!(values.push(&bytes), limits.frame);
    assert_eq!(
        values.next(),
        Some(Err(Fail::Protocol(resp::ParseError::FrameTooLarge)))
    );
    assert!(values.next().is_none());
    for bytes in [&b"+OK\r\n$9\r\nabc"[..], b"+OK\r\n:bad\r\n+later\r\n"] {
        contract::check_decode_with_alloc_limit(
            resp::Values::new,
            bytes,
            2 * resp::Values::new().capacity(),
        );
        let (values, error) = decode_all(resp::Values::new, bytes);
        assert_eq!(values, [resp::Value::ok()]);
        assert_eq!(
            error,
            Some(if bytes.ends_with(b"abc") {
                Fail::Truncated { unread: 7 }
            } else {
                Fail::Protocol(resp::ParseError::Malformed(b':'))
            })
        );
    }
    let bytes = b"PING\r\n*1\r\n+bad\r\nGET x\r\n";
    contract::check_decode_with_alloc_limit(
        resp::Commands::new,
        bytes,
        2 * resp::Commands::new().capacity(),
    );
    assert_eq!(
        decode_all(resp::Commands::new, bytes),
        (
            vec![resp::Command::new(["PING"])],
            Some(Fail::Protocol(resp::ParseError::ExpectedBulk(b'+'))),
        )
    );
    for limit in [0, 1, 2, 3, 4, 16, usize::MAX] {
        let limits = resp::Limits {
            frame: limit,
            ..resp::Limits::DEFAULT
        };
        let make = || resp::Values::with_limits(limits);
        assert!(make().capacity() <= resp::MAX_FRAME_LEN);
        contract::check_decode_with_alloc_limit(make, b"_\r\n+tail", 2 * make().capacity());
        contract::check_decode_with_alloc_limit(
            || resp::Commands::with_limits(limits),
            b"\n*0\r\nPING\n",
            2 * (resp::Commands::with_limits(limits)).capacity(),
        );
    }
}

#[test]
fn resp_strict_writers_preserve_types_and_roll_back() {
    let values = [
        resp::Value::NullArray,
        resp::Value::Array(vec![resp::Value::NullArray, resp::Value::Null]),
        resp::Value::Attribute {
            attributes: vec![(resp::Value::simple("meta"), resp::Value::Integer(1))],
            value: Box::new(resp::Value::Push(vec![
                resp::Value::bulk("message"),
                resp::Value::NullArray,
            ])),
        },
        resp::Value::Verbatim {
            format: *b"txt",
            text: b"hello\nworld".to_vec(),
        },
        resp::Value::Set(vec![resp::Value::Boolean(true), resp::Value::Double(1.5)]),
        resp::Value::Map(vec![(
            resp::Value::BigNumber("+123".into()),
            resp::Value::BulkError(vec![0, 255]),
        )]),
    ];
    for value in values {
        contract::check_wire_value(&value);
        let bytes = Wire::to_bytes(&value).unwrap();
        contract::check_wire::<resp::Value>(&bytes);
        contract::check_decode_with_alloc_limit(
            resp::Values::new,
            &bytes,
            2 * resp::Values::new().capacity(),
        );
    }
    for value in [
        resp::Value::simple("a\nb"),
        resp::Value::BigNumber("not a number".into()),
        resp::Value::Push(vec![]),
        resp::Value::Array(vec![resp::Value::Push(vec![resp::Value::simple("bad")])]),
        resp::Value::simple(vec![b'x'; resp::MAX_LINE_LEN + 1]),
    ] {
        contract::check_wire_value(&value);
        let mut out = b"prefix".to_vec();
        assert_eq!(
            Wire::write(&value, &mut out),
            Err(resp::WireError::Unwritable)
        );
        assert_eq!(out, b"prefix");
    }
    let mut deep = resp::Value::Null;
    for _ in 0..resp::MAX_DEPTH + 1 {
        deep = resp::Value::Array(vec![deep]);
    }
    assert_eq!(Wire::to_bytes(&deep), Err(resp::WireError::Unwritable));
    let command = resp::Command {
        args: vec![vec![0; resp::MAX_BULK_LEN + 1]],
    };
    contract::check_wire_value(&command);
    assert_eq!(Wire::to_bytes(&command), Err(resp::WireError::Unwritable));
    assert_eq!(
        <resp::Value as Wire>::parse(b"+OK\r\n+more\r\n"),
        Err(resp::WireError::Trailing)
    );
    assert_eq!(
        <resp::Value as Wire>::parse(b"+OK\r"),
        Err(resp::WireError::Incomplete)
    );
    assert_eq!(
        <resp::Command as Wire>::parse(b"PING\nGET x\n"),
        Err(resp::WireError::Trailing)
    );
    contract::check_wire::<resp::Command>(b"\r\n");
    // NaN is not reflexive under Value's existing PartialEq. Its wire form is.
    let bytes = Wire::to_bytes(&resp::Value::Double(f64::NAN)).unwrap();
    assert_eq!(bytes, b",nan\r\n");
    let resp::Value::Double(n) = <resp::Value as Wire>::parse(&bytes).unwrap() else {
        panic!()
    };
    assert!(n.is_nan());
    assert_eq!(Wire::to_bytes(&resp::Value::Double(n)).unwrap(), bytes);
}

#[test]
fn resp_scan_resumes_across_lines_and_aggregates() {
    let mut bytes = b"*?\r\n$?\r\n".to_vec();
    bytes.extend_from_slice(&b";1\r\nx\r\n".repeat(4096));
    bytes.extend_from_slice(b";0\r\n+");
    bytes.extend(std::iter::repeat_n(b'y', resp::MAX_LINE_LEN));
    bytes.extend_from_slice(b"\r\n.\r\n");
    contract::check_decode_with_alloc_limit(resp::Values::new, &bytes, 2 * resp::MAX_FRAME_LEN);
    let (values, error) = decode_all(resp::Values::new, &bytes);
    assert_eq!(error, None);
    assert_eq!(
        values,
        [resp::Value::Array(vec![
            resp::Value::bulk(vec![b'x'; 4096]),
            resp::Value::simple(vec![b'y'; resp::MAX_LINE_LEN]),
        ])]
    );
    let mut stream = Stream::new(resp::Commands::new());
    let command = resp::Command {
        args: vec![vec![b'z'; 1]; 4096],
    };
    let bytes = Wire::to_bytes(&command).unwrap();
    contract::check_decode_with_alloc_limit(resp::Commands::new, &bytes, 2 * resp::MAX_FRAME_LEN);
    let mut got = Vec::new();
    pump(&mut stream, &bytes, |c| got.push(c)).unwrap();
    finish(&mut stream, |c| got.push(c)).unwrap();
    assert_eq!(got, [command]);
}

#[test]
fn small_resp_capacity_drains_a_long_pipeline() {
    let limits = resp::Limits {
        frame: 4,
        ..resp::Limits::DEFAULT
    };
    let bytes = b"_\r\n".repeat(100);
    contract::check_decode_with_alloc_limit(|| resp::Values::with_limits(limits), &bytes, 8);
    assert_eq!(
        decode_all(|| resp::Values::with_limits(limits), &bytes),
        (vec![resp::Value::Null; 100], None)
    );
}

#[test]
fn resp_contracts_on_mutated_values() {
    let mut rng = Lcg::new(0x5eed);
    let seed = b"|1\r\n+k\r\n%?\r\n+a\r\n:1\r\n.\r\n>2\r\n+event\r\n*?\r\n$?\r\n;1\r\nx\r\n;0\r\n*-1\r\n.\r\n";
    for _ in 0..64 {
        let mut bytes = seed.to_vec();
        for _ in 0..rng.index(4) {
            mutate(&mut rng, &mut bytes);
        }
        let end = rng.index(bytes.len() + 1);
        bytes.truncate(end);
        // Compare strict encodings so NaN retains its wire equality.
        contract::check_decode_with_alloc_limit(
            || resp::Values::new().map(|v| Wire::to_bytes(&v)),
            &bytes,
            2 * (resp::Values::new().map(|v| Wire::to_bytes(&v))).capacity(),
        );
        contract::check_decode_with_alloc_limit(
            resp::Commands::new,
            &bytes,
            2 * resp::Commands::new().capacity(),
        );
    }
}
