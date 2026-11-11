//! Dynamic QPACK resource replay and compression measurements.
//! The workloads are synthetic HTTP field sets, not production captures.

#[path = "../verification/resources/alloc.rs"]
mod alloc;
#[path = "../verification/resources/cost.rs"]
mod cost;

use cost::{Charged, Costs, Linear};
use fictionet::stdlib::codec::Wire;
use fictionet::stdlib::protocols::qpack::{
    self, DecoderInstruction, Encoder, EncoderInstruction, Field, Policy, SectionResult, Selective,
    Style, Table,
};

#[test]
fn table_instructions_stay_within_table_and_scratch_reservations() {
    let mut total = Costs::new("qpack-table");
    for capacity in [0, 31, 32, 37, 128, 4096, 65536] {
        let mut costs = Costs::new(format!("qpack-table-{capacity}"));
        let mut table = Table::new(capacity);
        let charge = table.most_held();
        // A parsed instruction can hold two expanded MAX_STRING strings;
        // applying it can copy two table strings before eviction. This is
        // below the HTTP/3 connection's existing synchronous scratch reserve.
        let scratch = 4 * qpack::MAX_STRING;
        let mut instructions = vec![EncoderInstruction::SetCapacity(capacity)];
        instructions.push(EncoderInstruction::InsertWithNameRef {
            static_table: true,
            index: 35,
            value: vec![],
        });
        for length in [0, 1, 5, 80, 4000, 64000] {
            instructions.push(EncoderInstruction::InsertWithLiteralName {
                name: b"x-cache-key".to_vec(),
                value: vec![b'a'; length],
            });
            instructions.push(EncoderInstruction::Duplicate(0));
            instructions.push(EncoderInstruction::InsertWithNameRef {
                static_table: false,
                index: 0,
                value: b"next".to_vec(),
            });
        }
        // Force slot growth, evictions, and a fall that retains those slots.
        for _ in 0..140 {
            instructions.push(EncoderInstruction::InsertWithLiteralName {
                name: vec![],
                value: vec![],
            });
        }
        instructions.push(EncoderInstruction::SetCapacity(0));
        instructions.push(EncoderInstruction::SetCapacity(capacity));
        for instruction in instructions {
            let bytes = instruction.to_bytes().unwrap();
            costs.step(
                bytes.len(),
                charge + scratch,
                Linear {
                    // Huffman expansion <= 8/5, copied names <= capacity.
                    // The fixed term pays table-name duplication and slot growth,
                    // plus a static name copied even when capacity is zero.
                    num: 4,
                    den: 1,
                    fixed: 2 * charge
                        + qpack::STATIC_TABLE
                            .iter()
                            .map(|(name, _)| name.len())
                            .max()
                            .unwrap(),
                },
                || {
                    let parsed = EncoderInstruction::parse(&bytes).unwrap();
                    let _ = table.apply(parsed);
                    Charged::new((), 0)
                },
            );
            assert!(costs.live() <= table.held());
            assert!(table.held() <= charge);
            assert!(table.size() <= table.capacity());
        }
        total.absorb(&costs);
    }
    total.print();
}

#[test]
fn pending_duplicate_preserves_an_acknowledged_match() {
    let mut encoder = Encoder::new(4096, qpack::MAX_FIELD_SECTION_SIZE);
    let mut decoder = Table::new(4096);
    decoder.apply(encoder.set_capacity(4096).unwrap()).unwrap();
    let (index, instruction) = encoder.insert(b"server", b"fictionet").unwrap();
    decoder.apply(instruction).unwrap();
    encoder
        .apply_instruction(decoder.take_increment().unwrap())
        .unwrap();
    let (_, duplicate) = encoder.duplicate(index).unwrap();
    let fields = [Field::new("server", "fictionet")];
    let bytes = encoder.section(0, &fields).unwrap().to_bytes().unwrap();
    let SectionResult::Fields {
        fields: decoded,
        ack,
    } = qpack::decode_section(&decoder, 0, &bytes).unwrap()
    else {
        panic!("an acknowledged match must not block");
    };
    assert_eq!(decoded, fields);
    assert!(ack.is_some(), "the older dynamic entry remains usable");
    encoder.apply_instruction(ack.unwrap()).unwrap();
    decoder.apply(duplicate).unwrap();
}

#[test]
fn warm_policy_excludes_sensitive_changing_and_static_fields() {
    let mut encoder = Encoder::new(4096, qpack::MAX_FIELD_SECTION_SIZE);
    encoder.set_capacity(4096).unwrap();
    for field in [
        Field::new("authorization", "Bearer secret"),
        Field::new("set-cookie", "sid=secret"),
        Field::new("date", "Wed, 11 Nov 2026 12:00:00 GMT"),
        Field::new("content-length", "100"),
        Field::new("content-type", "application/json"),
    ] {
        assert!(encoder.warm(&field, &Selective).is_none());
    }
    let mut field = Field::new("server", "private");
    field.never_index = true;
    assert!(encoder.warm(&field, &Selective).is_none());
    assert!(encoder.warm(&field, &Every).is_none());
    field.never_index = false;
    assert!(encoder.warm(&field, &Selective).is_some());
    assert!(encoder.warm(&field, &Every).is_none());
    let bytes = encoder.section(0, &[field]).unwrap().to_bytes().unwrap();
    assert_eq!(
        bytes[0], 0,
        "unacknowledged insert cannot block the response"
    );
}

#[test]
fn advertised_limits_are_representable_and_bounded() {
    assert!(qpack::Settings::new(65536, 100).is_some());
    assert!(qpack::Settings::new(4096, 128).is_some());
    assert!(qpack::Settings::new(65537, 16).is_none());
    assert!(qpack::Settings::new(4096, 257).is_none());
}

/// Never uses the dynamic table.
struct StaticOnly;
impl Policy for StaticOnly {
    fn capacity(&self, _: u64) -> u64 {
        0
    }
    fn insert(&self, _: &Field, _: &Table) -> bool {
        false
    }
    fn style(&self) -> Style {
        Style::DEFAULT
    }
}

/// Inserts every field the encoder's shared rules allow.
struct Every;
impl Policy for Every {
    fn capacity(&self, peer_max: u64) -> u64 {
        peer_max
    }
    fn insert(&self, _: &Field, _: &Table) -> bool {
        true
    }
    fn style(&self) -> Style {
        Style::DEFAULT
    }
}

#[derive(Default, Debug)]
struct Bytes {
    sections: usize,
    instructions: usize,
    feedback: usize,
    cold: usize,
    warm: usize,
}

fn measure(workload: &[Vec<Field>], policy: &dyn Policy, feedback_every: usize) -> Bytes {
    let capacity = policy.capacity(4096).min(4096);
    let mut encoder = Encoder::new(capacity, qpack::MAX_FIELD_SECTION_SIZE);
    let mut decoder = Table::new(capacity);
    let mut bytes = Bytes::default();
    if capacity != 0 {
        let instruction = encoder.set_capacity(capacity).unwrap();
        bytes.instructions += instruction.to_bytes().unwrap().len();
        decoder.apply(instruction).unwrap();
    }
    let mut feedback = Vec::new();
    for (i, fields) in workload.iter().enumerate() {
        for field in fields {
            if let Some(instruction) = encoder.warm(field, policy) {
                bytes.instructions += instruction.to_bytes().unwrap().len();
                decoder.apply(instruction).unwrap();
            }
        }
        let encoded = encoder
            .section(i as u64 * 4, fields)
            .unwrap()
            .to_bytes()
            .unwrap();
        if i == 0 {
            bytes.cold = encoded.len();
        }
        bytes.warm = encoded.len();
        bytes.sections += encoded.len();
        let SectionResult::Fields {
            fields: decoded,
            ack,
        } = qpack::decode_section(&decoder, i as u64 * 4, &encoded).unwrap()
        else {
            panic!("ACK-only encoding must never block");
        };
        assert_eq!(&decoded, fields);
        if let Some(ack) = ack {
            feedback.push(ack);
        }
        if let Some(increment) = decoder.take_increment() {
            feedback.push(increment);
        }
        if (i + 1) % feedback_every == 0 || i + 1 == workload.len() {
            for instruction in feedback.drain(..) {
                bytes.feedback += instruction.to_bytes().unwrap().len();
                encoder.apply_instruction(instruction).unwrap();
            }
        }
        assert!(encoder.held() <= encoder.most_held());
    }
    bytes
}

fn browser(i: usize) -> Vec<Field> {
    vec![
        Field::new(":method", "GET"),
        Field::new(":scheme", "https"),
        Field::new(":authority", "shop.example.test"),
        Field::new(":path", format!("/assets/app.js?version={i}")),
        Field::new("accept", "*/*"),
        Field::new("accept-encoding", "gzip, deflate, br"),
        Field::new(
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        ),
        Field::new("accept-language", "en-US,en;q=0.9"),
        Field::new("sec-fetch-dest", "script"),
        Field::new("sec-fetch-mode", "no-cors"),
        Field::new("sec-fetch-site", "same-origin"),
    ]
}

fn response(i: usize) -> Vec<Field> {
    vec![
        Field::new(":status", "200"),
        Field::new("server", "nginx/1.26.2"),
        Field::new("content-type", "text/html; charset=UTF-8"),
        Field::new(
            "cache-control",
            "public, max-age=300, stale-while-revalidate=60",
        ),
        Field::new("vary", "Accept-Encoding"),
        Field::new("content-encoding", "br"),
        Field::new(
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        ),
        Field::new(
            "content-security-policy",
            "default-src 'self'; img-src 'self' data:; script-src 'self' https://cdn.example.test",
        ),
        Field::new("date", format!("Wed, 11 Nov 2026 12:00:{i:02} GMT")),
        Field::new("etag", format!("\"asset-{i:08x}\"")),
        Field::new("content-length", (12000 + i).to_string()),
    ]
}

fn api(i: usize) -> Vec<Field> {
    let mut auth = Field::new(
        "authorization",
        "Bearer eyJhbGciOiJSUzI1NiJ9.synthetic-session-token",
    );
    auth.never_index = true;
    vec![
        Field::new(":method", "POST"),
        Field::new(":scheme", "https"),
        Field::new(":authority", "api.example.test"),
        Field::new(":path", "/v1/events"),
        Field::new("content-type", "application/json"),
        Field::new("accept", "application/json"),
        Field::new("user-agent", "fictionet-client/2.1.0"),
        auth,
        Field::new("content-length", (300 + i).to_string()),
        Field::new("x-request-id", format!("request-{i:08x}")),
    ]
}

#[test]
fn realistic_field_sets_report_all_qpack_wire_bytes() {
    for (name, make) in [
        ("browser", browser as fn(usize) -> Vec<Field>),
        ("response", response),
        ("api", api),
    ] {
        let workload: Vec<_> = (0..20).map(make).collect();
        let policies: [(&str, &dyn Policy); 3] = [
            ("static", &StaticOnly),
            ("selective", &Selective),
            ("all", &Every),
        ];
        for (policy, rules) in policies {
            for feedback_every in [1, 4] {
                let bytes = measure(&workload, rules, feedback_every);
                println!(
                    "qpack {name} policy={policy} feedback_every={feedback_every} sections={} encoder={} decoder={} total={} cold={} last={}",
                    bytes.sections,
                    bytes.instructions,
                    bytes.feedback,
                    bytes.sections + bytes.instructions + bytes.feedback,
                    bytes.cold,
                    bytes.warm
                );
            }
        }
    }
}

#[test]
fn insert_feedback_cannot_advance_past_sent_entries() {
    let mut encoder = Encoder::new(4096, qpack::MAX_FIELD_SECTION_SIZE);
    assert_eq!(
        encoder.apply_instruction(DecoderInstruction::InsertCountIncrement(1)),
        Err(qpack::Error::Increment)
    );
    assert_eq!(encoder.known_received_count(), 0);
}

#[test]
fn stalled_acknowledgments_bound_the_encoder_and_fall_back_to_literals() {
    let mut costs = Costs::new("qpack-outstanding");
    let mut encoder = Encoder::new(128, qpack::MAX_FIELD_SECTION_SIZE);
    let charge = encoder.most_held();
    let linear = Linear {
        num: 8,
        den: 1,
        fixed: 2 * charge,
    };
    costs.step(16, charge + 1024, linear, || {
        encoder.set_capacity(128).unwrap();
        encoder.insert(b"server", b"fictionet").unwrap();
        encoder
            .apply_instruction(DecoderInstruction::InsertCountIncrement(1))
            .unwrap();
        Charged::new((), 0)
    });
    let fields = [Field::new("server", "fictionet")];
    for i in 0..qpack::MAX_OUTSTANDING + 2 {
        costs.step(16, charge + 1024, linear, || {
            let section = encoder.section(i as u64 * 4, &fields).unwrap();
            let bytes = section.to_bytes().unwrap();
            assert_eq!(bytes[0] == 0, i >= qpack::MAX_OUTSTANDING);
            Charged::new((), 0)
        });
        assert!(costs.live() <= encoder.held());
        assert!(encoder.held() <= charge);
    }
    costs.step(0, charge, linear, || {
        for i in 0..qpack::MAX_OUTSTANDING {
            encoder
                .apply_instruction(DecoderInstruction::StreamCancel(i as u64 * 4))
                .unwrap();
        }
        assert_eq!(encoder.known_received_count(), 1);
        Charged::new((), 0)
    });
    assert!(costs.live() <= encoder.held());
    costs.print();
}

#[test]
fn style_changes_only_how_strings_and_sensitivity_are_written() {
    use fictionet::stdlib::protocols::{huffman, qpack::Huffman};
    // A value whose Huffman code is exactly as long as the value.
    let tie = (b'!'..=b'~')
        .flat_map(|a| (b'!'..=b'~').map(move |b| [a, b]))
        .find(|v| huffman::encoded_len(v).unwrap() == v.len())
        .expect("a two-character tie");
    let mut secret = Field::new("x-secret", "token");
    secret.never_index = true;
    let fields = vec![Field::new("x-tie", tie), secret];
    let section = Encoder::new(0, qpack::MAX_FIELD_SECTION_SIZE)
        .section(0, &fields)
        .unwrap();
    let mut lengths = Vec::new();
    for huffman in [Huffman::Shorter, Huffman::NotLonger, Huffman::Never] {
        for never_index in [true, false] {
            let mut bytes = Vec::new();
            section
                .write_styled(
                    Style {
                        huffman,
                        never_index,
                    },
                    &mut bytes,
                )
                .unwrap();
            let SectionResult::Fields { fields: back, .. } =
                qpack::decode_section(&Table::new(0), 0, &bytes).unwrap()
            else {
                panic!("static section")
            };
            assert_eq!(back.len(), 2);
            assert_eq!(
                (&back[0].name, &back[0].value),
                (&fields[0].name, &fields[0].value)
            );
            assert!(!back[0].never_index);
            assert_eq!(back[1].value, b"token");
            assert_eq!(back[1].never_index, never_index);
            // The tie's value is the first field's last string: its length
            // prefix carries the Huffman bit.
            let tie_prefix = bytes[2 + 1 + huffman_name_len(&bytes[2..])];
            assert_eq!(tie_prefix & 0x80 != 0, huffman == Huffman::NotLonger);
            lengths.push((huffman, bytes.len()));
        }
    }
    let longest = lengths.iter().map(|(_, n)| *n).max().unwrap();
    assert!(
        lengths
            .iter()
            .all(|(h, n)| *h == Huffman::Never || *n < longest)
    );
}

/// The encoded length of a literal field line's name, after its first byte.
fn huffman_name_len(line: &[u8]) -> usize {
    // Literal with literal name: 001NHxxx with a 3-bit length prefix.
    assert_eq!(line[0] & 0xe0, 0x20);
    let length = (line[0] & 0x07) as usize;
    assert!(length < 7, "short names only");
    length
}
