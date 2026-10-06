# Fictionet code generation

`fictionet-codegen` turns a structured schema into a Fictionet protocol
module. Generate the file once. Copy it into your crate, edit it, and own
it. Regenerate only when you choose to replace those edits. The generated
file has no dependency on the generator at runtime.

The generator has a shared IR, a validator, one Rust emitter, and a
front end per input format. The built-in `ir` front end reads the IR
itself as JSON. The IR describes ordered binary layouts. Front ends for
formats such as SBE, FIX, FAST, XDR, protobuf, ASN.1, OpenAPI/JSON
Schema, and DCE/RPC parse their schemas into this IR. Tagged fields,
varints, padding rules, and text formats get their own IR encoding forms
when those front ends need them.

## Generate and use a module

From the SDK checkout:

```sh
CARGO_BUILD_JOBS=4 cargo run -p fictionet-codegen -- --list
CARGO_BUILD_JOBS=4 cargo run -p fictionet-codegen -- ir schema.json -o orders.rs
```

The equivalent spelling is `--format ir schema.json -o orders.rs`.
`ir` accepts exactly one JSON document. The registry API accepts a list
of inputs so future formats can support imports and multiple files.
The generator reads local files only. It uses no network, external
formatter, build script, proc macro, or third-party library.

Place the output in your consumer crate and use the public codec traits:

```rust,ignore
mod orders;
use fictionet::stdlib::codec::Wire;
let value = orders::Order::parse(bytes)?;
value.write(&mut output)?;
```

`Wire::parse` reads one exact value. `Wire::write` appends a value without
changing the destination if it returns an error. A generated stream type
implements `Decode`; use it with `codec::Stream`, `pump`, and `finish`.
Its associated `write` method writes the magic, length, and complete body.
A body's `Wire` implementation excludes this outer framing.

The header records the generator package version and escaped input
basenames. It never includes input directory paths or timestamps.
Declaration order is preserved. Identical validated inputs produce
identical output bytes, without a formatter installed.

## CLI limits

Options supply limits the schema does not give. Limits are baked into
named constants in the output. A field's explicit length limit wins over
`--max-collection`; all fields still share the message and work budgets.
An omitted collection limit is capped to the count or prefix width.

| Option | Default | Allowed range |
| --- | ---: | ---: |
| `--max-message` | 1,048,576 bytes | 1 through 16 MiB |
| `--max-collection` | 4,096 entries or bytes | 0 through 1 MiB |
| `--max-depth` | 32 | 1 through 64 |
| `--max-allocation` | 8 MiB | 1 through 64 MiB |
| `--max-nodes` | 65,536 | 1 through 1 MiB |

`MAX_MESSAGE` bounds encoded bytes per body. Each stream's capacity adds
its prefix and magic length. `MAX_ALLOCATION` bounds the sum of requested
heap storage for decoded vectors, strings, and boxed references. It also
checks the corresponding storage during writes. `MAX_NODES` bounds
structural visits, including named values, group entries, and present
flagged options. This prevents nested collections of empty values from
causing excessive work. `MAX_DEPTH` counts active named values, group
entries, and present flagged options. The parser and writer use the same
accounting. A schema can require more bytes or depth than an application
limit allows; such values are refused at runtime.

Parsing vectors reserves the checked length exactly. Allocation budgets
refer to requested storage; allocator bookkeeping is outside the budget.
Writers stage at most `MAX_MESSAGE` bytes, with vector growth bounded by
twice that number. Frame writers also stage at most 264 header bytes.
The caller owns and budgets the destination vector across multiple
writes. Allocation failures from fallible reservations are typed errors.

Generator limits are fixed and exported from `fictionet_codegen::ir`:

| Constant | Limit |
| --- | ---: |
| `MAX_INPUT` | 1 MiB per JSON input; CLI also checks the total |
| `MAX_JSON_DEPTH` | 64 active JSON values |
| `MAX_JSON_ELEMENTS` | 65,536 values plus object keys |
| `MAX_TYPES` | 256 named types and 256 stream forms |
| `MAX_FIELDS` | 4,096 fields, enum variants, and set bits in total |
| `MAX_STRUCT_FIELDS` | 256 fields per struct |
| `MAX_NESTING` | 16 active inline type nodes |
| `MAX_NAME` | 128 UTF-8 bytes per source name or input basename |
| `MAX_DOC` | 4,096 UTF-8 bytes per documentation string |
| `MAX_OUTPUT` | 32 MiB per emitted file |

Stream magic is limited to 256 bytes. Explicit collection limits are
limited to one MiB and must fit their prefix width. Fixed data must fit
`MAX_MESSAGE`. Zero-length fixed data and zero collection limits are
valid. Numeric nulls and enum discriminants retain full integer precision.

## IR JSON

This complete example has a closed enum, a message, variable data, an
optional number, and a stream decoder:

```json
{
  "doc": "Order messages.",
  "byte_order": "little",
  "types": [
    {
      "name": "Side",
      "kind": "enum",
      "repr": "u8",
      "variants": [
        { "name": "buy", "value": 1 },
        { "name": "sell", "value": 2 }
      ]
    },
    {
      "name": "Order",
      "kind": "struct",
      "fields": [
        { "name": "sequence", "type": "u64", "fixed_size": 8 },
        { "name": "side", "type": { "kind": "ref", "name": "Side" } },
        {
          "name": "symbol",
          "type": { "kind": "string", "prefix": "u8", "limit": 16 }
        },
        {
          "name": "quantity",
          "type": { "kind": "optional", "item": "u32", "null": 4294967295 }
        }
      ]
    }
  ],
  "streams": [
    {
      "name": "OrderFrames",
      "item": "Order",
      "prefix": "u32",
      "byte_order": "big",
      "magic": [70, 78]
    }
  ]
}
```

The root requires `types`. `doc`, `byte_order`, and `streams` are optional.
The default byte order is big-endian. Unknown members are errors, as are
duplicate object keys, trailing input, invalid UTF-8, malformed numbers,
and invalid Unicode escapes. UTF-16 escape pairs are decoded together.
JSON objects may use any key order. Field and declaration arrays retain
wire and output order.

Each named type requires `name` and `kind`. All definitions, fields,
variants, and bits accept an optional `doc` string.

| Definition kind | Required members | Meaning |
| --- | --- | --- |
| `struct` | `fields` | Ordered field array; empty structs are allowed |
| `enum` | `repr`, `variants` | Closed integer enum; variants have `name` and integer `value` |
| `set` | `repr`, `bits` | Unsigned bit set; bits have `name` and zero-based `bit` |

Enums require at least one variant. Their representation must be an
integer scalar. Discriminants must be unique and fit that scalar. Sets
use an unsigned width, require distinct bit positions, and refuse all
undeclared bits. Generated sets are tuple structs with named bit constants.

A field requires `name` and `type`. Optional `byte_order` overrides the
inherited order for the whole field, including prefixes and referenced
values. Optional `fixed_size` asserts an exact wire size. Validation
checks the assertion through references; variable layouts cannot have
one. Docs do not affect parsing.

| Type JSON | Wire encoding and Rust value |
| --- | --- |
| `"u8"`, `"u16"`, `"u32"`, `"u64"` | Fixed-width unsigned integer |
| `"i8"`, `"i16"`, `"i32"`, `"i64"` | Fixed-width two's complement integer |
| `"f32"`, `"f64"` | Finite IEEE 754 float; infinities and NaNs are refused |
| `{"kind":"bytes","size":4}` | Exactly four bytes as `Vec<u8>` |
| `{"kind":"string","size":4}` | Exactly four UTF-8 bytes as `String`; no padding or terminator |
| `{"kind":"bytes","prefix":"u16","limit":128}` | Unsigned byte count followed by bytes |
| `{"kind":"string","prefix":"u8","limit":32}` | Unsigned byte count followed by UTF-8 text |
| `{"kind":"group","count":"u16","limit":8,"item":"u32"}` | Unsigned entry count and consecutive entries as `Vec<T>` |
| `{"kind":"optional","flag":"u8","item":"i32"}` | A 0 or 1 flag; 1 is followed by a value, as `Option<T>` |
| `{"kind":"optional","null":-1,"item":"i32"}` | One scalar; the reserved value means `None` |
| `{"kind":"ref","name":"Order"}` | Named type, emitted as `Box<Order>` |

Prefix, count, flag, and set widths are `u8`, `u16`, `u32`, or `u64`.
Variable data and groups may omit `limit`; validation fills it from the
CLI default, capped to the width. Groups and flagged options can nest.
Null options require a scalar item, and the null must fit exactly.
Floating-point nulls must be finite and exactly representable. Float
sentinels compare by bits, so positive and negative zero remain distinct.
`Some(null)` is refused by the writer.

References use exact source names. All references are boxed, including
acyclic ones. Cycles are detected and listed by
`ValidatedSchema::recursive_types`. A mandatory reference cycle without
a terminating optional field or group has no finite value and is refused.
Every generated read and write has a depth guard.

A stream requires `name`, `item`, and `prefix`. `item` names a type.
Optional `magic` is an array of bytes. Optional `byte_order` controls the
length prefix and defaults to big-endian. Body fields retain the schema
order. The prefix measures only body bytes. Generated framers retain no
input, return `Need` for partial frames, and reject oversized lengths as
soon as the complete header is available. The driver reports truncation
at EOF. Invalid complete bodies terminate decoding.

## Rust identifiers

ASCII letters and digits form words. Punctuation and non-ASCII characters
separate words. A lower-case letter or digit followed by an upper-case
letter starts a word. Acronyms split before their final capital when a
lower-case letter follows: `HTTPMessage` becomes `http_message`.

Types and variants use UpperCamelCase. Fields use snake_case. Bit
constants use SCREAMING_SNAKE_CASE. A leading digit gains `N` for types,
`n_` for fields, or `N_` for constants. Rust keywords gain a trailing
underscore: `type` becomes `type_`, and `Self` becomes `Self_`.
Names with no ASCII letter or digit are refused. Source names must be
unique within their scope. Any collision after mapping is refused.

Type and stream names share a scope. `Error`, `String`, `Vec`, `Box`,
`Option`, `Result`, `Some`, `None`, `Ok`, and `Err` are reserved there.
Private emitted helpers use names beginning with `__`, which type mapping
cannot produce. No silent renaming or compatibility aliases are added.

## Library and new front ends

The crate exports `Schema`, `NamedType`, `Definition`, `Field`, `Type`,
`Primitive`, `Length`, `Presence`, `Number`, `Width`, `ByteOrder`, `Stream`,
and `Limits`. Construct them directly or use `FrontEnd::parse`. Call
`validate(schema, limits)` to obtain a `ValidatedSchema`, then
`emit(&validated, &input_names)` to get Rust source. `generate` combines
registry lookup, parsing, validation, and emission. `Error` carries an
`ErrorKind`, a location or schema path, and a short explanation.

Implement `FrontEnd: Sync` with `name()` and
`parse(&[Input], Limits) -> Result<Schema, Error>`. The parser must bound
its inputs and intermediates and preserve the format's declared limits.
It should fill documentation and source names without performing Rust
name mapping. Add a single instance to `FORMATS` in
`codegen/src/frontend.rs`. The CLI then lists and accepts the new format.
The validator and emitter remain shared. No registration macro or build
script is needed.

## Guarantees and checks

Generated modules use public `fictionet::stdlib::codec` APIs and their own
file-local support code. The same file compiles in SDK integration tests
and in the external copy-and-own fixture. Parsing is exact. Writing is
strict and transactional. Count and range arithmetic is checked; reads
use checked slicing. Resource and depth checks precede allocation and
recursive descent. Work is linear in visited fields, bytes, and entries,
under the node budget. There is no speculative parsing of partial stream
bodies. Returned values have bounded depth, including when dropped.

Generated tests build bounded values with public `codec::Lcg` and run
`contract::check_wire_value`. Stream tests also run
`check_decode_with_alloc_limit`. Tests cover invalid writes, malformed
bytes, recursion limits, every generator error category, CLI errors,
JSON limits, deterministic output, and exact golden source bytes.
The golden check runs `rustfmt --check` when `rustfmt` is on PATH.

The XDR example covers big-endian signed and unsigned numbers, enums,
fixed opaque bytes, counted arrays, and four-byte optional flags.
Differential tests build its equivalent IR, check the emitted source,
and compare generated reads and writes with `onc_rpc::Reader` and
`Writer` over sample values, Lcg-generated values, all truncated prefixes,
mutations, and arbitrary bytes. Protobuf and ASN.1 use tagged encodings.
Their front ends add the IR forms and the matching comparisons.

Goldens live in `codegen/tests/golden`. The root integration target
`tests/codegen.rs` compiles them and runs their emitted tests. Additional
fixtures check small allocation and work budgets, long identifiers, and
maximum-sized stream headers. To update:

```sh
CARGO_BUILD_JOBS=4 BLESS_CODEGEN=1 cargo test -p fictionet-codegen --test golden goldens_and_determinism
CARGO_BUILD_JOBS=4 cargo test --workspace --tests
```

The bless command also updates the checked-in example fuzz target.
Review changes to both the schema and its golden before accepting them.
To emit another target:

```sh
CARGO_BUILD_JOBS=4 cargo run -p fictionet-codegen -- ir schema.json -o protocol.rs --fuzz fuzz/fuzz_targets/protocol.rs
```

`--fuzz` writes a target-relative module path. The target needs the fuzz
workspace's `libfuzzer-sys` and `fictionet` dependencies. The generated
module itself still needs only Fictionet and the standard library. The
registered `codegen_ir` target checks recursive values and stream frames.
`fuzz/` keeps its separate workspace and builds on its own.
