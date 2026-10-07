# Fictionet code generation

`fictionet-codegen` turns a structured schema into a Fictionet protocol
module. Generate the file once. Copy it into your crate, edit it, and own
it. Regenerate only when you choose to replace those edits. The generated
file has no dependency on the generator at runtime.

The generator has a shared IR, a validator, one Rust emitter, and a
front end per input format. Two front ends are registered: `ir` reads
the IR itself as JSON, and `sbe` reads FIX Simple Binary Encoding 1.0 XML
message schemas. The IR describes ordered binary layouts: structs with
optional byte offsets, blocks whose wire length comes from a header,
headers of unsigned fields with roles, and unions selected by a header
tag. Front ends for formats such as FIX, FAST, XDR, protobuf, ASN.1,
OpenAPI/JSON Schema, and DCE/RPC parse their schemas into this IR.
Tagged fields, varints, and text formats get their own IR encoding forms
when those front ends need them.

## Generate and use a module

From the SDK checkout:

```sh
CARGO_BUILD_JOBS=4 cargo run -p fictionet-codegen -- --list
CARGO_BUILD_JOBS=4 cargo run -p fictionet-codegen -- ir schema.json -o orders.rs
CARGO_BUILD_JOBS=4 cargo run -p fictionet-codegen -- sbe templates.xml -o market.rs
```

The equivalent spelling is `--format ir schema.json -o orders.rs`.
`ir` accepts exactly one JSON document, and `sbe` exactly one XML schema. The registry API accepts a list
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
changing the destination if it returns an error. Each module defines its own
`Error`: `Truncated`, `Trailing`, `Limit`, `Depth`, `Value` (a scalar,
range, flag, enum, set, or null), `Utf8`, `Header` (magic, tag, version,
or a header constant), `Layout` (a block length too short for the
block's fixed fields), and `Allocation`. A generated stream type
implements `Decode`; use it with `codec::Stream`, `pump`, and `finish`.
Its associated `write` method writes the magic, length, and complete body.
A body's `Wire` implementation excludes this outer framing.

The header records the generator package version and escaped input
basenames, followed by a `#![doc]` attribute with the schema's
documentation. It never includes input directory paths or timestamps.
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
accounting. Validation refuses a named type if its minimum encoded size
or nesting depth exceeds these limits. Empty collections and absent
options define the minimum. Larger values are checked at runtime.

Parsing a group checks that its minimum entry sizes fit the remaining
input before reserving the checked count. Zero-byte entries still use
the node and allocation budgets. Allocation budgets refer to requested
storage; allocator bookkeeping is outside the budget.
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
| `MAX_HEADER` | 256 bytes, and 256 fields, per header |
| `MAX_CONSTANT` | 4,096 bytes per byte constant |
| `MAX_XML_DEPTH` | 32 nested XML elements |
| `MAX_XML_ELEMENTS` | 16,384 XML elements per document |
| `MAX_XML_ATTRIBUTES` | 32 attributes per XML element |

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
| `block` | `length`, `fields` | A struct whose fixed fields fill a block of `length` bytes; see below |
| `enum` | `repr`, `variants` | Closed integer enum; variants have `name` and integer `value` |
| `set` | `repr`, `bits` | Unsigned bit set; bits have `name` and zero-based `bit` |
| `union` | `header`, `cases` | A header, then the value its tag selects; see below |

Enums require at least one variant. Their representation must be an
integer scalar. Discriminants must be unique and fit that scalar. Sets
use an unsigned width, require distinct bit positions, and refuse all
undeclared bits. Generated sets are tuple structs with named bit constants.

A field requires `name` and `type`. Optional `byte_order` overrides the
inherited order for the whole field, including prefixes and referenced
values. Optional `fixed_size` asserts an exact wire size. Validation
checks the assertion through references; variable layouts cannot have
one. Optional `offset` places the field that many bytes after the start
of its struct. Every earlier field must have a fixed size, and offsets
may not move backwards. Skipped bytes are ignored when read and written
as zero. Docs do not affect parsing.

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
| `{"kind":"ref","name":"Order"}` | Named type, emitted as `Order` unless an inline cycle needs `Box<Order>` |
| `{"kind":"range","item":"u8","min":1,"max":9}` | One scalar; values outside the inclusive range are refused |
| `{"kind":"optional","null":0,"item":{"kind":"range",...}}` | A range with a reserved null outside it, as `Option<T>` |
| `{"kind":"optional","null":0,"item":{"kind":"ref","name":"Side"}}` | An enum whose representation reserves a null value |
| `{"kind":"constant","item":"i8","value":-9}` | No wire bytes; an associated constant `pub const NAME: i8` |
| `{"kind":"constant","bytes":[56]}` | No wire bytes; an associated `&[u8]` constant |
| `{"kind":"constant","enum":"Side","variant":"buy"}` | No wire bytes; an associated enum constant |
| `{"kind":"block_group","item":"Entry","header":{...},"limit":8}` | A header with a count, then that many entries, as `Vec<Entry>` |

Constants are only allowed as direct struct fields. They have no Rust
field and take no `offset` or `byte_order`. A null on an enum must fit
the enum's representation and differ from every variant.

A header is a fixed run of unsigned fields at explicit offsets:

```json
{
  "size": 8,
  "fields": [
    { "name": "blockLength", "offset": 0, "width": "u16", "role": "length", "max": 65534 },
    { "name": "templateId", "offset": 2, "width": "u16", "role": "tag" },
    { "name": "schemaId", "offset": 4, "width": "u16", "role": "constant", "value": 1 },
    { "name": "version", "offset": 6, "width": "u16", "role": "version", "current": 13, "minimum": 13 }
  ]
}
```

Fields must lie inside `size` and must not overlap. Bytes no field covers
are ignored when read and written as zero. Optional `max` bounds the
value; readers refuse larger values. Roles:

| Role | Read | Written |
| --- | --- | --- |
| `tag` | Selects a union case; unknown tags are refused | The case's tag |
| `length` | The wire length of the following block | The block's declared `length` |
| `count` | The number of group entries, at most the group's limit | The entry count |
| `version` | Refused below `minimum` | `current` |
| `constant` | Refused unless equal to `value` | `value` |

A union header has one `tag`, at most one `length` and one `version`,
and no `count`. A group header has one `count`, at most one `length`, and
no `tag` or `version`. Each union case has `name`, `tag`, `item`, and an
optional `doc`; names and tags are unique. A union may not take part in
a reference cycle. A group's omitted `limit` is the smaller of
`--max-collection` and the count field's maximum.

A `block` places its fixed-size fields first and its variable fields,
such as groups and length-prefixed data, after them. When a header with
a `length` precedes a block, readers accept any length that holds the
block's fixed fields. They skip the extra bytes of a longer block, the
way SBE extends a message (section 5.3 of the SBE standard). A group
header's length is checked against the entry's fixed fields even when
the count is zero. Writers always emit the declared length, padded with
zeros. A block read or written through its own `Wire` implementation
uses the declared length. A `length` role requires a block whose
declared length fits the length field.

Prefix, count, flag, and set widths are `u8`, `u16`, `u32`, or `u64`.
Variable data and groups may omit `limit`; validation fills it from the
CLI default, capped to the width. Groups and flagged options can nest.
Null options require a scalar item, and the null must fit exactly.
Floating-point null decimals must be finite and round-trip through the
width's shortest decimal spelling. Equivalent decimal spellings, such as
`1.25` and `125e-2`, are accepted. Extra digits that round away and nonzero
values that underflow to zero are refused for both widths. Integer nulls
must be exactly representable. In the library IR, `Number::Float` holds an
already parsed binary value; it must fit the target width without rounding.
Float sentinels compare by bits, so positive and negative zero remain distinct.
`Some(null)` is refused by the writer.

References use exact source names. Public fields show their Rust types
directly. Acyclic references use the named type. References inside a
`Vec` also use the named type. Direct fields and options use `Box` only
when they close a cycle through inline fields. A cycle through a `Vec`
already has the indirection Rust needs. All reference cycles are listed
by `ValidatedSchema::recursive_types`. A mandatory reference cycle without
a terminating optional field or group has no finite value and is refused.
Every generated read and write has a depth guard.

A stream requires `name`, `item`, and `prefix`. `item` names a type.
Optional `magic` is an array of bytes. Optional `byte_order` controls the
length prefix and defaults to big-endian. Body fields retain the schema
order. The prefix measures only body bytes. Generated framers retain no
input, return `Need` for partial frames, and reject oversized lengths as
soon as the complete header is available. The driver reports truncation
at EOF. Invalid complete bodies terminate decoding.

## SBE schemas

The `sbe` front end reads one `messageSchema` document of the
[SBE 1.0 standard](https://github.com/FIXTradingCommunity/fix-simple-binary-encoding/tree/master/v1-0-STANDARD/doc).
Its bounded XML reader accepts an XML declaration, comments, namespace
prefixes, and predefined or numeric character references. It refuses
DTDs, entities, CDATA, processing instructions, and includes.

| SBE | IR |
| --- | --- |
| `byteOrder` | The schema byte order; little-endian when omitted |
| Required `<type>` scalar | A `range` from the type's `minValue`/`maxValue`, excluding the null value (section 2) |
| Optional `<type>` scalar | `optional` with the type's null, around that range |
| `char` scalar | A `u8` range, 0x20 through 0x7e unless the schema says otherwise |
| `char` or `uint8` array | Fixed `bytes`; padding is kept |
| Constant `<type>` or `valueRef` | A `constant` field |
| `<enum>`, `<set>` | Named `enum` and `set`; `char` enums use byte values |
| Optional enum field | `optional` with the encoding's null around a `ref` |
| `<composite>` used by a message | A `struct`, with member offsets and constants |
| `<message>` | A `block` with its `blockLength` |
| `<group>` | A `block` named `<Owner>_<group>`, and a `block_group` with the dimension composite as its header |
| `<data>` | Variable `bytes` with the length member's width |
| `headerType` (default `messageHeader`) | The header of one union, `Message`, with a case per template |

The message header maps `blockLength` to `length`, `templateId` to
`tag`, `schemaId` to a `constant` of the schema id, and `version` to a
`version` with `current` and `minimum` both the schema version. Header
maxima come from the schema; `numInGroup` allows its full width unless
the schema sets `maxValue` (section 3.4.10). Group and data limits are
the smaller of the schema's maximum and `--max-collection`. Composites
that no message uses are left out; every enum and set is emitted.

Generated readers accept acting versions from the schema version up.
Longer blocks from newer senders are skipped. Senders on older versions
are refused, so fields need no "absent" form. `sinceVersion` and
`deprecated` may not exceed the schema version, and `sinceVersion` may
not decrease within a block or composite (section 5).

The front end refuses, with `Unsupported`, primitive arrays other than
`char` and `uint8`, optional floats (their null is NaN), optional
composite fields, and header or dimension composites with `numGroups` or
`numVarDataFields`. Other schema errors are `SchemaShape`, `InvalidName`,
`DuplicateName`, `UnknownReference`, or `InvalidSize`, with the input
name and the element path in the location.

`stdlib::cme_mdp3` is generated this way from CME's public MDP 3.0
schema, kept at `data/cme/templates_FixBinary.xml`. The generated code is
followed by hand-written packet framing: the binary packet header and
the two-byte message size. A test checks that the file still starts with
the generator's output. To regenerate the generated part and keep the
hand-written tail:

```sh
CARGO_BUILD_JOBS=4 BLESS_CODEGEN=1 cargo test --test sbe_codegen module_is
```

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
`Header`, `HeaderField`, `Role`, `Case`, `Constant`, and `Limits`, and the
front ends `IrFrontEnd` and `SbeFrontEnd`. Construct them directly or use `FrontEnd::parse`. Call
`validate(schema, limits)` to obtain a `ValidatedSchema`, then
`emit(&validated, &input_names)` to get Rust source. `generate` combines
registry lookup, parsing, validation, and emission. It returns `Generated`,
with `source: String` and `schema: ValidatedSchema`. The CLI uses this same
pipeline and uses the returned schema for an optional fuzz target.
`Error` carries an `ErrorKind`, a location or schema path, and a short
explanation. Front ends add three kinds: `XmlSyntax` for malformed XML,
`SchemaShape` for a missing attribute or a misplaced element, and
`Unsupported` for valid input the IR cannot express.

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
`contract::check_wire_value`. Each type and stream must sample and write
successfully at least once. Seed zero selects the minimum shape.
Stream tests also run `check_decode_with_alloc_limit`. Tests cover invalid writes, malformed
bytes, recursion limits, every generator error category, CLI errors,
JSON limits, deterministic output, and exact golden source bytes.
Formatting checks run `rustfmt --edition 2024 --check` over the goldens,
every name length from 1 through `MAX_NAME`, and deterministic random
schemas when rustfmt is on PATH. Random modules also compile with warnings
denied and run their generated tests. They use clippy when it is installed.

`tests/sbe_codegen.rs` compares generated SBE code with the runtime
decoder `stdlib::sbe`, loaded with the same XML, for every template of
CME MDP 3.0 and of `codegen/tests/schemas/sbe_sample.xml`. A third,
IR-driven encoder in the test makes random messages. Both decoders read
each one, and their values are compared field by field: the generated
value's `Debug` output against the runtime value tree. Both encoders then
reproduce the input bytes. The runtime also re-encodes each message with
longer blocks and a newer version, and the generated decoder reads the
same value. Mutated bytes must be accepted by both, with equal values,
or refused by both. The one expected difference is a version below the
schema's, which only the runtime reads.

The XDR example covers big-endian signed and unsigned numbers, enums,
fixed opaque bytes, counted arrays, and four-byte optional flags.
Differential tests build its equivalent IR, check the emitted source,
and compare generated reads and writes with `onc_rpc::Reader` and
`Writer` over sample values, Lcg-generated values, all truncated prefixes,
mutations, and arbitrary bytes. Protobuf and ASN.1 use tagged encodings.
Their front ends add the IR forms and the matching comparisons.

Goldens live in `codegen/tests/golden`. The `blocks` example covers
offsets, blocks, block groups, unions, ranges, constants, and enum nulls;
`sbe_sample` is the golden for the `sbe` front end. The codegen test target compiles
them and runs their emitted tests. It also runs the root integration checks
in `tests/codegen.rs`. Additional
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

Output paths are checked against every input and each other before any
input is read. Existing symlinks are resolved; Unix hard links are also
compared. The module and fuzz target are staged in temporary files before
renaming them into place. Each rename replaces one file; the pair is not
a filesystem transaction.

`--fuzz` writes a target-relative module path. The target needs the fuzz
workspace's `libfuzzer-sys` and `fictionet` dependencies. The generated
module itself still needs only Fictionet and the standard library. The
registered `codegen_ir` target checks recursive values and stream frames.
`fuzz/` keeps its separate workspace and builds on its own.
