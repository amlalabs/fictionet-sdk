# DNS verification

This directory checks the design of Fictionet's DNS engines in two ways, and
holds the Rust code to one of them:

| Part | What it is | Where |
|---|---|---|
| TLA+ | Three specs of the engines' behaviour over time (the resolver, the exchange contract, the validator), checked with TLC, each with ablations that must fail | [`tla/`](tla/README.md) |
| Lean 4 | Proofs about the pure functions (names, the wire format, truncation, zones, partial views, DNSSEC, the algorithm policy, the chain check, the cache, the resolver), and an executable reference that writes test vectors | [`lean/`](lean/README.md) |
| The differential test | The Rust code run on every Lean vector, compared field by field | [`tests/dns_vectors.rs`](../../tests/dns_vectors.rs) |

Each subdirectory's README says what is modelled, what each property or
theorem states, and the modelling choices to read before trusting one. This
file says how to run all three and what the differential test compares.

## Running

```sh
export TLA2TOOLS=~/.cache/adorably-fv/tla2tools.jar   # tla2tools.jar 2.19
export JAVA=~/.local/jdk21/bin/java                   # java when unset
cargo xtask dns-verify all
```

| Command | Does |
|---|---|
| `cargo xtask dns-verify tlc [spec] [config]` | TLC with all passing properties together and each ablation separately; optionally select a spec (`Resolution`) or config (`Resolution_base` or `base`) |
| `cargo xtask dns-verify lean` | `lake build`, then the axioms of every headline theorem |
| `cargo xtask dns-verify vectors [seed]` | `lake exe gen` into the vectors directory, from `seed`, or from each of seeds 1 to 8 when left out |
| `cargo xtask dns-verify diff [seed]` | the vectors, then `cargo test --test dns_vectors` against them, for each seed |
| `cargo xtask dns-verify all` | all of the above, with a summary |

Everything goes into an exclusive run directory beneath `dns-verify/` in
Cargo's target directory (`CARGO_TARGET_DIR`, or `target/`): `tlc/` holds each TLC run's config and
output, `lean/` the output of `lake`, `vectors/<seed>/` the vectors of each seed, `diff-<seed>.out` the
differential test's output, and `SUMMARY.txt` the summary of `all`. The
vectors are made again on every run and never committed; the same seed
always gives the same files.

Each invocation prints its exclusive run directory beneath `dns-verify/`.
Use that directory for logs and generated vectors.

`tlc` reads `TLA2TOOLS` and `JAVA` and runs TLC with `-Xmx6g`. A config
whose first lines read `\* expect violation: <Property>` must list exactly
those properties, and each must fail, in a run that checks it alone and
with one worker, so its counterexample is a shortest one. Every other
config must pass every property it lists. Lake is `$LAKE`, or `lake` on the
path; `lean` fails if any headline theorem printed by `Dns/Axioms.lean`
rests on an axiom other than `propext`, `Quot.sound`, and
`Classical.choice`.

The differential test is declared with `test = false`, so a plain
`cargo test` leaves it out. Run it by name with the vectors' directory in
`DNS_VECTORS`:

```sh
DNS_VECTORS=/path/to/printed-run-directory/vectors/1 cargo test --test dns_vectors -- --nocapture
```

## What the differential test compares

One test per kind of vector. Each fails listing the cases where Rust and
Lean disagree, and prints how many cases it read and how many it could
not compare whole, with why.

| Kind | Rust code | Compared |
|---|---|---|
| `names` | `LowerName`, `Name` | canonical order (RFC 4034 §6.1), equality ignoring case, folding, wire length |
| `wire` | `read_message`, the decoder the engines read replies with, and hickory's encoder | whether the message decodes; header, questions, and every record; the uncompressed encoding |
| `respond` | `Request::parse` and the server front (`ServerConfig::front`) | silence, the rejection's RCODE, ID, header bits, and OPT version, or the request's flags, question, and EDNS, and the header and OPT of an authoritative answer to it |
| `fit` | `protocols::dns::fit` | the size, TC, and the RRsets kept in each section |
| `framing` | `Queries` under `Framing::Stream`, `stream_framed`, `StreamMessage::parse` | the messages read from a stream that arrives in chunks, and the octets left; each message framed again reads back |
| `zone` | `zone::answer` over `Zone::from_master` | RCODE, AA, every section, and the required additional RRsets |
| `partial` | `zone::answer` over a view with unknown facts | the unknown name, or the response |
| `signed` | `Zone::signed`, `answer` with DO=1, `validate_rrset`, `validate_denial` | the answer's records and RRSIGs (for ANY, the NSEC and DNSKEY RRsets at the name too), its denial records, the DNSKEY RRset, and the validation of each answer RRset, paired by owner and type, and of the denial, its SOA RRset included, under the zone's own anchor or, for a zone below a signed parent, along the chain from the parent's anchor across the delegation, with the parent's DNSKEY RRset and its denial of the DS RRset compared too; NSEC3 zones hold their NSEC3PARAM RRset on both sides |
| `policy` | `AlgorithmPolicy::treat`, under `AlgorithmPolicy::iana` where the vector names `iana` | the treatment of a DS record's algorithm and digest type, so the policy Rust ships is held to the one the Lean theorems are about |
| `chain` | `check_chain` | the problems reported, as a set |
| `cache` | `resolver::Cache` | what each lookup serves, with TTLs counted down, looking first for an NXDOMAIN at the name or a Secure one above it, as `Resolver::cached` does (RFC 2308 §5, RFC 8020 §2) |
| `resolver` | `Resolver` driven by `memory::drive` over `AuthorityEngine`s of the zones | each answer, the answers under the work bound with nothing lost, the final cache, and the answers with some servers dead |
| `keytag` | `dnssec::key_tag` | the key tag of a DNSKEY's flags, algorithm, and public key (RFC 4034 Appendix B, RFC 6840 §5.5) |
| `minimise` | `resolver::Minimise::next_labels`, which `Resolver::next_question` calls | how many labels the next minimised query shows, or the whole question (RFC 9156 §2.3) |

Signatures in `signed.json` and `chain.json` are symbolic (Lean's
`Dnssec.Symbolic.scheme`): a key is a number, and a signature is the private
key with the message. The test signs through the Rust `Sign` trait with a
signer of that scheme and checks through the Rust `Verify` trait with an
oracle of it, so the signer and validator run unchanged. A second test,
`signed_real`, makes each symbolic key a real key from a seed (RSA/SHA-1 for
algorithm 5, through the `rsa` crate, since no world may sign with it),
turns every valid signature into a real one and every invalid one into a
real one with a bit flipped, and expects `Ring` to reach the validations
Lean reached. `chain` runs on real keys too, since `check_chain` verifies
with `Ring`; a symbolic DS digest is rewritten as the real DS of the key it
names.

Two faults are applied to a `signed.json` answer on both sides, as a broken
server could send it, before it is validated. A key marked `mistag` has its
RRSIGs carry a key tag no key of the zone has, signed over that tag by the
same key, so only the validator's key tag check (RFC 4035 §5.3.1) refuses
them; Lean writes the tag as the key's number plus 512, and the test maps the
real wrong tag to it. A case marked `strip_soa` has the RRSIGs of the SOA
RRset in its authority section removed, so a negative answer whose denial
records verify still fails on its SOA (RFC 4035 §3.1.1).

`resolver` compares what the Lean resolver and the Rust one share. The Lean
model has no priming, no retransmission, and no failure cache, so a loss
script does not line up query for query. Every server has an address of its
own. The test checks five things. With work to spare, every Rust answer is
the hierarchy's answer (Lean's `Resolver.spec`, computed from
`zone::answer` over the zones), and equals every Lean answer that is not
SERVFAIL, which `resolve_correct` says is the hierarchy's answer too. With
nothing lost, under the vector's work bound, the Rust resolver, primed
first since Lean starts from the hints, gives every Lean answer, SERVFAILs
included. Every NS RRset, glue RRset, and answer RRset in Lean's final
cache is in the Rust cache at the same rank or higher. With the vector's
`dead` servers never answering and work to spare, the Rust answers equal
Lean's `dead_answers`, SERVFAILs included: Lean drops a server at its first
loss and Rust after three tries (RFC 9520 §3.1), so both answer exactly
when every zone on the way has a server left. Under the vector's loss script
with work to spare, Lean's `lossy_answers` say, for each question, the answer
and the servers its losses made it give up on; with those servers silent for
that question, the Rust answers equal Lean's, SERVFAILs included, for the
same reason. AA and the additional section
are left out of answers: a resolver clears AA and, like Unbound with
`minimal-responses: yes`, sends no additional data.

## Where the Lean model and Rust differ

The test notes each case below and compares the rest of it; no other
difference passes. Each is a place where the Lean model leaves out what the
standards and Rust do, or where a standard lets both answers stand.

| Kind | Difference | Why Rust is kept |
|---|---|---|
| `wire` | `read_message` refuses messages holding a record hickory cannot read by its type's rules, such as an SRV without a target; the Lean codec carries such RDATA as octets (RFC 3597). A record the RFCs have ignored while the rest of the message stands (an NSEC3 or NSEC3PARAM of another hash algorithm or with unknown flags, RFC 5155 §8.1, §8.2, §4.1.2; a DNSKEY whose Protocol is not 3, RFC 4034 §2.1.2) is kept as octets by both, and compared | hickory's reading of typed RDATA |
| `fit` | `Gen.lean` sometimes splits one RRset (same owner and type) into two in a section, and the Lean `fit` keeps the two apart | RFC 2181 §5 makes them one RRset, which `fit` writes together |
| `zone`, `partial` | for QTYPE ANY answered with one RRset, Lean takes the first RRset in the zone's listed order and Rust the RRset of the lowest type; the test then checks that Rust answers Lean's RRset when asked for its type, after the same CNAME and DNAME chain when one leads to the name | RFC 8482 §4.1 lets a server pick any one RRset; a master file's order does not survive into a zone |
| `chain` | in a tree with a corrupted key, Rust also reports the breaks the bad signatures make, `SignatureInvalid` among them | the Lean check reads no signature and assumes honest signers (`check_sound`) |

Three differences the test found were faults in Rust and are fixed there:
`fit` now ends the additional section at the first optional RRset that does
not fit, as the Lean model proves (`fit_whole_rrsets`: each section is
written up to some RRset), instead of skipping it and writing later ones;
`check_chain` no longer asks a parent whose keys all use algorithms the
policy does not validate to prove that its unsigned delegations have no DS,
since a validator already finds that parent Insecure; and `Request::parse`
took a query whose MD, MF, MB, MG, MR, or MINFO record held RDATA that is no
name, which hickory reads as octets for these types; it now checks every
record's layout as RFC 3597 §4 asks (`respond.json`, seed 2).
