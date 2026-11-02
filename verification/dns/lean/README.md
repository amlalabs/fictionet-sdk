# DNS: Lean 4 verification

This directory holds machine-checked proofs about the pure parts of Fictionet's DNS: names, the wire format,
truncation, zones and the answer algorithm, partial views, authorities, and exchange matching. It also
holds an executable Lean reference that writes test vectors for the differential test (§18.3 and §18.4 of
the design). It uses Lean core only, with no Mathlib. The toolchain is `leanprover/lean4:v4.35.0` (see
`lean-toolchain`). A clean build takes about five seconds.

## Build and check

```sh
cd verification/dns/lean
lake build                       # every proof, Dns/Axioms.lean, and the generator; fails on any error
lake exe gen <dir> <seed>        # writes <dir>/{names,wire,restore,fit,respond,zone,partial}.json
```

`lake build` prints the axioms of every headline theorem from `Dns/Axioms.lean`. Each line must list only
`propext`, `Quot.sound`, and `Classical.choice`, or a subset of them. A `sorryAx` would mean an unfinished
proof; there is none. The design's `cargo xtask dns-verify` (§18.4) runs this check and writes the vectors
into `target/dns-verify/vectors/`. Vectors are regenerated, not committed. The same seed always
gives the same files.

## Theorems

| File | What it models | Headline theorems |
|---|---|---|
| `Dns/Name.lean` | labels as octet lists, the ASCII fold, the canonical order of RFC 4034 §6.1, "at or below", the 255-octet limit | `fold_idem`, `eqCI_iff_fold_eq`, `canon_total`, `canon_lt_trans`, `below_trans`, `wire_len_le_255` |
| `Dns/Wire.lean` | header, questions, records, name compression; `decode`, `encode`, `restore`, `parse`, `respondHeader` | `decode_encode`, `decode_terminates`, `decode_rejects_forward_pointer`, `compress_only_rfc1035_types`, `unknown_rdata_verbatim`, `restore_changes_only_id_and_case` |
| `Dns/Fit.lean` | `fit : Resp → Limit → Bytes × Bool` over whole RRsets | `fit_size_le`, `fit_whole_rrsets`, `fit_keeps_opt`, `tc_iff_required_dropped`, `additional_drop_no_tc` |
| `Dns/Zone.lean` | nodes, cuts, glue, empty non-terminals, wildcards, CNAME, DNAME; `answer`; the builder | `nxdomain_iff`, `ent_is_nodata`, `referral_iff_below_cut`, `referral_aa_false`, `negative_has_soa`, `neg_ttl_min`, `answer_in_zone`, `wildcard_blocked_by_node`, `dname_yx_iff_long`, `builder_rejects_iff` |
| `Dns/Partial.lean` | views with present, absent, and unknown facts; `answerPartial`; `Lazy` zones | `answer_partial_sound`, `agreeing_zone_exists`, `unknown_never_negative`, `lazy_view_one_revision` |
| `Dns/Authority.lean` | `respond : Req → Known → Step`, the engine's ask loop, `Relay`, `Overlay` | `respond_monotone`, `loop_terminates`, `relay_never_guesses` |
| `Dns/Exchange.lean` | tokens, generations, the matching rule of §6.2 | `obsolete_ignored`, `match_requires_tuple`, `advance_clears` |
| `Dns/Axioms.lean` | `#print axioms` for each headline theorem, and an example applying it to a concrete input | only the three standard axioms |
| `Gen.lean` | `lake exe gen <dir> <seed>` | writes the vectors below |

What each theorem says:

| Theorem | Statement |
|---|---|
| `fold_idem` | folding a folded name changes nothing |
| `eqCI_iff_fold_eq` | the octet-by-octet case-insensitive comparison holds exactly when the folded names are equal |
| `canon_total` | any two names are ordered one way, or equal up to case |
| `canon_lt_trans` | the canonical order is transitive |
| `below_trans` | "at or below" is transitive |
| `wire_len_le_255` | a name the label-by-label check accepts fits in 255 octets and is valid, and folding keeps its length |
| `decode_encode` | decoding inverts encoding for every well-formed message, with or without compression |
| `decode_terminates` | the decoder never runs out of steps: the fuel it gives each name, quadratic in the message length, always suffices |
| `decode_rejects_forward_pointer` | a compression pointer that does not point strictly before itself is rejected |
| `compress_only_rfc1035_types` | names written earlier change a record's RDATA octets, and enter the table, only for the RFC 1035 name-bearing types |
| `unknown_rdata_verbatim` | RDATA of any other type decodes to its exact octets and is written back identically, anywhere |
| `restore_changes_only_id_and_case` | `restore` keeps the reply's length, takes the client's ID, and changes nothing else but the question name's case |
| `fit_size_le` | when header, question, and OPT fit at all, the output is within the limit |
| `fit_whole_rrsets` | the output is the encoding of a prefix of each section, so RRsets are never split |
| `fit_keeps_opt` | the OPT record is always the output's last record |
| `tc_iff_required_dropped` | TC is set exactly when an answer, authority, or required additional RRset was dropped |
| `additional_drop_no_tc` | optional additional data never changes TC or what is kept of the answer and authority |
| `nxdomain_iff` | NXDOMAIN with an empty answer exactly when nothing above diverts the walk, no node is at or below the name, and no wildcard is at its closest encloser |
| `ent_is_nodata` | an empty non-terminal answers NODATA with the SOA |
| `referral_iff_below_cut` | NOERROR with no answer and AA=0 exactly when the name is at or below the highest cut on its path (other than DS at the cut) or matches a wildcard that is a cut |
| `referral_aa_false` | a referral has AA=0, no answer, and the cut's NS set in authority |
| `negative_has_soa` | NXDOMAIN and NODATA carry the zone's SOA in authority |
| `neg_ttl_min` | that SOA's TTL is min(SOA TTL, MINIMUM) |
| `answer_in_zone` | in a well-formed zone, every owner in every section is at or below the apex |
| `wildcard_blocked_by_node` | a node at the name answers with its own RRset, whatever wildcard the zone holds |
| `dname_yx_iff_long` | below a DNAME, YXDOMAIN with just the DNAME exactly when the substituted name would pass 255 octets |
| `builder_rejects_iff` | the builder fails exactly when one of its rules, stated as propositions, fails |
| `answer_partial_sound` | if a view answers, every complete zone that agrees with the view's present and absent facts gives the same response |
| `agreeing_zone_exists` | every consistent finite view has an agreeing complete zone, so the quantifier above is never empty |
| `unknown_never_negative` | an unknown fact on the walk ends the answer with that name: the name itself, or the wildcard when the name is known absent |
| `lazy_view_one_revision` | a lazy zone's view agrees with the zone it leaves behind, at that zone's revision, and the zone only grows |
| `respond_monotone` | once `respond` replies or stays silent, more observations never change that |
| `loop_terminates` | with the asks of one request in a finite list, the engine's loop ends within one more step than there are asks; instantiated for `Relay` (one ask) and an `Overlay` on a relay (two) |
| `relay_never_guesses` | every relayed reply is the `restore` of a reply the real server gave to this exact question |
| `obsolete_ignored` | a reply bearing a token of another generation is ignored and changes nothing |
| `match_requires_tuple` | a reply changes state only if its token is outstanding and current and it matches address, transport, ID, QNAME, QCLASS, and QTYPE; otherwise state is unchanged |
| `advance_clears` | after a session change nothing is outstanding, the cache is empty, every old token is abandoned, and every old reply is ignored |

Supporting results: `answer_never_unknown` (a complete zone never
answers Unknown), `build_wf` (the builder makes well-formed zones), `lazy_answer` (a lazy view's answer is
the answer of the zone it leaves behind), `relay_loop_terminates`, `overlay_loop_terminates`, and the
invariant `Exchange.Inv` with `inv_send`, `inv_onReply`, and `inv_advance` (no cache entry is ever of an older
generation, and tokens are fresh).

## Vectors

`lake exe gen <dir> <seed>` writes one JSON file per kind. Each is an array of cases with an `input` and an
`expected` object. Names are presentation strings with a trailing dot; octets outside letters, digits, `-`,
`_`, and `*` are written `\DDD`. Records are presentation-format lines. RDATA the model carries as octets
(every type outside A and AAAA in `wire`, `fit`, and `respond`, and unknown types in `zone`) uses the RFC 3597
form `\# <length> <hex>`. Octets are lowercase hex.

| File | Input | Expected |
|---|---|---|
| `names.json` | `a`, `b` | `cmp` (-1, 0, 1), `eq_ci`, `wire_len` ([a, b]) |
| `wire.json` | `bytes`: an encoded message, sometimes truncated, altered, given a bad pointer, or padded | `ok`; then `message` (header, question, answer, authority, additional) and `canonical` (the uncompressed encoding), or `error` |
| `restore.json` | `reply`, `query` | `restored`, or `error`: `question_mismatch` or `malformed` |
| `fit.json` | `response` (header, question, RRsets per section, `required_additional`, `opt`), `limit` (`udp512`, `udp_edns` with `size`, or `stream`) | `size_le`, `fits`, `length`, `tc`, and `kept`: the number of RRsets kept per section |
| `respond.json` | `bytes`, `transport` (`udp` or `tcp`) | `parsed`: `silent`; `reject` with `rcode` (extended), `flags`, and `opt` (its version, or null); or `request` with `rd`, `cd`, `ad`, `question`, and `edns` |
| `zone.json` | `zone` (`apex`, `records`), `any` (`hinfo`, `one_rrset`, `all`), `request` (`qname`, `qtype`) | `rcode`, `aa`, `answer`, `authority`, `additional`, `required_additional` |
| `partial.json` | as `zone.json`, plus `unknown`: names whose facts are unknown | `unknown` (a name), or `response` |

## Modelling choices (read before trusting a theorem)

- **Octets** are `Nat`. Theorems that rebuild numbers from octets say what range they need.
- **Names in zones are lowercase.** The zone, partial, and authority models take the question name as Rust's
  `LowerName`; restoring the question's case in owners is the server front's job (§7.3), which `restore`
  covers for relays.
- **Compression** points a name, or the rest of a name after some labels, at an earlier occurrence with
  exactly the same octets. hickory may choose differently, so `wire.json` gives the decoded sections and
  the uncompressed `canonical` octets rather than Lean's compressed octets as the expected value. `fit.json`
  sizes come from this compressor: a differential test comparing `kept` must either use the same choices or
  treat a case whose RRsets fit only under one compressor as a size difference, not a logic difference.
- **The decoder** gives each name `length² + length + 256` steps and proves that is enough. Octets after the
  last record are ignored. A name that reads past the end of its RDATA is rejected.
- **`parse`** answers FORMERR without an OPT when the message does not decode, and FORMERR with an OPT when the
  fault is in the OPT record (a second OPT, an owner other than the root, or options that do not split).
  Header fields and the question are not echoed in the model; `respond.json` checks the RCODE, flags, and the
  OPT's presence and version.
- **Fit** treats each RRset as a list of records with the same owner and type, and measures candidates by
  encoding the whole message, OPT included. Within a section it keeps RRsets in order while they fit.
- **Zones** hold nodes by name. An empty non-terminal is not stored: a name with no node of its own but nodes
  below it is reported as `Empty`. A wildcard that is itself a cut gives a referral to that cut. DNAME at the
  question name is ordinary data; DNAME above it substitutes. The synthesized HINFO answer to QTYPE ANY
  (RFC 8482 §4.2) takes the TTL of the node's first RRset.
- **DO=1 is outside these files.** RRSIGs, denial records, and a view's `denial` fact belong to the DNSSEC
  model of §18.2; the answers here are the DO=0 answers.
- **The CNAME chase** stops at the first repeated name, at a name outside the zone, or at YXDOMAIN. The
  definition carries fuel of 256^256 steps only to be total. Each step visits a new name, a CNAME target the
  zone holds or a DNAME substitution of at most 255 octets, so a chain ends another way long before that;
  this is an argument, not a theorem.
- **Every fact `answer` reads goes through the view**, including the address records of NS, MX, and SRV
  targets and sibling glue. An unknown fact there also ends the answer with Unknown, because a response that
  left them out would differ from the complete zone's. `partial.json` expects this of the Rust `answer`.
- **The builder** takes RRsets and delegations (child, NS targets, glue, DS) and checks the rules of
  `ZoneError` except `Master`, which is about parsing. Glue whose owner is not below its cut is never served
  rather than rejected. It merges RRsets of the same owner and type and collapses duplicate records
  (RFC 2181 §5). When several rules fail it reports the first in the order `firstError` lists, with the most
  specific of two overlapping CNAME rules first.
- **Lazy zones** ask the provider about every needed name the zone holds no node at: the path from the apex
  to the name and the wildcard below each name on it. Present answers are inserted as one new revision each;
  absent and unknown answers are not kept. The view reads every fact from the zone after the provider was
  asked, so it is one revision; a name with held names below it reads as `Empty` whatever the provider says,
  which is "the zone answers what it holds" of §5.4.
- **Authorities are trees of asks**: finished, or ask one server and continue with what a client of that
  server saw. A Rust `Authority` whose `respond` reads `known` only through `Known::get` and returns `Need`
  only for asks it has not seen is such a tree. `respond_monotone` therefore holds for every authority
  without a finite-asks hypothesis; `loop_terminates` needs one.
- **Exchanges** model the state the matching rule touches: the generation, the next exchange number, the
  outstanding exchanges with their tuples, and state derived from replies, tagged with its generation.
  Waiting client queries survive a session change, to be restarted under the new generation.

## How the Lean definitions correspond to the Rust code

| Lean | Rust (design section) |
|---|---|
| `Name.fold`, `Name.eqCI` | `LowerName` construction and comparison (hickory) |
| `Name.canonLt`, `Name.canonCmp` | `Name::cmp_canonical` (RFC 4034 §6.1) |
| `Name.below` | `Name::zone_of` |
| `Name.wireLen`, `Name.ofLabels?` | `Name::len` and the label checks of hickory's name decoder |
| `Wire.decode`, `Wire.encode` | hickory's `BinDecoder` and `BinEncoder` under `protocols::dns` (§4) |
| `Wire.compressible` | the record types hickory compresses names in (RFC 3597 §4) |
| `Wire.restore` | `protocols::dns::relay::restore` (§4.5) |
| `Wire.parse` | `protocols::dns::request::Request::parse` (§4.3) |
| `Wire.respondHeader` | the reply header the server front writes (§7.3) |
| `Fit.Resp`, `Fit.Limit`, `Fit.fit`, `Fit.Limit.forRequest` | `protocols::dns::fit::{Response, Limit, fit}`, `Limit::for_request` (§4.4) |
| `Zone.Fact`, `Zone.Node`, `Zone.Zone` | `services::dns::zone::{Fact, Node, Zone}` (§5.1, §5.2) |
| `Zone.look` | `View::node` of a complete zone's view |
| `Zone.answerWith`, `Zone.answer`, `Zone.Answered`, `Zone.AnyResponse` | `zone::answer`, `Answered`, `AnyResponse` (§5.3) |
| `Zone.Spec`, `Zone.build`, `Zone.ZoneError` | `ZoneBuilder::{rrset, delegate, build}`, `ZoneError` (§5.2) |
| `Zone.View`, `Zone.answerPartial` | `View` and `answer` over any view (§5.1) |
| `Zone.Lazy`, `Zone.Provider`, `Zone.lazyView` | `Lazy`, `Provider`, `Lazy::view` (§5.4) |
| `Authority.Ask`, `Observed`, `Known`, `Step`, `respond` | `services::dns::authority::{Ask, Observed, Known, Step, Authority::respond}` (§7.1) |
| `Authority.loop` | `AuthorityEngine`'s handling of `Need`, `Reply`, and `Failed` for one request (§7.2) |
| `Authority.relay`, `Authority.overlay`, `Authority.zones` | `Relay`, `Overlay`, `Zones` (§7.4) |
| `Exchange.Token`, `send`, `onReply`, `advance` | `services::dns::exchange::{Token, Transmit, Input::Reply, Engine::advance}` (§6.1, §6.2) |
