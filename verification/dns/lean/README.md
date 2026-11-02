# DNS: Lean 4 verification

This directory holds machine-checked proofs about the pure parts of Fictionet's DNS: names, the wire format,
truncation, zones and the answer algorithm, partial views, authorities, exchange matching, DNSSEC validation
and signing, the algorithm policy, providers and signers, the chain check, the resolver's cache, and the
resolver. It also holds an executable Lean reference that writes test vectors for the differential test,
`tests/dns_vectors.rs`. It uses Lean core only, with no Mathlib. The toolchain is
`leanprover/lean4:v4.35.0` (see `lean-toolchain`). A clean build takes about ten seconds.

## Build and check

```sh
cd verification/dns/lean
lake build                       # every proof, Dns/Axioms.lean, and the generator; fails on any error
lake exe gen <dir> <seed>        # writes <dir>/{names,wire,restore,fit,respond,zone,partial,signed,policy,chain,cache,resolver}.json
```

`lake build` prints the axioms of every headline theorem from `Dns/Axioms.lean`. Each line must list only
`propext`, `Quot.sound`, and `Classical.choice`, or a subset of them. A `sorryAx` would mean an unfinished
proof; there is none. `cargo xtask dns-verify` runs this check and writes the vectors
into `target/dns-verify/vectors/<seed>/`. Vectors are regenerated, not committed. The same seed always
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
| `Dns/Exchange.lean` | tokens, generations, the matching rule of the step contract | `obsolete_ignored`, `match_requires_tuple`, `advance_clears` |
| `Dns/Dnssec.lean` | keys, DS, RRSIGs, NSEC and NSEC3 as records; `class SigScheme` and a concrete symbolic instance; the validator; offline signing with complete chains; online covering records | `secure_sound`, `secure_complete`, `insecure_needs_proof`, `insecure_complete`, `optout_wildcard_insecure`, `optout_never_secure_denial`, `nsec_cover_sound`, `white_lie_covers_only_qname`, `cover_unknown_is_unknown`, `signed_answers_validate` |
| `Dns/Policy.lean` | the IANA registry rows RFC 9904 and RFC 9905 set; `iana` derived from them | `sha1_never_secure`, `unsupported_is_insecure_not_bogus`, `not_performed_never_ad`, `iana_matches_registry` |
| `Dns/Records.lean` | providers and signers as functions to published records; `Signed<D>` over any facts | `lazy_agrees_complete`, `signer_agnostic`, `validate_records_only` |
| `Dns/Chain.lean` | `check_chain` over a tree of signed zones; the problems as propositions | `check_sound`, `check_complete`, `check_reports_real` |
| `Dns/Cache.lean` | entries with rank, expiry, validation, and generation; failures apart from negatives | `served_ttl_le_original`, `expired_never_served`, `failure_never_negative`, `rrsig_caps_ttl`, `rank_monotone` |
| `Dns/Resolver.lean` | `step : State → Event → State × List Out` over correct servers answering with `Zone.answer` | `measure_decreases`, `resolve_terminates`, `resolve_correct`, `glue_never_served` |
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
| `secure_sound` | Secure means authentic: the RRset's type and records (with its original TTL, or as the wildcard it was expanded from) were signed with the private key of a key vouched for from an anchor, by the zone the RRset is in. `Vouched` walks the anchor's DS, the DNSKEY sets their keys signed, and the DS sets the parents signed, each signature in the chain made by a vouched key's holder |
| `secure_complete` | every properly signed chain (`SecureChain`: the anchored DNSKEY set signed by a key the anchor names, each link's DS set signed by the zone above and naming a SEP key that signed the link's DNSKEY set, and an RRSIG over the RRset by the last zone) validates Secure; `secure_iff` is both directions |
| `insecure_needs_proof` | Insecure only with a proof (`InsecureCase`): no anchor at or above the name; the anchor's DS set wholly unsupported; or, below a secure prefix, a link whose parent proved there is no DS (an NSEC or NSEC3 at the cut with NS and without DS and SOA, an opt-out cover of the next closer name of the closest provable encloser, or NSEC3 iterations above the limit) or signed a DS set the policy wholly does not support; or a trusted chain to the RRset's zone and a wildcard expansion that only an opt-out NSEC3 backs (`OptOutChain`). A failed fetch never makes an answer Insecure |
| `insecure_complete` | every such proof makes the answer Insecure (for some reason: the priority among reasons is the validator's) |
| `optout_wildcard_insecure` | a trusted chain to a wildcard expansion that only an opt-out NSEC3 backs (`OptOutChain`) validates Insecure, never Secure |
| `optout_never_secure_denial` | when no NSEC proves a name away and every NSEC3 covering its next closer name has opt-out, NXDOMAIN is never Secure |
| `nsec_cover_sound` | an NSEC of a complete chain that covers a name, with its next name not below it, is right: the zone holds no node at or below that name |
| `white_lie_covers_only_qname` | an NSEC3 white lie covers only the hash of the name it was made for |
| `cover_unknown_is_unknown` | an online covering record never rests on an unknown fact: an unknown name, or an unknown fact on the way up to the closest encloser, gives `unknown` and no record (`cover_knows`: a record for a name's nonexistence exists only when the view knows the name absent, its closest encloser present, and the wildcard there absent) |
| `signed_answers_validate` | every RRset a signed zone serves from its own nodes, with the RRSIGs it serves for them, validates Secure under the zone's own anchor while the window holds, with honest signers using validated algorithms and a SEP key |
| `sha1_never_secure` | under `iana`, an RRset signed only with algorithm 5 or 7 is never Secure |
| `unsupported_is_insecure_not_bogus` | a DS set the policy wholly does not support makes the zone Insecure, whatever its DNSKEY set and signatures are, at the anchor and (`unsupported_link_insecure`) at any link a secure chain reaches; `sha1_ds_insecure` is the RSASHA1 case under `iana` |
| `not_performed_never_ad` | with no anchors nothing is validated, and AD is set only for Secure data |
| `iana_matches_registry` | `iana`'s sets are the registry columns read through RFC 9905: validate what "Use for DNSSEC Validation" marks MUST or RECOMMENDED except 5, 7, and what ring cannot check; digests likewise; sign and delegate with what the code implements and the use columns allow |
| `lazy_agrees_complete` | a lazy zone that holds part of a complete zone, over a provider that agrees with it on every name it does not hold, answers every question as the complete zone does |
| `signer_agnostic` | the records an online signer publishes depend on each signer only through its DNSKEY and signing function, so two lists of signers of any two implementations that agree on those publish the same records |
| `validate_records_only` | composing the two: whatever lazy zone over whatever agreeing provider, and whichever agreeing signers, the validator reaches the same result as for the complete zone (`validate_providers_agree`: for two providers) |
| `check_sound` | when the check reports nothing, every RRset a zone serves from its own nodes validates Secure or Insecure along the chain from the anchored zone down a path of the tree; never Bogus or Indeterminate |
| `check_complete` | every problem the tree has is reported; `check_reports_real`: nothing else is |
| `served_ttl_le_original` | a served RRset's TTL, counted down, is never above the TTL it was offered with |
| `expired_never_served` | an entry is served only while it lives: written in the current generation and not expired |
| `failure_never_negative` | a cached failure never answers NXDOMAIN or NODATA; while it lives it answers SERVFAIL |
| `rrsig_caps_ttl` | a Secure RRset's entry expires no later than its RRSIG |
| `rank_monotone` | data offered at a lower rank than the live entry for its key changes nothing |
| `measure_decreases` | every step of a resolution spends work or finishes it |
| `resolve_terminates` | a resolution always ends, whatever the network loses |
| `resolve_correct` | whatever is lost, the answer is the hierarchy's answer (`spec`, from the root down) or SERVFAIL, and the cache stays sound; with nothing lost, root hints, and work for one query per label and one more, it is the hierarchy's answer |
| `glue_never_served` | every RRset in an answer is in the answer section of an authoritative server's answer to that question |

Supporting results: `answer_never_unknown` (a complete zone never
answers Unknown), `build_wf` (the builder makes well-formed zones), `lazy_answer` (a lazy view's answer is
the answer of the zone it leaves behind), `relay_loop_terminates`, `overlay_loop_terminates`, and the
invariant `Exchange.Inv` with `inv_send`, `inv_onReply`, and `inv_advance` (no cache entry is ever of an older
generation, and tokens are fresh). For the DNSSEC and resolver files: `walk_trusted`, `walk_insecure`, and
the step lemmas (`keyStep_ok`, `dsStep_ok`, `linkStep_ok`, `noDsProof_some`, `noDsProof_of_evidence`) relate
each step of the validator to a proposition; `Chain.link_step` and `Chain.path_walk` carry `check_sound`;
`Resolver.referral_stable` (a referral to a cut is the same for every name below it), `step_sound`,
`drive_sound`, `exhaust`, and `drive_complete` carry `resolve_correct`.

Each headline theorem has an `example` in `Dns/Axioms.lean` applying it to a concrete input, the DNSSEC ones
with the concrete scheme `Dnssec.Symbolic.scheme`: `example.com.` signed with a KSK and a ZSK, an RSASHA1
anchor, an opt-out denial, a lazy `example.org.` with a second `Sign` implementation, a parent and child the
chain check passes, a cache, and a root delegating `test.`. Computed facts there (a wildcard answer validating
Secure, the child's RRset validating Secure down the chain, the resolver's answer with and without a loss) are
checked by the kernel.

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
| `respond.json` | `bytes`, `transport` (`udp` or `tcp`) | `parsed`: `silent`; `reject` with `rcode` (extended), `flags`, and `opt` (its version, or null); or `request` with `rd`, `cd`, `ad`, `question`, `edns`, and the `answer` flags and `answer_opt` of an authoritative NOERROR answer to it through the server front |
| `zone.json` | `zone` (`apex`, `records`), `any` (`hinfo`, `one_rrset`, `all`), `request` (`qname`, `qtype`) | `rcode`, `aa`, `answer`, `authority`, `additional`, `required_additional` |
| `partial.json` | as `zone.json`, plus `unknown`: names whose facts are unknown | `unknown` (a name), or `response` |
| `signed.json` | `zone` (no DNAME), `keys` (`id`, `alg`, `sep`, `corrupt`), `window`, `denial` (`nsec`, or `nsec3` with `opt_out`), `request`, `time`, `policy`, `anchor_digest_type`, and for about a third of the cases a signed `parent` (`zone`, `keys`, `denial`) at the name above the apex, delegating to the zone with a DS set for its KSK, a wrong digest, RSASHA1, or no DS | `rcode`, `aa`, and with DO=1 the `answer` and `authority` lines each followed by its RRSIG lines, `additional`, `denial` (NSEC or NSEC3 lines with RRSIGs), `dnskey` (the DNSKEY set and its RRSIGs), and `validation`: one result per answer RRset and one for the denial of a negative answer, under the zone's own anchor (a DS of digest type 2 for each SEP key) and the one-link chain, or with a `parent` under the parent's anchor and the chain down the delegation, with `parent_dnskey` and `delegation` (the parent's DS set or no-DS proof, with RRSIGs); or `unknown` |
| `policy.json` | `algorithm`, `digest`, `policy`: the string `iana` for `Policy.iana`, which the test reads as Rust's `AlgorithmPolicy::iana`, or a random one (`validate`, `digests`, `max_nsec3_iterations`) | `treatment`: `supported`, `unsupported_algorithm`, or `unsupported_digest` |
| `chain.json` | `tree`: the parent and the child `sub`, each with `zone`, `keys`, `window`, `denial`; `time`; `policy` | `problems`: `ds_mismatch`, `no_ds_proof_missing` (with `parent`, `child`), `window_closed` (`apex`, `time`), `unsupported_algorithm` (`apex`, `algorithm`) |
| `cache.json` | `limits` (`max_ttl`, `failure_ttl`); `ops`: `offer` (positive, negative, or failure, with time), `advance`, `serve` (key and time) | `served`: for each `serve` in order, `null` or the served positive RRset with its TTL counted down and its validation, the negative with its SOA, or the failure |
| `resolver.json` | `zones` (a root and some of `test.`, `example.`, `sub.example.`, each server at an address of its own), `hints`, `work`, `any`, `questions`, `losses` (one per query sent, in order; `true` is lost), `dead` (servers that never answer) | `answers` (a response per question; a question past the script uses no loss), `dead_answers` (a response per question with the `dead` servers never answering and work to spare), `lossy_answers` (per question, under the loss script with work to spare, the `response` and the servers its losses made it give up on, `gone`), and the final `cache` (each item with its rank: a cut's NS set, glue, or a question and its answer) |

Symbolic keys and signatures in `signed.json` and `chain.json`. A key is a number below 256. Its DNSKEY's
public key field is the base64 of that one octet, and its key tag is the number. A signature made with
private key `p` has key tag `p mod 1000` and signature field the base64 of `p` as two octets; it verifies
exactly when `p` is the key tag (below 1000) and it covers the records shown. A `corrupt` key signs with
`p = key + 1000`, so its signatures never verify. A DS digest is the hex of the identity encoding of the owner
and the key (`Dnssec.Symbolic.scheme.digest`: the owner's canonical wire form, then the SEP bit, the algorithm,
and the key octet). NSEC3 hashes are real: SHA-1 over the owner's canonical wire form with an empty salt and no
extra iterations, in base32hex. RRSIG times are decimal. Validation results are `{"result": "secure"}`,
`not_performed`, `indeterminate`, `insecure` with `why`, or `bogus` with the EDE `ede` (RFC 8914).

## Modelling choices (read before trusting a theorem)

- **Octets** are `Nat`. Theorems that rebuild numbers from octets say what range they need.
- **Names in zones are lowercase.** The zone, partial, and authority models take the question name as Rust's
  `LowerName`; restoring the question's case in owners is the server front's job, which `restore`
  covers for relays.
- **Compression** points a name, or the rest of a name after some labels, at an earlier occurrence with
  exactly the same octets. hickory may choose differently, so `wire.json` gives the decoded sections and
  the uncompressed `canonical` octets rather than Lean's compressed octets as the expected value. `fit.json`
  sizes come from this compressor: a differential test comparing `kept` must either use the same choices or
  treat a case whose RRsets fit only under one compressor as a size difference, not a logic difference.
- **The decoder** gives each name `length² + length + 256` steps and proves that is enough. Octets after the
  last record are ignored. A name that reads past the end of its RDATA is rejected.
- **`parse`** answers FORMERR without an OPT when the message does not decode, and FORMERR with an OPT when the
  fault is in an OPT record (one that does not read, one outside the additional section, a second OPT, an owner
  other than the root, or options that do not split).
  Header fields and the question are not echoed in the model; `respond.json` checks the RCODE, flags, and the
  OPT's presence and version.
- **Fit** treats each RRset as a list of records with the same owner and type, and measures candidates by
  encoding the whole message, OPT included. Within a section it keeps RRsets in order while they fit.
- **Zones** hold nodes by name. An empty non-terminal is not stored: a name with no node of its own but nodes
  below it is reported as `Empty`. A wildcard that is itself a cut gives a referral to that cut. DNAME at the
  question name is ordinary data; DNAME above it substitutes. The synthesized HINFO answer to QTYPE ANY
  (RFC 8482 §4.2) takes the smallest TTL among the node's RRsets.
- **DO=1 is outside the zone files.** RRSIGs and denial records belong to `Dns/Dnssec.lean`, which adds them to
  `Zone.answer`'s response (`SignedZone.answerDo`); the answers of `Zone.answer` are the DO=0 answers.
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
  which is "the zone answers what it holds" of `Lazy`.
- **Authorities are trees of asks**: finished, or ask one server and continue with what a client of that
  server saw. A Rust `Authority` whose `respond` reads `known` only through `Known::get` and returns `Need`
  only for asks it has not seen is such a tree. `respond_monotone` therefore holds for every authority
  without a finite-asks hypothesis; `loop_terminates` needs one.
- **Exchanges** model the state the matching rule touches: the generation, the next exchange number, the
  outstanding exchanges with their tuples, and state derived from replies, tagged with its generation.
  Waiting client queries survive a session change, to be restarted under the new generation.
- **Signatures are symbolic.** `SigScheme` asks that a signature made with a private key verifies under its
  public key (`verify_sign`) and that one that verifies was made with a private key whose public key it is
  (`verify_sound`), which is what unforgeability means symbolically. The concrete scheme makes the signature
  the pair of private key and message. The differential test checks Rust with an oracle `Verify` of this
  scheme and then ties it to real signatures.
- **What is signed** is the RRSIG's algorithm, signer, labels, original TTL, and window, with the records. The
  type covered is the RRset's own. Key tags are not modelled: the validator tries every trusted key of the
  RRSIG's algorithm, which a key tag only narrows.
- **The validator** walks a chain of links from the deepest anchor at or above the name: each link has the
  parent's DS set or no-DS records, and the DNSKEY set, any of which may be a failed fetch. An RRSIG counts
  only when its signer is the zone, its algorithm is in the policy's `validate` and a trusted key's, and its
  window holds (RFC 4035 §5.3.1). When none verifies, the EDE is that of the first usable RRSIG's window
  (inverted 25, past 7, not yet 8) or a bad signature (6), or RRSIGs missing (10) when there is none. A DS
  set with no supported record makes the zone Insecure before the DNSKEY set is fetched. An RRSIG that counts
  fewer labels than the owner, not counting a leading `*`, is a wildcard expansion and needs a covering
  NSEC or NSEC3 for the next closer name (RFC 4035 §5.3.4); when only an opt-out NSEC3 covers it, an
  unsigned delegation may sit there, so the answer is Insecure, and so is a NODATA whose next closer name
  only an opt-out NSEC3 covers (RFC 5155 §6, its erratum 3441). A denial for a DS question is checked
  along the chain of the name above, since the parent zone holds DS (RFC 4035 §2.4), through the links whose
  zones hold that name; the root, which has no parent, answers its own DS question. A denial that proves
  nothing is Bogus for why its first unverified record failed, or for the missing denial. NSEC3 iterations
  above the policy's limit make a denial Insecure once its signature verifies (RFC 9276 §3.2); `iana` uses
  100, which RFC 9276 Appendix A found interoperable. A DNAME's synthesized CNAME is not validated through its DNAME, so `signed.json` zones
  have no DNAME.
- **Offline signing** signs the DNSKEY set with the SEP keys and everything else with the other keys (all
  keys when every key or no key has the bit). `Gen.lean` gives each zone keys of one algorithm; with keys of
  several, Rust makes that split within each algorithm, so every RRset is signed with each one (RFC 4035
  §2.2). The NSEC chain runs over the names that hold nodes, in
  canonical order. The NSEC3 chain also covers empty non-terminals; with opt-out it leaves out unsigned
  delegations and the empty non-terminals only they need. Records and denial carry the zone's negative TTL
  (RFC 9077 §3); the DNSKEY set carries the SOA's TTL.
- **Online covering records** (`cover`) are made per question from the view. NSEC uses the epsilon functions of
  RFC 4471 §3.1 (the immediate predecessor and the first name after the question and its descendants); that
  no existing name lies between them is RFC 4471's argument, not a theorem here. NSEC3 uses white lies
  (RFC 7129 §5), proved to cover only the question's hash.
- **Lazy zones ask for every name the answer reads.** `Records.onDemand` consults the provider for each name the
  answer reads that the zone does not hold: the path, the wildcard, CNAME targets, NS, MX, and SRV targets,
  and sibling glue. `Partial.lazyView` asks only for the path and the wildcards, so for an MX whose target the
  zone does not yet hold it answers Unknown. The Rust `Lazy` must ask for every name `answer` reads for
  `lazy_agrees_complete` to describe it. A provider describes a node by its RRsets, so a cut's glue is not
  something a provider gives: a lazy zone holds such cuts from the start (`Describable`).
- **Signers are an interface.** `Records.Sign` is Rust's `Sign` trait; `Records.publish` reads signers only
  through `signerView`, their DNSKEYs and signing functions, which is why `signer_agnostic` holds for any two
  implementations.
- **The chain check** runs over a list of signed zones; a zone's parent is the zone whose apex is its deepest
  strict ancestor. A parent that does not delegate to a zone it is the parent of reports the missing no-DS
  proof. `check_sound` assumes honest signers and DS sets owned by the child (`WellFormed`); the check itself
  does not look at signature bytes.
- **The cache** keeps one entry per key (name and type; the class is IN) and one TTL per RRset, so the rule that
  mixed TTLs in one RRset read as the lowest is the builder's (RFC 2181 §5.2). Times are seconds on the run's
  clock; RRSIG expirations arrive converted. A negative entry ranks as an authoritative answer and a failure
  below all data.
- **The resolver** follows referrals that go strictly down toward the name and asks a cut's servers in order,
  one query each, taking the next on a loss or a bizarre referral. Servers are named by the NS targets and
  answer with their zone's answer; a cut with no zone in the net never answers. It starts from the deepest
  cached cut at or above the name, except the name itself for DS, which its parent answers. CNAME and DNAME
  targets outside the answering zone are not chased and glueless NS addresses are not resolved; the
  hierarchy's answer `spec` is defined the same way, so `resolve_correct` compares like with like. `follow`
  recurses on the distance from the zone's apex to the name.

## How the Lean definitions correspond to the Rust code

| Lean | Rust |
|---|---|
| `Name.fold`, `Name.eqCI` | `LowerName` construction and comparison (hickory) |
| `Name.canonLt`, `Name.canonCmp` | `Name::cmp_canonical` (RFC 4034 §6.1) |
| `Name.below` | `Name::zone_of` |
| `Name.wireLen`, `Name.ofLabels?` | `Name::len` and the label checks of hickory's name decoder |
| `Wire.decode`, `Wire.encode` | hickory's `BinDecoder` and `BinEncoder` under `protocols::dns` |
| `Wire.compressible` | the record types hickory compresses names in (RFC 3597 §4) |
| `Wire.restore` | `protocols::dns::relay::restore` |
| `Wire.parse` | `protocols::dns::request::Request::parse` |
| `Wire.respondHeader` | the reply header the server front writes |
| `Fit.Resp`, `Fit.Limit`, `Fit.fit`, `Fit.Limit.forRequest` | `protocols::dns::fit::{Response, Limit, fit}`, `Limit::for_request` |
| `Zone.Fact`, `Zone.Node`, `Zone.Zone` | `services::dns::zone::{Fact, Node, Zone}` |
| `Zone.look` | `View::node` of a complete zone's view |
| `Zone.answerWith`, `Zone.answer`, `Zone.Answered`, `Zone.AnyResponse` | `zone::answer`, `Answered`, `AnyResponse` |
| `Zone.Spec`, `Zone.build`, `Zone.ZoneError` | `ZoneBuilder::{rrset, delegate, build}`, `ZoneError` |
| `Zone.View`, `Zone.answerPartial` | `View` and `answer` over any view |
| `Zone.Lazy`, `Zone.Provider`, `Zone.lazyView` | `Lazy`, `Provider`, `Lazy::view` |
| `Authority.Ask`, `Observed`, `Known`, `Step`, `respond` | `services::dns::authority::{Ask, Observed, Known, Step, Authority::respond}` |
| `Authority.loop` | `AuthorityEngine`'s handling of `Need`, `Reply`, and `Failed` for one request |
| `Authority.relay`, `Authority.overlay`, `Authority.zones` | `Relay`, `Overlay`, `Zones` |
| `Exchange.Token`, `send`, `onReply`, `advance` | `services::dns::exchange::{Token, Transmit, Input::Reply, Engine::advance}` |
| `Dnssec.Key`, `Ds`, `Rrsig`, `Nsec`, `Nsec3` | hickory's `DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3` under `protocols::dns::dnssec` |
| `Dnssec.SigScheme.verify`, `Symbolic.scheme` | `dnssec::Verify`; the differential test's oracle `Verify` |
| `Dnssec.Signer`, `Records.Sign` | `dnssec::{ZoneKey, Sign}` |
| `Dnssec.AlgorithmPolicy`, `AlgorithmPolicy.treat`, `Policy.iana` | `dnssec::AlgorithmPolicy`, its DS treatment, `AlgorithmPolicy::iana` |
| `Dnssec.Anchor`, `anchorFor` | `dnssec::{TrustAnchor, Anchors}` |
| `Dnssec.Link`, `Chain`, `walk` | `dnssec::Chain` and the walk from the anchor down |
| `Dnssec.noDsProof`, `denialResult`, `nx`, `nx3`, `nodata`, `nodata3` | `dnssec::proof` (RFC 4035 §5.4, RFC 5155 §8) |
| `Dnssec.validateRrset`, `validateDenial`, `Validation`, `Insecure`, `Ede` | `dnssec::{validate_rrset, validate_denial, Validation, Insecure}`, `EdeCode` |
| `Dnssec.SignedZone`, `nsecChain`, `nsec3Chain`, `answerDo` | `zone::Zone::signed` and the DO=1 answer |
| `Dnssec.cover`, `whiteLie`, `epsilonNsec` | `zone::cover` |
| `Records.onDemand`, `lazyAnswer` | `Lazy::view` with `answer` |
| `Records.publish` | `Signed<D>` serving one question |
| `Chain.check`, `Chain.Problem` | `zone::chain::{check_chain, ChainProblem}` |
| `Cache.Cache`, `Entry`, `Rank`, `insert`, `serve`, `advance` | `resolver::cache::{Cache, Entry, Rank}` and their store, lookup, and generation rules |
| `Resolver.step`, `start`, `run`, `runAll` | `Resolver` as an `Engine`, driven by `memory::drive` over a `MemoryNet` with scripted losses |
