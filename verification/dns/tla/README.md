# DNS in TLA+

Three specs model the DNS engines of `services::dns` and
`protocols::dns::dnssec`: the recursive resolver, the step contract every
engine keeps, and the
DNSSEC validator with the resolver's rendering of its result. Each spec has
flags that remove one rule the engines follow, so one spec gives both the
proof of the rule and the counterexample that shows why it is there.

| Spec | What it models | Rust |
|---|---|---|
| `Resolution.tla` | The resolver against zones `.`, `tld`, `sld.tld`, and `alt.tld`, each with one good and one lame server; an address, a CNAME, an empty non-terminal, a missing name, a glued nameserver, a CNAME loop across two zones, and a wildcard; questions of type A and AAAA; queries from a port and with a DNS ID drawn for each, and an off-path attacker forging replies; a rogue server adding a record outside its bailiwick; two clients; a network that loses and truncates; one world edit; TTLs of 1 and 2 | `services/dns/resolver/{mod,cache,resolution,front}.rs` |
| `Exchanges.tla` | The step contract of `Engine`: tokens with a generation and an exchange identity, matching on the token and the tuple, duplicate, late, and spoofed replies, `Gone`, `Advance`, one resolution shared by two clients | `services/dns/exchange.rs` (`Token`, `Generation`, `Input`, `Action`, `Engine`), kept by `AuthorityEngine` and `Resolver` |
| `Validation.tla` | The validator on a path root, tld, sld, with the data free per config (signer, parent proof, window, algorithm, changes after signing, the world's edits), clock skew, unreachable zones, the AD/CD rendering, `check_chain`, and two validators with signers and records of their own | `protocols/dns/dnssec/{validate,policy,proof}.rs`, `services/dns/zone/chain.rs`, `services/dns/resolver/front.rs` |

## Properties

| Spec | Property | Kind | Meaning |
|---|---|---|---|
| Resolution | `AnswersTrueWithinTtl` | invariant | every record of a NOERROR answer was in the data, for the name and type it was read for, at some second within its TTL before the reply, or, for a record fetched for the resolution that ran out before the reply, within its TTL before it ran out |
| | `NegativeTrue` | invariant | NXDOMAIN only for a name with no node at or below it and no wildcard; NODATA only for a name that exists, at a node or by a wildcard, without the type asked; each held within the negative TTL |
| | `NoPoison` | invariant | every cached record came from a server for a zone at or above its name |
| | `GlueNeverAnswers` | invariant | no answer to a client rests on glue |
| | `TtlSound` | invariant | no answer uses a record read from the cache at or after its expiry; every record goes out with a TTL that ends by its own expiry, so a record fetched for the resolution that ran out before the reply goes out with TTL 0 (RFC 1035 section 7.4) |
| | `CachedNegativeTrue` | invariant | every cached NXDOMAIN or NODATA was true, for its name and type, at some second within its TTL since it was stored, so nothing a truncated reply left out is cached as a negative (RFC 2181 section 9) |
| | `FailureNeverNegative` | invariant | a cached failure never answers NXDOMAIN or NODATA (RFC 9520) |
| | `CachedFailureTriedAll` | invariant | the resolution that cached a failure tried every server of its zone (RFC 9520 section 3.1), so a failure the work bound caused before every server was tried is never cached for another client |
| | `WorkBounded` | invariant | every client's question stays within `MaxWork` queries, and every resolution within `MaxChain` CNAME restarts |
| | `BoundIsOwn` | invariant | a client fails for want of queries only once its own question's budget is spent (RFC 1034 section 5.3.3), never because the client that started a shared resolution spent its own |
| | `ReferralsDescend` | invariant over steps (`PROPERTY`) | the cut a resolution works from always contains its name, and a referral is followed only strictly downward |
| | `LoopServfails` | invariant | the CNAME loop always ends in SERVFAIL |
| | `EveryQueryAnswered` | liveness | every question asked is answered, under weak fairness of delivery and of the resolver's steps |
| Exchanges | `MatchRequiresTuple` | invariant over steps (`PROPERTY`) | engine state changes on a reply only if its token is outstanding and its source, ID, and question equal the transmit's |
| | `ObsoleteNeverPopulates` | invariant | no cache entry and no answer rests on an exchange of an older generation |
| | `DuplicateHarmless` | invariant over steps (`PROPERTY`) | a second copy of a reply changes nothing |
| | `CancelPreservesWaiters` | invariant | after `Gone(c)`, every other client still waits on live work or has its answer |
| | `OneAnswerPerQuery` | invariant | each client query gets at most one answer |
| | `EveryAcceptedAnswered` | liveness | every accepted query is answered unless its client goes |
| Validation | `SecureImpliesChain` | invariant | Secure only with a valid chain from a configured anchor to the answer |
| | `InsecureNeedsProof` | invariant | Insecure only with no covering anchor, or below a validated chain a signed no-DS proof, an opt-out cover, or a DS whose algorithm the policy does not admit, each from a DS set that was fetched |
| | `UnreachableLinkIndeterminate` | invariant | a zone below a validated chain whose DS set cannot be fetched is Indeterminate, whatever that set would have said, as `Check::delegation` reads the DS fetch before `Check::dnskeys` reads the keys |
| | `NoDowngrade` | invariant | a valid chain is always Secure |
| | `IndeterminateOnlyUnreachable` | invariant | Indeterminate only when a zone could not be fetched |
| | `AdOnlySecure` | invariant | AD only for Secure data with DO or AD in the query; never for NotPerformed, never because an upstream set it |
| | `BogusServfails` | invariant | Bogus with CD=0 is SERVFAIL |
| | `CdPassesData` | invariant | with CD=1 the data reaches the client whatever the validation found |
| | `Sha1Insecure` | invariant | under the default policy a zone whose DS names algorithm 5 or 7 below a validated chain is Insecure, never Secure (RFC 9905 section 2) |
| | `RecordsOnly` | invariant | two validators, each with its own signer and records, reach the same result whenever their records are equal |
| | `CheckChainAgrees` | invariant | a tree `check_chain` passes validates Secure or Insecure everywhere |
| | `EditedWorldZoneSecure` | reachability | a zone of the world's own that it edited and signed validates Secure under the world's anchor; its `Never...` form must fail |
| | `EditedUnderRealAnchorBogus`, `InventedUnderOptOutInsecure`, `InventedTldUnderNsecBogus`, `WorldRootAllSecure`, `UnsignedWithIanaAnchorBogus`, `NoAnchorsNotPerformed` | reachability | each scenario happens; its `Never...` form must fail |

## Running

```sh
# JDK 21 in ~/.local/jdk21, tla2tools.jar 2.19 in ~/.cache/adorably-fv
java -XX:+UseParallelGC -Xmx6g -cp tla2tools.jar tlc2.TLC -workers 8 \
    -config Resolution_base.cfg Resolution.tla
```

`cargo xtask dns-verify tlc` runs TLC once per
property per config and writes its output to `target/dns-verify/tlc/`. A
config whose first lines read `\* expect violation: <Property>` is expected
to fail exactly that property, in a run that checks that property alone;
every other config must pass every property it lists. A config that lists a
liveness property has no `SYMMETRY`. Run TLC under a memory cap (`-Xmx6g`
fits every config here).

Configs:

* **Resolution:** `_base`, `_concurrent` (safety, clients symmetric),
  `_concurrent_live` (the same model, liveness, no symmetry), `_loop`,
  `_rogue`, `_edit`, `_types` (questions of type AAAA beside A), `_spoof`
  (two ports, two IDs, and a forged reply). Ablations: `_nobailiwick`,
  `_nobound`, `_cachetc`, `_noexpiry`, `_failureasnegative`,
  `_cachebounded`, `_nocountdown`, `_noid`, `_noport`, `_notype`,
  `_cachebyname`, `_sharedbound`.
* **Exchanges:** `_base`, `_advance`, `_cancel`. Ablations: `_idonly`,
  `_flushonly`, `_cancelshared`.
* **Validation:** `_paths`, `_skew`, `_unreachable`, `_policy`,
  `_signers`, the six `_witness_*` (one reachability witness each, every
  one expected to fail), and
  `_edits` (the witness that an edited zone of the world's own can be
  Secure). Ablations: `_trustupstreamad`, `_nopolicy`,
  `_missingasinsecure`, `_signerpeek`.

Bounds. Every counter is bounded in the enabling conditions of its
actions, never by a `CONSTRAINT`, so the liveness checks are sound:

* **Resolution:** the clock by `MaxTime` 4; `MaxWork` 4 upstream queries
  per client question and `MaxChain` 3 CNAME restarts per resolution
  (`MaxWork` 6 in `_loop`
  and `_nobound`; see the modelling choices); one loss, one truncation, one
  edit; one forged reply, two ports, and two IDs in `_spoof` and its
  ablations, and one port and one ID elsewhere; each client asks a fixed
  script, one question at a time. The work
  and chain counters count with or without the bounds and stop one past
  them, so in `_nobound` `WorkBounded` fails, and in
  `_nobound_unanswered` (the same constants) the loop repeats a state and
  TLC reports the liveness violation as a lasso. Every control names one
  property, so TLC's first error is the one expected.
* **Exchanges:** the clock by `MaxTime` 3, exchange identities by
  `MaxExchanges` 4, generations by `MaxGeneration` 2 in `_advance` and
  `_flushonly` and 1 in the other four configs; one duplicate, one spoofed
  reply, one `Gone`.
* **Validation:** no counters; the data dimensions are finite sets.

## Results

TLC 2.19, JDK 21, `-Xmx6g`, one TLC run per property: `-workers 8` for
the configs that must pass, `-workers 1` for ablations and witnesses so each
counterexample is a shortest one. "pass" means TLC found no error;
"violated" means it found the counterexample shown, as a sequence of
actions after the initial state. Every invariant of a config explores the
same state space, so a row covers all the invariants it names; times are
per run. A `PROPERTY` run keeps its config's symmetry, so `ReferralsDescend`
in `_concurrent` explores the same states as the invariants there.

| Config | Properties | Result | Distinct states | Depth | Time | Counterexample |
|---|---|---|---|---|---|---|
| Resolution_base | the 11 invariants, `ReferralsDescend` | pass | 2749819 | 66 | 11-16 s | |
| Resolution_base | `EveryQueryAnswered` | pass | 2749819 | 66 | 142 s | |
| Resolution_concurrent | the 11 invariants, `ReferralsDescend` (symmetry) | pass | 4359020 | 59 | 19-20 s | |
| Resolution_concurrent_live | `EveryQueryAnswered` | pending | pending: /home/souvik/Projects/amlalabs/.fictionet-comp-work/fvdeep-logs/dns-tla-Resolution_concurrent_live.log | pending | 519 s | |
| Resolution_loop | the 11 invariants, `ReferralsDescend`, `EveryQueryAnswered` | pass | 12560 | 30 | 0-1 s | |
| Resolution_rogue | the 11 invariants, `ReferralsDescend`, `EveryQueryAnswered` | pass | 36437 | 33 | 0-2 s | |
| Resolution_edit | the 11 invariants, `ReferralsDescend` | pass | 468532 | 45 | 2 s | |
| Resolution_edit | `EveryQueryAnswered` | pass | 468532 | 45 | 17 s | |
| Resolution_nobailiwick | `NoPoison` | violated | 312 | 11 | 1 s | Ask, Advance, Serve, Receive (root's referral), Advance, Serve, Receive (tld's referral), Advance, Serve, Receive: alt.tld's answer for x.w.alt.tld carries www.sld.tld, which is cached |
| Resolution_nobound | `WorkBounded` | violated | 5406 | 21 | 0 s | the loop's CNAME chase restarts past `MaxChain` |
| Resolution_nobound_unanswered | `EveryQueryAnswered` | violated | 38802 | lasso | 3 s | down to sld.tld and over to alt.tld, then round a lasso: the chain follows loop.sld.tld and loop.alt.tld from the cache forever, its counter stopped one past `MaxChain` |
| Resolution_cachetc | `CachedNegativeTrue` | violated | 33 | 6 | 0 s | Ask, Advance, Serve, Truncate, Receive: the truncated reply for cn.sld.tld, a CNAME, is cached as NODATA |
| Resolution_noexpiry | `TtlSound` | violated | 5031 | 20 | 0 s | Ask cn.sld.tld; Advance, Serve, Receive three times down to sld.tld; Advance follows the CNAME; Advance, Serve, Receive, Advance for www.sld.tld; Ask www.sld.tld; Tick, Tick, Advance: the cache answers www.sld.tld after its two-second TTL ran out |
| Resolution_failureasnegative | `FailureNeverNegative` | violated | 173 | 9 | 0 s | Ask, Advance, Lose, Timeout, Advance, Serve, Receive, Advance: the query to one root server is lost and times out, the other refuses, and the cached failure answers NXDOMAIN |
| Resolution_cachebounded | `CachedFailureTriedAll` | violated | 1283 | 15 | 0 s | Ask, then Advance, Serve, Receive twice down to sld.tld; Advance, Serve, Truncate, Receive (the TCP retry is the fourth query); Lose, Timeout, Advance: the work bound ends the resolution and its failure is cached, with one of sld.tld's servers never tried |
| Resolution_nocountdown | `TtlSound` | violated | 2248 | 17 | 0 s | Ask cn.sld.tld; Advance, Serve, Receive three times down to sld.tld, fetching the CNAME with its one-second TTL at second 0; Advance follows it; Advance, Tick, Serve, Receive, Advance for www.sld.tld: the answer at second 1 carries the CNAME, which ran out at second 1, with TTL 1 |
| Resolution_types | the 11 invariants, `ReferralsDescend`, `EveryQueryAnswered` | pass | 739960 | 58 | 3-31 s | |
| Resolution_spoof | the 11 invariants, `ReferralsDescend`, `EveryQueryAnswered` | pass | 157600 | 22 | 1-8 s | |
| Resolution_noid | `AnswersTrueWithinTtl` | violated | 381 | 6 | 0 s | Ask, Advance, Spoof (the root's exchange, the wrong ID), Receive, Advance: the forged www.sld.tld answer reaches the client |
| Resolution_noport | `AnswersTrueWithinTtl` | violated | 379 | 6 | 0 s | the same, with the wrong port |
| Resolution_notype | `AnswersTrueWithinTtl` | violated | 381 | 6 | 0 s | the same, with the question's type AAAA: an AAAA record answers the question for A |
| Resolution_cachebyname | `NegativeTrue` | violated | 2857 | 18 | 0 s | cn.sld.tld AAAA ends NODATA at www.sld.tld, cached under the name alone, which then answers www.sld.tld A NODATA |
| Resolution_sharedbound | `BoundIsOwn` | violated | 3402 | 16 | 0 s | Ask (c1, cn.sld.tld), Ask (c2 joins before any query); Advance, Serve, Receive twice down to sld.tld; Advance, Serve, Truncate, Receive (the TCP retry is c1's fourth query); Lose, Timeout, Advance: c1's budget is spent, and c2, which paid for none, gets SERVFAIL with it |
| Exchanges_base | the 3 invariants, `MatchRequiresTuple`, `DuplicateHarmless` | pass | 66914 | 19 | 1 s | |
| Exchanges_base | `EveryAcceptedAnswered` | pass | 66914 | 19 | 3 s | |
| Exchanges_advance | the 3 invariants, `MatchRequiresTuple`, `DuplicateHarmless` | pass | 4564834 | 28 | 10-12 s | |
| Exchanges_advance | `EveryAcceptedAnswered` | pass | 4564834 | 28 | 204 s | |
| Exchanges_cancel | the 3 invariants, `MatchRequiresTuple`, `DuplicateHarmless` | pass | 853762 | 23 | 2-3 s | |
| Exchanges_cancel | `EveryAcceptedAnswered` | pass | 853762 | 23 | 26 s | |
| Exchanges_idonly | `MatchRequiresTuple` | violated | 64 | 5 | 1 s | Query, Send, Spoof, Deliver |
| Exchanges_flushonly | `ObsoleteNeverPopulates` | violated | 282 | 6 | 0 s | Query, Send, Serve, Advance, Deliver |
| Exchanges_cancelshared | `CancelPreservesWaiters` | violated | 13 | 4 | 1 s | Query, Query, Gone |
| Validation_paths | the 11 invariants | pass | 124416 | 1 | 1-2 s | |
| Validation_skew | the 11 invariants | pass | 10368 | 1 | 0-1 s | |
| Validation_unreachable | the 11 invariants | pass | 147456 | 1 | 0-1 s | |
| Validation_policy | the 11 invariants | pass | 3456 | 1 | 0-1 s | |
| Validation_signers | the 11 invariants | pass | 65536 | 1 | 0-1 s | |
| Validation_witness_edited, _optout, _tld, _root, _unsigned, _noanchors | one `Never...` form each | violated (reachable) | 1 | 1 | 0-1 s | an initial state of each scenario |
| Validation_edits | `NeverEditedWorldZoneSecure` | violated (reachable) | 1 | 1 | 1 s | a world zone signed with key B under anchor B, an RRset of it edited and signed again: Secure |
| Validation_trustupstreamad | `AdOnlySecure` | violated | 1 | 1 | 0 s | no anchors configured (NotPerformed), the upstream reply has AD, the client gets AD |
| Validation_nopolicy | `Sha1Insecure` | violated | 1 | 1 | 1 s | a chain of key A where sld's DS names algorithm 5: Secure |
| Validation_missingasinsecure | `InsecureNeedsProof` | violated | 1 | 1 | 1 s | the root cannot be fetched: Insecure with no proof |
| Validation_signerpeek | `RecordsOnly` | violated | 1 | 1 | 0 s | sld's RRset changed after signing: Bogus for signer B, Secure for signer A |

## Modelling choices

General:

* Names, records, and messages are abstract values, not wire bytes. The
  wire, `fit`, and the answer algorithm are Lean's;
  these specs check the behavior of the engines around them.
* Properties that relate two states (`ReferralsDescend`,
  `MatchRequiresTuple`, `DuplicateHarmless`) are written as `[][A]_vars`
  and listed under `PROPERTY`; they are safety properties, checked on every
  step.
* While writing the specs, reachability was checked with throwaway
  invariants on every non-ablation config of Resolution and Exchanges:
  answers of each kind, the wildcard, shared resolutions, TC
  retries, chain restarts, the chain bound in `_loop`, stale glue and the
  edit's new values, spoofed, duplicate, and late replies delivered and
  ignored, SERVFAIL after both servers, answers after `Advance` and after
  another client's `Gone`. So no property holds only because its premise never
  occurs. The Validation witnesses are kept as the `_witness_*.cfg`
  configs, one per form.

Resolution:

* Questions are of type A or AAAA. The data holds only A and CNAME
  records, so AAAA ends NODATA after any CNAME, at a node or at the
  wildcard. The cache keeps each answer, a CNAME included, under the name
  and the type asked; Rust keeps a CNAME under its own type and finds it
  for every type, which gives the same answers for this data.
* Each resolution has at most one exchange outstanding. A query goes out
  from a port of `Ports` with a DNS ID of `IDs`, both drawn for it
  (RFC 5452), and the resolver takes a reply only when it comes from the
  server asked, over the same transport, to that port, with that ID and
  question, name and type (`exchange::matching`; Rust's token is the
  port). A reply no exchange takes is dropped (`Ignore`, as
  `Event::Ignored`). The forged reply of `_spoof` is the worst an off-path
  attacker does: it hits an exchange that is outstanding, from the server
  asked, about the name asked, with a poisoned answer, and gets every field
  right but one of the port, the ID, and the type, since guessing a 16-bit
  port and a 16-bit ID together is the attack RFC 5452 defeats. It does not
  hold back the timeout of the exchange it targets. Generations, duplicate
  replies, and spoofed sources are `Exchanges.tla`'s concern. `_noid`,
  `_noport`, and `_notype` each drop one field from the match, and the
  forged answer reaches a client; `_cachebyname` keeps answers by name
  alone, and the NODATA for AAAA answers a question for A.
* A lame server answers with an upward referral to the root (the root's
  lame server answers REFUSED). The resolver must reject the referral and
  try the other server.
* A server reads the data when it gets the query and replies at once. The
  clock does not advance while a reply is in flight, nor before the
  resolver acts on it, so a record's read time is the second the resolver
  stores it: simulated round trips are far shorter than a TTL second. A
  timeout is enabled by a lost message, not by the clock.
* The resolver starts with the root's servers known (priming is not
  modelled) and keeps every cut it learns: NS TTLs outlast `MaxTime`. Only
  `ns.sld.tld` is glued in the cache, which is the glue `GlueNeverAnswers`
  needs; the edit changes the child's address record and not the parent's
  glue, so stale glue is reachable.
* `MaxWork` counts upstream queries, TCP retries included, against each
  client's question, as Rust counts them against each client question's
  tree; `MaxChain` counts CNAME restarts. A resolution charges the client
  that started it. Once that client's budget is spent, a waiting client
  with queries left takes the resolution over and pays from then on, and
  the spent client gets SERVFAIL, as `Resolver::take_over` hands a lookup
  to another tree and fails the spent tree's nodes; with no such client,
  every client waiting gets SERVFAIL. `_sharedbound` lets only the client
  that started a resolution pay, and `BoundIsOwn` fails there.
  In `_loop` and `_nobound` `MaxWork` is 6, not the
  4 of the other configs: following the loop once takes five queries (root, tld,
  sld, tld again for alt, alt), so with 4 the work bound always ends the
  loop before the chain bound is ever reached, and the chain bound would go
  unchecked.
* Each record a resolution uses is marked as fetched in a reply to the
  resolution or read from the cache. A fetched record serves the
  resolution, whether or not the cache keeps it, with the TTL it has left,
  and with TTL 0 once that has run out (RFC 1035 section 7.4): following
  the chain again could only fetch it again. Only a link read from the
  cache that expires while the chase goes on makes the resolution follow
  the chain again from the question, keeping the work done. The first run
  found this case:
  without it the resolver answered a cached CNAME whose TTL had already run
  out (`TtlSound`). The Rust resolver does the same: `Resolver::ran_out`
  looks at the cached pieces of an answer, and when one ran out while the
  rest was resolved, `Resolver::answer_asker` clears the pieces and the
  chain is followed again from the question, its work so far still
  counted (the tree's `sent`) but its aliases counted afresh, since the
  alias count is the number of pieces; the model's restart keeps `spent`
  and starts `chain` at 0 the same way. A piece fetched for the question
  goes out with TTL 0. `_nocountdown`, where a fetched record keeps the
  TTL it came with, shows that `TtlSound` checks this.
* Rust asks one server address up to three times per transport before it
  gives up on it (`TRIES` in `resolver/resolution.rs`, RFC 9520 section
  3.1), each query charged to the work bound, and after a UDP timeout it
  picks again among the servers not given up on, the same one included.
  The model's one `Timeout` per server and transport stands for those
  tries, charges one query, and the next query goes to a server not yet
  tried.
* Rust rejects an upward or sideways referral through the same rule that
  drops out-of-bailiwick records: the authority section is kept only
  within the zone the server was asked for, so an NS RRset for a zone that
  is not strictly below it never counts as a referral (`answered` in
  `resolver/resolution.rs`). The model keeps `ReferralsDescend`'s rule
  apart from `CheckBailiwick`, so `_nobailiwick` removes less than
  deleting that filter from the Rust would.
* Rust keeps an NXDOMAIN under type ANY as well as under the type asked,
  so it answers every type at the name (`Cache::nxdomain_above`); the
  model keeps negatives under the name and type asked alone, and no script
  asks a missing name for two types.
* A failure after every server was tried is cached for `failure_ttl`
  (1 s) at the name the chain had reached. Rust caches a failure that
  persists twice as long as the one before it (RFC 9520 section 3.2);
  the model caches every failure for `failure_ttl`, and the Lean cache
  model checks the longer times. A resolution that reaches the
  work bound answers SERVFAIL without caching, as `Resolver::send` (in
  `resolver/resolution.rs`) leaves
  a failure the bound caused out of the cache: the bound is one question's
  budget and says nothing of the servers. When the bound is reached just
  as the last server has been tried, the model, like Rust, answers SERVFAIL
  without caching; `CachedFailureTriedAll` does not tell that case apart,
  since such a failure would be true. A chain that is too long answers
  SERVFAIL without caching too, so the cached CNAME stays.
* Wildcard synthesis is at the name's parent, which is all the data needs.
* Each client asks its script one question at a time, as a stub resolver
  does. With every question of one client in flight at once, `_base` passed
  four million states at depth 16 and was still growing when stopped;
  concurrency between resolutions is what `_concurrent` checks.
* `Clients` is a symmetry set only in `_concurrent`, which checks safety;
  `_concurrent_live` checks liveness on the same model without symmetry.

Exchanges:

* One piece of work shared by both clients, two servers, a deadline one
  second ahead; when both servers have been tried every waiter gets
  SERVFAIL.
* `MaxTime` stands for "`MaxTime` or later": at `MaxTime` every deadline
  counts as reached. The clock stays bounded and a deadline is never stuck
  in the future, so liveness stays sound.
* The driver ticks only while an exchange is outstanding, that is, while
  `next_deadline()` is some.
* The attacker is assumed to guess the 16-bit ID (the worst case); a
  spoofed reply differs in source address or question.
* Exchange identities never run out: each generation sends at most one
  exchange per server, so two generations use at most `MaxExchanges` 4.
* A server answers with the data of the session the exchange was sent in,
  and each reply carries that generation so `ObsoleteNeverPopulates` can be
  stated.
* The model's generations start at 1, so `MaxGeneration` 2 allows one
  `Advance`. Rust's start at 0 (`Tokens::new`, `Namespace::new`); only
  the order matters.
* After a timeout the model counts the server as tried at once, and when
  both are tried `GiveUp` answers SERVFAIL without a cache entry. Rust
  gives a server up after three timeouts per transport (`TRIES`), may ask
  the same server again before that, and caches the failure (`Entry::Failure`),
  which `Resolution.tla` models.

Validation:

* The validator is a function, so the spec has no steps: every behavior is
  one initial state, and TLC checks every combination of the config's
  choices (depth 1).
* Keys A and B. A DS names the key its digest matches (`DsA`, `DsB`), so a
  world can sign its root and every zone with its own key B under its own
  anchor.
* `alg[z]` is the algorithm the DS or the anchor names for `z`. An
  algorithm outside the policy makes the zone Insecure whatever its DNSKEY
  set holds: the resolver fetches the DS and DNSKEY sets of a zone together
  (`Resolver::link`), and `Check::dnskeys` decides from the DS algorithms
  before it reads the DNSKEY fetch (RFC 4035 section 5.2, RFC 9905 section
  2). DS digest types and the NSEC3
  iteration limit are not modelled; Lean's policy model covers them.
* Windows and the clock are three slots (past, now, future); skew is a
  clock that is not "now".
* An unreachable zone is one whose DNSKEY or DS set cannot be fetched. If
  `sld` is unreachable the answer itself is missing, so the client gets
  SERVFAIL even with CD. One bit stands for both sets; Rust tells them
  apart: a DS fetch that failed is Indeterminate (`Check::delegation`),
  while a DNSKEY fetch that failed under a DS set whose algorithms the
  policy does not validate is Insecure, since `Check::dnskeys` reads the
  algorithms first. Rust is also Indeterminate when the chain it gathered
  skips a cut or does not start at the anchor (`deeper_signer`,
  `Check::zone_keys`); the model takes the resolver to gather the whole
  path.
* With CD=1 the client checks signatures itself, so `Resolver` does not
  validate a fresh answer: it is NotPerformed and gets AD=0. An answer from
  the cache keeps what an earlier query without CD established (`cached`),
  so Secure data can still carry AD, and Bogus data passes with AD=0.
* Signer implementations publish the same records, and so do the world's
  complete and lazy zones, by the contracts Lean proves
  (`signer_agnostic`, `lazy_agrees_complete`). The check here is that the
  validator reads nothing else; `SignerPeek` lets it skip the signature
  check for signer A's records.
* The world signs its zones over their edits, so an edit (`edited`) is
  never a change after signing; `_edits` shows an edited zone of the
  world's own validating Secure under the world's anchor.
* `check_chain` reports five problems: `DsMismatch`, `NoDsProofMissing`,
  `WindowClosed`, `UnsupportedAlgorithm`, and `SignatureInvalid`. A zone
  whose RRset changed after signing (a `Zone::with` after `Zone::signed`)
  has none of the first four, yet validates Bogus; with only those,
  `CheckChainAgrees` fails in `_signers` on a tree signed with key A
  whose answer RRset changed after signing. `ChainProblem::SignatureInvalid
  { apex, owner, rtype }` is the fifth, for an RRset with no RRSIG that
  verifies under its zone's keys.

## How the models map to the Rust types

Resolution:

| Model | Rust |
|---|---|
| `cache[<<n, t>>]` | `Cache`, keyed by `(LowerName, RecordType, DNSClass)` |
| entry `t` = `"a"` or `"cname"` | `Entry::Positive { set, rank, expires, validation, proof }` |
| entry `t` = `"nx"` or `"nodata"` | `Entry::Negative { kind: Negative::NxDomain` or `NoData, .. }` |
| entry `t` = `"fail"` | `Entry::Failure { why: FailureKind, cd, until, lasts }`, kept for `Config::failure_ttl`; Rust keeps a failure that persists longer. The model has no CD bit: `cd` says whether the failed queries set it, for a forwarder that relays a client's CD |
| entry `rank` | `Rank::AuthAnswer` and `Rank::Glue` (two of the five ranks) |
| entry `readAt + ttl` | `expires: Instant` |
| entry `tried` of a failure | not stored: the model keeps what the failed resolution tried, since on the paths the model covers Rust writes `Entry::Failure` only when `Resolver::plan` has no server of the zone left to ask (RFC 9520 section 3.1); `Resolver::fail` also caches a failure for a priming cycle and for a name no known cut holds, which the model has no way to reach |
| a used record's `fetched` and `left` | `Piece::cached` (its negation) and the TTL `cache::ttl_left` renders |
| `known` | the cached cuts the resolution starts from |
| `res[q]` | one client question being answered: the `Asker` in `resolver/mod.rs` with the `Lookup` in `resolver/resolution.rs` it waits on, one lookup per name the chain reaches. `qn` is `Asker::next_question`, `zone` the cut `Resolver::plan` asks (`Lookup::delegation` or the deepest cached NS RRset), `out` the `Exchange` under the lookup's token (`to`, `transport`, `id`, `question`, `deadline`), `tried` is `Lookup::tried`, the addresses given up on per transport (RFC 9520 section 3.1), `payer` is `Lookup::tree`, `spent` is the tree's `sent` against `Config::work.queries`, and `chain` is the number of alias pieces against `Config::work.depth` |
| `waiting[q]` | the client queries waiting on one resolution, which they share |
| `ans[c][q]` | `Action::Answer`, rendered for its client |
| `Receive` | taking a reply that matches its exchange (`exchange::matching`): TC retries over TCP, answers stored in bailiwick only, referrals strictly below the cut, glue at glue rank |
| `Ignore` | a reply no exchange takes: `Event::Ignored` |
| `Timeout` | `Input::Tick` at the exchange's deadline |
| `CheckBailiwick`, `CacheTc`, `CheckExpiry`, `FailureAsNegative`, `BoundWork`, `CountDown` | the bailiwick check, "truncated replies are not cached", the `expires` check, `Entry::Failure` as its own variant, `Config::work`, and `cache::ttl_left` rendering each piece's TTL |

Exchanges:

| Model | Rust |
|---|---|
| `out`, each `[token, to, qn, txid, deadline]` | the engine's outstanding exchanges: `Token { generation, exchange }`, `Transmit::to`, the question, the DNS ID drawn from `entropy` |
| `gen` | `Engine::generation()`, a `Generation` |
| `Send` | `Action::Send(Transmit)` with a fresh token |
| `Deliver` | `Engine::handle(Input::Reply { token, from, transport, bytes })`; an ignored reply is `Event::Ignored` |
| `Timeout` | `Input::Tick` at `next_deadline()`, with `Action::Abandon(token)` |
| `GiveUp` | the SERVFAIL every waiter gets when no server is left |
| `Gone(c)` | `Input::Gone(Client)` |
| `Advance` | `Engine::advance(Session)`, driven by `world::net::dns::Namespace` |
| `cache`, `waiters` | the resolver's cache and waiters |

Validation:

| Model | Rust |
|---|---|
| `Records(..)` | the DNSKEY, DS, RRSIG, NSEC, and NSEC3 records a `Chain` gathers |
| `anchor` | `Config::anchors`: `None` is `"none"`; `Anchors` covering another tree is `"elsewhere"` |
| `PolicyAlgs` | `AlgorithmPolicy::validate`; `AlgorithmPolicy::iana()` admits no algorithm 5 or 7 |
| `clock` | `WallClock::at(now)`, the `Session` clock |
| `Walk`, `Validate` | `validate_rrset` and `validate_denial`, whose `Check::zone_keys` walks the chain with `Check::walk`, `Check::delegation`, and `Check::dnskeys`; `Resolver::check` gives NotPerformed with no anchors and an empty chain for an anchor elsewhere |
| result kinds | `Validation::{NotPerformed, Secure, Insecure(Insecure), Bogus(EdeCode), Indeterminate}`; reasons `Insecure::{ProvenNoDs, OptOutCovered, NoAnchor, UnsupportedAlgorithm}` and EDE codes 5, 6, 7, 8, 9, 12. `Insecure::{UnsupportedDigest, Nsec3Iterations}` and the other EDE codes are not modelled |
| `Established`, `Rendered` | what `Resolver` established (NotPerformed for a fresh answer under CD) and its front: AD, CD, SERVFAIL |
| `ChainProblems` | `check_chain -> Vec<ChainProblem>` |
| `impl1`, `impl2` | two `Sign` implementations |
| `edited`, `Stale` | a world's edit to a zone, which the world signs again; an RRset changed after signing (a `Zone::with` after `Zone::signed`) |
