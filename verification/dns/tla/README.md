# DNS in TLA+

Four specs model the DNS engines of `services::dns` and
`protocols::dns::dnssec`: the recursive resolver, the step contract every
engine keeps, the authority engine with its sources and providers, and the
DNSSEC validator with the resolver's rendering of its result. Each spec has
flags that remove one rule the engines follow, so one spec gives both the
proof of the rule and the counterexample that shows why it is there.

| Spec | What it models | Rust |
|---|---|---|
| `Resolution.tla` | The resolver against zones `.`, `tld`, `sld.tld`, and `alt.tld`, each with one good and one lame server; an address, a CNAME, an empty non-terminal, a missing name, a glued nameserver, a CNAME loop across two zones, and a wildcard; a rogue server adding a record outside its bailiwick; two clients; a network that loses and truncates; one world edit; TTLs of 1 and 2 | `services/dns/resolver/{mod,cache,resolution,front}.rs` |
| `Exchanges.tla` | The step contract of `Engine`: tokens with a generation and an exchange identity, matching on the token and the tuple, duplicate, late, and spoofed replies, `Gone`, `Advance`, one resolution shared by two clients | `services/dns/exchange.rs` (`Token`, `Generation`, `Input`, `Action`, `Engine`), kept by `AuthorityEngine` and `Resolver` |
| `Authority.tla` | `AuthorityEngine` at a root, a TLD, and an edited zone's address: `Relay` through an `Only` policy and a source that delays and fails, `Overlay` reading the edited zone's apex NS RRset and its target's addresses and then asking for its DS, `Lazy` over a `Provider` whose facts are present, absent, or unknown and change as the world runs | `services/dns/authority/{mod,engine,relay,overlay}.rs`, `services/dns/zone/{data,lazy}.rs`, `world/net/dns/source.rs` |
| `Validation.tla` | The validator on a path root, tld, sld, with the data free per config (signer, parent proof, window, algorithm, changes after signing), clock skew, unreachable zones, the AD/CD rendering, `check_chain`, and two validators with providers, signers, and records of their own | `protocols/dns/dnssec/{validate,policy,proof}.rs`, `services/dns/zone/chain.rs`, `services/dns/resolver/front.rs` |

## Properties

| Spec | Property | Kind | Meaning |
|---|---|---|---|
| Resolution | `AnswersTrueWithinTtl` | invariant | every record of a NOERROR answer was in the data at some second within its TTL before the reply |
| | `NegativeTrue` | invariant | NXDOMAIN only for a name with no node at or below it and no wildcard; NODATA only for a node without the type; each held within the negative TTL |
| | `NoPoison` | invariant | every cached record came from a server for a zone at or above its name |
| | `GlueNeverAnswers` | invariant | no answer to a client rests on glue |
| | `TtlSound` | invariant | no answer uses a record at or after its expiry |
| | `TcNotCached` | invariant | nothing from a truncated reply is cached (RFC 2181 section 9) |
| | `FailureNeverNegative` | invariant | a cached failure never answers NXDOMAIN or NODATA (RFC 9520) |
| | `BoundedNotCached` | invariant | a failure the work bound caused is never cached, so one question's spent budget never answers another client |
| | `WorkBounded` | invariant | every resolution stays within `MaxWork` queries and `MaxChain` CNAME restarts |
| | `ReferralsDescend` | invariant over steps (`PROPERTY`) | the cut a resolution works from always contains its name, and a referral is followed only strictly downward |
| | `LoopServfails` | invariant | the CNAME loop always ends in SERVFAIL |
| | `EveryQueryAnswered` | liveness | every question asked is answered, under weak fairness of delivery and of the resolver's steps |
| Exchanges | `MatchRequiresTuple` | invariant over steps (`PROPERTY`) | engine state changes on a reply only if its token is outstanding and its source, ID, and question equal the transmit's |
| | `ObsoleteNeverPopulates` | invariant | no cache entry and no answer rests on an exchange of an older generation |
| | `DuplicateHarmless` | invariant over steps (`PROPERTY`) | a second copy of a reply changes nothing |
| | `CancelPreservesWaiters` | invariant | after `Gone(c)`, every other client still waits on live work or has its answer |
| | `OneAnswerPerQuery` | invariant | each client query gets at most one answer |
| | `EveryAcceptedAnswered` | liveness | every accepted query is answered unless its client goes |
| Authority | `NeverGuess` | invariant | a relayed reply for an unedited name is the real server's reply to that question as it was when the source asked |
| | `PolicyHolds` | invariant | no ask the policy refuses reaches the source, root and TLD asks included |
| | `UnknownNeverNegative` | invariant | no NXDOMAIN or NODATA rests on an unknown fact |
| | `CoherentRevision` | invariant | every reply from the lazy zone agrees with one revision of it |
| | `RespondMonotone` | invariant | more observations never turn a reply into a `Need`: a request that knows what its ask observed never needs another |
| | `OneAskPerNeed` | invariant | a request sends at most one ask per `Need`, and one `Need` per generation |
| | `NoLockAcrossAsk` | invariant | a request parked on an ask holds no part of a view |
| | `EveryParkedAnswered` | liveness | every request that waits on an ask is answered or silently dropped |
| Validation | `SecureImpliesChain` | invariant | Secure only with a valid chain from a configured anchor to the answer |
| | `InsecureNeedsProof` | invariant | Insecure only with no covering anchor, or below a validated chain a signed no-DS proof, an opt-out cover, or a DS whose algorithm the policy does not admit, each from a DS set that was fetched |
| | `UnreachableLinkIndeterminate` | invariant | a zone below a validated chain whose DS set cannot be fetched is Indeterminate, whatever that set would have said, as `Check::delegation` fetches it first |
| | `NoDowngrade` | invariant | a valid chain is always Secure |
| | `IndeterminateOnlyUnreachable` | invariant | Indeterminate only when a zone could not be fetched |
| | `AdOnlySecure` | invariant | AD only for Secure data with DO or AD in the query; never for NotPerformed, never because an upstream set it |
| | `BogusServfails` | invariant | Bogus with CD=0 is SERVFAIL |
| | `CdPassesData` | invariant | with CD=1 the data reaches the client whatever the validation found |
| | `Sha1Insecure` | invariant | under the default policy a zone whose DS names algorithm 5 or 7 below a validated chain is Insecure, never Secure (RFC 9905 section 2) |
| | `RecordsOnly` | invariant | two validators, each with its own provider, signer, and records, reach the same result whenever their records are equal |
| | `CheckChainAgrees` | invariant | a tree `check_chain` passes validates Secure or Insecure everywhere |
| | `RelayedUneditedSecure`, `EditedUnderRealAnchorBogus`, `InventedUnderOptOutInsecure`, `InventedTldUnderNsecBogus`, `WorldRootAllSecure`, `UnsignedWithIanaAnchorBogus`, `NoAnchorsNotPerformed` | reachability | each scenario happens; its `Never...` form must fail |

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
  `_rogue`, `_edit`. Ablations: `_nobailiwick`, `_nobound`, `_cachetc`,
  `_noexpiry`, `_failureasnegative`, `_cachebounded`.
* **Exchanges:** `_base`, `_advance`, `_cancel`. Ablations: `_idonly`,
  `_flushonly`, `_cancelshared`.
* **Authority:** `_base`, `_fail`, `_lazy`, `_advance`. Ablations:
  `_nopolicy`, `_rootexempt`, `_unknownasabsent`, `_mixedrevision`,
  `_reask`, `_parkinview`.
* **Validation:** `_paths`, `_skew`, `_unreachable`, `_policy`,
  `_providers`, and `_witnesses` (every reachability witness, each expected
  to fail). Ablations: `_trustupstreamad`, `_nopolicy`,
  `_missingasinsecure`, `_signerpeek`.

Bounds. Every counter is bounded in the enabling conditions of its
actions, never by a `CONSTRAINT`, so the liveness checks are sound:

* **Resolution:** the clock by `MaxTime` 4; `MaxWork` 4 upstream queries
  and `MaxChain` 3 CNAME restarts per resolution (`MaxWork` 6 in `_loop`
  and `_nobound`; see the modelling choices); one loss, one truncation, one
  edit; each client asks a fixed script, one question at a time. The work
  and chain counters count with or without the bounds and stop one past
  them, so in `_nobound` `WorkBounded` fails, and the loop repeats a state
  and TLC reports the liveness violation as a lasso.
* **Exchanges:** the clock by `MaxTime` 3, exchange identities by
  `MaxExchanges` 4, generations by `MaxGeneration` 2 (1 in `_base` and
  `_cancel`); one duplicate, one spoofed reply, one `Gone`.
* **Authority:** revisions by `MaxRevision` 2 for world changes (inserts
  are bounded by the finite set of names), generations by `MaxGeneration` 2
  in `_advance`; one change to the real data.
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
| Resolution_base | the 10 invariants, `ReferralsDescend` | pass | 540040 | 68 | 2 s | |
| Resolution_base | `EveryQueryAnswered` | pass | 540040 | 68 | 18 s | |
| Resolution_concurrent | the 10 invariants, `ReferralsDescend` (symmetry) | pass | 3832718 | 60 | 10-11 s | |
| Resolution_concurrent_live | `EveryQueryAnswered` | pass | 7646409 | 60 | 326 s | |
| Resolution_loop | the 10 invariants, `ReferralsDescend`, `EveryQueryAnswered` | pass | 12779 | 30 | 0-1 s | |
| Resolution_rogue | the 10 invariants, `ReferralsDescend`, `EveryQueryAnswered` | pass | 28297 | 33 | 0-1 s | |
| Resolution_edit | the 10 invariants, `ReferralsDescend` | pass | 411683 | 48 | 1-2 s | |
| Resolution_edit | `EveryQueryAnswered` | pass | 411683 | 48 | 13 s | |
| Resolution_nobailiwick | `NoPoison` | violated | 312 | 11 | 1 s | Ask, Advance, Serve, Receive (root's referral), Advance, Serve, Receive (tld's referral), Advance, Serve, Receive: alt.tld's answer for x.w.alt.tld carries www.sld.tld, which is cached |
| Resolution_nobound | `WorkBounded` | violated | 5465 | 21 | 0 s | the loop's CNAME chase restarts past `MaxChain` |
| Resolution_nobound | `EveryQueryAnswered` | violated | 31258 | lasso | 2 s | down to sld.tld and over to alt.tld, then round a lasso: the chain follows loop.sld.tld and loop.alt.tld from the cache forever, its counter stopped one past `MaxChain` |
| Resolution_cachetc | `TcNotCached` | violated | 33 | 6 | 1 s | Ask, Advance, Serve, Truncate, Receive |
| Resolution_noexpiry | `TtlSound` | violated | 2345 | 17 | 0 s | Ask cn.sld.tld; Advance, Serve, Receive three times down to sld.tld; Advance follows the CNAME; Advance, Serve, Receive for www.sld.tld; Tick, Advance: the answer carries the CNAME after its one-second TTL ran out |
| Resolution_failureasnegative | `FailureNeverNegative` | violated | 173 | 9 | 0 s | Ask, Advance, Lose, Timeout, Advance, Serve, Receive, Advance: the query to one root server is lost and times out, the other refuses, and the cached failure answers NXDOMAIN |
| Resolution_cachebounded | `BoundedNotCached` | violated | 1279 | 15 | 0 s | Ask, then Advance, Serve, Receive twice down to sld.tld; Advance, Serve, Truncate, Receive (the TCP retry is the fourth query); Lose, Timeout, Advance: the work bound ends the resolution and its failure is cached |
| Exchanges_base | the 3 invariants, `MatchRequiresTuple`, `DuplicateHarmless` | pass | 66914 | 19 | 1 s | |
| Exchanges_base | `EveryAcceptedAnswered` | pass | 66914 | 19 | 3 s | |
| Exchanges_advance | the 3 invariants, `MatchRequiresTuple`, `DuplicateHarmless` | pass | 4564834 | 28 | 10-12 s | |
| Exchanges_advance | `EveryAcceptedAnswered` | pass | 4564834 | 28 | 204 s | |
| Exchanges_cancel | the 3 invariants, `MatchRequiresTuple`, `DuplicateHarmless` | pass | 853762 | 23 | 2-3 s | |
| Exchanges_cancel | `EveryAcceptedAnswered` | pass | 853762 | 23 | 26 s | |
| Exchanges_idonly | `MatchRequiresTuple` | violated | 64 | 5 | 1 s | Query, Send, Spoof, Deliver |
| Exchanges_flushonly | `ObsoleteNeverPopulates` | violated | 282 | 6 | 0 s | Query, Send, Serve, Advance, Deliver |
| Exchanges_cancelshared | `CancelPreservesWaiters` | violated | 13 | 4 | 1 s | Query, Query, Gone |
| Authority_base | the 7 invariants, `EveryParkedAnswered` | pass | 2072 | 17 | 0-1 s | |
| Authority_fail | the 7 invariants, `EveryParkedAnswered` | pass | 7096 | 17 | 0-1 s | |
| Authority_lazy | the 7 invariants, `EveryParkedAnswered` | pass | 544 | 12 | 0-1 s | |
| Authority_advance | the 7 invariants, `EveryParkedAnswered` | pass | 29372 | 19 | 0-1 s | |
| Authority_nopolicy | `PolicyHolds` | violated | 4 | 2 | 0 s | Step: the root server relays leak.evil to the source |
| Authority_rootexempt | `PolicyHolds` | violated | 4 | 2 | 1 s | Step: the same ask, exempt because it goes to a root server |
| Authority_unknownasabsent | `UnknownNeverNegative` | violated | 2 | 2 | 0 s | View: b.fict is unknown and the wildcard absent, so NXDOMAIN |
| Authority_mixedrevision | `CoherentRevision` | violated | 43 | 4 | 1 s | ReadName (a.fict absent), WorldChange, ReadRest (the wildcard present): a wildcard answer no revision gives |
| Authority_reask | `RespondMonotone` | violated | 17 | 3 | 0 s | Step (the policy refuses leak.evil, a timeout), Observe: the request knows its observation and needs again |
| Authority_parkinview | `NoLockAcrossAsk` | violated | 6 | 3 | 0 s | ReadOverlay, Step: the overlay reads the lazy zone, then parks on its DS ask while it still holds that read |
| Validation_paths | the 11 invariants | pass | 1119744 | 1 | 1-3 s | |
| Validation_skew | the 11 invariants | pass | 10368 | 1 | 0-1 s | |
| Validation_unreachable | the 11 invariants | pass | 147456 | 1 | 0-1 s | |
| Validation_policy | the 11 invariants | pass | 3456 | 1 | 0-1 s | |
| Validation_providers | the 11 invariants | pass | 589824 | 1 | 1-2 s | |
| Validation_witnesses | each of the 7 `Never...` forms, alone | violated (reachable) | 1 | 1 | 0-1 s | an initial state of each scenario |
| Validation_trustupstreamad | `AdOnlySecure` | violated | 1 | 1 | 0 s | no anchors configured (NotPerformed), the upstream reply has AD, the client gets AD |
| Validation_nopolicy | `Sha1Insecure` | violated | 1 | 1 | 1 s | a chain of key A where sld's DS names algorithm 5: Secure |
| Validation_missingasinsecure | `InsecureNeedsProof` | violated | 1 | 1 | 1 s | the root cannot be fetched: Insecure with no proof |
| Validation_signerpeek | `RecordsOnly` | violated | 1 | 1 | 0 s | sld's RRset changed after signing: Bogus for signer B, Secure for signer A |

## Modelling choices

General:

* Names, records, and messages are abstract values, not wire bytes. The
  wire, `restore`, `fit`, and the answer algorithm are Lean's (section
  18.2); these specs check the behavior of the engines around them.
* Properties that relate two states (`ReferralsDescend`,
  `MatchRequiresTuple`, `DuplicateHarmless`) are written as `[][A]_vars`
  and listed under `PROPERTY`; they are safety properties, checked on every
  step.
* While writing the specs, reachability was checked with throwaway
  invariants on every non-ablation config of Resolution, Exchanges, and
  Authority: answers of each kind, the wildcard, shared resolutions, TC
  retries, chain restarts, the chain bound in `_loop`, stale glue and the
  edit's new values, spoofed, duplicate, and late replies delivered and
  ignored, SERVFAIL after both servers, answers after `Advance` and after
  another client's `Gone`, silent relays, and revisions growing while a
  request is parked. So no property holds only because its premise never
  occurs. The Validation witnesses are kept as `_witnesses.cfg`.

Resolution:

* One question type (A). DNS IDs and ports are not modelled; matching is
  `Exchanges.tla`'s concern, so each resolution has at most one exchange
  outstanding and a reply always belongs to it.
* A lame server answers with an upward referral to the root (the root's
  lame server answers REFUSED). The resolver must reject the referral and
  try the other server.
* A server reads the data when it gets the query and replies at once. The
  clock does not advance while a reply is in flight, so a record's read
  time is the second the resolver stores it: simulated round trips are far
  shorter than a TTL second. A timeout is enabled by a lost message, not by
  the clock.
* The resolver starts with the root's servers known (priming is not
  modelled) and keeps every cut it learns: NS TTLs outlast `MaxTime`. Only
  `ns.sld.tld` is glued in the cache, which is the glue `GlueNeverAnswers`
  needs; the edit changes the child's address record and not the parent's
  glue, so stale glue is reachable.
* `MaxWork` counts upstream queries, TCP retries included; `MaxChain`
  counts CNAME restarts. In `_loop` and `_nobound` `MaxWork` is 6, not the
  4 of the other configs: following the loop once takes five queries (root, tld,
  sld, tld again for alt, alt), so with 4 the work bound always ends the
  loop before the chain bound is ever reached, and the chain bound would go
  unchecked.
* A chain whose link expires while the chase goes on is followed again from
  the question, keeping the work done. The first run found this case:
  without it the resolver answered a CNAME whose TTL had already run out
  (`TtlSound`). The Rust resolver does the same: when a record of an answer
  ran out while the rest was resolved, `Resolver` follows the chain again
  from the question, its work so far still counted.
* A failure after every server was tried is cached for `failure_ttl`
  (1 s) at the name the chain had reached. A resolution that reaches the
  work bound answers SERVFAIL without caching, as `Resolution::send` leaves
  a failure the bound caused out of the cache: the bound is one question's
  budget and says nothing of the servers. A chain that is too long answers
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
* Generations start at 1, so `MaxGeneration` 2 allows one `Advance`.

Authority:

* Each request needs at most one ask: the relayed question, or the
  overlay's `<apex> DS`. `RespondMonotone` is checked on the model's
  `respond` for every request once it knows its observation; `_reask`,
  where a timeout makes `respond` ask again, breaks it.
* The root server runs `Relay` and the TLD server `Overlay`, as a world
  puts the overlay on the `com` servers. Before its DS ask, the overlay
  reads the edited zone's apex NS RRset and the addresses of its target
  `ns.fict` from the lazy zone, as `Overlay::respond` asks the inner
  authority for `<apex> NS`, and a fact it does not know makes the
  referral SERVFAIL. The referral rests on those facts, so
  `UnknownNeverNegative` and `CoherentRevision` cover it.
* `Lazy::view` takes the zone's lock once, so the view is one atomic step.
  `MixedRevision` splits it into two steps, reading the name and then the
  wildcard, and the world may change between them.
* A revision is a snapshot: the world's state (what the provider says) and
  the names the zone has inserted. `CoherentRevision` checks a reply's facts
  against every snapshot that existed, not against a revision number, so a
  view that inserts the name it read still agrees with one revision.
* The policy refuses the guest-chosen name `leak.evil` at every server.
  `_nopolicy` and `_rootexempt` both let it reach the root server.
* `restore` is the identity on the modelled reply; Lean proves it changes
  only the ID and the question's case.
* `Advance` restarts parked requests with nothing known; observations for
  old tokens are ignored when they arrive.
* `NoLockAcrossAsk` holds because a view never waits and the overlay lets
  go of what it read from the lazy zone before it asks. The overlay's read
  is a step of its own (`ReadOverlay`), after which nothing but that
  request's `Step` runs, as one call of `respond` would, so the read is
  held in reachable states of every config. `_parkinview`, where the
  overlay sends its DS ask while it holds its read, breaks it.

Validation:

* The validator is a function, so the spec has no steps: every behavior is
  one initial state, and TLC checks every combination of the config's
  choices (depth 1).
* Keys A and B. A DS names the key its digest matches (`DsA`, `DsB`), so a
  world can sign its root and every zone with its own key B under its own
  anchor.
* `alg[z]` is the algorithm the DS or the anchor names for `z`. An
  algorithm outside the policy makes the zone Insecure before any fetch
  (RFC 4035 section 5.2, RFC 9905 section 2). DS digest types and the NSEC3
  iteration limit are not modelled; Lean's policy model covers them.
* Windows and the clock are three slots (past, now, future); skew is a
  clock that is not "now".
* An unreachable zone is one whose DNSKEY or DS set cannot be fetched. If
  `sld` is unreachable the answer itself is missing, so the client gets
  SERVFAIL even with CD.
* With CD=1 the client checks signatures itself, so `Resolver` does not
  validate a fresh answer: it is NotPerformed and gets AD=0. An answer from
  the cache keeps what an earlier query without CD established (`cached`),
  so Secure data can still carry AD, and Bogus data passes with AD=0.
* Providers and signer implementations publish the same records, by the
  contract Lean proves (`lazy_agrees_complete`, `signer_agnostic`). The
  check here is that the validator reads nothing else; `SignerPeek` lets it
  skip the signature check for signer A's records.
* `check_chain` reports five problems: `DsMismatch`, `NoDsProofMissing`,
  `WindowClosed`, `UnsupportedAlgorithm`, and `SignatureInvalid`. A zone
  whose RRset changed after signing (a `Zone::with` after `Zone::signed`)
  has none of the first four, yet validates Bogus; with only those,
  `CheckChainAgrees` fails in `_providers` on a tree signed with key A
  whose answer RRset changed after signing. `ChainProblem::SignatureInvalid
  { apex, owner, rtype }` is the fifth, for an RRset with no RRSIG that
  verifies under its zone's keys.

## How the models map to the Rust types

Resolution:

| Model | Rust |
|---|---|
| `cache[n]` | `Cache`, keyed by `(LowerName, RecordType, DNSClass)` |
| entry `t` = `"a"` or `"cname"` | `Entry::Positive { set, rank, expires, validation }` |
| entry `t` = `"nx"` or `"nodata"` | `Entry::Negative { kind: Negative::NxDomain` or `NoData, .. }` |
| entry `t` = `"fail"` | `Entry::Failure { why: FailureKind, until }`, kept for `Config::failure_ttl` |
| entry `rank` | `Rank::AuthAnswer` and `Rank::Glue` (two of the five ranks) |
| entry `readAt + ttl` | `expires: Instant` |
| `known` | the cached cuts the resolution starts from |
| `res[q]` | one resolution in `resolver/resolution.rs`: `qn` the name the chain has reached, `zone` the closest cut, `tried` the addresses tried per transport (RFC 9520 section 3.1), `work` and `chain` against `Config::work` (`Work { queries, depth }`) |
| `waiting[q]` | the client queries waiting on one resolution, which they share |
| `ans[c][q]` | `Action::Answer`, rendered for its client |
| `Receive` | taking a reply: TC retries over TCP, answers stored in bailiwick only, referrals strictly below the cut, glue at glue rank |
| `Timeout` | `Input::Tick` at the exchange's deadline |
| `CheckBailiwick`, `CacheTc`, `CheckExpiry`, `FailureAsNegative`, `BoundWork` | the bailiwick check, "truncated replies are not cached", the `expires` check, `Entry::Failure` as its own variant, and `Config::work` |

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
| `cache`, `waiters` | the resolver's cache and waiters, or the authority engine's parked requests |

Authority:

| Model | Rust |
|---|---|
| `Respond(r, k)` | `Authority::respond(req, local, client, known) -> Step` (`Reply`, `Need`, `Silent`) |
| `known[r]` | `Known`, holding `Observed::{Reply, Unreachable, Timeout}` |
| `st[r] = "parked"`, token `<<gen, id>>` | `AuthorityEngine.parked: BTreeMap<Token, Parked>` |
| `atSource`, `obsq` | the driver carrying a `Transmit` to the `Source` and back as `Input::Reply` or `Input::Failed` |
| `PolicyPasses` | `Only<S, P>` with `P: Fn(&Ask) -> bool`; a refused ask is `Observed::Timeout` |
| `View(r)` | `Lazy::view` under its one lock, then `zone::answer` |
| `Provider(w, n)` | `Provider::lookup -> Fact<Vec<RecordSet>>` |
| `ins`, `history`, `rev` | the lazy zone's `Mutex<Zone>` and its `Revision`s |
| `ViewReply` with `"unknown"` | `Answered::Unknown`, answered SERVFAIL by `Zones` |
| `Crosses(r)` | `Overlay::below` reading the inner authority's `<apex> NS` and asking `<apex> DS` before composing a referral |
| a relayed reply | `Relay`, with `restore` |

Validation:

| Model | Rust |
|---|---|
| `Records(..)` | the DNSKEY, DS, RRSIG, NSEC, and NSEC3 records a `Chain` gathers |
| `anchor` | `Config::anchors`: `None` is `"none"`; `Anchors` covering another tree is `"elsewhere"` |
| `PolicyAlgs` | `AlgorithmPolicy::validate`; `AlgorithmPolicy::iana()` admits no algorithm 5 or 7 |
| `clock` | `WallClock::at(now)`, the `Session` clock |
| `Walk`, `Validate` | `validate_rrset` and `validate_denial` |
| result kinds | `Validation::{NotPerformed, Secure, Insecure(Insecure), Bogus(EdeCode), Indeterminate}`; reasons `Insecure::{ProvenNoDs, OptOutCovered, NoAnchor, UnsupportedAlgorithm}` and EDE codes 5, 6, 7, 8, 9, 12 |
| `Established`, `Rendered` | what `Resolver` established (NotPerformed for a fresh answer under CD) and its front: AD, CD, SERVFAIL |
| `ChainProblems` | `check_chain -> Vec<ChainProblem>` |
| `provider1`, `impl1` | `Zone`, `Lazy`, or `Relay`; two `Sign` implementations |
