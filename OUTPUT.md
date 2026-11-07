# Fictionet quality review

This review covers the core runtime and networking stack, host and command-line integration, extras, code generation, and demo composition. Three Astra reviewers worked on these areas, with implementation and validation in this worktree. The supplied founder conversation informed the scope. This is a substantial review and repair pass, not a claim that every line or every possible execution has been proved correct.

## Repairs

- Replaced waiters are released after their owning locks are released across runtime, networking, service, and DNS paths. Reentrancy tests exercise destruction of replaced wakers.
- DNS cache rank protection now also applies to negative answers to ANY questions. Expired aggressive denial proofs are reclaimed during cache sweeps.
- Dedicated Linux socket mappings explicitly disable transparent huge pages, preserving the intended page-level residency behavior. The original residency test exposed this on the host and passed after the production correction.
- Proxy requests derive Host from the selected absolute target, including when incoming headers are duplicated or nominated as hop-by-hop. DNS answers are admitted only for the supported query operation and Internet class.
- Host uploads now yield between ready body chunks so Hyper can read an early upstream response even when another thread continuously refills the bounded upload channel. The existing early-rejection and duplex-streaming tests pass with unchanged assertions.
- Persistent search uses the shared domain-admission rules, rejects incompatible stored schemas, and retains total result counts when the requested page size is zero.
- Transport-extension, fuzz-input, and contribution documentation now describes the implementation and supported Cargo workflow.

## Composition

Workspace compilation exposed demo integrations referring to APIs already removed from the core. Nuclear and Artifactory now use current endpoints, native HTTP handlers, typed world-owned facts, and direct state/command interfaces. Their existing behavioral tests are migrated to those APIs. Removed generic event and viewer APIs are not restored through compatibility shims.

Nuclear separates trusted HMI routes from ordinary sandbox traffic, matching the core network ownership rules. Artifactory attaches repository facts to responses, projects protocol observations into its own facts and JSON log, and retains inventory, package, credential, SSRF, and incident handling. Its Unix observation socket now serves JSON and server-sent state updates. The preview DNS client now sends fully qualified question names so strict reply correlation accepts the echoed question. The apps use bounded state and command flows.

Core inspection also sampled cancellation and joins, socket buffer lifetimes, listener and route ownership, stream EOF and budget composition, HTTP/2 flow control and HPACK, passive TCP overlap handling, and several binary protocol decoders. This was not exhaustive line-by-line verification of every protocol.

Additional inspection covered code-generation validation and XML escaping, WARC lifecycles, model-transport secret redaction, host cancellation and packet queues, Python configuration/cache boundaries, Helm startup ordering, and task orchestration. No speculative changes were made where that inspection did not establish a defect.

HTTP completion observations retain typed response extensions and distinguish normal completion from cancellation. Body-byte counts include fully written pieces only; an interrupted final piece is excluded. Callbacks run synchronously and slow consumers must arrange their own handoff. Protocol failures before request dispatch are outside this callback.

## Validation

The final workspace run passed 6,581 tests, with zero failures and zero ignored tests. The following checks passed:

| Check | Command |
| --- | --- |
| Workspace tests, including documentation tests | `cargo test --locked --workspace --all-features --no-fail-fast` |
| Lints, with warnings denied | `cargo clippy --locked --workspace --all-features --all-targets -- -D warnings` |
| Formatting | `cargo fmt --all -- --check` |
| API documentation | `cargo doc --locked --workspace --all-features --no-deps` |
| Packet round-trip benchmark | `cargo bench --locked --profile test -p fictionet --all-features --bench network -- sched::packet_round_trips` |

The core suite includes 3,785 unit tests, 1,291 integration tests, and 291 documentation tests. Artifactory passes 58 world unit tests, 26 world integration tests, and 34 app tests. All 41 host tests pass, including early upstream rejection and a 64 MiB duplex upload. The Nuclear suites, CLI, extras, code generation, other demos, and vendored transport tests also pass in the workspace run.

The benchmark is a smoke measurement in the test profile, not a release-performance comparison. Both replacement viewer JavaScript modules passed syntax checks. HTTP tests exercise state delivery and command authorization; Artifactory replay exercises all four variants and shared/separate sessions.

New regression coverage checks ownership, admissibility, delivery accounting, cancellation, and composition rather than introducing golden response snapshots. Existing assertions were preserved when migrating removed APIs; individual protocol facts are checked separately from the retained aggregate JSON-log contract. No tests were skipped, timing budgets increased, or lint exceptions added to obtain passing results.

## Remaining limits

- Replaced-waker destruction was repaired, but the broader TCP stack still has synchronous wake callbacks and some resource destruction under endpoint locks. Arbitrary reentrant RawWaker behavior needs a separate ownership redesign; this pass does not claim universal callback reentrancy safety.
- The new Nuclear viewer exposes state, controls, and logs. Its former three-dimensional presentation is not mounted by the replacement viewer.
- Artifactory scripted stories now execute SSH and print output in the demo process rather than typing in a desktop terminal. Former generic packet/event crosslinks are absent.
- The CLI proxy DNS path does not retry truncated UDP replies over TCP; the host resolver has that behavior. This remains a resolver capability gap.
- Browser visual verification was unavailable because the in-app browser runtime was unavailable. HTTP-level validation does not establish visual quality.
- Privileged host and VM execution, external browser consoles, fuzz campaigns, and formal-model tooling require separate validation. No claim is made that those paths were exercised here.
