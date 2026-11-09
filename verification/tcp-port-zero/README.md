# Literal TCP port zero verification

This pass checks the port-zero changes in `c27e21447` against `8ccf47fae`.
The bounded TLA+ models and all three Kani harnesses check clean.
No bug in the current Rust code has
been established by a checker counterexample and a running reproduction.
The negative control described below is an intentional model mutation,
not a reported implementation bug. No runtime Rust implementation is changed.

## Socket lifecycle

[Socket.tla](Socket.tla) models all eleven smoltcp
TCP states, passive listening, active and simultaneous opens, accepted SYN,
ACK, FIN and RST events, local close, abort, reset dispatch, TIME-WAIT expiry,
and reuse. The finite domain has ports `{0, 1, 65535}`, two abstract valid
addresses, specific and wildcard listeners, and all 36 endpoint tuples.
`Absent` represents `None`; a listener with port zero remains present.

The correspondence to [the socket implementation](../../smoltcp/src/socket/tcp.rs)
is by transition and field:

| Model | Rust |
| --- | --- |
| `phase`, `listener`, `tuple` | `state`, `listen_endpoint`, `tuple` |
| `Listen`, `Connect`, `Open` | `listen`, `connect`, `reset`, `is_open` |
| `Accepts` | The ordered guards in `accepts`: closed, listening ACK/RST, tuple, listener |
| `PassiveSyn`, `ActiveSyn`, `ReceiveReset`, `ReceiveAck`, `ReceiveFin` | Corresponding state/control branches in `process` |
| `Close`, `Abort`, `DispatchReset`, `Expire` | `close`, `abort`, successful closed-state `dispatch`, `forget_connection` |

`origin` and `requested` record API call history independently of the stored
listener. Properties check listener provenance, tuple identity, admission
against that history, restoration of the original passive listener after a
handshake reset, and closure of active opens after reset. Closed sockets may
retain listener metadata; aborted sockets may retain a tuple until reset
dispatch. The model preserves both behaviors.

[Socket.cfg](Socket.cfg) completed with **18,192
generated states, 1,072 distinct states, depth 6, and an empty queue**. All
four invariants and both action properties passed together.

[Socket_nonzero_reset.cfg](Socket_nonzero_reset.cfg)
replaces the Option-based reset guard with the old nonzero-port guard while
still admitting port zero. TLC reports `PassiveResetRestores` violated:
closed → listen on zero → passive SYN → RST closes the socket. It exits 13
after 323 generated and 273 distinct states. This is a sensitivity check;
it neither models the whole old implementation nor reproduces a current bug.

State-changing receive events abstract packets that have passed sequence,
ACK and window validation. Invalid or repeated API calls and discarded packets
are implicit stutters; API return values are not modeled. Payload, options,
retransmission, clocks and address family validation are outside this
abstraction. Timeout closure is included
in the unconditional abort transition. There is no fairness or liveness claim.
The endpoint's choices for what a closed port answers and what a SYN from
source port 0 gets (`tcp::Settings::closed_port` and `source_port_zero`)
are outside it too: they act in the interface's fallback for a segment no
socket accepts, before any socket is asked, or after the handshake has
completed, and leave `accepts` and `process` as modeled.

## Binding and host preparation

[Binding.tla](Binding.tla) checks two separate
state spaces. Allocation models what the TCP layer in
[`tcp/engine.rs`](../../src/stdlib/network/tcp/engine.rs) does for
`TcpControl::Listen`, the cyclic allocator of its `connect` (for
`TcpControl::Connect`), `take_port`, `free_port`, `remove_conn`, and
`TcpControl::Unlisten`. `Endpoint::listen`, `Endpoint::connect` and a
listener's drop send those commands. The model checks reservation
conservation, exclusion between listeners and outgoing connections, ephemeral
source selection, availability, and preservation of the requested destination.
Connection removal represents actual resource release, not handle drop.

The port domain is `{0, 1, 49152, 65535}` and the ephemeral ring is compressed
to `<<49152, 65535>>`, with both possible initial cursors. This exercises
exhaustion, skipping occupied ports, wraparound, release and rebinding; it does
not exhaustively enumerate the real 16,384-port allocator.

Preparation models plain, nonsharing TCP service declarations in
[`Machine::prepare` and the installation path](../../src/stdlib/world/net/hosts.rs):
temporary listener ownership, duplicate rejection, release on error, and
publication only after every declaration succeeds. Bindings are staged
against the prepared shared packet driver in `network/endpoint.rs`;
it starts only at `PreparedMachine::commit`. The model's preparation and
rollback actions are unchanged. All declaration sequences
of lengths one through three over the same four ports are explored, including
duplicates at zero and reuse after failed preparations. Installed services
persist across successive preparations. Properties check listener ownership,
absence of premature publication, and rollback to the prior installed set.

| Configuration | Generated | Distinct | Depth | Result |
| --- | ---: | ---: | ---: | --- |
| `Binding_allocation.cfg` | 1,506 | 288 | 7 | All five invariants and the action property passed |
| `Binding_preparation.cfg` | 233,258 | 9,986 | 14 | All four invariants passed |

Both runs completed with empty queues. Neither model uses state constraints
or a depth cutoff. The two specifications are checked separately, not as a
combined concurrent host/allocator system. TLS, shared service callbacks,
UDP, cancellation, stopped endpoints, invalid addresses, and packet visibility
of temporary listeners on an already running machine are outside this model.

## Proofs against Rust

The Kani harnesses are included under `cfg(kani)` in the real smoltcp modules;
they call the production implementation rather than a translated copy.
The ordinary Cargo lint configuration recognizes that conditional compilation
name. The socket harness also uses the existing in-memory unit-test setup.
No runtime path or existing test assertion is changed.

[`SocketProof.rs`](SocketProof.rs) checks all
`u16` local/remote port pairs and both passive and active origins. It calls
`listen` or `connect`, then the actual `accepts` and `process` paths for SYN
and valid RST, and finally close and relisten. Assertions relate endpoint
identity and listener preservation to the symbolic input and pre-reset state.
Kani passed: **0 of 6,203 checks failed**, with 320 unreachable checks.
The unwind bound is 17 and unwinding assertions remain enabled. This proof
uses representative IPv4 addresses, fixed sequence numbers, 64-byte buffers,
and empty payload/options; it does not prove arbitrary sequence validation.

[`Wire.rs`](Wire.rs) contains a minimal-segment
roundtrip/checksum proof and a port-renaming proof for arbitrary 24-byte
segments. Both use the actual packet setters, checksum calculation and parser.
They relate decoded results to input ports, not golden packet snapshots.
The roundtrip harness ranges over every pair of `u16` ports on a 20-byte
segment and checks that a single-bit corruption is rejected. The renaming
harness ranges over arbitrary 24-byte segments, replacement ports and both
malformed-option parsing modes; it recomputes checksums before comparing
acceptance and the complete parsed representation modulo ports. Both use
representative same-family IPv4 and IPv6 address pairs. Longer options,
larger payloads and arbitrary addresses are outside these harnesses.
The minimal-segment proof passed with **0 of 476 checks failed**, including
unwinding assertions, and 20 unreachable checks. Its unwind bound is 13.
The arbitrary-segment renaming proof also passed: **0 of 761 checks failed**,
including unwinding assertions, with 19 unreachable checks and unwind bound
15. It completed in about eight minutes. All three harnesses used Kani 0.68.0
with its default solver and safety checks; no assumptions restrict the
symbolic ports, origin or packet bytes. No harness failed or was abandoned.

### Rerun against the TCP layer, and failing controls

All three harnesses were rerun on `comp/v-tcp-obs`, with TCP running as a
layer, under Kani 0.68.0 (CBMC 6.11.0). `SocketProof.rs` now shares its
setup with its control; the proof itself is unchanged.

| Harness | Checks | Result |
| --- | ---: | --- |
| `handshake_reset_preserves_only_passive_listeners` | 6,203 (320 unreachable) | 0 failed, 14 s |
| `every_port_pair_roundtrips_and_checksums_are_required` | 452 (19 unreachable) | 0 failed, 9 s |
| `renaming_ports_preserves_packet_validation` | 739 (18 unreachable) | 0 failed, 388 s |

Each harness has a failing control that changes one thing and must fail on
the one assertion its comment names. Each failed on exactly that check:

| Control | What it changes | Failed check |
| --- | --- | --- |
| `handshake_reset_without_port_zero_listeners` | reads a listening port of zero as no listener, as the reset guard before `c27e21447` did | "a passive socket listens again after a handshake reset" (1 of 6,165) |
| `every_port_pair_without_a_single_bit_flip` | flips one bit in each port, which the ones'-complement sum cannot see; the proof claims only single flips | "a corrupted segment is rejected" (1 of 448) |
| `renaming_ports_without_the_checksum_refilled` | renames the ports without filling the checksum again | "renaming keeps the verdict" (1 of 448) |

## Executed Rust validation

Existing tests were run unchanged to check concrete behavior corresponding to
the abstractions. The smoltcp socket module passed 253 tests and the TCP wire
module passed 22 tests. The Fictionet literal-port conversation test passed
across IPv4/IPv6 and ports zero, one and the largest port, checking payload
roundtrips, endpoint identity, refusal and
rebinding. All 29 network service tests passed, including zero-port host
conversations and rollback after duplicate listeners. These executions support
the correspondence; they are not a proof of refinement.

Scoped rustfmt, smoltcp clippy with warnings denied, and smoltcp documentation
with rustdoc warnings denied passed. No benchmark was needed for proof-only
additions. Every Cargo invocation used the prescribed target directory, four
build jobs and a `systemd-run --user --scope -p MemoryMax=10G` scope.

## Repeating the model checks

TLC was version 2.19. Three configs must report "No error has been found".
`Socket_nonzero_reset.cfg` is the negative control: its
`\* expect violation: PassiveResetRestores` line names the property it must
violate. Run the four from the repository root:

```sh
export CARGO_TARGET_DIR=/home/souvik/Projects/amlalabs/.pz-formal-target
export CARGO_BUILD_JOBS=4
export JAVA=/home/souvik/.local/jdk21/bin/java
export TLA2TOOLS=/home/souvik/.cache/adorably-fv/tla2tools.jar

"$JAVA" -Xmx2g -cp "$TLA2TOOLS" tlc2.TLC -workers 1 \
  -metadir "$CARGO_TARGET_DIR/port-zero-model/socket" \
  -config verification/tcp-port-zero/Socket.cfg verification/tcp-port-zero/Socket.tla
"$JAVA" -Xmx2g -cp "$TLA2TOOLS" tlc2.TLC -workers 1 \
  -metadir "$CARGO_TARGET_DIR/port-zero-model/socket-nonzero-reset" \
  -config verification/tcp-port-zero/Socket_nonzero_reset.cfg verification/tcp-port-zero/Socket.tla
"$JAVA" -Xmx1g -cp "$TLA2TOOLS" tlc2.TLC -workers 1 \
  -metadir "$CARGO_TARGET_DIR/tcp-port-zero/binding-allocation" \
  -config verification/tcp-port-zero/Binding_allocation.cfg verification/tcp-port-zero/Binding.tla
"$JAVA" -Xmx1g -cp "$TLA2TOOLS" tlc2.TLC -workers 1 \
  -metadir "$CARGO_TARGET_DIR/tcp-port-zero/binding-preparation" \
  -config verification/tcp-port-zero/Binding_preparation.cfg verification/tcp-port-zero/Binding.tla
```

The negative-control command must fail on the named property; a parse error,
crash, or successful check is not its expected result. Logs from this pass are
under `$CARGO_TARGET_DIR/port-zero-model/` and
`$CARGO_TARGET_DIR/tcp-port-zero/logs/`. Generated checker files stay outside git.
Kani completion output is retained in `$CARGO_TARGET_DIR/kani-socket.log`,
`kani-wire-pair.log`, and `kani-wire-roundtrip.log`; the first two contain
completion excerpts captured from the tool output.

Run the Kani harnesses individually, using the environment exports above:

```sh
systemd-run --user --scope -p MemoryMax=10G cargo kani -p smoltcp --lib --tests \
  --harness handshake_reset_preserves_only_passive_listeners --output-format terse
systemd-run --user --scope -p MemoryMax=10G cargo kani -p smoltcp --lib \
  --harness every_port_pair_roundtrips_and_checksums_are_required --output-format terse
systemd-run --user --scope -p MemoryMax=10G cargo kani -p smoltcp --lib \
  --harness renaming_ports_preserves_packet_validation --output-format terse
```

The controls run the same way and must report `VERIFICATION:- FAILED` with
the check named above:

```sh
systemd-run --user --scope -p MemoryMax=10G cargo kani -p smoltcp --lib --tests \
  --harness handshake_reset_without_port_zero_listeners \
  --harness every_port_pair_without_a_single_bit_flip \
  --harness renaming_ports_without_the_checksum_refilled --output-format terse
```

The corresponding ordinary checks are:

```sh
systemd-run --user --scope -p MemoryMax=10G cargo test --locked -p smoltcp --lib socket::tcp::test::
systemd-run --user --scope -p MemoryMax=10G cargo test --locked -p smoltcp --lib wire::tcp::test::
systemd-run --user --scope -p MemoryMax=10G cargo test --locked -p fictionet --test it literal_ports_carry_streams_and_keep_their_identity
systemd-run --user --scope -p MemoryMax=10G cargo test --locked -p fictionet --test it services::network::
systemd-run --user --scope -p MemoryMax=10G cargo fmt -p smoltcp -- --check
systemd-run --user --scope -p MemoryMax=10G rustfmt --check --edition 2024 verification/tcp-port-zero/Wire.rs verification/tcp-port-zero/SocketProof.rs
systemd-run --user --scope -p MemoryMax=10G cargo clippy --locked -p smoltcp --lib --tests -- -D warnings
systemd-run --user --scope -p MemoryMax=10G env RUSTDOCFLAGS=-Dwarnings cargo doc --locked -p smoltcp --no-deps
```

The TLA+ correspondence is manually reviewed, not a machine-checked refinement
from Rust. No claim is made about an entire network stack, external kernels,
or arbitrary traffic. The `ssh-connect` change only removes a destination-port
rejection before passing the parsed address to `Endpoint::connect`; the CLI,
relay, DHCP and stdio bridge are not formally modeled here.

All executed network tests use simulated packets. No XDP, AF_XDP or vfio
binary was run, and no host network configuration was changed. Nothing was
pushed.
