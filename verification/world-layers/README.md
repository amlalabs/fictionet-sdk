# World hosts on the TCP, UDP and IP layers

The checks of the integrated world layers: each world machine
now runs one packet dispatcher (`network::endpoint::drive`) with one IP
layer, the TCP and UDP layers above it, and application stacks attached
straight to the transports' children. The IP layer and TCP are
replaceable through `packet::Factory` and `tcp::Factory`. This pass asks
what the host guarantees, and whether a replacement gets the same.

| Part | What it is | Where |
|---|---|---|
| TLA+ | `Staging`: installing a host on its machines, transactionally. `Admission`: admission, reset and retirement through the transport boundary, for a TCP that may refuse commands | [`tla/`](tla) |
| Kani | The dispatcher's sorting over packets the production IP code makes | [`kani/`](kani) |
| Tests | The reproductions of the bugs below, and a tunnel whose inner packets carry the outer packets' fragment keys | `tests/it/world_layers.rs`, `tests/it/packet_composition.rs`, unit tests |

Each spec names the source lines it follows in its header. Every
property but three has a configuration that must fail on it for the
reason its first line gives (`\* expect violation: <Property>`).
`TypeOK` is the type invariant; `WithinLimit` follows from the admission
test alone and `CommitServesAll` from the commit step, and no flag of
either model breaks them.

## Bugs found

Four, each fixed with a test that fails without the fix.

| Bug | Found by | Fix | Test |
|---|---|---|---|
| A TCP may refuse any command for now (`Admit::Blocked`). `Host::command` dropped a refused control. A refused `Hold` dropped its `PeerGuard`, so an open connection stopped counting against its peer, and a refused `Abort` never reset the connection past the limit. The standard `TcpLayer` never refuses a control, so only a replacement installed with `tcp::Factory` was exposed. | `Admission_dropblocked`, `Admission_dropblocked_reset` | `Host::controls` in `network/tcp.rs` keeps refused controls in order and `Host::pump` offers them again whenever the host steps the transport. `Listen` and `Connect`, whose answers the caller reads at once, go through `Host::request` and are never queued, so a failed `listen` leaves nothing for the transport to take later. A stopped endpoint drops the queue with what it holds. | `world_layers::a_tcp_that_refuses_commands_for_now_keeps_the_peer_count_and_resets` |
| The dispatcher sent each packet its IP layer handed up to the transport the packet named. A replacement IP layer could hand up an observed copy (no IPv4 header check, no host policy) or a packet of another network, and the UDP layer delivered both. | review of `drive` | First a check in `destination` and a network label on each raw packet. Now the types: the IP layer's upper port carries only `CheckedIpPacket`, captured copies are `ObservedIpPacket`, and an endpoint owns its interface, so its raw packets carry no network to check. | The check's world test went with the check; the compile_fail example in the `network::packet` module docs shows an observed copy cannot be handed to a transport |
| `Peers::enter` inserted a zero entry for a peer it refused, so under `Limits::connections_per_peer` of zero the map grew by one entry for every address that tried. | the test; no `kani/peers.rs` exists in the tree or its history | `enter` reads the count and inserts only when it admits. | `hosts::tests::a_refused_peer_leaves_nothing_counted` |
| `packet::Framed` handed up a second `PacketEvent::Ended` when the stream was reset after its end, which a peer may do. | review | A reset after the end ends nothing more. | `packet::framed::tests::a_reset_after_the_end_ends_the_packets_once` |

## What was checked

**Staging is transactional.** `tla/Staging.tla` follows
`Installation::place_inner`, `place_on_lan` and `gateway` across both of a
host's addresses: `Machine::stage` (an existing machine, or a new one with
its IP layer, TCP, UDP and dispatcher built and not started),
`Machine::prepare` binding sockets and listeners one declaration at a time
with any one failing, the join that may fail after preparation, and the
commit that publishes routes, starts the dispatchers and attaches the
application factories. Installations repeat, and the initial world has any
machines with any ports.

| Property | Meaning |
|---|---|
| `RouteOnlyToMachines`, `RunsOnlyInTheWorld`, `FactoriesOnlyOnServedPorts` | nothing is visible before commit: no route, running dispatcher or attached factory for a machine or port the world does not have |
| `ServedOnlyInstalled` | an application is built only for a port its machine serves |
| `OneDispatcher` | each machine has one dispatcher, so one IP layer |
| `FailureLeavesTheWorld` | a failed installation leaves the world as it found it, with nothing bound |
| `CommitServesAll` | a committed one serves every declaration at every address, each port with its factory |

**Admission goes through the transport boundary.** `tla/Admission.tla`
follows the listener's `budget` selector, which admits or refuses a child
before `Children` builds its application, `Peers::admit_transport`,
`GoneWatch::hold_until_gone` and `reset`, `Host::control` and its queue,
`Children::close_finished`, and a transport that implements the `Tcp`
contract and may refuse control commands for now. The host has no way to
admit, reset or release but the boundary.

| Property | Meaning |
|---|---|
| `CountedUntilGone` | an admitted connection counts against its peer until the transport says it is gone, through every closing state, whatever its application does |
| `NotHeldWhenGone` | the transport keeps no count of a connection that is gone |
| `WithinLimit` | a peer never has more counted than it may |
| `BuiltOnlyAdmitted` | an application is built only for an admitted connection |
| `RefusedAreReset` | a refused connection is reset |
| `GoneReleases` | the count of a connection that is gone is let go |

The fairness asks that a transport that refuses for now takes a command
offered again and again (strong fairness on the offer). Without that a
transport could refuse forever, and no host could do better.

`BuiltOnlyAdmitted` covers the peer limit, whose selector runs before
the factory. The port's `Counted` limit (`StackAccept::stack`, hosts.rs
242-247) runs inside the factory: it holds and resets through the same
boundary, and a connection it refuses gets an empty `Tunnel` stack in
place of the application. The `Tcp` contract lets a transport release
what `Hold` kept when the connection is gone or when it is forgotten
(`TcpNotice::Gone`); the transport modeled releases at gone, as the
standard one does, so `NotHeldWhenGone` asks that of a replacement,
where the contract asks only `GoneReleases`.

**Each packet passes exactly one IP layer, and only checked packets reach
the host's transports.** A world machine's only packet
path is `drive`, built once per machine by `Machine::stage` through
`network::endpoint::prepare`; `OneDispatcher` checks that staging never
builds a second. The UDP facade of a machine (`udp::Endpoint`) and its TCP
handles are views of the transports `drive` owns, with no IP layer of their
own. The endpoint owns its interface, so every packet it takes in is of
its own network, and the IP layer's upper port carries `CheckedIpPacket`,
which a captured copy (`ObservedIpPacket`) is not: a replacement IP layer
cannot hand a transport an observed copy, and the compile_fail example in the
`network::packet` module docs checks that. `kani/dispatch.rs` has one harness on the
production `destination`, a child module of `network/endpoint.rs` under
`cfg(kani)`, with no stubs. `a_host_packet_goes_only_to_its_transport`:
a 28-byte IPv4 packet from 10.0.0.2 to 10.0.0.1 with any protocol,
"don't fragment" or not, any eight payload bytes and a header checksum
that verifies or is wrong, taken in by the standard `IpLayer`, reaches
exactly the transport its own bytes name, and only whole with a checksum
that verifies. The header's other fields are fixed, since with every
header byte symbolic the proof ran past 25 minutes. Eight payload bytes
sort TCP, UDP and a plain ICMP message; an ICMP error that quotes a
transport needs more and is not reached. The harness was rewritten for
`CheckedIpPacket` and has not been run since; the run recorded for its
earlier form also covered a network label the endpoint no longer has.

**Application stacks attach directly to transport children, and counts
outlive them.** `tcp::Listener::attach` and `udp::Socket::attach` hand the
transports' children to the stacks; `Admission` checks that closing a
finished application never releases the count.

**The tunnel keeps inner and outer networks apart.** A stream carrying
packet frames feeds an IP layer through its own input path, so
inner fragments never meet the host's reassembly. The new test
`packet_composition::inner_fragments_with_the_outer_keys_stay_in_their_network`
gives the inner network the outer connection's addresses, and both
networks number fragments from the same serial, with overlapping poisoned
copies on both: the echo still comes back whole. The model of one IP layer
fed two networks is `verification/packet-udp/tla/Reassembly.tla`.

## Results

TLC on main e2858ccc4, 2 workers, `-Xmx2g`; each configuration finished
in under 20 seconds.

| Configuration | States generated / distinct | Result |
|---|---|---|
| `Admission_base` | 16,499 / 3,766 | passed |
| `Admission_standard` | 1,237 / 383 | passed |
| `Admission_wide` (four connections) | 292,627 / 57,410 | passed |
| `Admission_appfirst` | 745 / 307 | `BuiltOnlyAdmitted` violated |
| `Admission_childlifetime` | 37 / 28 | `CountedUntilGone` violated |
| `Admission_dropblocked` | 63 / 43 | `CountedUntilGone` violated |
| `Admission_dropblocked_reset` | 7,389 / 1,634 | `RefusedAreReset` violated: the refused connection stays open |
| `Admission_keepsgone` | 221 / 112 | `NotHeldWhenGone` violated |
| `Admission_keepsgone_release` | 22,565 / 5,458 | `GoneReleases` violated: a guard stays held after the connection is gone |
| `Staging_base` | 336,305 / 48,084 | passed |
| `Staging_join` | 336,305 / 48,084 | passed |
| `Staging_attachearly` | 16,575 / 4,949 | `ServedOnlyInstalled` violated |
| `Staging_attachearly_factories` | 2,844 / 2,118 | `FactoriesOnlyOnServedPorts` violated |
| `Staging_buildagain` | 38,614 / 9,055 | `OneDispatcher` violated |
| `Staging_keeponfailure` | 17,067 / 5,017 | `FailureLeavesTheWorld` violated |
| `Staging_publishearly` | 519 / 519 | `RouteOnlyToMachines` violated |
| `Staging_startearly` | 519 / 519 | `RunsOnlyInTheWorld` violated |

`Staging_join` has the same state graph as `Staging_base`: with `Joins`
the last address ends in a "joining" phase, where `Fail` and `Commit`
are enabled exactly as they are after preparation without a join, so a
failed join is covered either way.

## What is left out

- The dispatcher's loop itself (`held`, `raw`, the batching and the
  timers) is not modeled; `verification/packet-udp/tla/Dispatch.tla`
  models the IP layer's slots, and the composition tests run the loop.
- `split_protocols` followed by `tcp::endpoint` or `udp::endpoint`, the
  standalone composition outside world hosts that the CLI, Nuclear and the
  test sandbox use, still passes each packet through two IP layers: the
  splitter's and the facade's dispatcher's. World machines do not use it.
- The bytes, the handshake and the TCP states of a closing connection are
  in `verification/tcp-layer` and `verification/lifecycle`.
- The correspondence between the specs and the code is reviewed by hand,
  not a machine-checked refinement.
- Four things the code does that the specs do not see, each in its
  spec's header: a gateway machine is built and started like a host's
  but never entered in `world.machines`; a listener staged on an
  existing machine completes handshakes into its backlog before commit;
  a UDP port is never shared, where `Staging` shares it; and `Children`
  may refuse an admitted child for its child limit or its sandbox
  budget, closing it with its guard still held in the transport.

## Running

TLC, one config at a time, from `tla/`:

```sh
cd verification/world-layers/tla
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx2g -cp ~/.cache/adorably-fv/tla2tools.jar tlc2.TLC \
    -workers 2 -metadir "$STATES/Admission_base" -config Admission_base.cfg Admission.tla
```

Kani, one harness at a time, from the root of the repository:

```sh
systemd-run --user --scope -q --slice=fictionet-work.slice -p MemoryMax=10G -p MemorySwapMax=0 \
  env CARGO_BUILD_JOBS=4 cargo kani -p fictionet --lib --harness a_host_packet_goes_only_to_its_transport
```

The tests:

```sh
cargo test -p fictionet --test it -- world_layers packet_composition
cargo test -p fictionet --lib -- a_refused_peer_leaves_nothing_counted a_reset_after_the_end
```
