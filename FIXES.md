# Literal TCP port 0: the fixes

Four bugs came out of the review passes over `c27e21447`. Each had port 0
read as a sentinel somewhere ("any port" or "no port") where every other
path reads it as a port. All four are fixed on this branch, one commit each,
and the tests that showed them pass.

## What changed

**UDP services declared on port 0** (`src/stdlib/world/net/hosts.rs`).
`Host::udp(0, ..)` binds an ephemeral port, but `Machine` told the service
it was at port 0 and recorded 0 in a `udp_ports` set of its own, so the
service's local address was wrong and a second `udp(0, ..)` on the same
machine was refused as "already served". The set is gone. The socket is
bound in `prepare`, so a duplicate port is what `bind` refuses, and the
service is started with `socket.local_addr()`, the port it has.

**The attach stack** (`cli/src/proxy/stack.rs`). `Stack::connect` returned
`Fail::BadAddress("port 0")` before sending anything, so the SOCKS5 door
answered reply 8 for a port the world may listen on. The check is deleted;
`BadAddress` is for IPv6 only.

**The HTTP door** (`cli/src/attach_proxy/http.rs`). `authority` dropped a
port of 0 (`.filter(|&p| p != 0)`), so `CONNECT host:0` and
`GET http://host:0/` were 400s. The filter is deleted, and
`example.test:0` is no longer among the bad targets in `connect_targets`.

**`cargo xtask port-zero-verify`** (`xtask/src/port_zero_verify.rs`). Runs
the TLC configs in `verification/tcp-port-zero/` with the runner of
`mptcp-verify tlc`, whose `tlc` now takes the directories it reads and
writes instead of the MPTCP paths. `Socket_nonzero_reset.cfg` carries the
`\* expect violation: PassiveResetRestores` line that runner reads, so the
negative control passes only by failing on that property. `MODEL.md` says
so. The model itself did not change: it covers TCP sockets, binding and
plain TCP service preparation, which these fixes leave as they were; UDP
services and the attach doors are outside it.

## How it was checked

Every Cargo command ran with `CARGO_TARGET_DIR=.pz-fix-target`,
`CARGO_BUILD_JOBS=6`, under `systemd-run --user --scope -p MemoryMax=16G`.

The tests that showed each bug, run against the unfixed code first and the
fixed code after:

| Test | Unfixed | Fixed |
| --- | --- | --- |
| `services::network::ephemeral_udp_service_reports_its_wire_endpoint` (`tests/it`) | failed: reported address differs from the wire source | passes |
| `services::network::two_ephemeral_udp_services_fit_on_one_machine` (`tests/it`) | failed: second service refused | passes |
| `proxy::stack::tests::port_zero_reaches_a_listener_through_the_stack` (`fictionet-cli` binary) | — (new) | passes |
| `attach_proxy::http::tests::port_zero_targets_are_literal` (`fictionet-cli` library) | — (new) | passes |
| `proxy::port_zero_through_the_http_door` (`cli/tests/it`) | failed: 400 | passes |
| `proxy::port_zero_through_the_socks5_door` (`cli/tests/it`) | failed: SOCKS5 reply 8 | passes |

The tests next to them:

- `cargo test -p fictionet --test it -- services::network::`: 31 passed.
- `cargo test -p fictionet-cli --lib -- proxy::stack:: attach_proxy::http::`: 8 passed.
- `cargo test -p fictionet-cli --bins -- proxy::stack::`: 2 passed.
- `cargo test -p fictionet-cli --test it -- proxy::`: 22 passed.

The model checks, through `cargo xtask port-zero-verify` with
`JAVA=~/.local/jdk21/bin/java` and
`TLA2TOOLS=~/.cache/adorably-fv/tla2tools.jar`: `Binding_allocation`
(288 distinct states, depth 7), `Binding_preparation` (9,986 distinct
states, depth 14) and `Socket` (1,072 distinct states, depth 6) pass with
every property checked together; `Socket_nonzero_reset` violates
`PassiveResetRestores` (273 distinct states, depth 4), as it must. These
match the counts in `MODEL.md`.

`cargo fmt -p fictionet -p fictionet-cli -p xtask -- --check` and
`cargo clippy -p fictionet -p fictionet-cli -p xtask --all-targets -- -D warnings`
are clean.

No XDP, AF_XDP or vfio program ran. Nothing was pushed.
