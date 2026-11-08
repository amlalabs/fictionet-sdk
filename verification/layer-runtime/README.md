# Layer runtime verification

The code that runs layer stacks on live sockets, and the first stacks
ported onto it: `layer::Framed` (`src/stdlib/layer/framed.rs`), the
runners `services::stack::stream` and `services::stack::datagrams`
(`src/stdlib/services/stack/`, the stream runner in `live.rs`) that `Host::tcp_stack` and
`Host::udp_stack` serve ports with, the Nuclear controllers' Modbus/TCP
stack (`demos/nuclear/world/src/plc.rs`) and the Search time server
(`demos/search/world/src/ntp.rs`).

| Part | What it is | Where |
|---|---|---|
| TLA+ | The two runners' loops over an abstract stack and an abstract peer, checked with TLC, each rule with a configuration that turns it off and must fail | [`tla/`](tla/) |
| Kani | Bounded proofs over the production Rust of `Framed`, the connection count port servers keep (`Counted`), the PLC server, the time server and `ntp::server_reply` | [`kani/`](kani/) |

[VERIFICATION.md](VERIFICATION.md) says what each model and proof covers,
what it leaves out, the results, and the three bugs found.

```sh
# TLC. Every *_base.cfg must pass; every *_without_<flag>.cfg must violate
# the one property it names. StreamRunner_halfclose.cfg must pass;
# StreamRunner_without_finishinput.cfg preserves its old counterexample.
cd verification/layer-runtime/tla
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar \
  tlc2.TLC -workers 4 -metadir ~/.cache/adorably-fv/states/stream \
  -config StreamRunner_base.cfg StreamRunner.tla
systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 \
  ~/.cache/adorably-fv/jdk/bin/java -Xmx6g -cp ~/.cache/adorably-fv/tla2tools.jar \
  tlc2.TLC -workers 4 -metadir ~/.cache/adorably-fv/states/datagrams \
  -config DatagramRunner_base.cfg DatagramRunner.tla

# Kani, from the root of the repository. A --harness filter matches by
# substring and runs the harnesses one after another; none needs more
# than a few GiB.
cd ../../..
cargo kani -p fictionet --harness the_buffer_is_charged_before_bytes_are_taken \
  --harness every_charge_comes_back --harness units_come_up_in_order \
  --harness a_decoder_failure_comes_up_once_then_ended \
  --harness a_reply_comes_only_for_a_request --harness a_header_of_mode_0_6_or_7 \
  --harness connections_are_counted_up_to_the_maximum
cargo kani -p nuclear-world --harness each_request_gets_one_answer_in_order \
  --harness a_pipelined_request_waits -Z unstable-options \
  --cbmc-args --unwindset "$(cat verification/layer-runtime/kani/plant.unwindset)"
cargo kani -p web-world --harness the_time_server \
  --harness one_conversation_answers_each_request_in_turn

# The regressions for the bugs.
cargo test -p fictionet --lib -- layer::framed services::stack
```

TLC 2.19; Kani 0.68 with CBMC 6.11.
