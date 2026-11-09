# TLS layer

The TLA+ models of the server TLS layer (`tla/Layer.tla`, for
`src/stdlib/services/tls/layer.rs` as `Driver` and `Harness` drive it) and
of write cancellation in the live connection (`tla/Write.tla`, for
`Opened::poll_write` in `src/stdlib/services/stack/open.rs`), the Kani
proofs over the layer's write accounting (`kani/LayerProof.rs`), and the
tests that the crypto provider draws only from the entropy it was given
(`entropy.rs`). What each covers, what it leaves out, and the two bugs it
found are in [VERIFICATION.md](VERIFICATION.md).

Each `.tla` has configs of the code as it is (`*_base.cfg`) and configs
that drop one rule and name the one property TLC must then violate
(`*_without_<flag>.cfg`):

| Config | Checks |
| --- | --- |
| `Layer_base.cfg` | every invariant of `Layer`, four peer inputs and three commands |
| `Layer_live_base.cfg` | every invariant and the four liveness properties, three peer inputs and two commands |
| `Layer_repeat_base.cfg` | a carrier that reports a byte it never took: completions still never pass what was produced |
| `Layer_without_quietafterclose.cfg` | rustls before fix 1: violates `NoWriteAfterEnd` |
| `Layer_without_droplatedone.cfg` | `on_done` before fix 2: violates `NoWriteAfterEnd` |
| `Layer_without_checkwritten.cfg` | no bound on `Written`, with the broken carrier: violates `Bounded` |
| `Layer_without_countproduced.cfg` | alert bytes not counted in `produced`: violates `Conservation` |
| `Layer_without_fence.cfg` | credit without the fence: violates `CreditAfterDelivery` |
| `Layer_without_takecredit.cfg` | `take_event` keeps the credit it hands up: violates `ExactlyOnce` |
| `Layer_without_checkhandshake.cfg` | writes taken while handshaking: violates `NoWriteBeforeHandshake` |
| `Layer_without_rustlsholdsearlydata.cfg` | rustls's reader yields plaintext mid-handshake: violates `NoReadBeforeHandshake` |
| `Layer_without_checkclosing.cfg` | writes taken after close_notify: violates `NoPlaintextAfterClose` |
| `Layer_without_endafterdrain.cfg` | End before the ciphertext is complete: violates `EndAfterDrainInv` |
| `Layer_without_endonce.cfg` | no `end_sent`: violates `OneEnd` |
| `Layer_without_abortclears.cfg` | `abort` keeps queued output: violates `ResetStops` |
| `Layer_without_creditonwritten_flush.cfg` | `Written` never credits: violates `FlushedMeansCredited` |
| `Layer_without_creditonwritten.cfg` | the same: violates `PendingResolves` |
| `Layer_without_clearalert.cfg` | a written alert is never dropped: violates `FailureReported` |
| `Layer_without_clearalert_close.cfg` | the same: violates `CloseCompletes` |
| `Layer_without_readafterclose.cfg` | no reading after close_notify is queued: violates `PlaintextDelivered` |
| `Write_base.cfg` | every invariant of `Write` |
| `Write_without_matchcontent.cfg` | a retry credited whatever its bytes: violates `ConfirmedIsTheCallers` |
| `Write_without_takepending.cfg` | the earlier write kept after it is settled: violates `ConfirmedOnce` |
| `Write_without_rememberwrite.cfg` | no `pending_write`: violates `NoDuplicate` |
| `Write_without_pumpfirst.cfg` | `poll_write` looks at the earlier write before it runs the stack: violates `NoHang` |

Run one with TLC (Java 11 or later and `tla2tools.jar`):

```sh
cd verification/tls/tla
java -Xmx6g -cp "$TLA2TOOLS" tlc2.TLC -workers 4 -config Layer_base.cfg Layer.tla
java -Xmx6g -cp "$TLA2TOOLS" tlc2.TLC -workers 4 -config Layer_live_base.cfg Layer.tla
java -Xmx2g -cp "$TLA2TOOLS" tlc2.TLC -workers 2 -config Write_base.cfg Write.tla
```

`CHECK_DEADLOCK FALSE` is set because a behavior ends when its inputs and
commands run out, or when the layer returns an error.

The Kani harnesses are compiled into `tls::layer` under `cfg(kani)` and
call the real `on_event`, `on_command`, `advance`, `take_command` and
`take_event`:

```sh
cargo kani -p fictionet --harness a_completion_credits_the_pending_write_once_at_its_fence
cargo kani -p fictionet --harness a_write_is_acknowledged_once_after_its_ciphertext_completes
cargo kani -p fictionet --harness a_reset_drops_what_is_owed_and_sends_only_a_reset
```

The entropy tests are compiled into `tests/it` as a child of `tls.rs`:

```sh
cargo test -p fictionet --test it tls::entropy
```

The November 9 rerun of all three TLS accounting harnesses was interrupted before any completed result; it remains incomplete after the requested proof stop.
