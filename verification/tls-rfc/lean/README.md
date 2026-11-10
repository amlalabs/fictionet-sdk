# TLS record layer in Lean

Two Lean 4 models of the vendored rustls's record layer (`rustls/src`), with
the vectors a Rust test replays against the real code. Core Lean only, no
Mathlib.

| File | Proves |
| --- | --- |
| `TlsRecord/Header.lean` | `check`, the rule for a record before it is decrypted or parsed: type, legacy version, empty fragments, and the length limits of RFC 8446 sections 5.1 and 5.2 and RFC 5246 section 6.2 in each read state. An accepted record is within its state's limit (`accept_within_limit`, `accept_unprotected`, `accept_tls13`), has a known type (`accept_known`), and is not empty unless it is application data (`accept_nonempty`); a record is refused for its length exactly when it passes the limit (`overflow_iff`); shortening an accepted record keeps it accepted (`accept_shorter`). |
| `TlsRecord/Nonce.lean` | `run`, the sending side through budget outcomes (paid, refused before encryption, dropped after encryption) and KeyUpdate requests and replies. No (key, sequence number) pair is encrypted twice (`nonce_unique`); the wire starts at key 0, sequence 0, skips no sequence number and changes key only right after a KeyUpdate (`wire_chain`); the wire is the oldest part of what was encrypted, so nothing goes out after a lost record (`wire_suffix`); while the connection has not failed every encrypted record is on the wire or is the one KeyUpdate waiting (`live_loses_nothing`); a refusal before encryption changes nothing (`refused_changes_nothing`). `old` is the code before commit 1f181ea41, and `old.hole_after_drop` and `old.record_without_key_update` are the two holes it had. |
| `TlsRecord/Axioms.lean` | prints the axioms of each headline theorem: Lean's standard three at most. |
| `Gen.lean` | `lake exe gen <dir> <seed>`: `header.txt` (every combination of 9 types, 5 versions and 13 lengths at the limits, in 3 states: 1755 cases) and `nonce.txt` (2000 random sequences of 1 to 12 operations). |

The vectors are replayed by `rustls/src/budget/tests/record_vectors.rs`
(a real server connection in each read state, before keys or after a TLS
1.2 or TLS 1.3 handshake: the error, the alert the client receives, and for
an accepted protected record that it reached decryption) and
`rustls/src/common_state/nonce_vectors.rs` (a real `CommonState` with an
encrypter that writes its key number and sequence number into each record,
and a budget set per operation).

```sh
cargo xtask tls-verify lean           # lake build, no sorry, standard axioms only
cargo xtask tls-verify vectors [seed] # lake exe gen, then both replays
```
