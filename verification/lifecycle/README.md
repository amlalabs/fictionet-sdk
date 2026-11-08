# Connection lifecycle

The TLA+ model of one TCP connection's life (`tla/Conn.tla`, for
`src/stdlib/network/tcp/engine.rs` and the handles in `tcp.rs`). What it
models, what it leaves out, and what it found is in
[VERIFICATION.md](VERIFICATION.md), which also says where the obligations
of the serving engine's model and proofs went when the engine was deleted.

The model has a config of the code as it is, and configs that keep an
earlier or weakened rule and name the property TLC must then violate:

| Config | Checks |
| --- | --- |
| `Conn.cfg` | every invariant and property of `Conn` |
| `Conn_without_orphantimer.cfg` | no `expire_orphans`: violates `OrphanRemoved` |
| `Conn_without_resetunread.cfg` | a drop with unread bytes closes instead of resetting: violates `DropResetsUnread` |

Run one with TLC (Java 11 or later and `tla2tools.jar`):

```sh
cd verification/lifecycle/tla
java -Xmx4g -cp "$TLA2TOOLS" tlc2.TLC -workers 2 -config Conn.cfg Conn.tla
```

Every config finishes in seconds. `CHECK_DEADLOCK FALSE` is set because a
connection that has been removed has nothing left to do.
