# A custom Modbus gateway

The gateway accepts a nonzero Modbus protocol identifier. Its service runs on
a `Net`. A `DashboardObserver` installs its presenter, which uses the copied
parser. The example sends a request that the standard parser refuses, reads
holding register 42, and exits. It takes no arguments and serves no observation
socket. See [Fictionet Observe](../../observe/README.md) to serve a collector's
handle and connect with `fictionet observe --observation unix:PATH`.

Run it without external networking:

```sh
cargo run --locked --example custom_protocol
```

The teaching change is in the parser: the copy accepts nonzero protocol
identifiers in the MBAP header, which the standard parser rejects. The
identifier is not kept in `Frame`, and the writer still emits zero, including
in replies. The example sends identifier 1 and checks that register 42
returns `0xc0de`.

The source comparison also includes differences in macro usage for error
formatting, framing and test assertions. It shows more than the parser change:

```sh
diff -u src/stdlib/protocols/modbus.rs demos/custom_protocol/modbus.rs
```

See [Changing a protocol by copying it](../../src/stdlib/mod.rs).
