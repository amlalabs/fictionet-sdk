# A custom Modbus gateway

The gateway accepts a nonzero Modbus protocol identifier. Its service runs on a `Net`, and its presenter uses the copied parser in the dashboard registry. The example sends a request that the standard parser refuses and reads holding register 42.

Run it without external networking:

```sh
cargo run --offline -j 8 --example custom_protocol
```

The teaching change is in the parser: the copy accepts nonzero protocol
identifiers in the MBAP header, which the standard parser rejects. The
identifier is not kept in `Frame`, and the writer still emits zero, including
in replies. The example sends identifier 1 and checks that register 42
returns `0xc0de`.

The source comparison also includes differences in macro usage for error
formatting, framing and test assertions. It shows more than the parser change:

```sh
diff -u src/stdlib/protocols/modbus.rs examples/custom_protocol/modbus.rs
```

See [Changing a protocol by copying it](../../src/stdlib/mod.rs).
