# A custom Modbus gateway

The gateway accepts a nonzero Modbus protocol identifier. Its service runs on a `Net`, and its presenter uses the copied parser in the dashboard registry. The example sends a request that the standard parser refuses and reads holding register 42.

Run it without external networking:

```sh
cargo run --offline -j 8 --example custom_protocol
```

The copy differs only in accepting nonzero protocol identifiers and the corresponding docs and tests:

```sh
diff -u src/stdlib/modbus.rs examples/custom_protocol/modbus.rs
```

See [Changing a protocol by copying it](../../src/stdlib/mod.rs).
