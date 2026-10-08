# A world in the browser

This example runs a small Fictionet world inside a JavaScript engine, built
for `wasm32-unknown-unknown`. The world has one website, `hello.test` at
203.0.113.10, served by `web::Sites` with DNS at the gateway, 10.0.0.1.
The same process plays one sandbox: an IP stack of its own, made from
`ip::split_protocols`, `tcp::endpoint` and `udp::endpoint`, on the `End` returned by
`Attacher::attach`. The sandbox asks DNS for `hello.test` over UDP, opens a
TCP connection to the address it got, and sends one GET with hyper's
client. Over HTTPS, the sandbox runs a rustls client, and the site
answers with a certificate from a CA the example makes when it starts.

Every packet goes through smoltcp, in the world and in the sandbox. There
are no sockets, threads or files, so the same code runs natively and in a
browser.

## Run the tests

On the host:

```sh
cargo test
```

In Node.js, with `wasm-pack` (it fetches the matching
`wasm-bindgen-test-runner` on first use):

```sh
wasm-pack test --node
```

The tests make requests over HTTP/1.1 and HTTP/2, each plain and over
HTTPS. Three of them run the world under `fictionet::block_on`, which in a
JavaScript engine fires the timers itself and spins between them. The
fourth awaits it on the event loop, as a page would, where the timers fire
from `setTimeout`.

ring's C code compiles for wasm32 with clang. A clang that lists `wasm32`
in `clang --print-targets` is enough; set `CC_wasm32_unknown_unknown` to
pick a different one.

## Build it for a page

```sh
wasm-pack build --release --target web
```

The package exports one function, `fetchText(https, http2)`, which runs
the world and resolves to the status line and body:

```js
import init, { fetchText } from './pkg/wasm_world.js';
await init();
console.log(await fetchText(true, true));
// 200 HTTP/2.0 from 203.0.113.10
// hello from hello.test: GET /from-the-browser
```

The release build is about 1.9 MB of wasm after `wasm-bindgen` and
`wasm-opt`, and about 750 KB gzipped.

## What a browser build cannot serve

HTTP/1.1 is served by the stdlib's own `httpd::Http1` service, which reads
only Fictionet's clock, so it works here as on the host. Two cases go
through hyper or h2, which read `std`'s clock, and that panics on
`wasm32-unknown-unknown`:

- A request that asks to switch protocols (an HTTP/1 Upgrade, such as a
  WebSocket handshake). `httpd` hands it to hyper's HTTP/1 server, which
  calls `SystemTime::now`.
- An HTTP/2 stream that the world's side resets, for example when a
  handler fails partway through a body. The h2 crate notes the time with
  `Instant::now`.
