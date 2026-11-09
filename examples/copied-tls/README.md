# Owning a TLS implementation

This crate owns a copy of the stdlib TLS layer. It depends on Fictionet through public APIs and on the same vendored rustls crate as the SDK. Its deliberate change limits outgoing TLS records to 512 bytes of plaintext. It does not delegate TLS processing to the stdlib layer.

Install the copy through the normal site builder:

```rust
use fictionet::stdlib::services::tls;

let factory = tls::Factory::new(|opening| {
    fictionet_copied_tls::TlsLayer::selecting(move |cx, hello| {
        let selected = (opening.select)(cx, hello.server_name().map(str::to_owned));
        let cx = opening.cx.clone();
        async move {
            let selected = selected.await?;
            Some(std::sync::Arc::new(selected.rustls_config(&cx, std::time::SystemTime::UNIX_EPOCH).ok()?))
        }
    })
    .handshake_by(opening.deadline)
});
// let server = httpd::Server::new(handler).tls_with(certificate).tls_layer(factory);
// web::Site::from_server(server).into_host("site.example");
```

Certificate selection returns `Selected`: the standard DER certificate chain and private key, plus the selected site's ALPN list. The copied layer uses the public `rustls_config` adapter; a different TLS engine reads the DER material directly. Configuration uses `opening.cx`, the connection's stable runtime context, so retaining it does not retain the selection job's context. The stdlib factory separately keeps a bounded cache of configurations for session resumption, isolated by run, certificate and ALPN. This example constructs a fresh configuration for every handshake and does not exercise resumption; a copied implementation that needs it must retain its engine's session state with the same isolation.

`Secure` provides the `Chain<TlsLayer, Later<Application>>` composition and defers the application until the copy reports successful negotiation. The same factory installs on `dns::encrypted::Fronts` with `tls_layer`. Sites sharing one address and port use the first installed site's TLS factory.

The world tests fetch a large site over HTTP/1.1 and HTTP/2, verify both ALPN and the response version, and parse the received ciphertext to verify the smaller records. They also exchange DNS queries over TLS and over both HTTPS versions using this same copied layer and an independent query service.

A second world installs a small, separate HTTP/1 application on a later site sharing the first site’s listener, while retaining stdlib TLS and HTTP/2. The first site keeps its standard application. A custom ALPN identifier selects an echo application on the later site. That example serves one request per connection with the public HTTP wire codec and a `Tunnel` layer; it is intentionally not a general HTTP server. The HTTP/2 branch calls the public `http_for` builder and retains the site's routing handler.

Run with `cargo test -p fictionet-copied-tls`.
