//! Feature-specific runtime contracts.

#[cfg(feature = "std")]
#[test]
fn http_alpn_matches_transport_features() {
    use fictionet::stdlib::{httpd, net::PortServer};
    let server = httpd::Server::new(httpd::Router::new());
    #[cfg(feature = "tokio")]
    assert_eq!(server.alpn(), [b"h2".to_vec(), b"http/1.1".to_vec()]);
    #[cfg(not(feature = "tokio"))]
    assert_eq!(server.alpn(), [b"http/1.1".to_vec()]);
}

#[test]
fn mutex_guard_excludes_another_lock() {
    let mutex = fictionet::sync::Mutex::new(0);
    let mut guard = mutex.lock();
    assert!(mutex.try_lock().is_none());
    *guard = 9;
    drop(guard);
    assert_eq!(*mutex.try_lock().unwrap(), 9);
}

#[cfg(all(feature = "std", not(feature = "observe"), not(target_arch = "wasm32")))]
#[test]
fn world_socket_refuses_disabled_observer_sessions() {
    let path = std::env::temp_dir().join(format!("fictionet-features-{}.sock", std::process::id()));
    let (attacher, _attachments) = fictionet::attachments();
    let listening = fictionet::listen(fictionet::WorldSocket::UnixSocket(path.clone()), attacher)
        .expect("listen on the test socket");
    let error = match fictionet::relay::observer::Client::connect(path.to_str().unwrap(), "test") {
        Ok(_) => panic!("observer sessions must be refused without observe"),
        Err(error) => error,
    };
    assert!(error.contains("observer sessions are disabled"), "{error}");
    drop(listening);
}
