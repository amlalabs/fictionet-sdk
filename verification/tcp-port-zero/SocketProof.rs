#[kani::proof]
#[kani::unwind(17)]
fn handshake_reset_preserves_only_passive_listeners() {
    let local_port: u16 = kani::any();
    let remote_port: u16 = kani::any();
    let passive: bool = kani::any();
    let mut socket = socket();
    let local = IpEndpoint {
        port: local_port,
        ..LOCAL_END
    };
    let remote = IpEndpoint {
        port: remote_port,
        ..REMOTE_END
    };
    if passive {
        socket.listen(local).unwrap();
    } else {
        socket
            .socket
            .connect(&mut socket.cx, remote, local)
            .unwrap();
    }
    let listener = socket.listen_endpoint;
    let syn = TcpRepr {
        src_port: remote_port,
        dst_port: local_port,
        control: TcpControl::Syn,
        seq_number: REMOTE_SEQ,
        ack_number: None,
        ..SEND_TEMPL
    };
    send(&mut socket, Instant::ZERO, &syn);
    assert_eq!(socket.local_endpoint(), Some(local));
    assert_eq!(socket.remote_endpoint(), Some(remote));
    let reset = TcpRepr {
        control: TcpControl::Rst,
        seq_number: syn.seq_number + 1,
        ..syn
    };
    send(&mut socket, Instant::ZERO, &reset);
    assert_eq!(socket.is_open(), passive);
    assert_eq!(socket.listen_endpoint, listener);
    assert!(socket.local_endpoint().is_none());
    assert!(socket.remote_endpoint().is_none());

    socket.close();
    assert!(!socket.is_open());
    socket.listen(remote).unwrap();
    assert_eq!(socket.listen_endpoint, Some(remote.into()));
}
