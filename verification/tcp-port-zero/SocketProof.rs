/// A socket listening on `local` (`passive`) or connecting from it to
/// `remote`, after the peer's SYN and then its RST, with the listener it
/// had before them. Checks the SYN on the way: the socket names both ends.
fn reset_after_syn(
    local_port: u16,
    remote_port: u16,
    passive: bool,
) -> (TestSocket, Option<IpListenEndpoint>, IpEndpoint) {
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
    (socket, listener, remote)
}

#[kani::proof]
#[kani::unwind(17)]
fn handshake_reset_preserves_only_passive_listeners() {
    let local_port: u16 = kani::any();
    let remote_port: u16 = kani::any();
    let passive: bool = kani::any();
    let (mut socket, listener, remote) = reset_after_syn(local_port, remote_port, passive);
    assert_eq!(socket.is_open(), passive);
    assert_eq!(socket.listen_endpoint, listener);
    assert!(socket.local_endpoint().is_none());
    assert!(socket.remote_endpoint().is_none());

    socket.close();
    assert!(!socket.is_open());
    socket.listen(remote).unwrap();
    assert_eq!(socket.listen_endpoint, Some(remote.into()));
}

/// The failing control: the reset guard before c27e21447 read a listening
/// port of zero as no listener, so a passive socket on port zero closed on
/// the RST instead of listening again. Must fail on "a passive socket
/// listens again after a handshake reset".
#[kani::proof]
#[kani::unwind(17)]
fn handshake_reset_without_port_zero_listeners() {
    let local_port: u16 = kani::any();
    let remote_port: u16 = kani::any();
    let passive: bool = kani::any();
    let (socket, _, _) = reset_after_syn(local_port, remote_port, passive);
    let listening_again = socket.is_open() && local_port != 0;
    assert!(
        listening_again == passive,
        "a passive socket listens again after a handshake reset"
    );
}
