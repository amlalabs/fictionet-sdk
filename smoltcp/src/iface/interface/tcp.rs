use super::*;

impl InterfaceInner {
    pub(crate) fn process_tcp<'a>(
        &mut self,
        sockets: &mut SocketSet,
        ip: IpRepr,
        payload: &'a [u8],
    ) -> Option<(IpRepr, TcpRepr<'a>)> {
        let (src, dst) = (ip.src_addr(), ip.dst_addr());
        if src.is_unspecified() || dst.is_unspecified() {
            return None;
        }
        let packet = TcpPacket::new_checked(payload).ok()?;
        let tcp = TcpRepr::parse(&packet, &src, &dst).ok()?;
        for (_, socket) in sockets.iter_mut() {
            if socket.accepts(self, &ip, &tcp) {
                return socket.process(self, &ip, &tcp);
            }
        }
        // A reset never answers another reset.
        (tcp.control != TcpControl::Rst).then(|| crate::socket::tcp::Socket::rst_reply(&ip, &tcp))
    }
}
