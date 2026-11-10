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
        let tcp = TcpRepr::parse_with(&packet, &src, &dst, self.ignore_malformed_options).ok()?;
        // The connection that owns the tuple: the segment is its or no
        // socket's.
        let owner = self.ingress_target.filter(|&target| {
            sockets
                .try_get(target)
                .is_some_and(|socket| socket.state() != crate::socket::tcp::State::Listen)
        });
        let accepted = match owner {
            Some(target) => sockets
                .get(target)
                .accepts(self, &ip, &tcp)
                .then_some(target),
            None => sockets
                .iter()
                .find(|(_, socket)| socket.accepts(self, &ip, &tcp))
                .map(|(handle, _)| handle),
        };
        if let Some(handle) = accepted {
            return sockets
                .get_mut(handle)
                .process(self, &ip, &tcp, packet.options());
        }
        // A reset never answers another reset, and a host set to answer
        // nothing for a closed port answers nothing.
        (self.reset_closed_ports && tcp.control != TcpControl::Rst)
            .then(|| crate::socket::tcp::Socket::rst_reply(&ip, &tcp))
    }
}
