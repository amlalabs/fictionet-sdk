use super::*;

impl InterfaceInner {
    pub(super) fn process_ipv4<'a>(
        &mut self,
        sockets: &mut SocketSet,
        packet: &Ipv4Packet<&'a [u8]>,
    ) -> Option<(IpRepr, TcpRepr<'a>)> {
        let ip = Ipv4Repr::parse(packet).ok()?;
        if !ip.src_addr.x_is_unicast()
            || !self.has_ip_addr(ip.dst_addr)
            || ip.next_header != IpProtocol::Tcp
        {
            return None;
        }
        self.process_tcp(sockets, ip.into(), packet.payload())
    }
}
